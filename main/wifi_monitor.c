#include "wifi_monitor.h"
#include "wifi_manager.h"
#include "log_store.h"
#include "telegram.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

// Fall back to safe defaults so the module builds against an older config.h
// (config.h values, included above, take precedence over these).
#ifndef WIFI_MON_ENABLE
#define WIFI_MON_ENABLE             1
#endif
#ifndef WIFI_MON_WINDOW_MS
#define WIFI_MON_WINDOW_MS          2000    // evaluation window
#endif
#ifndef WIFI_MON_DEAUTH_THRESHOLD
#define WIFI_MON_DEAUTH_THRESHOLD   20      // deauth+disassoc frames per window = flood
#endif
#ifndef WIFI_MON_COOLDOWN_S
#define WIFI_MON_COOLDOWN_S         60      // min seconds between flood alerts
#endif

static const char *TAG = "WIFI-MON";

// 802.11 management subtypes (frame-control type == 0).
#define SUBTYPE_DEAUTH    12
#define SUBTYPE_DISASSOC  10

// Counters shared between the promiscuous RX callback (Wi-Fi task) and the
// evaluation task. Guarded by a spinlock — the callback must stay tiny.
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t s_count;          // deauth+disassoc frames in the current window
static uint8_t  s_src[6];         // transmitter MAC of the most recent frame
static uint8_t  s_bssid[6];       // BSSID (addr3) of the most recent frame

// ── Promiscuous RX callback (runs in the Wi-Fi task — keep it minimal) ──────────
static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT || !buf) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = pkt->payload;            // 802.11 frame
    uint8_t fc0 = f[0];
    if (((fc0 >> 2) & 0x3) != 0) return;        // not a management frame
    uint8_t subtype = (fc0 >> 4) & 0xF;
    if (subtype != SUBTYPE_DEAUTH && subtype != SUBTYPE_DISASSOC) return;

    portENTER_CRITICAL(&s_mux);
    s_count++;
    memcpy(s_src,   f + 10, 6);                 // addr2 = transmitter
    memcpy(s_bssid, f + 16, 6);                 // addr3 = BSSID
    portEXIT_CRITICAL(&s_mux);
}

// ── Alert (same pipeline the honeypots use) ─────────────────────────────────────
static void raise_flood_alert(uint32_t count, const uint8_t src[6], const uint8_t bssid[6])
{
    char src_s[WIFI_MAC_STR_LEN], bssid_s[WIFI_MAC_STR_LEN];
    wifi_manager_format_mac(src,   src_s,   sizeof(src_s));
    wifi_manager_format_mac(bssid, bssid_s, sizeof(bssid_s));

    attack_log_t e = {
        .type      = ATTACK_WIFI,
        .src_ip    = 0,                          // radio-layer event — no IP
        .timestamp = (uint32_t)time(NULL),
    };
    memcpy(e.src_mac, src, 6);
    snprintf(e.payload, sizeof(e.payload),
             "Deauth flood: %lu frames/%dms from %s -> BSSID %s",
             (unsigned long)count, WIFI_MON_WINDOW_MS, src_s, bssid_s);

    ESP_LOGW(TAG, "%s", e.payload);
    log_store_append(&e);
    telegram_notify(&e);
}

void wifi_monitor_task(void *arg)
{
#if !WIFI_MON_ENABLE
    ESP_LOGI(TAG, "Wi-Fi threat monitor disabled (WIFI_MON_ENABLE=0)");
    vTaskDelete(NULL);
#else
    // Only management frames reach the callback — keeps CPU cost negligible.
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(promisc_cb);

    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Could not enable promiscuous mode (%s) — monitor off",
                 esp_err_to_name(err));
        vTaskDelete(NULL);
    }
    ESP_LOGI(TAG, "Wi-Fi threat monitor running (deauth flood >= %d / %dms)",
             WIFI_MON_DEAUTH_THRESHOLD, WIFI_MON_WINDOW_MS);

    time_t last_alert = 0;

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(WIFI_MON_WINDOW_MS));

        uint32_t count;
        uint8_t  src[6], bssid[6];
        portENTER_CRITICAL(&s_mux);
        count = s_count;
        memcpy(src, s_src, 6);
        memcpy(bssid, s_bssid, 6);
        s_count = 0;                             // reset window
        portEXIT_CRITICAL(&s_mux);

        if (count >= WIFI_MON_DEAUTH_THRESHOLD) {
            time_t now = time(NULL);
            if (now - last_alert >= WIFI_MON_COOLDOWN_S) {
                last_alert = now;
                raise_flood_alert(count, src, bssid);
            }
        }
    }
#endif  // WIFI_MON_ENABLE
}
