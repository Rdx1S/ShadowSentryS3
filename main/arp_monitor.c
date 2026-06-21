#include "arp_monitor.h"
#include "wifi_manager.h"
#include "log_store.h"
#include "telegram.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "lwip/inet.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

// Fall back to sane defaults so the module also builds against a config.h that
// predates the ARP-monitor block (config.h values, if present, win — they are
// included above this point).
#ifndef ARP_MONITOR_ENABLE
#define ARP_MONITOR_ENABLE      1
#endif
#ifndef ARP_SCAN_INTERVAL_S
#define ARP_SCAN_INTERVAL_S     8
#endif
#ifndef ARP_ALERT_COOLDOWN_S
#define ARP_ALERT_COOLDOWN_S    300
#endif

static const char *TAG = "ARP-MON";

// Learned-once baseline for the gateway's MAC.
static uint8_t  s_gw_mac[6];
static bool     s_gw_learned = false;

// Debounce: suppress repeat alerts about the same attacker MAC for a cooldown.
static uint8_t  s_last_mac[6];
static time_t   s_last_alert = 0;

static inline bool mac_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

static inline bool mac_is_zero(const uint8_t *m)
{
    static const uint8_t zero[6] = {0};
    return memcmp(m, zero, 6) == 0;
}

// Emit one ARP anomaly through the same pipeline the honeypots use.
static void raise_alert(uint32_t spoof_ip, const uint8_t mac[6], const char *detail)
{
    time_t now = time(NULL);

    // One attacker MAC can trip both checks in the same scan; rate-limit it.
    if (mac_eq(mac, s_last_mac) && (now - s_last_alert) < ARP_ALERT_COOLDOWN_S)
        return;
    memcpy(s_last_mac, mac, 6);
    s_last_alert = now;

    attack_log_t e = {
        .type      = ATTACK_ARP,
        .src_ip    = spoof_ip,
        .timestamp = (uint32_t)now,
    };
    memcpy(e.src_mac, mac, 6);
    strlcpy(e.payload, detail, sizeof(e.payload));

    ESP_LOGW(TAG, "%s", detail);
    log_store_append(&e);
    telegram_notify(&e);
}

void arp_monitor_task(void *arg)
{
#if !ARP_MONITOR_ENABLE
    ESP_LOGI(TAG, "ARP-spoof monitor disabled (ARP_MONITOR_ENABLE=0)");
    vTaskDelete(NULL);
#else
    ESP_LOGI(TAG, "ARP-spoof monitor running (scan=%ds, cooldown=%ds)",
             ARP_SCAN_INTERVAL_S, ARP_ALERT_COOLDOWN_S);

    wifi_arp_entry_t tbl[WIFI_ARP_MAX_ENTRIES];

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(ARP_SCAN_INTERVAL_S * 1000));

        uint32_t gw_ip = 0;
        bool have_gw = wifi_manager_get_gateway(&gw_ip);

        int n = wifi_manager_arp_snapshot(tbl, WIFI_ARP_MAX_ENTRIES);
        if (n <= 0) continue;

        // ── Check 1: gateway MAC baseline / change ──────────────────────────
        if (have_gw) {
            for (int i = 0; i < n; i++) {
                if (tbl[i].ip != gw_ip || mac_is_zero(tbl[i].mac)) continue;

                if (!s_gw_learned) {
                    memcpy(s_gw_mac, tbl[i].mac, 6);
                    s_gw_learned = true;
                    char ms[WIFI_MAC_STR_LEN];
                    wifi_manager_format_mac(s_gw_mac, ms, sizeof(ms));
                    ESP_LOGI(TAG, "Gateway MAC baseline learned: %s", ms);
                } else if (!mac_eq(tbl[i].mac, s_gw_mac)) {
                    char nm[WIFI_MAC_STR_LEN], om[WIFI_MAC_STR_LEN], gws[16];
                    wifi_manager_format_mac(tbl[i].mac, nm, sizeof(nm));
                    wifi_manager_format_mac(s_gw_mac,   om, sizeof(om));
                    struct in_addr a = {.s_addr = gw_ip};
                    strlcpy(gws, inet_ntoa(a), sizeof(gws));
                    char detail[128];
                    snprintf(detail, sizeof(detail),
                             "Gateway %s MAC changed %s -> %s (MITM redirect)",
                             gws, om, nm);
                    raise_alert(gw_ip, tbl[i].mac, detail);
                }
                break;  // only one gateway entry expected
            }
        }

        // ── Check 2: one MAC claiming multiple IPs ──────────────────────────
        // A snapshot can show one MAC on two IPs simply because a host changed
        // DHCP lease and lwIP still holds the stale-but-STABLE old mapping. So
        // before alerting we actively re-verify the pair (flush + re-request both
        // IPs, require both to answer with the same MAC). The verify costs ~1s and
        // flushes the ARP cache, so do at most one per scan, and skip it entirely
        // for a MAC already alerted within the cooldown.
        for (int i = 0; i < n; i++) {
            if (mac_is_zero(tbl[i].mac)) continue;
            for (int j = i + 1; j < n; j++) {
                if (tbl[i].ip == tbl[j].ip || !mac_eq(tbl[i].mac, tbl[j].mac))
                    continue;
                char ms[WIFI_MAC_STR_LEN], ip1[16], ip2[16];
                wifi_manager_format_mac(tbl[i].mac, ms, sizeof(ms));
                struct in_addr a1 = {.s_addr = tbl[i].ip};
                struct in_addr a2 = {.s_addr = tbl[j].ip};
                strlcpy(ip1, inet_ntoa(a1), sizeof(ip1));
                strlcpy(ip2, inet_ntoa(a2), sizeof(ip2));

                // Already alerted on this MAC recently — don't churn the cache.
                if (mac_eq(tbl[i].mac, s_last_mac) &&
                    (time(NULL) - s_last_alert) < ARP_ALERT_COOLDOWN_S) {
                    i = n;
                    break;
                }

                if (wifi_manager_arp_confirm_pair(tbl[i].ip, tbl[j].ip, tbl[i].mac)) {
                    char detail[128];
                    snprintf(detail, sizeof(detail),
                             "MAC %s claims %s and %s (ARP cache poisoning)",
                             ms, ip1, ip2);
                    raise_alert(tbl[i].ip, tbl[i].mac, detail);
                } else {
                    ESP_LOGI(TAG, "MAC %s on %s and %s not confirmed live "
                             "(stale entry / DHCP lease change) — ignoring",
                             ms, ip1, ip2);
                }
                i = n;          // one verification (and at most one report) per scan
                break;
            }
        }
    }
#endif  // ARP_MONITOR_ENABLE
}
