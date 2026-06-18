#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"

#include "wifi_manager.h"
#include "log_store.h"
#include "rtsp_trap.h"
#include "http_trap.h"
#include "telnet_trap.h"
#include "ssh_trap.h"
#include "ftp_trap.h"
#include "admin_panel.h"
#include "telegram.h"
#include "arp_monitor.h"
#include "geoip.h"
#include "wifi_monitor.h"
#include "config.h"

static const char *TAG = "MAIN";

// ── Task parameters ───────────────────────────────────────────────────────────
//
// Stack budget reasoning (all in bytes):
//
//  rtsp   : buf[512] + resp[256] + b64[128] + decoded[128] + attack_log_t(240)
//           + mbedTLS base64 frame (~800) + lwIP/FreeRTOS overhead (~1200)
//           → 6144 gives ~2.9 KB headroom
//
//  http   : buf[1024] + key[64] + user[32] + pass[64] + path[48] + ua[96]
//           + attack_log_t(240) + overhead (~1200)
//           → 5120 still gives ~2.3 KB headroom
//
//  telnet : user[32] + pass[64] + attack_log_t(240) + overhead (~1200)
//           → 4096 gives ~2.5 KB headroom
//
//  ssh    : line[256] + attack_log_t(240) + overhead (~1200)
//           → 3072 gives ~1.4 KB headroom
//
//  ftp    : line[256] + user[32] + pass[64] + attack_log_t(240) + overhead (~1200)
//           → 3072 gives ~1.3 KB headroom
//
//  tg     : user_h[96] + pass_h[192] + pay_h[384] + msg[768]
//           + body[1280] + json_text[1024] + url[128]
//           + esp_http_client internal frame (~1.5 KB) + overhead (~1 KB)
//           → 8192 gives ~2.8 KB headroom
//
//  admin  : buf[1024] + hdr[160] + expected[128] + b64[128] + decoded[128]
//           + JSON buffer is static (BSS, not stack) + overhead (~1200)
//           → 8192 gives ~5.4 KB headroom

#define STACK_RTSP      6144
#define STACK_HTTP      5120
#define STACK_TELNET    4096
#define STACK_SSH       3072
#define STACK_FTP       3072
#define STACK_TELEGRAM  8192
#define STACK_ADMIN     8192
//  arpmon : tbl[16]×10B (160) + MAC/IP format buffers + detail[128]
//           + overhead (~1200)  → 3072 gives ~1.3 KB headroom
#define STACK_ARPMON    3072
//  geoip  : esp_http_client GET + body[512] + parse temporaries
//           + client internal frame (~1.5 KB) + overhead (~1 KB)
//           → 5120 gives ~2 KB headroom
#define STACK_GEOIP     5120
//  wifimon: promiscuous setup + MAC format buffers + attack_log_t(240)
//           + overhead (~1200)  → 3072 gives ~1.5 KB headroom
#define STACK_WIFIMON   3072

// Priority 5 = equal to lwIP core; keeps honeypot latency low.
// Telegram is 3 — non-critical, may wait behind WiFi driver work on Core 1.
// ARP monitor is 2 — periodic background scan, lowest of the lot.
#define PRIO_HONEYPOT   5
#define PRIO_ADMIN      5
#define PRIO_TELEGRAM   3
#define PRIO_ARPMON     2
#define PRIO_GEOIP      3
#define PRIO_WIFIMON    2

// ── Helper macro ──────────────────────────────────────────────────────────────

// Spawns a pinned task and halts boot with a descriptive message if
// allocation fails (out-of-heap is unrecoverable at this stage).
#define SPAWN(func, name, stack, prio, core)  do {                      \
    BaseType_t _r = xTaskCreatePinnedToCore(                            \
        (func), (name), (stack), NULL, (prio), NULL, (core));           \
    if (_r != pdPASS) {                                                 \
        ESP_LOGE(TAG, "FATAL: failed to create task '%s' "             \
                 "(stack=%u, free heap=%lu)", (name), (stack),          \
                 (unsigned long)esp_get_free_heap_size());              \
        configASSERT(0);                                                \
    }                                                                   \
    ESP_LOGD(TAG, "Task '%s' spawned on core %d "                      \
             "(stack=%u, free heap=%lu)",                               \
             (name), (core), (stack),                                   \
             (unsigned long)esp_get_free_heap_size());                  \
} while(0)

// ── Boot ──────────────────────────────────────────────────────────────────────

void app_main(void)
{
    // ── NVS (required by WiFi driver) ────────────────────────────────────────
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition corrupt — erasing and re-initialising");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // ── Banner ───────────────────────────────────────────────────────────────
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "  ╔══════════════════════════════════════╗");
    ESP_LOGI(TAG, "  ║    ShadowSentry S3  v1.0             ║");
    ESP_LOGI(TAG, "  ║    Edge Deception HoneyPot           ║");
    ESP_LOGI(TAG, "  ║    ESP32-S3  |  ESP-IDF v5.x         ║");
    ESP_LOGI(TAG, "  ╚══════════════════════════════════════╝");
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "Free heap at boot: %lu B  (internal: %lu B)",
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));

    // ── Storage ──────────────────────────────────────────────────────────────
    ESP_LOGI(TAG, "Mounting SPIFFS and loading attack log...");
    log_store_init();
    ESP_LOGI(TAG, "All-time attack count from flash: %lu",
             (unsigned long)log_store_total_count());

    // ── WiFi ─────────────────────────────────────────────────────────────────
    ESP_LOGI(TAG, "Connecting to \"%s\"...", WIFI_SSID);
    wifi_manager_init();
    wifi_manager_wait_for_ip();     // blocks until DHCP assigns an address

    char ip[WIFI_IP_STR_LEN];
    wifi_manager_get_ip_str(ip, sizeof(ip));

    // ── Startup summary ──────────────────────────────────────────────────────
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "  Device ready — %s", ip);
    ESP_LOGI(TAG, "  ┌─ Core 0  Hacker World ──────────────────");
    ESP_LOGI(TAG, "  │  RTSP    port %-5d  (Fake Hikvision camera)",  RTSP_PORT);
    ESP_LOGI(TAG, "  │  HTTP    port %-5d  (Fake NVR login page)",    HTTP_PORT);
    ESP_LOGI(TAG, "  │  Telnet  port %-5d  (Fake Ubuntu 20.04)",      TELNET_PORT);
    ESP_LOGI(TAG, "  │  SSH     port %-5d  (Fake OpenSSH 8.9p1)",     SSH_PORT);
    ESP_LOGI(TAG, "  │  FTP     port %-5d  (Fake vsFTPd 3.0.5)",      FTP_PORT);
    ESP_LOGI(TAG, "  ├─ Core 1  Admin World ───────────────────");
    ESP_LOGI(TAG, "  │  Panel   http://%s:%d", ip, ADMIN_PORT);
#if MDNS_ENABLE
    ESP_LOGI(TAG, "  │          http://%s.local:%d  (stable name)",
             MDNS_HOSTNAME, ADMIN_PORT);
#endif
    ESP_LOGI(TAG, "  │  Telegram alerts: %s",
             (TELEGRAM_BOT_TOKEN[0] == 'Y') ? "NOT CONFIGURED" : "enabled");
    ESP_LOGI(TAG, "  │  ARP-spoof / MITM monitor: active");
    ESP_LOGI(TAG, "  │  Threat-intel enrichment: ip-api.com");
    ESP_LOGI(TAG, "  │  Wi-Fi threat monitor: deauth/disassoc flood");
    ESP_LOGI(TAG, "  └─────────────────────────────────────────");
    ESP_LOGI(TAG, "");

    // ── Core 0 — Hacker World ────────────────────────────────────────────────
    // Each honeypot is a blocking accept loop; lower-priority tasks (Core 1)
    // cannot starve because the honeypots sleep inside accept() most of the time.
    SPAWN(rtsp_trap_task,   "rtsp",   STACK_RTSP,     PRIO_HONEYPOT, 0);
    SPAWN(http_trap_task,   "http",   STACK_HTTP,     PRIO_HONEYPOT, 0);
    SPAWN(telnet_trap_task, "telnet", STACK_TELNET,   PRIO_HONEYPOT, 0);
    SPAWN(ssh_trap_task,    "ssh",    STACK_SSH,      PRIO_HONEYPOT, 0);
    SPAWN(ftp_trap_task,    "ftp",    STACK_FTP,      PRIO_HONEYPOT, 0);

    // ── Core 1 — Admin World ─────────────────────────────────────────────────
    // Pass IP to telegram before spawning so the task can send the boot alert.
    telegram_set_boot_ip(ip);
    SPAWN(geoip_task,       "geoip",  STACK_GEOIP,    PRIO_GEOIP,    1);
    SPAWN(telegram_task,    "tg",     STACK_TELEGRAM, PRIO_TELEGRAM, 1);
    SPAWN(admin_panel_task, "admin",  STACK_ADMIN,    PRIO_ADMIN,    1);
    SPAWN(arp_monitor_task, "arpmon", STACK_ARPMON,   PRIO_ARPMON,   1);
    SPAWN(wifi_monitor_task,"wifimon",STACK_WIFIMON,  PRIO_WIFIMON,  1);

    ESP_LOGI(TAG, "All tasks spawned — free heap: %lu B",
             (unsigned long)esp_get_free_heap_size());

    // app_main() may return — FreeRTOS scheduler keeps the tasks running.
}
