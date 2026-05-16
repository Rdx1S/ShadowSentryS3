#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"

#include "wifi_manager.h"
#include "log_store.h"
#include "rtsp_trap.h"
#include "http_trap.h"
#include "telnet_trap.h"
#include "admin_panel.h"
#include "telegram.h"

static const char *TAG = "MAIN";

void app_main(void)
{
    // NVS — required for WiFi
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "╔══════════════════════════════════╗");
    ESP_LOGI(TAG, "║   ShadowSentry S3  v1.0          ║");
    ESP_LOGI(TAG, "║   Edge Deception HoneyPot        ║");
    ESP_LOGI(TAG, "╚══════════════════════════════════╝");

    log_store_init();
    wifi_manager_init();
    wifi_manager_wait_for_ip();

    char ip[WIFI_IP_STR_LEN];
    wifi_manager_get_ip_str(ip, sizeof(ip));
    ESP_LOGI(TAG, "Network up — IP %s — starting honeypots", ip);

    // ── Core 0: Hacker World ─────────────────────────────────────────────────
    xTaskCreatePinnedToCore(rtsp_trap_task,   "rtsp",   4096, NULL, 5, NULL, 0);
    xTaskCreatePinnedToCore(http_trap_task,   "http",   4096, NULL, 5, NULL, 0);
    xTaskCreatePinnedToCore(telnet_trap_task, "telnet", 4096, NULL, 5, NULL, 0);

    // ── Core 1: Admin World ──────────────────────────────────────────────────
    xTaskCreatePinnedToCore(telegram_task,    "tg",     6144, NULL, 3, NULL, 1);
    xTaskCreatePinnedToCore(admin_panel_task, "admin",  8192, NULL, 5, NULL, 1);
}
