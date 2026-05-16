#include "wifi_manager.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_log.h"
#include "lwip/inet.h"
#include <string.h>

static const char *TAG = "WIFI";

// ── Internal state ────────────────────────────────────────────────────────────

#define WIFI_GOT_IP_BIT BIT0

static EventGroupHandle_t s_wifi_eg;
static volatile bool      s_connected   = false;
static bool               s_sntp_inited = false;
static int                s_retry_count = 0;
static char               s_ip_str[WIFI_IP_STR_LEN] = {0};

// ── SNTP ──────────────────────────────────────────────────────────────────────

static void sntp_start_once(void)
{
    if (s_sntp_inited) return;

    esp_sntp_config_t sntp_cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG(WIFI_SNTP_SERVER);
    esp_netif_sntp_init(&sntp_cfg);

    s_sntp_inited = true;
    ESP_LOGI(TAG, "SNTP sync started via %s", WIFI_SNTP_SERVER);
}

// ── Event handler ─────────────────────────────────────────────────────────────

static void on_wifi_event(void *arg, esp_event_base_t base,
                          int32_t id, void *data)
{
    if (base != WIFI_EVENT) return;

    switch (id) {
        case WIFI_EVENT_STA_START:
            ESP_LOGI(TAG, "STA started — connecting to \"%s\"", WIFI_SSID);
            esp_wifi_connect();
            break;

        case WIFI_EVENT_STA_CONNECTED:
            ESP_LOGI(TAG, "Associated with AP \"%s\"", WIFI_SSID);
            s_retry_count = 0;
            break;

        case WIFI_EVENT_STA_DISCONNECTED: {
            s_connected = false;
            xEventGroupClearBits(s_wifi_eg, WIFI_GOT_IP_BIT);
            s_ip_str[0] = '\0';

            s_retry_count++;
            if (s_retry_count == 1 ||
                s_retry_count % WIFI_LOG_RETRY_INTERVAL == 0) {
                ESP_LOGW(TAG, "Disconnected (attempt %d) — retrying in %d ms",
                         s_retry_count, WIFI_RECONNECT_DELAY_MS);
            }

            // Brief delay prevents a tight connect/fail/connect loop that
            // saturates the event queue when the AP is unreachable.
            vTaskDelay(pdMS_TO_TICKS(WIFI_RECONNECT_DELAY_MS));
            esp_wifi_connect();
            break;
        }

        default:
            break;
    }
}

static void on_ip_event(void *arg, esp_event_base_t base,
                        int32_t id, void *data)
{
    if (base != IP_EVENT || id != IP_EVENT_STA_GOT_IP) return;

    ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;

    // Cache the IP string — esp_ip4addr_ntoa writes a static buf internally
    snprintf(s_ip_str, sizeof(s_ip_str), IPSTR, IP2STR(&ev->ip_info.ip));

    s_connected   = true;
    s_retry_count = 0;

    xEventGroupSetBits(s_wifi_eg, WIFI_GOT_IP_BIT);

    ESP_LOGI(TAG, "IP acquired: %s  (mask %s  gw %s)",
             s_ip_str,
             ip4addr_ntoa((const ip4_addr_t *)&ev->ip_info.netmask),
             ip4addr_ntoa((const ip4_addr_t *)&ev->ip_info.gw));

    ESP_LOGI(TAG, "Admin panel → http://%s:%d", s_ip_str, ADMIN_PORT);

    // Start SNTP exactly once — even across IP renewals / reconnects
    sntp_start_once();
}

// ── Public API ────────────────────────────────────────────────────────────────

void wifi_manager_init(void)
{
    s_wifi_eg = xEventGroupCreate();
    configASSERT(s_wifi_eg);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    configASSERT(sta_netif);

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));

    // Register handlers for WiFi and IP events on separate bases
    ESP_ERROR_CHECK(esp_event_handler_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, on_ip_event, NULL));

    wifi_config_t wifi_cfg = {0};
    strlcpy((char *)wifi_cfg.sta.ssid,     WIFI_SSID,     sizeof(wifi_cfg.sta.ssid));
    strlcpy((char *)wifi_cfg.sta.password, WIFI_PASSWORD, sizeof(wifi_cfg.sta.password));

    // Accept WPA2 or WPA3-SAE — the AP selects the highest common mode.
    // Set to WIFI_AUTH_WPA2_PSK if your AP does not support WPA3.
    wifi_cfg.sta.threshold.authmode   = WIFI_AUTH_WPA2_PSK;
    wifi_cfg.sta.sae_pwe_h2e          = WPA3_SAE_PWE_BOTH;
    wifi_cfg.sta.pmf_cfg.capable      = true;
    wifi_cfg.sta.pmf_cfg.required     = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());
    // esp_wifi_connect() is called from on_wifi_event on WIFI_EVENT_STA_START
}

void wifi_manager_wait_for_ip(void)
{
    xEventGroupWaitBits(s_wifi_eg,
                        WIFI_GOT_IP_BIT,
                        pdFALSE,    // do not clear the bit after returning
                        pdTRUE,
                        portMAX_DELAY);
}

bool wifi_manager_is_connected(void)
{
    return s_connected;
}

char *wifi_manager_get_ip_str(char *buf, size_t len)
{
    strlcpy(buf, s_ip_str, len);
    return buf;
}
