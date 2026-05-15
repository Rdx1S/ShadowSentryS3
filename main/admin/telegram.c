#include "telegram.h"
#include "config.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "lwip/inet.h"
#include <stdio.h>
#include <string.h>

static const char *TAG     = "TELEGRAM";
static QueueHandle_t s_queue;

void telegram_notify(const attack_log_t *entry)
{
    if (s_queue)
        xQueueSend(s_queue, entry, 0);   // non-blocking, drop if full
}

static void send_message(const char *text)
{
    char url[128];
    snprintf(url, sizeof(url),
             "https://api.telegram.org/bot%s/sendMessage", TELEGRAM_BOT_TOKEN);

    char body[512];
    int body_len = snprintf(body, sizeof(body),
        "{\"chat_id\":\"%s\",\"text\":\"%s\",\"parse_mode\":\"HTML\"}",
        TELEGRAM_CHAT_ID, text);

    esp_http_client_config_t cfg = {
        .url                    = url,
        .method                 = HTTP_METHOD_POST,
        .transport_type         = HTTP_TRANSPORT_OVER_SSL,
        // For production, provide a proper CA cert bundle instead
        .skip_cert_common_name_check = true,
        .crt_bundle_attach      = NULL,
        .timeout_ms             = 10000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, body_len);

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK)
        ESP_LOGW(TAG, "Send failed: %s", esp_err_to_name(err));

    esp_http_client_cleanup(client);
}

void telegram_task(void *arg)
{
    s_queue = xQueueCreate(10, sizeof(attack_log_t));

    static const char *type_label[] = {"RTSP", "HTTP", "Telnet"};
    static const char *type_emoji[] = {"&#128249;", "&#127760;", "&#128187;"};

    attack_log_t entry;
    while (1) {
        if (xQueueReceive(s_queue, &entry, portMAX_DELAY) != pdTRUE) continue;

        struct in_addr ip_addr = {.s_addr = entry.src_ip};
        char msg[480];
        snprintf(msg, sizeof(msg),
            "&#128680; <b>ShadowSentry S3 Alert</b>\\n\\n"
            "%s Attack: <b>%s</b>\\n"
            "&#127758; IP: <code>%s</code>\\n"
            "&#128100; Creds: <code>%s:%s</code>\\n"
            "&#128203; <code>%.100s</code>",
            type_emoji[entry.type],
            type_label[entry.type],
            inet_ntoa(ip_addr),
            entry.username[0] ? entry.username : "-",
            entry.password[0] ? entry.password : "-",
            entry.payload);

        send_message(msg);
    }
}
