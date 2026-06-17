#include "telegram.h"
#include "wifi_manager.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "lwip/inet.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "TELEGRAM";

static QueueHandle_t s_queue;
static char s_boot_ip[INET_ADDRSTRLEN];

// ── UTF-8 emoji constants ─────────────────────────────────────────────────────
// Stored as byte sequences to avoid editor encoding issues.
// Verified against Unicode 15: U+1F6A8, U+1F4F9, U+1F310, U+1F4BB
#define EMOJI_ALERT  "\xF0\x9F\x9A\xA8"   // 🚨
#define EMOJI_RTSP   "\xF0\x9F\x93\xB9"   // 📹
#define EMOJI_HTTP   "\xF0\x9F\x8C\x90"   // 🌐
#define EMOJI_TELNET "\xF0\x9F\x92\xBB"   // 💻
#define EMOJI_SSH    "\xF0\x9F\x94\x91"   // 🔑
#define EMOJI_FTP    "\xF0\x9F\x93\x81"   // 📁
#define EMOJI_IP     "\xF0\x9F\x8C\x8D"   // 🌍
#define EMOJI_CREDS  "\xF0\x9F\x91\xA4"   // 👤
#define EMOJI_LOG    "\xF0\x9F\x93\x8B"   // 📋
#define EMOJI_MAC    "\xF0\x9F\x94\x97"   // 🔗
#define EMOJI_ARP    "\xF0\x9F\x95\xB8"   // 🕸  (U+1F578 — spoof / MITM web)

static const char *s_type_label[] = {"RTSP", "HTTP", "Telnet", "SSH", "FTP", "ARP"};
static const char *s_type_emoji[] = {EMOJI_RTSP, EMOJI_HTTP, EMOJI_TELNET, EMOJI_SSH, EMOJI_FTP, EMOJI_ARP};

// ── String escaping helpers ───────────────────────────────────────────────────

// HTML-escape &, <, > so attacker-supplied strings are safe inside <code> tags.
// Returns number of bytes written (not including null terminator).
static int html_escape(const char *src, char *dst, size_t dstlen)
{
    size_t pos = 0;
    for (; *src && pos < dstlen - 1; src++) {
        switch (*src) {
            case '&':
                if (pos + 5 >= dstlen) goto done;
                memcpy(dst + pos, "&amp;", 5); pos += 5; break;
            case '<':
                if (pos + 4 >= dstlen) goto done;
                memcpy(dst + pos, "&lt;",  4); pos += 4; break;
            case '>':
                if (pos + 4 >= dstlen) goto done;
                memcpy(dst + pos, "&gt;",  4); pos += 4; break;
            default:
                dst[pos++] = *src;
        }
    }
done:
    dst[pos] = '\0';
    return (int)pos;
}

// JSON-escape a string for use as a JSON string value (between the quotes).
// Handles: " \ \n \r \t and ASCII control chars < 0x20.
static int json_escape(const char *src, char *dst, size_t dstlen)
{
    size_t pos = 0;
    for (; *src && pos < dstlen - 2; src++) {
        unsigned char c = (unsigned char)*src;
        switch (c) {
            case '"':  dst[pos++] = '\\'; dst[pos++] = '"';  break;
            case '\\': dst[pos++] = '\\'; dst[pos++] = '\\'; break;
            case '\n': dst[pos++] = '\\'; dst[pos++] = 'n';  break;
            case '\r': dst[pos++] = '\\'; dst[pos++] = 'r';  break;
            case '\t': dst[pos++] = '\\'; dst[pos++] = 't';  break;
            default:
                if (c < 0x20) {
                    // Other control chars as \uXXXX
                    if (pos + 6 >= dstlen) goto done;
                    pos += snprintf(dst + pos, dstlen - pos, "\\u%04x", c);
                } else {
                    dst[pos++] = (char)c;
                }
        }
    }
done:
    dst[pos] = '\0';
    return (int)pos;
}

// ── HTTPS sender ──────────────────────────────────────────────────────────────

// Sends html_text to the configured Telegram chat.
// html_text may contain Telegram-supported HTML tags (<b>, <code>, etc.)
// and actual Unicode — but NOT raw double-quotes or backslashes.
static void send_message(const char *html_text)
{
    char url[128];
    snprintf(url, sizeof(url),
             "https://api.telegram.org/bot%s/sendMessage",
             TELEGRAM_BOT_TOKEN);

    // JSON-escape the HTML message before embedding it in the JSON body
    char json_text[1024];
    json_escape(html_text, json_text, sizeof(json_text));

    char body[1280];
    int body_len = snprintf(body, sizeof(body),
        "{\"chat_id\":\"%s\",\"text\":\"%s\",\"parse_mode\":\"HTML\"}",
        TELEGRAM_CHAT_ID, json_text);

    esp_http_client_config_t cfg = {
        .url               = url,
        .method            = HTTP_METHOD_POST,
        .transport_type    = HTTP_TRANSPORT_OVER_SSL,
        .crt_bundle_attach = esp_crt_bundle_attach,   // validates api.telegram.org cert
        .timeout_ms        = TELEGRAM_HTTP_TIMEOUT_MS,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        return;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, body_len);

    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Send failed: %s", esp_err_to_name(err));
    } else {
        int status = esp_http_client_get_status_code(client);
        if (status == 429)
            ESP_LOGW(TAG, "Rate limited by Telegram (HTTP 429) — increase TELEGRAM_RATE_LIMIT_MS");
        else if (status != 200)
            ESP_LOGW(TAG, "Unexpected HTTP %d from Telegram", status);
        else
            ESP_LOGI(TAG, "Alert sent OK");
    }

    esp_http_client_cleanup(client);
}

// ── Public API ────────────────────────────────────────────────────────────────

void telegram_notify(const attack_log_t *entry)
{
    if (!s_queue) return;
    // Non-blocking: drop if the queue is full rather than stalling the caller.
    if (xQueueSend(s_queue, entry, 0) != pdTRUE)
        ESP_LOGD(TAG, "Queue full — notification dropped");
}

void telegram_set_boot_ip(const char *ip_str)
{
    strlcpy(s_boot_ip, ip_str, sizeof(s_boot_ip));
}

// ── Task entry point ──────────────────────────────────────────────────────────

void telegram_task(void *arg)
{
    s_queue = xQueueCreate(TELEGRAM_QUEUE_DEPTH, sizeof(attack_log_t));
    configASSERT(s_queue);

    ESP_LOGI(TAG, "Ready (queue=%d, timeout=%dms, rate_limit=%dms)",
             TELEGRAM_QUEUE_DEPTH, TELEGRAM_HTTP_TIMEOUT_MS, TELEGRAM_RATE_LIMIT_MS);

    // Send boot-online notification if Telegram is configured and IP is known
    if (TELEGRAM_BOT_TOKEN[0] != 'Y' && s_boot_ip[0] != '\0') {
        char msg[256];
        snprintf(msg, sizeof(msg),
            "\xF0\x9F\x9F\xA2"  // 🟢
            " <b>ShadowSentry S3 Online</b>\n\n"
            "\xF0\x9F\x8C\x90"  // 🌐
            " IP: <code>%s</code>\n"
            "\xF0\x9F\x9B\xA1"  // 🛡
            " Honeypots: RTSP / HTTP / Telnet / SSH / FTP\n"
            "\xF0\x9F\x94\x91"  // 🔑
            " Admin: <code>http://%s:%d</code>",
            s_boot_ip, s_boot_ip, ADMIN_PORT);
        send_message(msg);
        ESP_LOGI(TAG, "Boot notification sent");
    }

    attack_log_t entry;
    while (1) {
        if (xQueueReceive(s_queue, &entry, portMAX_DELAY) != pdTRUE) continue;

        // Rate limit: enforce minimum gap between API calls
        vTaskDelay(pdMS_TO_TICKS(TELEGRAM_RATE_LIMIT_MS));

        // HTML-escape attacker-supplied strings before embedding in the message
        char user_h[96], pass_h[192], pay_h[384];
        html_escape(entry.username[0] ? entry.username : "-",
                    user_h, sizeof(user_h));
        html_escape(entry.password[0] ? entry.password : "-",
                    pass_h, sizeof(pass_h));
        html_escape(entry.payload,
                    pay_h, sizeof(pay_h));

        // Resolve IP to a printable string before building the message
        struct in_addr ip_addr = {.s_addr = entry.src_ip};
        char ip_str[INET_ADDRSTRLEN];
        strlcpy(ip_str, inet_ntoa(ip_addr), sizeof(ip_str));

        // MAC + vendor line. Both come from local sources (ARP cache and a
        // built-in OUI table) and contain no HTML metacharacters, so no escaping
        // is needed. vendor is "" when unrecognised → the "(…)" suffix is dropped.
        char mac_str[WIFI_MAC_STR_LEN];
        wifi_manager_format_mac(entry.src_mac, mac_str, sizeof(mac_str));
        const char *vendor = wifi_manager_mac_vendor(entry.src_mac);
        char mac_line[96];
        snprintf(mac_line, sizeof(mac_line),
                 EMOJI_MAC " MAC: <code>%s</code>%s%s%s",
                 mac_str,
                 vendor[0] ? " (" : "", vendor, vendor[0] ? ")" : "");

        char msg[768];
        if (entry.type == ATTACK_ARP) {
            // ARP / MITM: network-level event, no credentials. The payload holds
            // the description (e.g. "Gateway 192.168.1.1 MAC changed ...").
            snprintf(msg, sizeof(msg),
                EMOJI_ALERT " <b>ShadowSentry S3 Alert</b>\n\n"
                EMOJI_ARP   " Attack: <b>ARP spoofing / MITM</b>\n"
                EMOJI_IP    " IP: <code>%s</code>\n"
                "%s\n"
                EMOJI_LOG   " <code>%.200s</code>",
                ip_str,
                mac_line,
                pay_h);
        } else if (entry.type == ATTACK_SSH) {
            // SSH: no credentials (auth is encrypted); show client fingerprint only
            snprintf(msg, sizeof(msg),
                EMOJI_ALERT " <b>ShadowSentry S3 Alert</b>\n\n"
                EMOJI_SSH   " Attack: <b>SSH</b>\n"
                EMOJI_IP    " IP: <code>%s</code>\n"
                "%s\n"
                EMOJI_LOG   " <code>%.200s</code>",
                ip_str,
                mac_line,
                pay_h);
        } else {
            snprintf(msg, sizeof(msg),
                EMOJI_ALERT " <b>ShadowSentry S3 Alert</b>\n\n"
                "%s Attack: <b>%s</b>\n"
                EMOJI_IP    " IP: <code>%s</code>\n"
                EMOJI_CREDS " Creds: <code>%s:%s</code>\n"
                "%s\n"
                EMOJI_LOG   " <code>%.200s</code>",
                s_type_emoji[entry.type],
                s_type_label[entry.type],
                ip_str,
                user_h, pass_h,
                mac_line,
                pay_h);
        }

        ESP_LOGD(TAG, "Sending alert for %s (%s)", ip_str,
                 s_type_label[entry.type]);

        send_message(msg);
    }
}
