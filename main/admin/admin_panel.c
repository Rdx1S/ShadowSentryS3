#include "admin_panel.h"
#include "log_store.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "mbedtls/base64.h"
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

static const char *TAG = "ADMIN";

// Dashboard HTML — linked by CMake EMBED_TXTFILES directive in main/CMakeLists.txt
extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");

// ── JSON helper ───────────────────────────────────────────────────────────────

// Escape a string for use as a JSON string value (between the double-quotes).
// Handles: " \ \n \r \t and ASCII control chars < 0x20.
// Returns number of bytes written (excluding null terminator).
static int json_escape_str(const char *src, char *dst, size_t dstlen)
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

// ── Authentication ────────────────────────────────────────────────────────────

static bool check_auth(const char *req)
{
    const char *p = strstr(req, "Authorization: Basic ");
    if (!p) return false;
    p += 21;

    char b64[128] = {0};
    size_t i = 0;
    while (*p && *p != '\r' && *p != '\n' && i < sizeof(b64) - 1)
        b64[i++] = *p++;

    unsigned char decoded[128] = {0};
    size_t olen = 0;
    if (mbedtls_base64_decode(decoded, sizeof(decoded), &olen,
                              (const unsigned char *)b64, i) != 0)
        return false;

    // Build expected "admin:<password>" and compare.
    // ADMIN_PASSWORD is never written to the log anywhere in this file.
    char expected[128];
    int elen = snprintf(expected, sizeof(expected), "admin:%s", ADMIN_PASSWORD);
    if (elen <= 0 || (size_t)elen >= sizeof(expected)) return false;

    return ((int)olen == elen && memcmp(decoded, expected, (size_t)olen) == 0);
}

// ── HTTP response helpers ─────────────────────────────────────────────────────

static void send_401(int sock)
{
    const char resp[] =
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: Basic realm=\"ShadowSentry\"\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n";
    send(sock, resp, sizeof(resp) - 1, 0);
}

static void send_204(int sock)
{
    const char resp[] =
        "HTTP/1.1 204 No Content\r\n"
        "Connection: close\r\n\r\n";
    send(sock, resp, sizeof(resp) - 1, 0);
}

static void send_404(int sock)
{
    const char resp[] =
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n";
    send(sock, resp, sizeof(resp) - 1, 0);
}

// ── Route handlers ────────────────────────────────────────────────────────────

static void serve_status_json(int sock)
{
    int8_t rssi = 0;
    wifi_ap_record_t ap = {0};
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK)
        rssi = ap.rssi;

    char json[128];
    int len = snprintf(json, sizeof(json),
        "{\"uptime_s\":%llu,\"free_heap\":%lu,\"rssi\":%d}",
        (unsigned long long)(esp_timer_get_time() / 1000000ULL),
        (unsigned long)esp_get_free_heap_size(),
        (int)rssi);

    char hdr[160];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        len);
    send(sock, hdr, hdr_len, 0);
    send(sock, json, len, 0);
}

static void serve_dashboard(int sock)
{
    size_t html_len = (size_t)(index_html_end - index_html_start);
    char hdr[160];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        html_len);
    send(sock, hdr, hdr_len, 0);
    send(sock, index_html_start, html_len, 0);
}

static void serve_attacks_json(int sock)
{
    attack_log_t entries[ADMIN_MAX_LOG_ENTRIES];
    int      n      = log_store_get_recent(entries, ADMIN_MAX_LOG_ENTRIES);
    uint32_t total  = log_store_total_count();

    // Compute per-type counts and unique-IP count from the current window
    uint32_t seen_ips[ADMIN_MAX_LOG_ENTRIES];
    int      unique   = 0;
    int      by_type[3] = {0};

    for (int i = 0; i < n; i++) {
        if ((int)entries[i].type < 3)
            by_type[(int)entries[i].type]++;

        bool dup = false;
        for (int j = 0; j < unique; j++) {
            if (seen_ips[j] == entries[i].src_ip) { dup = true; break; }
        }
        if (!dup && unique < ADMIN_MAX_LOG_ENTRIES)
            seen_ips[unique++] = entries[i].src_ip;
    }

    // Static buffer — safe because the accept loop is single-threaded
    // (only one client is processed at a time on Core 1).
    static char json[ADMIN_JSON_BUF_SIZE];
    int pos = 0;
    int remaining = (int)sizeof(json);

#define JPRINTF(...)  do { \
    int _n = snprintf(json + pos, (size_t)remaining, __VA_ARGS__); \
    if (_n > 0) { pos += _n; remaining -= _n; } \
} while(0)

    JPRINTF("{\"total\":%lu,\"unique_ips\":%d,"
            "\"by_type\":[%d,%d,%d],\"entries\":[",
            (unsigned long)total, unique,
            by_type[0], by_type[1], by_type[2]);

    for (int i = 0; i < n && remaining > 256; i++) {
        // Escape all attacker-supplied strings before embedding in JSON
        char user_j[96],  pass_j[192], pay_j[512];
        json_escape_str(entries[i].username, user_j, sizeof(user_j));
        json_escape_str(entries[i].password, pass_j, sizeof(pass_j));
        json_escape_str(entries[i].payload,  pay_j,  sizeof(pay_j));

        if (i > 0) JPRINTF(",");
        JPRINTF("{\"ts\":%lu,\"ip\":%lu,\"type\":%d,"
                "\"user\":\"%s\",\"pass\":\"%s\",\"payload\":\"%s\"}",
                (unsigned long)entries[i].timestamp,
                (unsigned long)entries[i].src_ip,
                (int)entries[i].type,
                user_j, pass_j, pay_j);
    }

    JPRINTF("]}");
#undef JPRINTF

    char hdr[160];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n",
        pos);
    send(sock, hdr, hdr_len, 0);
    send(sock, json, pos, 0);
}

// ── Request dispatch ──────────────────────────────────────────────────────────

static void handle_client(int sock)
{
    char buf[1024];
    struct timeval tv = {.tv_sec = ADMIN_RECV_TIMEOUT_S, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int len = recv(sock, buf, sizeof(buf) - 1, 0);
    if (len <= 0) return;
    buf[len] = '\0';

    if (!check_auth(buf)) {
        ESP_LOGD(TAG, "Auth failed");
        send_401(sock);
        return;
    }

    if (strncmp(buf, "GET", 3) == 0 && strstr(buf, " /api/attacks")) {
        serve_attacks_json(sock);
    } else if (strncmp(buf, "GET", 3) == 0 && strstr(buf, " /api/status")) {
        serve_status_json(sock);
    } else if (strncmp(buf, "POST", 4) == 0 && strstr(buf, " /api/clear")) {
        log_store_clear();
        ESP_LOGI(TAG, "Logs cleared via admin panel");
        send_204(sock);
    } else if (strncmp(buf, "GET", 3) == 0) {
        serve_dashboard(sock);
    } else {
        send_404(sock);
    }
}

// ── Task entry point ──────────────────────────────────────────────────────────

void admin_panel_task(void *arg)
{
    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    configASSERT(srv >= 0);

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(ADMIN_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    configASSERT(bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    configASSERT(listen(srv, ADMIN_BACKLOG) == 0);

    // Password intentionally omitted from log — visible on the serial monitor
    // only to someone with physical access to the device.
    ESP_LOGI(TAG, "Admin panel on port %d (user: admin) — "
                  "http://<device-ip>:%d", ADMIN_PORT, ADMIN_PORT);

    while (1) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int csock = accept(srv, (struct sockaddr *)&client, &clen);
        if (csock < 0) continue;

        ESP_LOGD(TAG, "Admin connection from %s", inet_ntoa(client.sin_addr));
        handle_client(csock);
        close(csock);
    }
}
