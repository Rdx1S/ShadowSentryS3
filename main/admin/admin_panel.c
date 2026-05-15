#include "admin_panel.h"
#include "log_store.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "mbedtls/base64.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "ADMIN";

// Dashboard HTML embedded by CMake (EMBED_TXTFILES "index.html")
extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[]   asm("_binary_index_html_end");

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
    mbedtls_base64_decode(decoded, sizeof(decoded), &olen,
                          (const unsigned char *)b64, i);

    char expected[128];
    int elen = snprintf(expected, sizeof(expected), "admin:%s", ADMIN_PASSWORD);
    return ((int)olen == elen && memcmp(decoded, expected, olen) == 0);
}

static void send_401(int sock)
{
    const char resp[] =
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: Basic realm=\"ShadowSentry\"\r\n"
        "Content-Length: 0\r\nConnection: close\r\n\r\n";
    send(sock, resp, sizeof(resp) - 1, 0);
}

static void serve_dashboard(int sock)
{
    size_t html_len = (size_t)(index_html_end - index_html_start);
    char hdr[128];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n", html_len);
    send(sock, hdr, hdr_len, 0);
    send(sock, index_html_start, html_len, 0);
}

static void serve_attacks_json(int sock)
{
    attack_log_t entries[50];
    int n     = log_store_get_recent(entries, 50);
    uint32_t total = log_store_total_count();

    uint32_t seen_ips[50];
    int      unique = 0;
    int      by_type[3] = {0};

    for (int i = 0; i < n; i++) {
        by_type[entries[i].type]++;
        bool dup = false;
        for (int j = 0; j < unique; j++)
            if (seen_ips[j] == entries[i].src_ip) { dup = true; break; }
        if (!dup && unique < 50) seen_ips[unique++] = entries[i].src_ip;
    }

    // Stack is too small for 8KB; use static buffer
    static char json[8192];
    int pos = 0;
    pos += snprintf(json + pos, sizeof(json) - pos,
        "{\"total\":%lu,\"unique_ips\":%d,\"by_type\":[%d,%d,%d],\"entries\":[",
        (unsigned long)total, unique, by_type[0], by_type[1], by_type[2]);

    for (int i = 0; i < n && pos < (int)sizeof(json) - 256; i++) {
        if (i > 0) json[pos++] = ',';
        pos += snprintf(json + pos, sizeof(json) - pos,
            "{\"ts\":%u,\"ip\":%u,\"type\":%d,"
            "\"user\":\"%s\",\"pass\":\"%s\",\"payload\":\"%s\"}",
            entries[i].timestamp, entries[i].src_ip, (int)entries[i].type,
            entries[i].username, entries[i].password, entries[i].payload);
    }
    pos += snprintf(json + pos, sizeof(json) - pos, "]}");

    char hdr[128];
    int hdr_len = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n", pos);
    send(sock, hdr, hdr_len, 0);
    send(sock, json, pos, 0);
}

static void handle_client(int sock)
{
    char buf[1024];
    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int len = recv(sock, buf, sizeof(buf) - 1, 0);
    if (len <= 0) return;
    buf[len] = '\0';

    if (!check_auth(buf)) { send_401(sock); return; }

    if (strstr(buf, "GET /api/attacks"))
        serve_attacks_json(sock);
    else if (strstr(buf, "POST /api/clear")) {
        log_store_clear();
        const char ok[] = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
        send(sock, ok, sizeof(ok) - 1, 0);
    } else
        serve_dashboard(sock);
}

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
    configASSERT(listen(srv, 2) == 0);

    ESP_LOGI(TAG, "Admin panel on port %d (user: admin / pass: %s)", ADMIN_PORT, ADMIN_PASSWORD);

    while (1) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int csock = accept(srv, (struct sockaddr *)&client, &clen);
        if (csock < 0) continue;

        handle_client(csock);
        close(csock);
    }
}
