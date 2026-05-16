#include "rtsp_trap.h"
#include "log_store.h"
#include "telegram.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "mbedtls/base64.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char *TAG = "RTSP";

// Fake Hikvision camera RTSP responses
static const char RTSP_OPTIONS_RESP[] =
    "RTSP/1.0 200 OK\r\n"
    "CSeq: %d\r\n"
    "Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n"
    "Server: Hikvision-Webs\r\n"
    "\r\n";

static const char RTSP_UNAUTH_RESP[] =
    "RTSP/1.0 401 Unauthorized\r\n"
    "CSeq: %d\r\n"
    "WWW-Authenticate: Basic realm=\"RTSP Server\"\r\n"
    "\r\n";

// ── Helpers ───────────────────────────────────────────────────────────────────

static int parse_cseq(const char *req)
{
    const char *p = strstr(req, "CSeq:");
    if (!p) return 1;
    return atoi(p + 6);
}

// Decodes "Authorization: Basic <b64>" into user/pass buffers.
// Returns true only when both user and password are successfully extracted.
static bool parse_basic_auth(const char *req,
                              char *user, size_t ulen,
                              char *pass, size_t plen)
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

    char *colon = memchr(decoded, ':', olen);
    if (!colon) return false;

    size_t user_len = (size_t)(colon - (char *)decoded);
    if (user_len >= ulen) user_len = ulen - 1;
    memcpy(user, decoded, user_len);
    user[user_len] = '\0';

    size_t pass_len = olen - user_len - 1;
    if (pass_len >= plen) pass_len = plen - 1;
    memcpy(pass, colon + 1, pass_len);
    pass[pass_len] = '\0';

    return true;
}

// ── Per-connection handler ────────────────────────────────────────────────────

static void handle_client(int sock, struct sockaddr_in *addr)
{
    char buf[512];
    char resp[256];

    struct timeval tv = {.tv_sec = RTSP_RECV_TIMEOUT_S, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (1) {
        int len = recv(sock, buf, sizeof(buf) - 1, 0);
        if (len <= 0) break;
        buf[len] = '\0';

        int cseq = parse_cseq(buf);

        if (strncmp(buf, "OPTIONS", 7) == 0) {
            snprintf(resp, sizeof(resp), RTSP_OPTIONS_RESP, cseq);
            send(sock, resp, strlen(resp), 0);

        } else if (strncmp(buf, "DESCRIBE", 8) == 0) {
            char user[32] = {0}, pass[64] = {0};

            if (parse_basic_auth(buf, user, sizeof(user), pass, sizeof(pass))) {
                ESP_LOGW(TAG, "[%s] creds captured: %s:%s",
                         inet_ntoa(addr->sin_addr), user, pass);

                attack_log_t entry = {
                    .type      = ATTACK_RTSP,
                    .src_ip    = addr->sin_addr.s_addr,
                    .timestamp = (uint32_t)time(NULL),
                };
                strlcpy(entry.username, user, sizeof(entry.username));
                strlcpy(entry.password, pass, sizeof(entry.password));
                snprintf(entry.payload, sizeof(entry.payload),
                         "RTSP DESCRIBE creds=%s:%s", user, pass);

                log_store_append(&entry);
                telegram_notify(&entry);
            }

            // Always reply 401 — never grant access
            snprintf(resp, sizeof(resp), RTSP_UNAUTH_RESP, cseq);
            send(sock, resp, strlen(resp), 0);

        } else {
            // Unknown method — drop the connection
            break;
        }
    }
}

// ── Task entry point ──────────────────────────────────────────────────────────

void rtsp_trap_task(void *arg)
{
    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    configASSERT(srv >= 0);

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(RTSP_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    configASSERT(bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    configASSERT(listen(srv, RTSP_BACKLOG) == 0);

    ESP_LOGI(TAG, "Honeypot listening on port %d (backlog=%d, timeout=%ds)",
             RTSP_PORT, RTSP_BACKLOG, RTSP_RECV_TIMEOUT_S);

    while (1) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int csock = accept(srv, (struct sockaddr *)&client, &clen);
        if (csock < 0) continue;

        ESP_LOGI(TAG, "Connection from %s", inet_ntoa(client.sin_addr));
        handle_client(csock, &client);
        close(csock);
    }
}
