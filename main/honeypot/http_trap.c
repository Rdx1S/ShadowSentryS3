#include "http_trap.h"
#include "log_store.h"
#include "telegram.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

static const char *TAG = "HTTP";

// Fake Hikvision NVR login page
static const char FAKE_LOGIN[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Server: App-webs/\r\n"
    "Connection: close\r\n\r\n"
    "<!DOCTYPE html><html><head><meta charset=UTF-8>"
    "<title>Network Camera</title>"
    "<style>"
    "body{background:#111;display:flex;align-items:center;justify-content:center;"
    "height:100vh;margin:0;font-family:Arial,sans-serif}"
    ".box{background:#1e1e1e;border:1px solid #333;padding:36px 40px;border-radius:6px;width:320px;text-align:center}"
    "h2{color:#d4a017;margin:0 0 6px;font-size:1.1rem;letter-spacing:2px}"
    "p{color:#666;font-size:.75rem;margin:0 0 24px}"
    "input{width:100%;padding:10px 12px;margin:6px 0;background:#2a2a2a;border:1px solid #444;"
    "color:#eee;border-radius:4px;box-sizing:border-box;font-size:.9rem}"
    "button{width:100%;padding:11px;background:#d4a017;border:none;color:#111;"
    "font-weight:700;cursor:pointer;border-radius:4px;margin-top:14px;font-size:.9rem}"
    "</style></head><body>"
    "<div class=box>"
    "<h2>&#127909; HIKVISION</h2>"
    "<p>Network Video Recorder</p>"
    "<form method=POST action=/doc/page/login.asp>"
    "<input type=text name=username placeholder=Username autocomplete=off>"
    "<input type=password name=password placeholder=Password>"
    "<button>Login</button>"
    "</form></div></body></html>";

static const char HTTP_REDIRECT[] =
    "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

static const char HTTP_404[] =
    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

static void url_decode(char *str)
{
    char *src = str, *dst = str;
    while (*src) {
        if (*src == '%' && src[1] && src[2]) {
            char hex[3] = {src[1], src[2], 0};
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

static bool extract_field(const char *body, const char *field, char *out, size_t outlen)
{
    char key[64];
    snprintf(key, sizeof(key), "%s=", field);
    const char *p = strstr(body, key);
    if (!p) return false;
    p += strlen(key);
    size_t i = 0;
    while (*p && *p != '&' && i < outlen - 1)
        out[i++] = *p++;
    out[i] = '\0';
    url_decode(out);
    return true;
}

static void handle_client(int sock, struct sockaddr_in *addr)
{
    char buf[1024];

    struct timeval tv = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int len = recv(sock, buf, sizeof(buf) - 1, 0);
    if (len <= 0) return;
    buf[len] = '\0';

    if (strncmp(buf, "GET", 3) == 0) {
        send(sock, FAKE_LOGIN, strlen(FAKE_LOGIN), 0);

    } else if (strncmp(buf, "POST", 4) == 0) {
        char *body = strstr(buf, "\r\n\r\n");
        if (!body) return;
        body += 4;

        char user[32] = {0}, pass[64] = {0};
        extract_field(body, "username", user, sizeof(user));
        extract_field(body, "password", pass, sizeof(pass));

        ESP_LOGW(TAG, "[%s] login: %s:%s", inet_ntoa(addr->sin_addr), user, pass);

        attack_log_t entry = {
            .type      = ATTACK_HTTP,
            .src_ip    = addr->sin_addr.s_addr,
            .timestamp = (uint32_t)time(NULL),
        };
        strlcpy(entry.username, user, sizeof(entry.username));
        strlcpy(entry.password, pass, sizeof(entry.password));
        snprintf(entry.payload, sizeof(entry.payload), "POST /login %s:%s", user, pass);
        log_store_append(&entry);
        telegram_notify(&entry);

        send(sock, HTTP_REDIRECT, strlen(HTTP_REDIRECT), 0);

    } else {
        send(sock, HTTP_404, strlen(HTTP_404), 0);
    }
}

void http_trap_task(void *arg)
{
    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    configASSERT(srv >= 0);

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(HTTP_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    configASSERT(bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    configASSERT(listen(srv, 4) == 0);

    ESP_LOGI(TAG, "Honeypot listening on port %d", HTTP_PORT);

    while (1) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int csock = accept(srv, (struct sockaddr *)&client, &clen);
        if (csock < 0) continue;

        ESP_LOGI(TAG, "Connect from %s", inet_ntoa(client.sin_addr));
        handle_client(csock, &client);
        close(csock);
    }
}
