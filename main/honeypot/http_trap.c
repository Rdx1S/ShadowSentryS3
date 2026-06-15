#include "http_trap.h"
#include "log_store.h"
#include "telegram.h"
#include "wifi_manager.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include <string.h>
#include <strings.h>   // strncasecmp() — case-insensitive header matching
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

// Copies the request-target (path) from the request line
//   "<METHOD> <path> HTTP/x.x"
// into out. Falls back to "?" if the line is malformed.
static void extract_path(const char *req, char *out, size_t outlen)
{
    const char *sp = strchr(req, ' ');          // end of method
    if (!sp) { strlcpy(out, "?", outlen); return; }
    sp++;
    size_t i = 0;
    while (*sp && *sp != ' ' && *sp != '\r' && *sp != '\n' && i < outlen - 1)
        out[i++] = *sp++;
    out[i] = '\0';
    if (i == 0) strlcpy(out, "/", outlen);
}

// Finds an HTTP header by name (case-insensitive) and copies its value
// (trimmed of leading spaces, up to CR/LF) into out. Returns true if found.
static bool extract_header(const char *req, const char *name,
                           char *out, size_t outlen)
{
    size_t nlen = strlen(name);
    for (const char *p = req; *p; ) {
        if (strncasecmp(p, name, nlen) == 0) {
            p += nlen;
            while (*p == ' ' || *p == '\t') p++;
            size_t i = 0;
            while (*p && *p != '\r' && *p != '\n' && i < outlen - 1)
                out[i++] = *p++;
            out[i] = '\0';
            return true;
        }
        const char *nl = strchr(p, '\n');       // advance to next header line
        if (!nl) break;
        p = nl + 1;
    }
    out[0] = '\0';
    return false;
}

static void handle_client(int sock, struct sockaddr_in *addr)
{
    char buf[1024];

    struct timeval tv = {.tv_sec = HTTP_RECV_TIMEOUT_S, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int len = recv(sock, buf, sizeof(buf) - 1, 0);
    if (len <= 0) return;
    buf[len] = '\0';

    // Fingerprint the request: target path + the scanner's User-Agent.
    // The User-Agent is often the single most useful signal — masscan, nmap,
    // Hydra, Mirai loaders and curl/python clients each carry a giveaway string
    // (or none at all, which is itself a tell).
    char path[48] = {0}, ua[96] = {0};
    extract_path(buf, path, sizeof(path));
    if (!extract_header(buf, "User-Agent:", ua, sizeof(ua)))
        strlcpy(ua, "-", sizeof(ua));

    attack_log_t entry = {
        .type      = ATTACK_HTTP,
        .src_ip    = addr->sin_addr.s_addr,
        .timestamp = (uint32_t)time(NULL),
    };

    if (strncmp(buf, "POST", 4) == 0) {
        char *body = strstr(buf, "\r\n\r\n");
        char user[32] = {0}, pass[64] = {0};
        if (body) {
            body += 4;
            extract_field(body, "username", user, sizeof(user));
            extract_field(body, "password", pass, sizeof(pass));
        }

        ESP_LOGW(TAG, "[%s] POST %s  login=%s:%s  ua=%s",
                 inet_ntoa(addr->sin_addr), path, user, pass, ua);

        strlcpy(entry.username, user, sizeof(entry.username));
        strlcpy(entry.password, pass, sizeof(entry.password));
        snprintf(entry.payload, sizeof(entry.payload),
                 "POST %s %s:%s | UA=%s", path, user, pass, ua);

        send(sock, HTTP_REDIRECT, strlen(HTTP_REDIRECT), 0);

    } else if (strncmp(buf, "GET", 3) == 0) {
        ESP_LOGW(TAG, "[%s] GET %s  ua=%s",
                 inet_ntoa(addr->sin_addr), path, ua);

        snprintf(entry.payload, sizeof(entry.payload),
                 "GET %s | UA=%s", path, ua);

        send(sock, FAKE_LOGIN, strlen(FAKE_LOGIN), 0);

    } else {
        // Any other verb (HEAD, OPTIONS, PUT, exploit probes…) — log the method.
        char method[12] = {0};
        for (int i = 0; i < (int)sizeof(method) - 1 && buf[i] &&
                        buf[i] != ' ' && buf[i] != '\r' && buf[i] != '\n'; i++)
            method[i] = buf[i];

        ESP_LOGW(TAG, "[%s] %s %s  ua=%s",
                 inet_ntoa(addr->sin_addr), method, path, ua);

        snprintf(entry.payload, sizeof(entry.payload),
                 "%s %s | UA=%s", method, path, ua);

        send(sock, HTTP_404, strlen(HTTP_404), 0);
    }

    // Resolve the attacker's L2 MAC from ARP (same-LAN host) before storing.
    wifi_manager_lookup_mac(addr->sin_addr.s_addr, entry.src_mac);

    // Every connection to port 80 is an anomaly — log and alert on all of them.
    log_store_append(&entry);
    telegram_notify(&entry);
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
    configASSERT(listen(srv, HTTP_BACKLOG) == 0);

    ESP_LOGI(TAG, "Honeypot listening on port %d (backlog=%d, timeout=%ds)",
             HTTP_PORT, HTTP_BACKLOG, HTTP_RECV_TIMEOUT_S);

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
