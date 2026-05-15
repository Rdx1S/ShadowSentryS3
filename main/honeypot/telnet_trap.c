#include "telnet_trap.h"
#include "log_store.h"
#include "telegram.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include <string.h>
#include <time.h>

static const char *TAG = "TELNET";

// Mimics Ubuntu 20.04 login prompt
static const char BANNER[] =
    "\r\n"
    "Ubuntu 20.04.6 LTS\r\n"
    "Kernel 5.15.0-89-generic on an x86_64\r\n"
    "\r\n"
    "myserver login: ";

static const char PASS_PROMPT[] = "Password: ";
static const char LOGIN_FAIL[]  = "\r\nLogin incorrect\r\n\r\nmyserver login: ";

// Read a line from socket, stripping telnet IAC option bytes
static int read_line(int sock, char *out, size_t outlen)
{
    size_t pos = 0;
    char c;

    while (pos < outlen - 1) {
        if (recv(sock, &c, 1, 0) <= 0) return -1;

        // Consume telnet option negotiation (IAC + 2 bytes)
        if ((unsigned char)c == 0xFF) {
            char opt[2];
            recv(sock, opt, 2, 0);
            continue;
        }

        if (c == '\r' || c == '\n') {
            // Consume trailing \n after \r
            if (c == '\r') {
                char peek;
                struct timeval tv = {.tv_sec = 0, .tv_usec = 50000};
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                recv(sock, &peek, 1, 0);
                tv.tv_sec = 30; tv.tv_usec = 0;
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            }
            break;
        }

        out[pos++] = c;
    }

    out[pos] = '\0';
    return (int)pos;
}

static void handle_client(int sock, struct sockaddr_in *addr)
{
    struct timeval tv = {.tv_sec = 30, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    send(sock, BANNER, strlen(BANNER), 0);

    char user[32], pass[64];
    int attempts = 0;

    while (attempts < 5) {
        memset(user, 0, sizeof(user));
        memset(pass, 0, sizeof(pass));

        if (read_line(sock, user, sizeof(user)) < 0) return;
        if (!user[0]) continue;

        send(sock, PASS_PROMPT, strlen(PASS_PROMPT), 0);

        if (read_line(sock, pass, sizeof(pass)) < 0) return;

        ESP_LOGW(TAG, "[%s] login: %s:%s", inet_ntoa(addr->sin_addr), user, pass);

        attack_log_t entry = {
            .type      = ATTACK_TELNET,
            .src_ip    = addr->sin_addr.s_addr,
            .timestamp = (uint32_t)time(NULL),
        };
        strlcpy(entry.username, user, sizeof(entry.username));
        strlcpy(entry.password, pass, sizeof(entry.password));
        snprintf(entry.payload, sizeof(entry.payload), "Telnet %s:%s", user, pass);
        log_store_append(&entry);
        telegram_notify(&entry);

        send(sock, LOGIN_FAIL, strlen(LOGIN_FAIL), 0);
        attempts++;
    }
}

void telnet_trap_task(void *arg)
{
    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    configASSERT(srv >= 0);

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(TELNET_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    configASSERT(bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    configASSERT(listen(srv, 4) == 0);

    ESP_LOGI(TAG, "Honeypot listening on port %d", TELNET_PORT);

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
