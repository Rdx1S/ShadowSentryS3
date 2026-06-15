#include "ssh_trap.h"
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
#include <time.h>

static const char *TAG = "SSH";

// Mimics OpenSSH 8.9p1 on Ubuntu 22.04 LTS
static const char BANNER[] = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n";

static void handle_client(int sock, struct sockaddr_in *addr)
{
    struct timeval tv = {.tv_sec = SSH_RECV_TIMEOUT_S, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    send(sock, BANNER, sizeof(BANNER) - 1, 0);

    // RFC 4253 §4.2: client MUST send its own version string before any
    // other data; the string is plaintext and terminated by \r\n or \n.
    char line[256] = {0};
    size_t pos = 0;
    char c;
    while (pos < sizeof(line) - 1) {
        if (recv(sock, &c, 1, 0) <= 0) return;
        if (c == '\n') break;
        if (c != '\r') line[pos++] = c;
    }
    line[pos] = '\0';

    // Only log valid SSH banners; ignore HTTP scanners probing port 22
    if (strncmp(line, "SSH-", 4) != 0) return;

    ESP_LOGW(TAG, "[%s] %s", inet_ntoa(addr->sin_addr), line);

    attack_log_t entry = {
        .type      = ATTACK_SSH,
        .src_ip    = addr->sin_addr.s_addr,
        .timestamp = (uint32_t)time(NULL),
    };
    // username/password left zeroed — SSH v2 encrypts auth after key exchange
    strlcpy(entry.payload, line, sizeof(entry.payload));
    wifi_manager_lookup_mac(addr->sin_addr.s_addr, entry.src_mac);
    log_store_append(&entry);
    telegram_notify(&entry);
}

void ssh_trap_task(void *arg)
{
    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    configASSERT(srv >= 0);

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(SSH_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    configASSERT(bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    configASSERT(listen(srv, SSH_BACKLOG) == 0);

    ESP_LOGI(TAG, "Honeypot listening on port %d (backlog=%d, timeout=%ds)",
             SSH_PORT, SSH_BACKLOG, SSH_RECV_TIMEOUT_S);

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
