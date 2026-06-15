#include "ftp_trap.h"
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
#include <strings.h>   // strncasecmp — FTP commands are case-insensitive per RFC 959
#include <time.h>

static const char *TAG = "FTP";

// vsFTPd 3.0.5 responses
static const char BANNER[]     = "220 (vsFTPd 3.0.5)\r\n";
static const char NEED_PASS[]  = "331 Please specify the password.\r\n";
static const char LOGIN_FAIL[] = "530 Login incorrect.\r\n";
static const char GOODBYE[]    = "221 Goodbye.\r\n";
// Advertise no features — keeps AUTH TLS probes away
static const char FEAT_REPLY[] = "211-Features:\r\n211 End\r\n";
static const char UNKNOWN[]    = "500 Unknown command.\r\n";

// Read one CRLF-terminated line from socket.
// Strips \r, keeps up to buflen-1 chars. Returns byte count or -1 on error.
static int read_line(int sock, char *buf, size_t buflen)
{
    size_t pos = 0;
    char c;
    while (pos < buflen - 1) {
        if (recv(sock, &c, 1, 0) <= 0) return -1;
        if (c == '\n') break;
        if (c != '\r') buf[pos++] = c;
    }
    buf[pos] = '\0';
    return (int)pos;
}

static void handle_client(int sock, struct sockaddr_in *addr)
{
    struct timeval tv = {.tv_sec = FTP_RECV_TIMEOUT_S, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    send(sock, BANNER, sizeof(BANNER) - 1, 0);

    char user[32] = {0};
    char line[256];
    int  attempts = 0;

    while (attempts < FTP_MAX_ATTEMPTS) {
        if (read_line(sock, line, sizeof(line)) < 0) return;
        if (!line[0]) continue;

        if (strncasecmp(line, "USER ", 5) == 0) {
            strlcpy(user, line + 5, sizeof(user));
            // Strip trailing whitespace that some clients add
            size_t n = strlen(user);
            while (n > 0 && (user[n-1] == ' ' || user[n-1] == '\t')) user[--n] = '\0';
            send(sock, NEED_PASS, sizeof(NEED_PASS) - 1, 0);

        } else if (strncasecmp(line, "PASS ", 5) == 0) {
            char pass[64] = {0};
            strlcpy(pass, line + 5, sizeof(pass));
            size_t n = strlen(pass);
            while (n > 0 && (pass[n-1] == ' ' || pass[n-1] == '\t')) pass[--n] = '\0';

            ESP_LOGW(TAG, "[%s] login: %s:%s", inet_ntoa(addr->sin_addr), user, pass);

            attack_log_t entry = {
                .type      = ATTACK_FTP,
                .src_ip    = addr->sin_addr.s_addr,
                .timestamp = (uint32_t)time(NULL),
            };
            strlcpy(entry.username, user, sizeof(entry.username));
            strlcpy(entry.password, pass, sizeof(entry.password));
            snprintf(entry.payload, sizeof(entry.payload), "FTP %s:%s", user, pass);
            wifi_manager_lookup_mac(addr->sin_addr.s_addr, entry.src_mac);
            log_store_append(&entry);
            telegram_notify(&entry);

            send(sock, LOGIN_FAIL, sizeof(LOGIN_FAIL) - 1, 0);
            memset(user, 0, sizeof(user));
            attempts++;

        } else if (strncasecmp(line, "QUIT", 4) == 0) {
            send(sock, GOODBYE, sizeof(GOODBYE) - 1, 0);
            return;

        } else if (strncasecmp(line, "FEAT", 4) == 0) {
            send(sock, FEAT_REPLY, sizeof(FEAT_REPLY) - 1, 0);

        } else {
            send(sock, UNKNOWN, sizeof(UNKNOWN) - 1, 0);
        }
    }
}

void ftp_trap_task(void *arg)
{
    int srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    configASSERT(srv >= 0);

    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(FTP_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    configASSERT(bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    configASSERT(listen(srv, FTP_BACKLOG) == 0);

    ESP_LOGI(TAG, "Honeypot listening on port %d (backlog=%d, timeout=%ds, max_attempts=%d)",
             FTP_PORT, FTP_BACKLOG, FTP_RECV_TIMEOUT_S, FTP_MAX_ATTEMPTS);

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
