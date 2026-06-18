#include "ssh_trap.h"
#include "fake_shell.h"
#include "ssh_hostkey.h"
#include "log_store.h"
#include "telegram.h"
#include "wifi_manager.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
// wolfSSL is built with a user_settings.h (WOLFSSL_USER_SETTINGS); consumers must
// define the same macro before including any wolf headers, otherwise wolfssl/ssh.h
// falls back to the autoconf wolfssl/options.h (which doesn't exist here).
#define WOLFSSL_USER_SETTINGS
#include <wolfssh/ssh.h>
#include <wolfssh/error.h>
#include <string.h>
#include <time.h>

static const char *TAG = "SSH";

// Shared server context (host key + auth callback). Built once at task start.
static WOLFSSH_CTX *s_ctx;

// Per-connection state handed to the user-auth callback so it can log the
// attacker and remember the username for the shell prompt.
typedef struct {
    struct sockaddr_in *addr;
    char username[32];
    bool  authed;
} ssh_conn_t;

// ── User authentication ─────────────────────────────────────────────────────────
// The whole point of a real SSH server here: unlike a banner-only trap, wolfSSH
// decrypts the auth exchange, so we capture the plaintext username AND password.
// We accept ANY password (it's a honeypot) and reject 'none'/publickey so the
// client falls back to a password we can record.
static int ssh_userauth(byte authType, WS_UserAuthData *authData, void *ctx)
{
    ssh_conn_t *c = (ssh_conn_t *)ctx;
    (void)authType;

    if (authData->type != WOLFSSH_USERAUTH_PASSWORD)
        return WOLFSSH_USERAUTH_FAILURE;        // force a password attempt

    char user[32] = {0}, pass[64] = {0};
    word32 ul = authData->usernameSz;
    if (ul > sizeof(user) - 1) ul = sizeof(user) - 1;
    if (authData->username) memcpy(user, authData->username, ul);
    word32 pl = authData->sf.password.passwordSz;
    if (pl > sizeof(pass) - 1) pl = sizeof(pass) - 1;
    if (authData->sf.password.password) memcpy(pass, authData->sf.password.password, pl);

    strlcpy(c->username, user[0] ? user : "root", sizeof(c->username));
    c->authed = true;

    ESP_LOGW(TAG, "[%s] SSH login %s:%s", inet_ntoa(c->addr->sin_addr), user, pass);

    attack_log_t e = {
        .type      = ATTACK_SSH,
        .src_ip    = c->addr->sin_addr.s_addr,
        .timestamp = (uint32_t)time(NULL),
    };
    strlcpy(e.username, user, sizeof(e.username));
    strlcpy(e.password, pass, sizeof(e.password));
    snprintf(e.payload, sizeof(e.payload), "SSH login %s:%s", user, pass);
    wifi_manager_lookup_mac(c->addr->sin_addr.s_addr, e.src_mac);
    log_store_append(&e);
    telegram_notify(&e);

    return WOLFSSH_USERAUTH_SUCCESS;             // accept any — let them in
}

// ── fake-shell transport over the encrypted wolfSSH channel ─────────────────────

static int ssh_read_byte(void *io)
{
    WOLFSSH *ssh = (WOLFSSH *)io;
    byte c;
    int r = wolfSSH_stream_read(ssh, &c, 1);
    if (r == 1) return c;
    return -1;                                   // EOF / error / idle timeout → end
}

static int ssh_write(void *io, const char *buf, int len)
{
    WOLFSSH *ssh = (WOLFSSH *)io;
    int sent = 0;
    while (sent < len) {
        int r = wolfSSH_stream_send(ssh, (byte *)buf + sent, (word32)(len - sent));
        if (r > 0) { sent += r; continue; }
        if (wolfSSH_get_error(ssh) == WS_WANT_WRITE) continue;
        return sent > 0 ? sent : -1;
    }
    return sent;
}

static void handle_client(int sock, struct sockaddr_in *addr)
{
    // Bound a session: long enough for a human to think between commands, short
    // enough that one idle attacker can't pin the (single) SSH task forever.
    struct timeval tv = {.tv_sec = SSH_RECV_TIMEOUT_S, .tv_usec = 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    WOLFSSH *ssh = wolfSSH_new(s_ctx);
    if (!ssh) {
        ESP_LOGE(TAG, "wolfSSH_new failed");
        return;
    }

    ssh_conn_t conn = { .addr = addr };
    wolfSSH_SetUserAuthCtx(ssh, &conn);
    wolfSSH_set_fd(ssh, sock);

    int rc = wolfSSH_accept(ssh);                // handshake + auth + open shell channel
    if (rc == WS_SUCCESS) {
        shell_io_t io = {
            .io        = ssh,
            .read_byte = ssh_read_byte,
            .write     = ssh_write,
            .echo      = true,                   // SSH PTY is raw — server echoes
        };
        fake_shell_run(&io, addr, conn.authed ? conn.username : "root");
    } else {
        ESP_LOGI(TAG, "[%s] handshake ended rc=%d (err=%d)",
                 inet_ntoa(addr->sin_addr), rc, wolfSSH_get_error(ssh));
    }

    wolfSSH_stream_exit(ssh, 0);
    wolfSSH_free(ssh);
}

void ssh_trap_task(void *arg)
{
    if (wolfSSH_Init() != WS_SUCCESS) {
        ESP_LOGE(TAG, "wolfSSH_Init failed — SSH honeypot disabled");
        vTaskDelete(NULL);
    }
    s_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    configASSERT(s_ctx);

    if (wolfSSH_CTX_UsePrivateKey_buffer(s_ctx, ssh_hostkey_der,
                                         ssh_hostkey_der_len, WOLFSSH_FORMAT_ASN1) < 0) {
        ESP_LOGE(TAG, "Host key load failed — SSH honeypot disabled");
        vTaskDelete(NULL);
    }
    wolfSSH_SetUserAuth(s_ctx, ssh_userauth);

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

    ESP_LOGI(TAG, "Honeypot listening on port %d (backlog=%d, timeout=%ds) — real SSH server",
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
