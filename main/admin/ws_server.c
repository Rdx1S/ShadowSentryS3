#include "ws_server.h"
#include "log_store.h"
#include "geoip.h"
#include "wifi_manager.h"
#include "config.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "lwip/inet.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "WS";

static httpd_handle_t s_server;
// Connected client socket fds (-1 = empty). Only ever touched from the httpd
// task (ws_handler on connect, broadcast_work on send), so no lock is needed.
static int s_clients[ADMIN_WS_MAX_CLIENTS];

// ── JSON helpers ────────────────────────────────────────────────────────────────

// Minimal JSON string escaper for embedding attacker-supplied text.
static void jesc(const char *in, char *out, size_t outlen)
{
    size_t o = 0;
    for (; in && *in && o + 7 < outlen; in++) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = c; }
        else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else if (c == '\r') { out[o++] = '\\'; out[o++] = 'r'; }
        else if (c < 0x20)  { o += snprintf(out + o, outlen - o, "\\u%04x", c); }
        else out[o++] = (char)c;
    }
    out[o] = '\0';
}

// Serialize one attack into the same per-entry JSON shape as the REST API, so
// the dashboard's existing render code consumes it unchanged. Geo fields are
// usually empty at push time (enrichment is async) and fill in on the next poll.
static void format_entry_json(const attack_log_t *e, char *buf, size_t len)
{
    char user_j[96], pass_j[192], pay_j[400];
    jesc(e->username, user_j, sizeof(user_j));
    jesc(e->password, pass_j, sizeof(pass_j));
    jesc(e->payload,  pay_j,  sizeof(pay_j));

    char mac_j[WIFI_MAC_STR_LEN];
    wifi_manager_format_mac(e->src_mac, mac_j, sizeof(mac_j));
    const char *vendor = wifi_manager_mac_vendor(e->src_mac);

    geoip_info_t gi;
    char ctry_j[40] = "", org_j[100] = "";
    if (geoip_lookup(e->src_ip, &gi)) {
        jesc(gi.country, ctry_j, sizeof(ctry_j));
        jesc(gi.org,     org_j,  sizeof(org_j));
    } else {
        gi.cc[0] = gi.asn[0] = gi.tag[0] = '\0';
    }

    snprintf(buf, len,
        "{\"ts\":%lu,\"ip\":%lu,\"type\":%d,"
        "\"user\":\"%s\",\"pass\":\"%s\",\"payload\":\"%s\","
        "\"mac\":\"%s\",\"vendor\":\"%s\","
        "\"cc\":\"%s\",\"country\":\"%s\",\"org\":\"%s\","
        "\"asn\":\"%s\",\"geotag\":\"%s\"}",
        (unsigned long)e->timestamp, (unsigned long)e->src_ip, (int)e->type,
        user_j, pass_j, pay_j, mac_j, vendor,
        gi.cc, ctry_j, org_j, gi.asn, gi.tag);
}

// ── Client tracking (httpd task context only) ───────────────────────────────────

static void add_client(int fd)
{
    for (int i = 0; i < ADMIN_WS_MAX_CLIENTS; i++)
        if (s_clients[i] == fd) return;              // already tracked
    for (int i = 0; i < ADMIN_WS_MAX_CLIENTS; i++)
        if (s_clients[i] < 0) { s_clients[i] = fd; return; }
    ESP_LOGW(TAG, "client table full — dropping fd=%d", fd);
}

// ── Broadcast (runs on the httpd task via httpd_queue_work) ──────────────────────

// Carries a raw copy of the entry — NOT a pre-formatted string. The ~1 KB of
// stack that format_entry_json() needs must be spent on the httpd task, never on
// the appending task: honeypot traps like FTP run on a 3 KB stack and would
// overflow if the formatting happened in their context.
typedef struct { attack_log_t e; } ws_msg_t;

static void broadcast_work(void *arg)
{
    ws_msg_t *m = (ws_msg_t *)arg;
    char json[512];
    format_entry_json(&m->e, json, sizeof(json));      // heavy work on httpd stack
    free(m);

    httpd_ws_frame_t f = {
        .final   = true,
        .type    = HTTPD_WS_TYPE_TEXT,
        .payload = (uint8_t *)json,
        .len     = strlen(json),
    };
    for (int i = 0; i < ADMIN_WS_MAX_CLIENTS; i++) {
        if (s_clients[i] < 0) continue;
        if (httpd_ws_send_frame_async(s_server, s_clients[i], &f) != ESP_OK) {
            ESP_LOGI(TAG, "client fd=%d closed", s_clients[i]);
            s_clients[i] = -1;
        }
    }
}

// log_store listener — runs in the appending (honeypot/monitor) task, so it must
// stay tiny: just copy the raw entry and hand off to the httpd task. All string
// formatting and socket I/O happen there, off the caller's (small) stack.
static void on_attack(const attack_log_t *e)
{
    if (!s_server) return;
    ws_msg_t *m = (ws_msg_t *)malloc(sizeof(*m));
    if (!m) return;
    m->e = *e;
    if (httpd_queue_work(s_server, broadcast_work, m) != ESP_OK) free(m);
}

// ── WebSocket endpoint ──────────────────────────────────────────────────────────

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {                   // handshake already completed
        int fd = httpd_req_to_sockfd(req);
        add_client(fd);
        ESP_LOGI(TAG, "client connected (fd=%d)", fd);
        return ESP_OK;
    }
    // We never expect data from the dashboard; drain any frame and move on.
    httpd_ws_frame_t f;
    memset(&f, 0, sizeof(f));
    f.type = HTTPD_WS_TYPE_TEXT;
    esp_err_t r = httpd_ws_recv_frame(req, &f, 0);   // length only
    if (r == ESP_OK && f.len) {
        uint8_t tmp[64];
        if (f.len < sizeof(tmp)) { f.payload = tmp; httpd_ws_recv_frame(req, &f, sizeof(tmp)); }
    }
    return ESP_OK;
}

void ws_server_start(void)
{
    for (int i = 0; i < ADMIN_WS_MAX_CLIENTS; i++) s_clients[i] = -1;

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port      = ADMIN_WS_PORT;
    cfg.ctrl_port        = ADMIN_WS_PORT + 1;        // own control port (distinct)
    cfg.max_open_sockets = ADMIN_WS_MAX_CLIENTS + 1;
    cfg.lru_purge_enable = true;
    cfg.stack_size       = 8192;                     // broadcast_work formats JSON here

    if (httpd_start(&s_server, &cfg) != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed — live push disabled");
        s_server = NULL;
        return;
    }

    httpd_uri_t ws_uri = {
        .uri          = "/ws",
        .method       = HTTP_GET,
        .handler      = ws_handler,
        .is_websocket = true,
    };
    httpd_register_uri_handler(s_server, &ws_uri);

    log_store_set_listener(on_attack);
    ESP_LOGI(TAG, "WebSocket push server on ws://<device-ip>:%d/ws", ADMIN_WS_PORT);
}
