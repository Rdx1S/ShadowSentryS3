#include "geoip.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "lwip/inet.h"
#include <string.h>
#include <stdio.h>

// Fall back to safe defaults so the module builds against an older config.h
// (config.h values, included above, take precedence over these).
#ifndef GEOIP_ENABLE
#define GEOIP_ENABLE            1
#endif
#ifndef GEOIP_CACHE_SIZE
#define GEOIP_CACHE_SIZE        24      // distinct IPs remembered (RAM-resident)
#endif
#ifndef GEOIP_QUEUE_DEPTH
#define GEOIP_QUEUE_DEPTH       8
#endif
#ifndef GEOIP_HTTP_TIMEOUT_MS
#define GEOIP_HTTP_TIMEOUT_MS   5000
#endif

static const char *TAG = "GEOIP";

// ── Cache (IP → geoip_info_t) ────────────────────────────────────────────────
typedef struct {
    uint32_t     ip;        // network byte order; 0 = empty slot
    geoip_info_t info;
} geo_slot_t;

static geo_slot_t       s_cache[GEOIP_CACHE_SIZE];
static int              s_next;             // round-robin replacement index
static SemaphoreHandle_t s_cache_mtx;
static QueueHandle_t     s_queue;

// ── Helpers ───────────────────────────────────────────────────────────────────

// RFC1918 / loopback / link-local / CGNAT — never sent to the public API.
static bool ip_is_private(uint32_t ip_net)
{
    uint32_t h = ntohl(ip_net);
    uint8_t a = (h >> 24) & 0xFF, b = (h >> 16) & 0xFF;
    if (a == 10)                       return true;   // 10.0.0.0/8
    if (a == 192 && b == 168)          return true;   // 192.168.0.0/16
    if (a == 172 && (b >= 16 && b <= 31)) return true;// 172.16.0.0/12
    if (a == 127)                      return true;   // loopback
    if (a == 169 && b == 254)          return true;   // link-local
    if (a == 100 && (b >= 64 && b <= 127)) return true; // CGNAT 100.64/10
    if (a == 0 || a >= 224)            return true;   // this-net / multicast
    return false;
}

static bool cache_get(uint32_t ip, geoip_info_t *out)
{
    bool found = false;
    xSemaphoreTake(s_cache_mtx, portMAX_DELAY);
    for (int i = 0; i < GEOIP_CACHE_SIZE; i++) {
        if (s_cache[i].ip == ip && ip != 0) { *out = s_cache[i].info; found = true; break; }
    }
    xSemaphoreGive(s_cache_mtx);
    return found;
}

static void cache_put(uint32_t ip, const geoip_info_t *info)
{
    xSemaphoreTake(s_cache_mtx, portMAX_DELAY);
    int slot = -1;
    for (int i = 0; i < GEOIP_CACHE_SIZE; i++) {
        if (s_cache[i].ip == ip) { slot = i; break; }   // refresh existing
    }
    if (slot < 0) { slot = s_next; s_next = (s_next + 1) % GEOIP_CACHE_SIZE; }
    s_cache[slot].ip   = ip;
    s_cache[slot].info = *info;
    xSemaphoreGive(s_cache_mtx);
}

// Minimal JSON scalar extractors for the small, fixed ip-api response.
static bool json_str(const char *buf, const char *key, char *out, size_t len)
{
    char pat[24];
    int pn = snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    if (pn <= 0) { out[0] = '\0'; return false; }
    const char *p = strstr(buf, pat);
    if (!p) { out[0] = '\0'; return false; }
    p += pn;
    size_t i = 0;
    while (*p && *p != '"' && i < len - 1) {
        if (*p == '\\' && p[1]) p++;        // skip escape char
        out[i++] = *p++;
    }
    out[i] = '\0';
    return true;
}

static bool json_true(const char *buf, const char *key)
{
    char pat[24];
    int pn = snprintf(pat, sizeof(pat), "\"%s\":", key);
    if (pn <= 0) return false;
    const char *p = strstr(buf, pat);
    return p && strncmp(p + pn, "true", 4) == 0;
}

// ── HTTP body collector ───────────────────────────────────────────────────────
typedef struct { char *buf; int len; int cap; } resp_t;

static esp_err_t http_ev(esp_http_client_event_t *e)
{
    if (e->event_id == HTTP_EVENT_ON_DATA && e->user_data) {
        resp_t *r = (resp_t *)e->user_data;
        int n = e->data_len;
        if (n > r->cap - 1 - r->len) n = r->cap - 1 - r->len;   // clamp to buffer
        if (n > 0) { memcpy(r->buf + r->len, e->data, n); r->len += n; r->buf[r->len] = '\0'; }
    }
    return ESP_OK;
}

// Performs the ip-api lookup for a public IP and fills *info. Returns false on
// any network/parse failure (caller leaves the IP unresolved to retry later).
static bool fetch_geo(uint32_t ip_net, geoip_info_t *info)
{
    struct in_addr a = {.s_addr = ip_net};
    char url[160];
    snprintf(url, sizeof(url),
        "http://ip-api.com/json/%s"
        "?fields=status,country,countryCode,isp,org,as,mobile,proxy,hosting",
        inet_ntoa(a));

    char body[512] = {0};
    resp_t r = { .buf = body, .len = 0, .cap = (int)sizeof(body) };

    esp_http_client_config_t cfg = {
        .url           = url,
        .method        = HTTP_METHOD_GET,
        .timeout_ms    = GEOIP_HTTP_TIMEOUT_MS,
        .event_handler = http_ev,
        .user_data     = &r,
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) return false;

    bool ok = false;
    if (esp_http_client_perform(c) == ESP_OK &&
        esp_http_client_get_status_code(c) == 200) {
        char status[12];
        json_str(body, "status", status, sizeof(status));
        if (strcmp(status, "success") == 0) {
            memset(info, 0, sizeof(*info));
            json_str(body, "countryCode", info->cc,      sizeof(info->cc));
            json_str(body, "country",     info->country, sizeof(info->country));

            // Prefer ISP; fall back to org for the human-readable network name.
            char isp[48] = {0};
            json_str(body, "isp", isp, sizeof(isp));
            if (isp[0]) strlcpy(info->org, isp, sizeof(info->org));
            else        json_str(body, "org", info->org, sizeof(info->org));

            // "as" looks like "AS24940 Hetzner Online GmbH" — keep the leading token.
            char as[48] = {0};
            json_str(body, "as", as, sizeof(as));
            size_t k = 0;
            while (as[k] && as[k] != ' ' && k < sizeof(info->asn) - 1) { info->asn[k] = as[k]; k++; }
            info->asn[k] = '\0';

            // One reputation tag, in priority order.
            if      (json_true(body, "proxy"))   strlcpy(info->tag, "proxy",   sizeof(info->tag));
            else if (json_true(body, "hosting")) strlcpy(info->tag, "hosting", sizeof(info->tag));
            else if (json_true(body, "mobile"))  strlcpy(info->tag, "mobile",  sizeof(info->tag));
            ok = true;
        }
    }
    esp_http_client_cleanup(c);
    return ok;
}

// ── Public API ────────────────────────────────────────────────────────────────

void geoip_enqueue(uint32_t ip_net)
{
#if GEOIP_ENABLE
    if (!s_queue || ip_net == 0) return;
    geoip_info_t tmp;
    if (cache_get(ip_net, &tmp)) return;        // already known — don't re-fetch
    xQueueSend(s_queue, &ip_net, 0);            // non-blocking; drop if full
#else
    (void)ip_net;
#endif
}

bool geoip_lookup(uint32_t ip_net, geoip_info_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!s_cache_mtx) return false;
    return cache_get(ip_net, out);
}

void geoip_task(void *arg)
{
#if !GEOIP_ENABLE
    ESP_LOGI(TAG, "GeoIP enrichment disabled (GEOIP_ENABLE=0)");
    vTaskDelete(NULL);
#else
    s_cache_mtx = xSemaphoreCreateMutex();
    s_queue     = xQueueCreate(GEOIP_QUEUE_DEPTH, sizeof(uint32_t));
    configASSERT(s_cache_mtx && s_queue);
    ESP_LOGI(TAG, "Threat-intel enrichment ready (ip-api.com, cache=%d)",
             GEOIP_CACHE_SIZE);

    uint32_t ip;
    while (1) {
        if (xQueueReceive(s_queue, &ip, portMAX_DELAY) != pdTRUE) continue;

        geoip_info_t info;
        if (cache_get(ip, &info)) continue;     // resolved while we waited

        if (ip_is_private(ip)) {
            memset(&info, 0, sizeof(info));
            strlcpy(info.country, "Private LAN",     sizeof(info.country));
            strlcpy(info.org,     "Private network", sizeof(info.org));
            strlcpy(info.tag,     "local",           sizeof(info.tag));
            cache_put(ip, &info);
            continue;
        }

        if (fetch_geo(ip, &info)) {
            cache_put(ip, &info);
            struct in_addr a = {.s_addr = ip};
            ESP_LOGI(TAG, "%s -> %s / %s %s [%s]",
                     inet_ntoa(a), info.cc, info.org, info.asn, info.tag);
        } else {
            struct in_addr a = {.s_addr = ip};
            ESP_LOGW(TAG, "lookup failed for %s", inet_ntoa(a));
        }
    }
#endif  // GEOIP_ENABLE
}
