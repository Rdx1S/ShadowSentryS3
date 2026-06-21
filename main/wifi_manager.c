#include "wifi_manager.h"
#include "config.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_netif_net_stack.h"   // esp_netif_get_netif_impl()
#include "esp_log.h"
#include "lwip/inet.h"
#include "lwip/etharp.h"           // etharp_find_addr()
#include "lwip/tcpip.h"            // tcpip_callback() — run in lwIP thread
#include <string.h>

#if MDNS_ENABLE
#include "mdns.h"
#endif

static const char *TAG = "WIFI";

// ── Internal state ────────────────────────────────────────────────────────────

#define WIFI_GOT_IP_BIT BIT0

static EventGroupHandle_t s_wifi_eg;
static esp_netif_t       *s_sta_netif   = NULL;
static volatile bool      s_connected   = false;
static bool               s_sntp_inited = false;
static int                s_retry_count = 0;
static volatile uint32_t  s_disconnect_count = 0;   // all forced STA disconnects
static volatile uint32_t  s_deauth_disc_count = 0;  // disconnects attributable to a received deauth/disassoc
static volatile uint8_t   s_last_disc_reason = 0;   // 802.11 reason of the most recent disconnect
static char               s_ip_str[WIFI_IP_STR_LEN] = {0};
#if MDNS_ENABLE
static bool               s_mdns_inited = false;
#endif

// ── SNTP ──────────────────────────────────────────────────────────────────────

static void sntp_start_once(void)
{
    if (s_sntp_inited) return;

    esp_sntp_config_t sntp_cfg = ESP_NETIF_SNTP_DEFAULT_CONFIG(WIFI_SNTP_SERVER);
    esp_netif_sntp_init(&sntp_cfg);

    s_sntp_inited = true;
    ESP_LOGI(TAG, "SNTP sync started via %s", WIFI_SNTP_SERVER);
}

// ── mDNS ────────────────────────────────────────────────────────────────────────

#if MDNS_ENABLE
// Brings up multicast-DNS so the device answers to "<MDNS_HOSTNAME>.local".
// Idempotent (guarded by s_mdns_inited) so reconnects / IP renewals do not
// re-initialise the stack. mDNS keeps working across IP changes — the whole
// point is that the name stays valid no matter what the DHCP server assigns.
static void mdns_start_once(void)
{
    if (s_mdns_inited) return;

    esp_err_t err = mdns_init();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "mDNS init failed (%s) — .local name unavailable",
                 esp_err_to_name(err));
        return;
    }

    mdns_hostname_set(MDNS_HOSTNAME);
    mdns_instance_name_set(MDNS_INSTANCE);

#if MDNS_ADVERTISE_ADMIN
    // Announce the dashboard so it shows up in Bonjour / mDNS browsers.
    mdns_txt_item_t txt[] = {
        {"path", "/"},
    };
    mdns_service_add(NULL, "_http", "_tcp", ADMIN_PORT,
                     txt, sizeof(txt) / sizeof(txt[0]));
#endif

    s_mdns_inited = true;
    ESP_LOGI(TAG, "mDNS started → http://%s.local:%d", MDNS_HOSTNAME, ADMIN_PORT);
}
#endif  // MDNS_ENABLE

// ── Event handler ─────────────────────────────────────────────────────────────

static void on_wifi_event(void *arg, esp_event_base_t base,
                          int32_t id, void *data)
{
    if (base != WIFI_EVENT) return;

    switch (id) {
        case WIFI_EVENT_STA_START:
            ESP_LOGI(TAG, "STA started — connecting to \"%s\"", WIFI_SSID);
            esp_wifi_connect();
            break;

        case WIFI_EVENT_STA_CONNECTED:
            ESP_LOGI(TAG, "Associated with AP \"%s\"", WIFI_SSID);
            s_retry_count = 0;
            break;

        case WIFI_EVENT_STA_DISCONNECTED: {
            const wifi_event_sta_disconnected_t *d =
                (const wifi_event_sta_disconnected_t *)data;
            uint8_t reason = d ? d->reason : 0;
            s_last_disc_reason = reason;
            s_connected = false;
            s_disconnect_count++;          // observed by the Wi-Fi threat monitor

            // Tell a deauth/disassoc attack apart from a benign disconnect by the
            // 802.11 reason code. Deauth tools (aireplay-ng / mdk4 / ESP deauthers)
            // send low attack codes — 1 (unspecified), 2, 7 — and even a single
            // spoofed frame forces a reconnect that can leak the 4-way handshake, so
            // one such drop is already a signal. Excluded as benign (NOT attacks):
            //   - reason >= 200 : local/internal RF failures (beacon timeout, no-AP,
            //                     handshake-timeout, roaming) reported by our own radio
            //   - 3 AUTH_LEAVE                : AP administratively tears down our auth
            //   - 4 DISASSOC_DUE_TO_INACTIVITY: AP kicks an *idle* station — this fires
            //                                   while the device just sits there, so
            //                                   without this exclusion every idle-kick
            //                                   looked like a deauth attack
            //   - 8 ASSOC_LEAVE              : normal deassoc-due-to-leaving / roaming
            bool deauth_reason = (reason != 0 && reason < 200 &&
                                  reason != WIFI_REASON_AUTH_LEAVE &&                 // 3
                                  reason != WIFI_REASON_DISASSOC_DUE_TO_INACTIVITY && // 4
                                  reason != WIFI_REASON_ASSOC_LEAVE);                 // 8
            if (deauth_reason) {
                s_deauth_disc_count++;
            }

            xEventGroupClearBits(s_wifi_eg, WIFI_GOT_IP_BIT);
            s_ip_str[0] = '\0';

            s_retry_count++;
            if (deauth_reason || s_retry_count == 1 ||
                s_retry_count % WIFI_LOG_RETRY_INTERVAL == 0) {
                ESP_LOGW(TAG, "Disconnected reason=%u (attempt %d) — retrying in %d ms",
                         reason, s_retry_count, WIFI_RECONNECT_DELAY_MS);
            }

            // Brief delay prevents a tight connect/fail/connect loop that
            // saturates the event queue when the AP is unreachable.
            vTaskDelay(pdMS_TO_TICKS(WIFI_RECONNECT_DELAY_MS));
            esp_wifi_connect();
            break;
        }

        default:
            break;
    }
}

static void on_ip_event(void *arg, esp_event_base_t base,
                        int32_t id, void *data)
{
    if (base != IP_EVENT || id != IP_EVENT_STA_GOT_IP) return;

    ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;

    // Cache the IP string — esp_ip4addr_ntoa writes a static buf internally
    snprintf(s_ip_str, sizeof(s_ip_str), IPSTR, IP2STR(&ev->ip_info.ip));

    s_connected   = true;
    s_retry_count = 0;

    xEventGroupSetBits(s_wifi_eg, WIFI_GOT_IP_BIT);

    ESP_LOGI(TAG, "IP acquired: %s  (mask %s  gw %s)",
             s_ip_str,
             ip4addr_ntoa((const ip4_addr_t *)&ev->ip_info.netmask),
             ip4addr_ntoa((const ip4_addr_t *)&ev->ip_info.gw));

    ESP_LOGI(TAG, "Admin panel → http://%s:%d", s_ip_str, ADMIN_PORT);

    // Start SNTP exactly once — even across IP renewals / reconnects
    sntp_start_once();

#if MDNS_ENABLE
    // Start mDNS exactly once so http://<hostname>.local works regardless of IP
    mdns_start_once();
#endif
}

// ── Public API ────────────────────────────────────────────────────────────────

void wifi_manager_init(void)
{
    s_wifi_eg = xEventGroupCreate();
    configASSERT(s_wifi_eg);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_sta_netif = esp_netif_create_default_wifi_sta();
    configASSERT(s_sta_netif);

    esp_netif_set_hostname(s_sta_netif, DEVICE_HOSTNAME);

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));

    // Register handlers for WiFi and IP events on separate bases
    ESP_ERROR_CHECK(esp_event_handler_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, on_ip_event, NULL));

    wifi_config_t wifi_cfg = {0};
    strlcpy((char *)wifi_cfg.sta.ssid,     WIFI_SSID,     sizeof(wifi_cfg.sta.ssid));
    strlcpy((char *)wifi_cfg.sta.password, WIFI_PASSWORD, sizeof(wifi_cfg.sta.password));

    // Accept WPA2 or WPA3-SAE — the AP selects the highest common mode.
    // Set to WIFI_AUTH_WPA2_PSK if your AP does not support WPA3.
    wifi_cfg.sta.threshold.authmode   = WIFI_AUTH_WPA2_PSK;
    wifi_cfg.sta.sae_pwe_h2e          = WPA3_SAE_PWE_BOTH;
    wifi_cfg.sta.pmf_cfg.capable      = true;
    wifi_cfg.sta.pmf_cfg.required     = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    // Disable Wi-Fi modem-sleep. This device is mains-powered and always-on, so
    // power-save buys nothing — and a sleeping STA looks "inactive" to the AP,
    // which then periodically evicts it (seen here as a reason=2 AUTH_EXPIRE drop
    // every ~20 min of idle). The Wi-Fi threat monitor would flag each such
    // eviction as a deauth attack, so keeping the radio awake removes that
    // false-positive at its source while leaving real deauth detection intact.
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    // esp_wifi_connect() is called from on_wifi_event on WIFI_EVENT_STA_START
}

void wifi_manager_wait_for_ip(void)
{
    xEventGroupWaitBits(s_wifi_eg,
                        WIFI_GOT_IP_BIT,
                        pdFALSE,    // do not clear the bit after returning
                        pdTRUE,
                        portMAX_DELAY);
}

bool wifi_manager_is_connected(void)
{
    return s_connected;
}

uint32_t wifi_manager_disconnect_count(void)
{
    return s_disconnect_count;
}

uint32_t wifi_manager_deauth_disconnect_count(void)
{
    return s_deauth_disc_count;
}

char *wifi_manager_get_ip_str(char *buf, size_t len)
{
    strlcpy(buf, s_ip_str, len);
    return buf;
}

// ── MAC resolution (ARP) ────────────────────────────────────────────────────────

// Context passed to the lwIP-thread callback. The ARP table must only be read
// from the TCP/IP thread (core locking is disabled in this build), so the
// actual etharp_find_addr() call is marshalled there via tcpip_callback().
typedef struct {
    ip4_addr_t        ip;
    uint8_t          *mac_out;
    volatile bool     found;
    SemaphoreHandle_t done;
} mac_query_t;

static void mac_query_cb(void *arg)
{
    mac_query_t *q = (mac_query_t *)arg;

    struct netif *nif = s_sta_netif
        ? (struct netif *)esp_netif_get_netif_impl(s_sta_netif) : NULL;

    struct eth_addr  *eth   = NULL;
    const ip4_addr_t *ipret = NULL;
    if (nif && etharp_find_addr(nif, &q->ip, &eth, &ipret) >= 0 && eth) {
        memcpy(q->mac_out, eth->addr, 6);
        q->found = true;
    }
    xSemaphoreGive(q->done);
}

bool wifi_manager_lookup_mac(uint32_t ip_net, uint8_t mac_out[6])
{
    memset(mac_out, 0, 6);
    if (!s_sta_netif) return false;

    mac_query_t q = { .mac_out = mac_out, .found = false };
    q.ip.addr = ip_net;                       // lwIP ip4_addr_t is network order
    q.done    = xSemaphoreCreateBinary();
    if (!q.done) return false;

    // tcpip_callback() is guaranteed to run once queued, so we can wait
    // unconditionally — no use-after-free window on the stack-local context.
    if (tcpip_callback(mac_query_cb, &q) == ERR_OK)
        xSemaphoreTake(q.done, portMAX_DELAY);

    vSemaphoreDelete(q.done);
    return q.found;
}

bool wifi_manager_get_gateway(uint32_t *gw_net)
{
    if (!gw_net || !s_sta_netif) return false;
    esp_netif_ip_info_t info;
    if (esp_netif_get_ip_info(s_sta_netif, &info) != ESP_OK) return false;
    if (info.gw.addr == 0) return false;
    *gw_net = info.gw.addr;        // esp_ip4_addr_t is network byte order
    return true;
}

// ── ARP table snapshot ──────────────────────────────────────────────────────────
// Walks the lwIP ARP cache from inside the TCP/IP thread (core locking is off in
// this build) and copies stable IP↔MAC pairs out. Consumed by the ARP-spoof
// monitor to spot poisoning (a MAC owning several IPs, or the gateway flipping).

typedef struct {
    wifi_arp_entry_t *out;
    int               max;
    volatile int      count;
    SemaphoreHandle_t done;
} arp_snap_t;

static void arp_snap_cb(void *arg)
{
    arp_snap_t *q = (arp_snap_t *)arg;
    int c = 0;

    for (size_t i = 0; i < ARP_TABLE_SIZE && c < q->max; i++) {
        ip4_addr_t      *ip  = NULL;
        struct netif    *nif = NULL;
        struct eth_addr *eth = NULL;
        // Returns 1 only for entries in the STABLE state (not pending/empty).
        if (etharp_get_entry(i, &ip, &nif, &eth) == 1 && ip && eth) {
            q->out[c].ip = ip->addr;
            memcpy(q->out[c].mac, eth->addr, 6);
            c++;
        }
    }

    q->count = c;
    xSemaphoreGive(q->done);
}

int wifi_manager_arp_snapshot(wifi_arp_entry_t *out, int max)
{
    if (!out || max <= 0 || !s_sta_netif) return 0;

    arp_snap_t q = { .out = out, .max = max, .count = 0 };
    q.done = xSemaphoreCreateBinary();
    if (!q.done) return 0;

    if (tcpip_callback(arp_snap_cb, &q) == ERR_OK)
        xSemaphoreTake(q.done, portMAX_DELAY);

    vSemaphoreDelete(q.done);
    return q.count;
}

// ── Active ARP re-verification ────────────────────────────────────────────────
// lwIP keeps a STABLE cache entry for an IP a host has abandoned (e.g. after a
// DHCP lease change) for minutes, so a passive snapshot can show one MAC on two
// IPs and look like poisoning when it is just churn. Before alerting, flush the
// cache and actively re-request both IPs: only a host still defending both will
// answer for both; a moved host won't answer for its old IP.

#define ARP_REVERIFY_WAIT_MS 1000   // time for who-has replies to repopulate

typedef struct {
    ip4_addr_t        ip1, ip2, gw;
    bool              have_gw;
    SemaphoreHandle_t done;
} arp_reverify_t;

static void arp_reverify_kick_cb(void *arg)
{
    arp_reverify_t *q = (arp_reverify_t *)arg;
    struct netif *nif = s_sta_netif
        ? (struct netif *)esp_netif_get_netif_impl(s_sta_netif) : NULL;
    if (nif) {
        etharp_cleanup_netif(nif);                    // drop all dynamic entries
        if (q->have_gw) etharp_request(nif, &q->gw);  // restore the uplink ASAP
        etharp_request(nif, &q->ip1);                 // who really owns these now?
        etharp_request(nif, &q->ip2);
    }
    xSemaphoreGive(q->done);
}

bool wifi_manager_arp_confirm_pair(uint32_t ip1_net, uint32_t ip2_net,
                                   const uint8_t mac[6])
{
    if (!s_sta_netif) return false;

    // Phase 1 — flush the cache and broadcast fresh who-has for both IPs.
    arp_reverify_t q = { .have_gw = false };
    q.ip1.addr = ip1_net;
    q.ip2.addr = ip2_net;
    uint32_t gw;
    if (wifi_manager_get_gateway(&gw)) { q.gw.addr = gw; q.have_gw = true; }
    q.done = xSemaphoreCreateBinary();
    if (!q.done) return false;
    if (tcpip_callback(arp_reverify_kick_cb, &q) == ERR_OK)
        xSemaphoreTake(q.done, portMAX_DELAY);
    vSemaphoreDelete(q.done);

    // Phase 2 — give the real owners time to answer.
    vTaskDelay(pdMS_TO_TICKS(ARP_REVERIFY_WAIT_MS));

    // Phase 3 — re-resolve both; confirmed only if both still map to `mac`.
    uint8_t m1[6], m2[6];
    bool f1 = wifi_manager_lookup_mac(ip1_net, m1);
    bool f2 = wifi_manager_lookup_mac(ip2_net, m2);
    return f1 && f2 && memcmp(m1, mac, 6) == 0 && memcmp(m2, mac, 6) == 0;
}

void wifi_manager_format_mac(const uint8_t mac[6], char *buf, size_t len)
{
    static const uint8_t zero[6] = {0};
    if (memcmp(mac, zero, 6) == 0) {
        strlcpy(buf, "unknown", len);
        return;
    }
    snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char *wifi_manager_mac_vendor(const uint8_t mac[6])
{
    static const uint8_t zero[6] = {0};
    if (memcmp(mac, zero, 6) == 0) return "";

    // Bit 1 of the first octet = locally-administered address. Modern phones
    // (iOS / Android) randomise their MAC, so this is a strong "mobile / private"
    // signal and far more reliable than any OUI table.
    if (mac[0] & 0x02) return "randomized (private)";

    // Curated OUI → vendor table. Deliberately small: covers the chips most
    // likely to appear on a home / SMB LAN. No match → "" (caller shows none).
    static const struct { uint8_t oui[3]; const char *name; } TBL[] = {
        // Espressif (ESP32 / ESP8266 — other IoT, or a second honeypot)
        {{0x24,0x0A,0xC4}, "Espressif"}, {{0x24,0x6F,0x28}, "Espressif"},
        {{0x30,0xAE,0xA4}, "Espressif"}, {{0x7C,0x9E,0xBD}, "Espressif"},
        {{0xA0,0x76,0x4E}, "Espressif"}, {{0xEC,0x94,0xCB}, "Espressif"},
        // Raspberry Pi
        {{0xB8,0x27,0xEB}, "Raspberry Pi"}, {{0xDC,0xA6,0x32}, "Raspberry Pi"},
        {{0xE4,0x5F,0x01}, "Raspberry Pi"}, {{0x28,0xCD,0xC1}, "Raspberry Pi"},
        // Intel (PC / laptop NICs)
        {{0xB0,0xDC,0xEF}, "Intel"}, {{0x00,0x1B,0x21}, "Intel"},
        {{0x34,0x13,0xE8}, "Intel"}, {{0xA0,0xA8,0xCD}, "Intel"},
        {{0x3C,0xA9,0xF4}, "Intel"}, {{0x94,0x65,0x9C}, "Intel"},
        // TP-Link (routers / smart plugs)
        {{0x50,0xC7,0xBF}, "TP-Link"}, {{0x14,0xCC,0x20}, "TP-Link"},
        {{0xEC,0x08,0x6B}, "TP-Link"},
        // Xiaomi (phones / IoT)
        {{0x28,0x6C,0x07}, "Xiaomi"}, {{0x64,0x09,0x80}, "Xiaomi"},
        {{0x78,0x11,0xDC}, "Xiaomi"},
        // Hikvision / Dahua (real cameras / NVRs — interesting on this network!)
        {{0x44,0x19,0xB6}, "Hikvision"}, {{0x4C,0xBD,0x8F}, "Hikvision"},
        {{0xC0,0x56,0xE3}, "Hikvision"}, {{0x3C,0xEF,0x8C}, "Dahua"},
        {{0x90,0x02,0xA9}, "Dahua"},
        // Virtualisation (a scan from a VM)
        {{0x00,0x0C,0x29}, "VMware"}, {{0x00,0x50,0x56}, "VMware"},
        {{0x08,0x00,0x27}, "VirtualBox"}, {{0x52,0x54,0x00}, "QEMU/KVM"},
    };

    for (size_t i = 0; i < sizeof(TBL) / sizeof(TBL[0]); i++)
        if (memcmp(mac, TBL[i].oui, 3) == 0)
            return TBL[i].name;

    return "";
}
