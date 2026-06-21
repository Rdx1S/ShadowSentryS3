#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * WiFi Manager — Station mode + SNTP
 *
 * Connects the ESP32-S3 to the configured AP (WIFI_SSID / WIFI_PASSWORD
 * from config.h), handles reconnection transparently, and starts SNTP
 * time synchronisation after the first successful IP acquisition.
 *
 * Typical usage in app_main():
 *
 *   wifi_manager_init();           // configure + start, non-blocking
 *   wifi_manager_wait_for_ip();    // block until first IP is assigned
 *   // start honeypot tasks here
 *
 * Reconnection policy:
 *   On every WIFI_EVENT_STA_DISCONNECTED event the driver waits
 *   WIFI_RECONNECT_DELAY_MS and calls esp_wifi_connect() again.
 *   There is no hard retry limit — the device must stay online.
 *   A warning is logged after every WIFI_LOG_RETRY_INTERVAL retries.
 *
 * SNTP:
 *   Uses esp_netif_sntp_init() (ESP-IDF v5.x API) with WIFI_SNTP_SERVER.
 *   Initialised exactly once after the first IP acquisition. Accurate
 *   timestamps are not guaranteed until SNTP sync completes (~5 s after
 *   connect); attack log entries before sync have Unix epoch from NVS RTC.
 */

// Milliseconds to wait before each reconnection attempt.
// Short enough to recover quickly; non-zero to avoid a tight busy-loop.
#define WIFI_RECONNECT_DELAY_MS     1000

// Log a warning every N retries so serial output stays readable under a
// prolonged AP outage without spamming a line per second.
#define WIFI_LOG_RETRY_INTERVAL     10

// NTP server used for time synchronisation after IP acquisition.
#define WIFI_SNTP_SERVER            "pool.ntp.org"

// Size of the internal IP string buffer (fits a dotted-decimal IPv4).
#define WIFI_IP_STR_LEN             16

// Initialise WiFi in STA mode and begin connecting.
// Must be called once from app_main() before wifi_manager_wait_for_ip().
// Calls esp_netif_init() and esp_event_loop_create_default() internally —
// do NOT call those again elsewhere.
void wifi_manager_init(void);

// Block the calling task until an IP address is assigned for the first time.
// Returns immediately if already connected.
void wifi_manager_wait_for_ip(void);

// Return true if the station currently has an IP address.
// Thread-safe (reads a volatile flag set by the event handler).
bool wifi_manager_is_connected(void);

// Monotonic count of ALL forced STA disconnects since boot. Thread-safe.
uint32_t wifi_manager_disconnect_count(void);

// Monotonic count of disconnects attributable to a received deauth/disassoc
// frame, classified by the 802.11 reason code (low codes 1-9, excluding
// assoc-leave) vs. benign RF losses (beacon-timeout / no-AP / handshake-timeout,
// reason 200+). A single deauth-attributable drop is enough to grab a handshake,
// so the Wi-Fi threat monitor alerts on the first one rather than on a storm.
// Thread-safe (reads a volatile counter).
uint32_t wifi_manager_deauth_disconnect_count(void);

// Copy the current IPv4 address into buf (at least WIFI_IP_STR_LEN bytes).
// Writes an empty string if not connected. Returns buf for convenience.
char *wifi_manager_get_ip_str(char *buf, size_t len);

// Buffer size that always fits a formatted MAC ("aa:bb:cc:dd:ee:ff" + NUL,
// or the literal "unknown").
#define WIFI_MAC_STR_LEN            18

// Resolve the Ethernet MAC of a same-LAN host from the lwIP ARP cache.
//   ip_net  — IPv4 in network byte order (e.g. sockaddr_in.sin_addr.s_addr)
//   mac_out — receives the 6-byte MAC; zeroed if the lookup fails
// Returns true only when an ARP entry exists. Best-effort: works for hosts on
// the local segment that the device has exchanged packets with (which an
// attacker connecting to a honeypot port always has). Runs the lookup in the
// lwIP TCP/IP thread, so it is safe to call from any honeypot task.
bool wifi_manager_lookup_mac(uint32_t ip_net, uint8_t mac_out[6]);

// Format a 6-byte MAC as "aa:bb:cc:dd:ee:ff" into buf (>= WIFI_MAC_STR_LEN).
// Writes "unknown" if mac is all-zero.
void wifi_manager_format_mac(const uint8_t mac[6], char *buf, size_t len);

// Best-effort manufacturer name from the MAC OUI (first 3 bytes), or a
// "randomized (private)" hint when the locally-administered bit is set
// (common for modern phones). Returns "" when the vendor is not recognised.
// The lookup table is small and curated — absence of a match is expected.
const char *wifi_manager_mac_vendor(const uint8_t mac[6]);

// Maximum number of ARP entries copied by wifi_manager_arp_snapshot().
// lwIP's default ARP_TABLE_SIZE is 10; 16 leaves headroom.
#define WIFI_ARP_MAX_ENTRIES        16

// One resolved ARP-cache entry: IPv4 (network byte order) <-> Ethernet MAC.
typedef struct {
    uint32_t ip;            // network byte order (matches sockaddr_in.sin_addr)
    uint8_t  mac[6];
} wifi_arp_entry_t;

// Copy the current default gateway's IPv4 (network byte order) into *gw_net.
// Returns false if not connected or the gateway is unknown (0.0.0.0).
bool wifi_manager_get_gateway(uint32_t *gw_net);

// Snapshot the stable entries of the lwIP ARP cache into out[] (up to max),
// returning the number copied. Safe to call from any task — the actual table
// walk is marshalled into the lwIP TCP/IP thread via tcpip_callback(), the same
// way wifi_manager_lookup_mac() is. Used by the ARP-spoof / MITM monitor.
int wifi_manager_arp_snapshot(wifi_arp_entry_t *out, int max);

// Actively re-verify a suspected ARP-spoof pair before alerting. Flushes the ARP
// cache, broadcasts fresh who-has requests for both IPs (and the gateway, so the
// uplink re-resolves promptly), waits briefly for replies, then re-resolves both.
// Returns true only if BOTH IPs answer and still map to `mac` — i.e. one host is
// actively defending two addresses (real poisoning). A host that merely changed
// DHCP lease will not answer for its old IP, so the stale mapping drops out and
// this returns false. Blocks ~1 s — call only from a low-priority task (the ARP
// monitor) and only when a suspicious pair is actually found.
bool wifi_manager_arp_confirm_pair(uint32_t ip1_net, uint32_t ip2_net,
                                   const uint8_t mac[6]);
