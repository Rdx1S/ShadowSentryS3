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
