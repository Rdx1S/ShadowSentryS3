#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * GeoIP / threat-intel enrichment
 *
 * For each attacker IP, looks up geolocation + network reputation and caches
 * the result in RAM keyed by IP. The honeypots stay fast (they only enqueue an
 * IP); a low-priority worker task does the network call in the background, so
 * nothing on the hot path ever blocks and the attack-log / SPIFFS format is
 * left unchanged. Both the dashboard (/api/attacks JSON) and the Telegram alert
 * simply read the cache via geoip_lookup().
 *
 * Provider: ip-api.com — free, no API key required (works out of the box for
 * anyone who clones the repo). Private / RFC1918 source IPs are short-circuited
 * to "Private LAN" without any network call (the common case for a LAN honeypot).
 *
 * Tunables live in config.h (GEOIP_ENABLE / GEOIP_CACHE_SIZE / etc.); geoip.c
 * falls back to safe defaults if they are absent.
 */

typedef struct {
    char cc[4];          // ISO-3166 country code, e.g. "DE" ("" if unknown/LAN)
    char country[28];    // human name, e.g. "Germany" / "Private LAN"
    char org[48];        // ISP or organisation
    char asn[16];        // autonomous system, e.g. "AS24940"
    char tag[12];        // "hosting" / "proxy" / "mobile" / "local" / ""
} geoip_info_t;

// Worker task: drains the request queue and fills the cache. Spawn once.
void geoip_task(void *arg);

// Request background enrichment of ip_net (network byte order). Non-blocking;
// silently ignored if the IP is already cached, the queue is full, or GeoIP is
// disabled. Safe to call from any task before the worker has started.
void geoip_enqueue(uint32_t ip_net);

// Copy cached enrichment for ip_net into *out. Returns false (and zeroes *out)
// if the IP has not been resolved yet — callers should treat that as "unknown".
bool geoip_lookup(uint32_t ip_net, geoip_info_t *out);
