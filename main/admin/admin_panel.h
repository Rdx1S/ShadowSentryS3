#pragma once
#include <stdint.h>

/*
 * Admin Panel — Port ADMIN_PORT (default 9999) — Core 1 (Admin World)
 *
 * Minimal single-threaded HTTP/1.1 server that serves the ShadowSentry
 * dashboard and a small JSON REST API. Protected by HTTP Basic Auth.
 *
 * Endpoints:
 *   GET  /              → 200  text/html   embedded dashboard (index.html)
 *   GET  /api/attacks   → 200  application/json  recent attack log + stats
 *   GET  /api/status    → 200  application/json  device health (uptime_s/free_heap/rssi)
 *   POST /api/clear     → 204  wipe flash log
 *   *                   → 401  if credentials missing or wrong
 *
 * JSON schema for GET /api/attacks:
 *   {
 *     "total":      <uint32 all-time attack count>,
 *     "unique_ips": <int unique IPs in current window>,
 *     "by_type":    [<rtsp>, <http>, <telnet>],
 *     "entries": [
 *       { "ts": <unix>, "ip": <uint32 network-order>,
 *         "type": 0|1|2, "user": "...", "pass": "...", "payload": "..." },
 *       ...
 *     ]
 *   }
 *
 * Authentication:
 *   HTTP Basic Auth — username "admin", password from config.h ADMIN_PASSWORD.
 *   Credentials decoded via mbedTLS Base64 and compared with constant-time
 *   memcmp (timing-safe enough for a local-network admin panel).
 *
 * Security notes:
 *   - All attacker-supplied strings (username, password, payload) are
 *     JSON-escaped before being embedded in the response body.
 *   - ADMIN_PASSWORD is never printed to the serial log.
 *   - The server runs on ADMIN_PORT (not 80) and is invisible to the
 *     honeypot ports — attackers hitting port 80 see the fake NVR page.
 *
 * Designed to run pinned to Core 1 with xTaskCreatePinnedToCore().
 */

// listen() backlog — only one admin at a time is expected.
#define ADMIN_BACKLOG           2

// Per-connection receive timeout in seconds.
#define ADMIN_RECV_TIMEOUT_S    5

// Maximum number of log entries returned by GET /api/attacks.
// Each serialised entry is at most ~420 bytes; 50 × 420 = 21 KB fits in
// ADMIN_JSON_BUF_SIZE with room for the envelope.
#define ADMIN_MAX_LOG_ENTRIES   50

// Static JSON response buffer size (bytes). Allocated in BSS (not stack).
// Must fit: envelope (~120 B) + ADMIN_MAX_LOG_ENTRIES × max-entry (~420 B).
#define ADMIN_JSON_BUF_SIZE     24576   // 24 KB

// FreeRTOS task entry point. Pass NULL as arg.
// Pin to Core 1 with xTaskCreatePinnedToCore().
void admin_panel_task(void *arg);
