#pragma once

/*
 * ShadowSentry S3 — User Configuration
 *
 * This is the ONLY file you need to edit before flashing.
 * All tuneable parameters live here; module headers contain
 * implementation constants (timeouts, backlog sizes, etc.) that
 * rarely need to change.
 *
 * Minimum required changes before first flash:
 *   1. WIFI_SSID / WIFI_PASSWORD
 *   2. TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID  (or leave as-is to disable)
 *   3. ADMIN_PASSWORD
 */

// ── Firmware version ──────────────────────────────────────────────────────────
#define SHADOWSENTRY_VERSION        "1.0.0"

// ── WiFi ─────────────────────────────────────────────────────────────────────
//
// 2.4 GHz only (ESP32-S3 limitation).
// Supports WPA2-PSK and WPA3-SAE (auto-negotiated).
// Open networks (no password) are not supported by design — a honeypot
// on an open network is itself a security risk.

#define WIFI_SSID                   "YourWiFiSSID"
#define WIFI_PASSWORD               "YourWiFiPassword"

// ── Telegram ─────────────────────────────────────────────────────────────────
//
// How to obtain:
//   Token  → send /newbot to @BotFather, copy the token it replies with
//   Chat ID → send any message to your bot, then open:
//             https://api.telegram.org/bot<TOKEN>/getUpdates
//             find "chat":{"id": ...} in the JSON response
//
// Leave both as the placeholder strings below to disable Telegram alerts
// entirely. The system detects unconfigured state by checking the first
// character of TELEGRAM_BOT_TOKEN for 'Y'.

#define TELEGRAM_BOT_TOKEN          "YOUR_BOT_TOKEN"
#define TELEGRAM_CHAT_ID            "YOUR_CHAT_ID"

// ── Admin panel ───────────────────────────────────────────────────────────────
//
// Dashboard is accessible at http://<device-ip>:ADMIN_PORT
// Credentials: username = "admin", password = ADMIN_PASSWORD
//
// ADMIN_PORT must be in range 1024–65535 and must not collide with any
// honeypot port. The default 9999 is deliberately obscure.
//
// ADMIN_PASSWORD minimum length is 8 characters (enforced at compile time).
// The password is never written to the serial log.

#define ADMIN_PORT                  9999
#define ADMIN_PASSWORD              "changeme1"

// ── Honeypot ports ────────────────────────────────────────────────────────────
//
// Standard ports that IoT malware and network scanners probe first.
// Changing these reduces detection coverage — do so only if there is a
// genuine port conflict on your network.

#define RTSP_PORT                   554     // Mirai / Mozi RTSP bruteforce
#define HTTP_PORT                   80      // Web scanner / NVR login harvest
#define TELNET_PORT                 23      // Telnet bruteforce (default creds)
#define SSH_PORT                    22      // SSH scanner version fingerprinting

// ── Storage ───────────────────────────────────────────────────────────────────
//
// Both files live in the "storage" SPIFFS partition (see partitions.csv).
//
// LOG_FILE_PATH  — binary ring dump, max LOG_RING_SIZE × sizeof(attack_log_t)
// LOG_CTR_PATH   — 4-byte uint32 all-time counter; survives log_store_clear()
//
// Memory impact: LOG_RING_SIZE × sizeof(attack_log_t) bytes are allocated in
// BSS at startup. sizeof(attack_log_t) = 4+4+4+32+64+128 = 236 B (aligned
// to ~240 B). At the default of 200 entries that is ~47 KB of internal SRAM.

#define LOG_FILE_PATH               "/spiffs/attacks.bin"
#define LOG_CTR_PATH                "/spiffs/total.bin"
#define LOG_RING_SIZE               200

// ── Compile-time validation ───────────────────────────────────────────────────
//
// These assertions fire as build errors, not runtime panics, so
// misconfiguration is caught before the firmware ever runs on hardware.

// sizeof includes the null terminator, so an 8-char password has sizeof = 9
_Static_assert(sizeof(ADMIN_PASSWORD) >= 9,
    "ADMIN_PASSWORD must be at least 8 characters");

_Static_assert(ADMIN_PORT >= 1024 && ADMIN_PORT <= 65535,
    "ADMIN_PORT must be in range 1024–65535");

_Static_assert(LOG_RING_SIZE >= 10 && LOG_RING_SIZE <= 500,
    "LOG_RING_SIZE must be 10–500  (500 entries ≈ 117 KB RAM)");

// Port collision guards
_Static_assert(RTSP_PORT   != HTTP_PORT,   "RTSP_PORT and HTTP_PORT must differ");
_Static_assert(RTSP_PORT   != TELNET_PORT, "RTSP_PORT and TELNET_PORT must differ");
_Static_assert(HTTP_PORT   != TELNET_PORT, "HTTP_PORT and TELNET_PORT must differ");
_Static_assert(ADMIN_PORT  != RTSP_PORT,   "ADMIN_PORT collides with RTSP_PORT");
_Static_assert(ADMIN_PORT  != HTTP_PORT,   "ADMIN_PORT collides with HTTP_PORT");
_Static_assert(ADMIN_PORT  != TELNET_PORT, "ADMIN_PORT collides with TELNET_PORT");
_Static_assert(ADMIN_PORT  != SSH_PORT,    "ADMIN_PORT collides with SSH_PORT");
_Static_assert(SSH_PORT    != RTSP_PORT,   "SSH_PORT and RTSP_PORT must differ");
_Static_assert(SSH_PORT    != HTTP_PORT,   "SSH_PORT and HTTP_PORT must differ");
_Static_assert(SSH_PORT    != TELNET_PORT, "SSH_PORT and TELNET_PORT must differ");
