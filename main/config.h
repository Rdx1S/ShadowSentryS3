#pragma once

// ── WiFi ──────────────────────────────────────────────────────────────────────
#define WIFI_SSID           "YourWiFiSSID"
#define WIFI_PASSWORD       "YourWiFiPass"

// ── Telegram ──────────────────────────────────────────────────────────────────
#define TELEGRAM_BOT_TOKEN  "YOUR_BOT_TOKEN"
#define TELEGRAM_CHAT_ID    "YOUR_CHAT_ID"

// ── Admin panel ───────────────────────────────────────────────────────────────
#define ADMIN_PORT          9999
#define ADMIN_PASSWORD      "shadow_admin"

// ── Honeypot ports ────────────────────────────────────────────────────────────
#define RTSP_PORT           554
#define HTTP_PORT           80
#define TELNET_PORT         23

// ── Storage ───────────────────────────────────────────────────────────────────
#define LOG_FILE_PATH       "/spiffs/attacks.bin"
#define LOG_RING_SIZE       200
