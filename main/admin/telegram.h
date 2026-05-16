#pragma once
#include "log_store.h"

/*
 * Telegram Notifier — Core 1 (Admin World)
 *
 * Sends push alerts to a Telegram bot when an attack is detected.
 * Designed to be non-blocking for the caller: telegram_notify() enqueues
 * the entry and returns immediately. The actual HTTPS request is handled
 * asynchronously inside telegram_task() on Core 1.
 *
 * Message format (HTML parse_mode):
 *   🚨 ShadowSentry S3 Alert
 *
 *   📹 Attack: RTSP
 *   🌍 IP: 192.168.1.55
 *   👤 Creds: admin:123456
 *   📋 RTSP DESCRIBE creds=admin:123456
 *
 * Rate limiting:
 *   TELEGRAM_RATE_LIMIT_MS enforces a minimum gap between API calls to
 *   avoid HTTP 429 "Too Many Requests" from Telegram (bot limit: ~30 msg/s
 *   globally, recommended ≤ 1 msg/s per chat). During a flood attack the
 *   queue absorbs bursts; excess entries are dropped when the queue is full.
 *
 * SSL:
 *   Uses esp_crt_bundle_attach (Mozilla CA bundle bundled in ESP-IDF) to
 *   properly validate api.telegram.org — no skip_cert_common_name_check.
 *   Requires CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y in sdkconfig.
 *
 * Configuration (main/config.h):
 *   TELEGRAM_BOT_TOKEN — token from @BotFather
 *   TELEGRAM_CHAT_ID   — numeric chat/user ID from @userinfobot
 */

// FreeRTOS queue depth. When full, telegram_notify() drops new entries
// silently (never blocks the caller).
#define TELEGRAM_QUEUE_DEPTH      10

// HTTPS request timeout in milliseconds.
#define TELEGRAM_HTTP_TIMEOUT_MS  10000

// Minimum delay between successive API calls (milliseconds).
// Keeps the bot under Telegram's per-chat rate limit.
#define TELEGRAM_RATE_LIMIT_MS    2000

// Enqueue an attack notification. Non-blocking — safe to call from any task/core.
// Drops the entry silently if the queue is full.
void telegram_notify(const attack_log_t *entry);

// Store the device IP so telegram_task() can send a boot-online notification.
// Call this before spawning telegram_task(), after WiFi IP is acquired.
void telegram_set_boot_ip(const char *ip_str);

// FreeRTOS task entry point. Pass NULL as arg.
// Pin to Core 1 with xTaskCreatePinnedToCore().
// Sends a boot-online message, then blocks on the attack queue indefinitely.
void telegram_task(void *arg);
