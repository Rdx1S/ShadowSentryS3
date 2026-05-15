#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    ATTACK_RTSP   = 0,
    ATTACK_HTTP   = 1,
    ATTACK_TELNET = 2,
} attack_type_t;

typedef struct {
    uint32_t      timestamp;     // Unix epoch (seconds)
    uint32_t      src_ip;        // IPv4 in network byte order
    attack_type_t type;
    char          username[32];
    char          password[64];
    char          payload[128];
} attack_log_t;

// Must be called once before any other function (from Core 1 / admin world)
void log_store_init(void);

// Thread-safe: can be called from any core/task
void log_store_append(const attack_log_t *entry);

// Copy up to max_count most-recent entries into out[], newest first.
// Returns actual number of entries copied.
int  log_store_get_recent(attack_log_t *out, int max_count);

// All-time attack counter (persisted across reboots via SPIFFS).
uint32_t log_store_total_count(void);

// Wipe RAM ring buffer and SPIFFS files.
void log_store_clear(void);
