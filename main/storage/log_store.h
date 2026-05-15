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
    uint32_t     timestamp;   // Unix epoch (seconds)
    uint32_t     src_ip;      // Network byte order
    attack_type_t type;
    char         username[32];
    char         password[64];
    char         payload[128];
} attack_log_t;

void log_store_init(void);
void log_store_append(const attack_log_t *entry);
int  log_store_get_recent(attack_log_t *out, int max_count);
int  log_store_total_count(void);
void log_store_clear(void);
