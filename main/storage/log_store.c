#include "log_store.h"
#include "config.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "LOGSTORE";

// Path for the binary ring dump and the all-time counter
#define LOG_FILE_PATH   "/spiffs/attacks.bin"
#define CTR_FILE_PATH   "/spiffs/total.bin"

// ── In-RAM ring buffer ────────────────────────────────────────────────────────
static attack_log_t  s_ring[LOG_RING_SIZE];
static int           s_head  = 0;   // next write position
static int           s_count = 0;   // entries currently in ring (≤ LOG_RING_SIZE)
static uint32_t      s_total = 0;   // all-time counter (survives clear via SPIFFS)

static SemaphoreHandle_t s_mutex;
static bool              s_spiffs_ok = false;

// ── SPIFFS helpers ────────────────────────────────────────────────────────────

static void persist_counter(void)
{
    FILE *f = fopen(CTR_FILE_PATH, "wb");
    if (!f) return;
    fwrite(&s_total, sizeof(s_total), 1, f);
    fclose(f);
}

// Rewrite the entire ring dump to SPIFFS (called after clear and on overflow cap).
static void rewrite_ring(void)
{
    FILE *f = fopen(LOG_FILE_PATH, "wb");
    if (!f) return;

    // Write entries from oldest to newest
    for (int i = 0; i < s_count; i++) {
        int idx = ((s_head - s_count + i) + LOG_RING_SIZE) % LOG_RING_SIZE;
        fwrite(&s_ring[idx], sizeof(attack_log_t), 1, f);
    }
    fclose(f);
}

// ── Public API ────────────────────────────────────────────────────────────────

void log_store_init(void)
{
    s_mutex = xSemaphoreCreateMutex();

    esp_vfs_spiffs_conf_t conf = {
        .base_path              = "/spiffs",
        .partition_label        = "storage",
        .max_files              = 4,
        .format_if_mount_failed = true,
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SPIFFS mount failed (%s) — running without persistence",
                 esp_err_to_name(ret));
        return;
    }
    s_spiffs_ok = true;

    // Restore all-time counter
    FILE *fc = fopen(CTR_FILE_PATH, "rb");
    if (fc) {
        fread(&s_total, sizeof(s_total), 1, fc);
        fclose(fc);
    }

    // Replay binary log into ring buffer
    FILE *fl = fopen(LOG_FILE_PATH, "rb");
    if (!fl) {
        ESP_LOGI(TAG, "No previous log found — starting fresh (total ever: %lu)",
                 (unsigned long)s_total);
        return;
    }

    attack_log_t entry;
    int loaded = 0;
    while (fread(&entry, sizeof(entry), 1, fl) == 1) {
        s_ring[s_head] = entry;
        s_head = (s_head + 1) % LOG_RING_SIZE;
        if (s_count < LOG_RING_SIZE) s_count++;
        loaded++;
    }
    fclose(fl);

    ESP_LOGI(TAG, "Loaded %d entries from flash (total ever: %lu)",
             loaded, (unsigned long)s_total);
}

void log_store_append(const attack_log_t *entry)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    bool was_full = (s_count == LOG_RING_SIZE);

    s_ring[s_head] = *entry;
    s_head = (s_head + 1) % LOG_RING_SIZE;
    if (s_count < LOG_RING_SIZE) s_count++;
    s_total++;

    xSemaphoreGive(s_mutex);

    if (!s_spiffs_ok) return;

    if (was_full) {
        // Ring wrapped — rewrite the whole file so SPIFFS stays in sync
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        rewrite_ring();
        xSemaphoreGive(s_mutex);
    } else {
        // Fast path: just append the new record
        FILE *f = fopen(LOG_FILE_PATH, "ab");
        if (f) {
            fwrite(entry, sizeof(*entry), 1, f);
            fclose(f);
        }
    }

    persist_counter();
}

int log_store_get_recent(attack_log_t *out, int max_count)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    int n = (s_count < max_count) ? s_count : max_count;
    for (int i = 0; i < n; i++) {
        // Most recent first
        int idx = ((s_head - 1 - i) + LOG_RING_SIZE) % LOG_RING_SIZE;
        out[i] = s_ring[idx];
    }

    xSemaphoreGive(s_mutex);
    return n;
}

uint32_t log_store_total_count(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    uint32_t n = s_total;
    xSemaphoreGive(s_mutex);
    return n;
}

void log_store_clear(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    memset(s_ring, 0, sizeof(s_ring));
    s_head  = 0;
    s_count = 0;
    // s_total is intentionally kept — it tracks history even after clear
    xSemaphoreGive(s_mutex);

    if (s_spiffs_ok) {
        remove(LOG_FILE_PATH);
        // Persist updated counter (unchanged) so it survives reboot
        persist_counter();
    }
}
