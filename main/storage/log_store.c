#include "log_store.h"
#include "config.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "LOGSTORE";

static attack_log_t  s_ring[LOG_RING_SIZE];
static int           s_head  = 0;
static int           s_count = 0;
static SemaphoreHandle_t s_mutex;
static bool          s_spiffs_ok = false;

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
        ESP_LOGW(TAG, "SPIFFS mount failed (%s) — persistence disabled", esp_err_to_name(ret));
        return;
    }
    s_spiffs_ok = true;

    // Replay persisted entries into ring buffer
    FILE *f = fopen(LOG_FILE_PATH, "rb");
    if (!f) return;

    attack_log_t entry;
    while (fread(&entry, sizeof(entry), 1, f) == 1) {
        s_ring[s_head] = entry;
        s_head = (s_head + 1) % LOG_RING_SIZE;
        if (s_count < LOG_RING_SIZE) s_count++;
    }
    fclose(f);
    ESP_LOGI(TAG, "Loaded %d entries from flash", s_count);
}

void log_store_append(const attack_log_t *entry)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    s_ring[s_head] = *entry;
    s_head = (s_head + 1) % LOG_RING_SIZE;
    if (s_count < LOG_RING_SIZE) s_count++;

    xSemaphoreGive(s_mutex);

    if (s_spiffs_ok) {
        FILE *f = fopen(LOG_FILE_PATH, "ab");
        if (f) {
            fwrite(entry, sizeof(*entry), 1, f);
            fclose(f);
        }
    }
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

int log_store_total_count(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int n = s_count;
    xSemaphoreGive(s_mutex);
    return n;
}

void log_store_clear(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_head  = 0;
    s_count = 0;
    xSemaphoreGive(s_mutex);

    if (s_spiffs_ok) remove(LOG_FILE_PATH);
}
