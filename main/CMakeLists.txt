# ── ShadowSentry S3 — main component ─────────────────────────────────────────
#
# Single ESP-IDF component that contains the entire firmware.
# Source layout:
#
#   main.c                  — app_main(), task spawn
#   wifi_manager.c          — WiFi STA + SNTP
#   honeypot/rtsp_trap.c    — port 554, fake Hikvision camera (Core 0)
#   honeypot/http_trap.c    — port 80,  fake NVR login page  (Core 0)
#   honeypot/telnet_trap.c  — port 23,  fake Ubuntu banner   (Core 0)
#   admin/admin_panel.c     — port 9999, HTTP dashboard       (Core 1)
#   admin/telegram.c        — HTTPS alert sender              (Core 1)
#   storage/log_store.c     — ring buffer + SPIFFS persistence
#
# EMBED_TXTFILES "index.html"
#   CMake embeds the dashboard HTML into the firmware binary and exposes it
#   as two linker symbols accessed in admin_panel.c:
#     extern const uint8_t index_html_start[] asm("_binary_index_html_start");
#     extern const uint8_t index_html_end[]   asm("_binary_index_html_end");
#   The file is embedded as text (null-terminated); use EMBED_FILES for binary.

idf_component_register(
    SRCS
        "main.c"
        "wifi_manager.c"
        "arp_monitor.c"
        "geoip.c"
        "wifi_monitor.c"
        "honeypot/rtsp_trap.c"
        "honeypot/http_trap.c"
        "honeypot/telnet_trap.c"
        "honeypot/ssh_trap.c"
        "honeypot/ftp_trap.c"
        "admin/admin_panel.c"
        "admin/telegram.c"
        "storage/log_store.c"

    INCLUDE_DIRS
        "."            # config.h, wifi_manager.h
        "honeypot"     # rtsp_trap.h, http_trap.h, telnet_trap.h
        "admin"        # admin_panel.h, telegram.h
        "storage"      # log_store.h

    EMBED_TXTFILES
        "index.html"   # dashboard → _binary_index_html_{start,end}

    REQUIRES
        # Core system
        nvs_flash           # nvs_flash_init() — required by WiFi driver
        esp_wifi            # esp_wifi_*
        esp_netif           # esp_netif_*, esp_netif_sntp_init()
        esp_event           # esp_event_loop_create_default()
        mdns                # managed component espressif/mdns (see idf_component.yml)
                            # — .local name resolution in wifi_manager.c

        # Network stack
        lwip                # BSD sockets (socket/bind/listen/accept/recv/send),
                            # lwip/inet.h, lwip/sockets.h

        # Storage
        spiffs              # esp_vfs_spiffs_register(), SPIFFS on flash
                            # (maps to the "storage" partition in partitions.csv)

        # Crypto / TLS
        mbedtls             # mbedtls_base64_decode() — used by RTSP and admin auth
                            # esp_crt_bundle.h — Mozilla CA bundle for Telegram SSL
        esp-tls             # esp_crt_bundle_attach() — wires cert bundle into
                            # esp_http_client for api.telegram.org validation

        # Timer
        esp_timer           # esp_timer_get_time() — device uptime in /api/status

        # HTTP client
        esp_http_client     # telegram.c — HTTPS POST to Telegram Bot API
)
