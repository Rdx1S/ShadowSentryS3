cmake_minimum_required(VERSION 3.16)

# ── IDF_PATH guard ────────────────────────────────────────────────────────────
# Catches the most common mistake: running cmake before sourcing export.sh
if(NOT DEFINED ENV{IDF_PATH})
    message(FATAL_ERROR
        "\n"
        "  IDF_PATH is not set.\n"
        "  Activate ESP-IDF first:\n"
        "\n"
        "    . ~/esp/esp-idf/export.sh\n"
        "\n"
        "  Then re-run:  idf.py build\n")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# ── ESP-IDF version check ─────────────────────────────────────────────────────
# esp_netif_sntp_init() and WPA3 SAE PWE support require ESP-IDF v5.2 or later.
# IDF_VERSION is set by project.cmake above.
if(IDF_VERSION VERSION_LESS "5.2.0")
    message(FATAL_ERROR
        "\n"
        "  ShadowSentry S3 requires ESP-IDF v5.2.0 or later.\n"
        "  Detected version: ${IDF_VERSION}\n"
        "\n"
        "  Update your ESP-IDF installation:\n"
        "    cd ~/esp/esp-idf && git checkout v5.2.1 && ./install.sh esp32s3\n")
endif()

# ── Project ───────────────────────────────────────────────────────────────────
project(shadow_sentry_s3)
