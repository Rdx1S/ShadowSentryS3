#pragma once
#include <stdint.h>

/*
 * RTSP Honeypot — Port 554
 *
 * Impersonates a Hikvision IP camera. Accepts RTSP OPTIONS and DESCRIBE
 * requests, responds with a 401 Unauthorized to provoke Basic-auth retry,
 * then extracts and logs the Base64-encoded credentials.
 *
 * Designed to run pinned to Core 0 (Hacker World).
 * Logs are forwarded to log_store + telegram via the shared attack_log_t API.
 *
 * Captured credential example (Mirai variant):
 *   DESCRIBE rtsp://192.168.1.x:554/... RTSP/1.0
 *   Authorization: Basic YWRtaW46MTIzNDU2  →  admin:123456
 */

// Maximum concurrent TCP connections held open on port 554.
// Each connection runs synchronously inside rtsp_trap_task, so this
// controls how many pending SYNs lwIP will queue before refusing.
#define RTSP_BACKLOG        4

// Per-connection receive timeout in seconds. Keeps a slow attacker from
// blocking the accept loop indefinitely.
#define RTSP_RECV_TIMEOUT_S 10

// FreeRTOS task entry point. Pass NULL as arg.
// Pin to Core 0 with xTaskCreatePinnedToCore().
void rtsp_trap_task(void *arg);
