#pragma once
#include <stdint.h>

/*
 * HTTP Honeypot — Port 80
 *
 * Impersonates a Hikvision NVR web interface. Serves a convincing dark-themed
 * login page on GET requests and harvests form credentials on POST requests.
 *
 * Attack flow:
 *   1. Scanner probes port 80 → receives fake Hikvision login page
 *   2. Attacker submits username/password via POST /doc/page/login.asp
 *   3. Credentials are URL-decoded, logged, and forwarded to Telegram
 *   4. Device replies with 302 redirect back to / (simulating a failed login)
 *
 * Captured form fields: username=<val>&password=<val>
 * Server header spoofed as "App-webs/" (real Hikvision fingerprint).
 *
 * Designed to run pinned to Core 0 (Hacker World).
 */

// Maximum queued TCP connections on port 80 before lwIP starts refusing SYNs.
#define HTTP_BACKLOG            4

// Per-connection receive timeout in seconds.
// Short on purpose — web scanners send requests immediately.
#define HTTP_RECV_TIMEOUT_S     5

// Maximum body size read from a POST request (bytes).
// Credentials are never longer than this in practice.
#define HTTP_BODY_MAX           512

// FreeRTOS task entry point. Pass NULL as arg.
// Pin to Core 0 with xTaskCreatePinnedToCore().
void http_trap_task(void *arg);
