#pragma once
#include <stdint.h>

/*
 * FTP Honeypot — Port 21
 *
 * Impersonates vsFTPd 3.0.5 on Linux. Captures username and password from
 * the plaintext USER/PASS exchange defined in RFC 959. Unlike SSH, FTP
 * transmits credentials in clear text before any encryption negotiation,
 * so full credential capture is possible without a crypto stack.
 *
 * Attack flow:
 *   1. Scanner connects to port 21
 *   2. Device sends "220 (vsFTPd 3.0.5)" banner
 *   3. Client sends "USER <name>" → device replies "331 Please specify password"
 *   4. Client sends "PASS <pass>" → credentials logged + Telegram alert sent
 *   5. Device replies "530 Login incorrect" — never grants access
 *   6. Steps 3-5 repeat up to FTP_MAX_ATTEMPTS times, then connection closes
 *
 * Also handled: FEAT (advertises no features → discourages AUTH TLS),
 * QUIT (clean disconnect), unknown commands (500).
 *
 * Designed to run pinned to Core 0 (Hacker World).
 */

// Maximum queued TCP connections on port 21.
#define FTP_BACKLOG         4

// Per-connection idle timeout in seconds.
#define FTP_RECV_TIMEOUT_S  30

// Maximum login attempts per connection before forceful close.
#define FTP_MAX_ATTEMPTS    5

// FreeRTOS task entry point. Pass NULL as arg.
// Pin to Core 0 with xTaskCreatePinnedToCore().
void ftp_trap_task(void *arg);
