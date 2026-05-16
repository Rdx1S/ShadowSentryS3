#pragma once
#include <stdint.h>

/*
 * Telnet Honeypot — Port 23
 *
 * Impersonates an Ubuntu 20.04 LTS machine with a standard login prompt.
 * Collects username/password pairs from bruteforce tools and botnets
 * (Mirai, Mozi, and similar IoT worms that target default Telnet credentials).
 *
 * Attack flow:
 *   1. Bot connects to port 23
 *   2. Device sends a realistic Ubuntu 20.04 kernel banner + "login: " prompt
 *   3. Bot submits a username → device replies "Password: "
 *   4. Bot submits a password → credentials logged + Telegram alert sent
 *   5. Device replies "Login incorrect" and loops back to "login: "
 *   6. After TELNET_MAX_ATTEMPTS the connection is closed
 *
 * IAC option negotiation bytes (0xFF prefix, 3-byte sequences) are silently
 * consumed so raw Telnet clients don't corrupt the captured credentials.
 *
 * Designed to run pinned to Core 0 (Hacker World).
 */

// Maximum queued TCP connections on port 23.
#define TELNET_BACKLOG          4

// Per-connection idle timeout in seconds.
// Bots usually respond within a second; 30s is generous.
#define TELNET_RECV_TIMEOUT_S   30

// Short timeout used while consuming the optional \n after a \r (milliseconds).
#define TELNET_CR_DRAIN_MS      50

// Number of login attempts accepted per connection before forceful close.
// Limits log spam from persistent bruteforcers without cutting off too early.
#define TELNET_MAX_ATTEMPTS     5

// FreeRTOS task entry point. Pass NULL as arg.
// Pin to Core 0 with xTaskCreatePinnedToCore().
void telnet_trap_task(void *arg);
