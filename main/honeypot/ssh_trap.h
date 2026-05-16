#pragma once
#include <stdint.h>

/*
 * SSH Honeypot — Port 22
 *
 * Impersonates OpenSSH 8.9p1 on Ubuntu 22.04. Captures the attacker's
 * SSH client software version string from the mandatory plaintext banner
 * exchange that begins every SSH-2.0 connection. This fingerprint
 * (e.g. "SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-Mirai") is
 * stored in attack_log_t.payload and forwarded to Telegram.
 *
 * Why no credentials?
 *   SSH v2 encrypts all traffic — including usernames and passwords —
 *   after the key exchange. A full key-exchange + AES-CTR stack is
 *   prohibitively heavy for an embedded honeypot. The version fingerprint
 *   alone identifies the scanning software and provides actionable threat
 *   intel: any connection to port 22 on this device is 100% anomalous.
 *
 * Attack flow:
 *   1. Scanner connects to port 22
 *   2. Device sends "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
 *   3. Client replies with its own version banner (plaintext, per RFC 4253 §4.2)
 *   4. Device logs the client fingerprint + source IP and closes
 *
 * Designed to run pinned to Core 0 (Hacker World).
 */

// Maximum queued TCP connections on port 22.
#define SSH_BACKLOG         4

// Per-connection receive timeout in seconds.
#define SSH_RECV_TIMEOUT_S  10

// FreeRTOS task entry point. Pass NULL as arg.
// Pin to Core 0 with xTaskCreatePinnedToCore().
void ssh_trap_task(void *arg);
