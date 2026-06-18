#pragma once
#include <stdint.h>

/*
 * SSH Honeypot — Port 22  (real SSH server via wolfSSH)
 *
 * A genuine SSH-2.0 server: wolfSSH performs the full key exchange (curve25519),
 * presents an ECDSA host key, and decrypts the authentication exchange. Because
 * the server terminates the crypto, it captures the plaintext USERNAME and
 * PASSWORD — something a banner-only trap can never do — then "accepts" the login
 * (any password works; it's a decoy) and drops the attacker into the same
 * interactive fake shell as Telnet (see fake_shell.c), logging every command.
 *
 * Attack flow:
 *   1. Scanner / brute-forcer connects to port 22
 *   2. wolfSSH completes the SSH-2.0 handshake (ECDH + ECDSA host key)
 *   3. Client sends username + password → captured in the user-auth callback
 *      (logged as ATTACK_SSH with credentials + Telegram alert)
 *   4. Login is accepted; the attacker lands in the fake Ubuntu shell
 *   5. Every command is logged as ATTACK_SHELL (post-login TTPs / IOCs)
 *
 * Note: wolfSSH advertises its own SSH version string in the banner, so a
 * fingerprinting client can tell this is wolfSSH rather than OpenSSH. The value
 * is the credential + command capture, not banner mimicry.
 *
 * Designed to run pinned to Core 0 (Hacker World). Needs a large stack for the
 * handshake crypto — see STACK_SSH in main.c.
 */

// Maximum queued TCP connections on port 22.
#define SSH_BACKLOG         4

// Per-connection receive timeout in seconds. Covers each handshake round-trip
// and bounds an idle interactive session so one stalled attacker can't pin the
// single SSH task indefinitely.
#define SSH_RECV_TIMEOUT_S  30

// FreeRTOS task entry point. Pass NULL as arg.
// Pin to Core 0 with xTaskCreatePinnedToCore().
void ssh_trap_task(void *arg);
