#pragma once
#include <stdint.h>
#include <stdbool.h>

struct sockaddr_in;   // forward decl — avoid pulling lwip/sockets.h into the header

/*
 * Fake interactive shell — Telnet & SSH post-login (Cowrie-style)
 *
 * Once a honeypot "accepts" a login it hands the connection here. Instead of the
 * usual "Login incorrect" loop, the attacker drops into a believable Ubuntu 20.04
 * shell that answers common reconnaissance commands (ls, cat /etc/passwd,
 * uname -a, ps, ifconfig, wget, ...) while logging EVERY command they type.
 * Capturing the post-login command set is the whole point: it reveals attacker
 * TTPs and IOCs (which payloads they fetch, which binaries they try to run) that
 * a credential-only honeypot never sees.
 *
 * Nothing is ever executed. Responses are canned, the filesystem is fictional,
 * and downloads are faked — the box is a decoy, not a sandbox.
 *
 * Transport-agnostic: the emulator talks through a shell_io_t so the same shell
 * drives both the plaintext Telnet socket and the encrypted wolfSSH channel. The
 * Telnet client does its own local echo and line editing; an SSH PTY is in raw
 * mode, so the SSH transport sets echo=true and the reader echoes input back.
 *
 * Logging:
 *   - session open               → ATTACK_SHELL event + Telegram alert
 *   - every command              → ATTACK_SHELL event (dashboard transcript)
 *   - download / exec IOC command → additional Telegram alert (wget/curl/tftp/…)
 *
 * Returns when the attacker logs out, the per-session command cap is hit, or the
 * transport closes.
 */

// Hard cap on commands handled per session — bounds log volume and run time
// against a bot that never disconnects.
#ifndef FAKE_SHELL_MAX_COMMANDS
#define FAKE_SHELL_MAX_COMMANDS   200
#endif

// Maximum length of a single command line (longer input is truncated).
#ifndef FAKE_SHELL_CMD_MAXLEN
#define FAKE_SHELL_CMD_MAXLEN     256
#endif

// Transport abstraction. The Telnet trap backs this with a raw socket; the SSH
// trap backs it with a wolfSSH channel. read_byte returns one byte (0-255) or a
// negative value on close/timeout; write returns bytes written (<0 on error).
typedef struct {
    void *io;                                       // opaque transport handle
    int (*read_byte)(void *io);                     // one byte, or <0 on close/timeout
    int (*write)(void *io, const char *buf, int len);
    bool echo;                                      // server echoes input (SSH: true)
} shell_io_t;

// Run the fake shell over an already-"authenticated" transport.
//   io   — transport callbacks (see shell_io_t)
//   addr — client address, for logging + MAC/geo enrichment
//   user — the username the attacker logged in as (drives prompt + whoami)
void fake_shell_run(const shell_io_t *io, struct sockaddr_in *addr, const char *user);
