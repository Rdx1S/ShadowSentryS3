#pragma once
#include <stdint.h>

struct sockaddr_in;   // forward decl — avoid pulling lwip/sockets.h into the header

/*
 * Fake interactive shell — Telnet post-login (Cowrie-style)
 *
 * After the Telnet honeypot "accepts" a login it hands the connection here.
 * Instead of the usual "Login incorrect" loop, the attacker drops into a
 * believable Ubuntu 20.04 shell that answers common reconnaissance commands
 * (ls, cat /etc/passwd, uname -a, ps, ifconfig, wget, ...) while logging
 * EVERY command they type. Capturing the post-login command set is the whole
 * point: it reveals attacker TTPs and IOCs (which payloads they fetch, which
 * binaries they try to run) that a credential-only honeypot never sees.
 *
 * Nothing is ever executed. Responses are canned, the filesystem is fictional,
 * and downloads are faked — the box is a decoy, not a sandbox.
 *
 * Logging:
 *   - session open               → ATTACK_SHELL event + Telegram alert
 *   - every command              → ATTACK_SHELL event (dashboard transcript)
 *   - download / exec IOC command → additional Telegram alert (wget/curl/tftp/…)
 *
 * Runs inline on the Telnet trap task (Core 0). Returns when the attacker logs
 * out, the per-session command cap is hit, or the socket closes.
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

// Run the fake shell over an already-"authenticated" Telnet socket.
//   sock — connected client socket (a recv timeout should already be set)
//   addr — client address, for logging + MAC/geo enrichment
//   user — the username the attacker logged in as (drives prompt + whoami)
void fake_shell_run(int sock, struct sockaddr_in *addr, const char *user);
