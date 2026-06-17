#pragma once

/*
 * Wi-Fi Threat Monitor — 802.11 radio-layer attack detection
 *
 * Puts the ESP32-S3 radio into promiscuous mode (MGMT-frame filter) and watches
 * for the management-frame floods that a software honeypot running on a normal
 * Linux/TCP stack can never see: Wi-Fi deauthentication / disassociation
 * attacks. A burst of deauth/disassoc frames above a threshold within a short
 * window is reported as an ATTACK_WIFI event (logged + Telegram), carrying the
 * attacker's transmitter MAC and target BSSID.
 *
 * Design:
 *   - The promiscuous RX callback runs in the Wi-Fi task and must stay tiny: it
 *     only classifies the frame and bumps a counter under a short spinlock.
 *   - A separate low-priority task evaluates the counter once per window and
 *     raises the alert, so nothing blocks inside the radio path. Mirrors the
 *     arp_monitor design.
 *
 * Scope & limits: detection runs on the channel the station is associated to —
 * exactly where deauth attacks against this network are transmitted — so it
 * works while the device stays connected, with no channel hopping. Detecting
 * rogue/evil-twin APs or beacon floods would require hopping channels (which
 * drops the STA link) and is intentionally out of scope for now.
 *
 * Tunables live in config.h (WIFI_MON_ENABLE / WIFI_MON_DEAUTH_THRESHOLD /
 * WIFI_MON_WINDOW_MS / WIFI_MON_COOLDOWN_S); wifi_monitor.c falls back to safe
 * defaults if they are absent.
 */
void wifi_monitor_task(void *arg);
