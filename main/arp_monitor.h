#pragma once

/*
 * ARP-spoof / MITM monitor
 *
 * A low-priority FreeRTOS task that periodically snapshots the lwIP ARP cache
 * (via wifi_manager_arp_snapshot) and looks for cache-poisoning signatures:
 *
 *   1. The default gateway's MAC changing after a stable baseline was learned
 *      — the classic "I am now your gateway" man-in-the-middle redirect.
 *   2. A single MAC claiming two or more distinct IPs — what an attacker's NIC
 *      looks like once it has poisoned several victims.
 *
 * On a hit it builds an attack_log_t with type ATTACK_ARP (src_ip = the spoofed
 * IP, src_mac = the attacker's MAC, payload = a human-readable description),
 * appends it to the log store and fires a Telegram alert — the same path the
 * port honeypots use, so ARP events show up in the dashboard feed and the bot.
 *
 * Scope & limits: this only sees ARP entries the device itself holds, so it
 * catches spoofing that targets this host or is broadcast network-wide
 * (the default for bettercap / ettercap). A strictly point-to-point spoof
 * between two other hosts that never touches this device's cache is out of
 * scope — detecting that would need promiscuous-mode packet capture.
 *
 * Tunables live in config.h (ARP_MONITOR_ENABLE / ARP_SCAN_INTERVAL_S /
 * ARP_ALERT_COOLDOWN_S); arp_monitor.c provides safe defaults if they are
 * absent, so the feature compiles against an older config.h unchanged.
 */
void arp_monitor_task(void *arg);
