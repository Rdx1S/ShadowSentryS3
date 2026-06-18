#pragma once

/*
 * Live WebSocket push server
 *
 * A small esp_http_server instance dedicated to pushing attack events to the
 * dashboard in real time, so the browser no longer has to poll /api/attacks.
 * It registers a log_store listener; every new attack is marshalled onto the
 * httpd task (httpd_queue_work) and broadcast as a JSON text frame to all
 * connected WebSocket clients — the same per-entry shape the REST API emits, so
 * the dashboard reuses its existing render code.
 *
 * Runs on its own port (ADMIN_WS_PORT) alongside the raw-socket admin panel.
 * The endpoint is unauthenticated: it only emits attack metadata already shown
 * on the LAN dashboard, same threat model as the panel itself. Polling remains
 * as a fallback for browsers that can't open the socket.
 */

// Dedicated port for the WebSocket endpoint (ws://<device-ip>:ADMIN_WS_PORT/ws).
#ifndef ADMIN_WS_PORT
#define ADMIN_WS_PORT   9998
#endif

// Maximum simultaneous dashboard WebSocket clients. Kept small: every slot the
// WS httpd reserves is an lwIP socket taken from the shared pool that the 6
// honeypot listeners + admin panel + Telegram/GeoIP clients also draw on.
#ifndef ADMIN_WS_MAX_CLIENTS
#define ADMIN_WS_MAX_CLIENTS  3
#endif

// Start the WebSocket push server and hook it into the log store. Call once
// after the network is up (Core 1). esp_http_server manages its own task.
void ws_server_start(void);
