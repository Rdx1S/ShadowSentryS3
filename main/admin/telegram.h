#pragma once
#include "log_store.h"

// Enqueue a non-blocking push notification
void telegram_notify(const attack_log_t *entry);

void telegram_task(void *arg);
