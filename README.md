# ShadowSentry S3

> Zero-Configuration, Serverless Hardware HoneyPot on a Single ESP32-S3

ShadowSentry S3 — автономний апаратний honeypot класу **Edge Deception**. Перетворює одну плату ESP32-S3 (~$5) на невидиму пастку для ботнетів, сканерів та малварі всередині локальної мережі. Не потребує Raspberry Pi, хмарних серверів чи зовнішніх баз даних — усі обчислення та логи зберігаються всередині одного чипа.

---

## Як це працює

Завдяки двоядерному процесору Xtensa LX7 проєкт розділено на два ізольованих світи:

| Ядро | Роль | Задачі |
|------|------|--------|
| **Core 0** — Hacker World | Приймає атаки | RTSP :554 · HTTP :80 · Telnet :23 |
| **Core 1** — Admin World  | Управління та сповіщення | Admin Panel :9999 · Telegram · LittleFS |

```
Зловмисник/бот
     │
     ├─ Port 554 (RTSP)   → Fake Hikvision camera    ─┐
     ├─ Port 80  (HTTP)   → Fake NVR login page       ├─► log_store → SPIFFS
     └─ Port 23  (Telnet) → Fake Ubuntu 20.04          ─┘       │
                                                                  ▼
                                                        Telegram Push Alert
                                                                  │
                                                        Admin Panel :9999
                                                        (Dark-mode Dashboard)
```

---

## Вимоги

### Апаратне забезпечення

- **ESP32-S3** DevKit (будь-яка плата з ≥ 4 MB Flash)
- USB-кабель для прошивки
- Доступ до Wi-Fi мережі (2.4 GHz)

### Програмне забезпечення

| Компонент | Версія |
|-----------|--------|
| [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/) | **v5.2+** |
| Python | 3.8+ |
| CMake | 3.16+ |
| Git | будь-яка |

---

## Встановлення ESP-IDF

### macOS / Linux

```bash
git clone --recursive https://github.com/espressif/esp-idf.git ~/esp/esp-idf
cd ~/esp/esp-idf
git checkout v5.2.1
./install.sh esp32s3
. ./export.sh
```

### Windows

Завантажити та запустити [ESP-IDF Windows Installer](https://dl.espressif.com/dl/esp-idf/).

> Після інсталяції відкривати **ESP-IDF Command Prompt** для всіх команд нижче.

---

## Налаштування

Усі параметри знаходяться в **одному файлі** — `main/config.h`:

```c
// Wi-Fi
#define WIFI_SSID       "your_wifi_name"
#define WIFI_PASSWORD   "your_wifi_password"

// Telegram (отримати через @BotFather)
#define TELEGRAM_BOT_TOKEN  "123456789:AAxxxxx"
#define TELEGRAM_CHAT_ID    "your_chat_id"   // @userinfobot покаже твій ID

// Admin panel
#define ADMIN_PASSWORD  "changeme"           // пароль для http://<ip>:9999
#define ADMIN_PORT      9999

// Honeypot ports
#define RTSP_PORT       554
#define HTTP_PORT       80
#define TELNET_PORT     23
```

### Отримати Telegram Bot Token

1. Написати `/newbot` боту [@BotFather](https://t.me/BotFather)
2. Скопіювати отриманий token в `TELEGRAM_BOT_TOKEN`
3. Написати будь-що своєму боту, потім відкрити:
   `https://api.telegram.org/bot<TOKEN>/getUpdates`
4. Знайти `"chat":{"id":...}` — це твій `TELEGRAM_CHAT_ID`

---

## Збірка та прошивка

```bash
# 1. Клонувати репозиторій
git clone https://github.com/Rdx1S/ShadowSentryS3.git
cd ShadowSentryS3

# 2. Активувати ESP-IDF (якщо не активовано)
. ~/esp/esp-idf/export.sh

# 3. Встановити target (ESP32-S3)
idf.py set-target esp32s3

# 4. Відредагувати конфіг
nano main/config.h

# 5. Зібрати
idf.py build

# 6. Прошити (замінити /dev/ttyUSB0 на свій порт)
idf.py -p /dev/ttyUSB0 flash

# 7. Відкрити монітор
idf.py -p /dev/ttyUSB0 monitor
```

Кроки 6 і 7 можна об'єднати:

```bash
idf.py -p /dev/ttyUSB0 flash monitor
```

### Визначення порту

| OS | Команда |
|----|---------|
| Linux | `ls /dev/ttyUSB*` або `ls /dev/ttyACM*` |
| macOS | `ls /dev/cu.usb*` |
| Windows | Диспетчер пристроїв → Ports (COM & LPT) |

---

## Перший запуск

Після прошивки в моніторі з'явиться:

```
I (1234) MAIN: ╔══════════════════════════════════╗
I (1234) MAIN: ║   ShadowSentry S3  v1.0          ║
I (1234) MAIN: ║   Edge Deception HoneyPot        ║
I (1234) MAIN: ╚══════════════════════════════════╝
I (2100) WIFI: Got IP: 192.168.1.105
I (2101) WIFI: Admin panel: http://192.168.1.105:9999
I (2102) RTSP: Honeypot listening on port 554
I (2103) HTTP: Honeypot listening on port 80
I (2104) TELNET: Honeypot listening on port 23
```

Відкрити браузер → `http://192.168.1.105:9999`
Ввести логін: `admin` / пароль з `ADMIN_PASSWORD`.

---

## Admin Dashboard

Dark-mode веб-інтерфейс з авто-оновленням кожні 10 секунд:

- **Статистика** — загальна кількість атак, унікальні IP, розбивка по протоколах
- **Таблиця атак** — timestamp, IP-адреса, протокол, перехоплені облікові дані, payload
- **Кнопка Clear** — очищення логів з флеш-пам'яті
- **REST API** — `GET /api/attacks` → JSON, `POST /api/clear`

---

## Структура проєкту

```
ShadowSentryS3/
├── CMakeLists.txt              ESP-IDF root build file
├── sdkconfig.defaults          ESP32-S3 defaults (240MHz, dual-core)
├── partitions.csv              NVS(20KB) + App(3MB) + SPIFFS(1MB)
└── main/
    ├── config.h                ← Єдине місце для налаштувань
    ├── main.c                  Точка входу, pinToCore розподіл задач
    ├── wifi_manager.c/h        WiFi STA + SNTP синхронізація часу
    ├── index.html              Dashboard HTML (вбудовується в прошивку)
    ├── CMakeLists.txt
    ├── honeypot/               ── Core 0 — Hacker World ────────────
    │   ├── rtsp_trap.c/h       Port 554, Base64 creds capture
    │   ├── http_trap.c/h       Port 80, Fake Hikvision NVR login
    │   └── telnet_trap.c/h     Port 23, Fake Ubuntu 20.04 banner
    ├── admin/                  ── Core 1 — Admin World ─────────────
    │   ├── admin_panel.c/h     Port 9999, Basic-auth dashboard
    │   └── telegram.c/h        Async FreeRTOS queue → Telegram API
    └── storage/
        └── log_store.c/h       RAM ring buffer (200) + SPIFFS persist
```

---

## Як детектується атака

Будь-який звичайний домашній пристрій (ноутбук, телефон, Smart TV) **ніколи** не звертається до портів 554, 80 або 23 на ESP32-плату. Тому:

> **Будь-яке підключення до ShadowSentry S3 = 100% аномалія.**

Типові сценарії виявлення:

| Загроза | Поведінка | Час виявлення |
|---------|-----------|---------------|
| Mirai-ботнет | Брутфорс RTSP/Telnet | < 5 сек |
| Ransomware Lateral Movement | Сканування підмережі | < 5 сек |
| Ручний скан (nmap) | SYN на будь-який порт | < 1 сек |
| Веб-сканер (Shodan-like) | GET / на порт 80 | < 1 сек |

---

## Залежності ESP-IDF (автоматично)

Всі компоненти входять до складу ESP-IDF, окремо нічого встановлювати не потрібно:

- `lwIP` — TCP/IP стек, raw сокети
- `FreeRTOS` — мультизадачність, черги, м'ютекси
- `esp_http_client` — Telegram webhook
- `mbedTLS` — Base64 decode для auth
- `SPIFFS` / `LittleFS` — файлова система у флеші
- `esp_sntp` — синхронізація часу

---

## Вирішення проблем

**Не підключається до Wi-Fi**
```
Перевір SSID/пароль в config.h. ESP32-S3 підтримує лише 2.4 GHz.
```

**`idf.py: command not found`**
```bash
. ~/esp/esp-idf/export.sh   # активувати ESP-IDF у поточному терміналі
```

**Permission denied на /dev/ttyUSB0 (Linux)**
```bash
sudo usermod -a -G dialout $USER
# Перезайти в сесію
```

**Помилка `SPIFFS: mount failed`**
```bash
idf.py -p /dev/ttyUSB0 erase-flash   # очистити флеш повністю
idf.py -p /dev/ttyUSB0 flash         # прошити заново
```

**Telegram не надсилає сповіщення**
```
Переконайся що бот не заблокований і CHAT_ID вірний (число, може бути від'ємним для груп).
```

---

## Ліцензія

MIT License — використовуй, модифікуй, розповсюджуй вільно.
