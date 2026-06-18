<div align="center">

# ShadowSentry S3

> Zero-Configuration, Serverless Hardware Honeypot on a Single ESP32-S3

**🌐 Мова:** [English](README.md) · **Українська**

![Platform](https://img.shields.io/badge/platform-ESP32--S3-E7352C?logo=espressif&logoColor=white)
![Framework](https://img.shields.io/badge/framework-ESP--IDF%20v5.x-blue)
![Language](https://img.shields.io/badge/language-C-555555?logo=c&logoColor=white)
![Traps](https://img.shields.io/badge/honeypots-RTSP%20%7C%20HTTP%20%7C%20Telnet%20%7C%20SSH%20%7C%20FTP-1f9d55)
![Alerts](https://img.shields.io/badge/alerts-Telegram-26A5E4?logo=telegram&logoColor=white)
![Status](https://img.shields.io/badge/status-active-success)

![ShadowSentry S3 Dashboard](docs/demo.gif)

<sub>Живий дашборд стрімить захоплені атаки в реальному часі — пастки протоколів, джерела з GeoIP, вкрадені креденшали та перехоплена shell-сесія. (Дані ілюстративні.)</sub>

</div>

ShadowSentry S3 — автономний апаратний honeypot класу **Edge Deception**. Перетворює одну плату ESP32-S3 (~$5) на невидиму пастку для ботнетів, сканерів та малварі всередині локальної мережі. Не потребує Raspberry Pi, хмарних серверів чи зовнішніх баз даних — усі обчислення та логи зберігаються на одному чипі.

---

## Можливості

**Honeypot-пастки (Core 0)**
- **5 протокольних пасток** — RTSP (554, фейкова камера Hikvision), HTTP (80, фейковий вхід NVR + фінгерпринт кожного запиту), Telnet (23), SSH (22), FTP (21). Кожна пара кредів захоплюється.
- **Справжній SSH-сервер (wolfSSH)** — повноцінний SSH-2.0 хендшейк (curve25519 + ECDSA host-key), що розшифровує auth-обмін і **захоплює відкритий логін + пароль** — а не лише банер-fingerprint.
- **Інтерактивна фейкова оболонка (у стилі Cowrie)** — Telnet *і* SSH приймають логін і кидають атакуючого у правдоподібну оболонку Ubuntu 20.04, яка відповідає на recon-команди й **логує кожну команду**; команди завантаження/запуску (`wget`/`curl`/`chmod +x`/`./…`) позначаються як IOC і ескалюються.

**Мережеві та радіо-монітори (Core 1)**
- **ARP-spoof / MITM монітор** — стежить за ARP-кешем lwIP на ознаки отруєння (зміна MAC шлюзу, один MAC претендує на кілька IP).
- **Wi-Fi монітор загроз** — виявляє 802.11 deauth/disassoc атаки (зокрема одиночний deauth для перехоплення хендшейка) через класифіковані за reason-кодом примусові розриви + promiscuous-сніфінг broadcast-флуду.
- **MAC + виробник** для кожної події — резолвить L2 MAC атакуючого з ARP-таблиці зі здогадом про виробника (OUI); рандомізовані (приватні) MAC позначаються.
- **Threat-intel / GeoIP збагачення** — резолвить IP атакуючого в країну, ISP/ASN і репутаційний тег (`hosting`/`proxy`/`mobile`) через ip-api.com; приватні IP позначаються `Private LAN` без зовнішнього запиту.

**Платформа**
- **Live веб-дашборд + REST API** на порту 9999 (HTTP Basic Auth) — картки статистики, стрічка атак, клікабельне модальне вікно деталей. Окремий **WebSocket push-сервер** (порт 9998) стрімить кожну нову атаку в дашборд у реальному часі — стрічка оновлюється миттєво, не чекаючи наступного опитування.
- **Telegram-сповіщення** — асинхронна черга зі стійкою доставкою (чекає реконект + ретраїть, тож алерт переживає той самий deauth, що скинув плату з мережі).
- **SPIFFS-персистентність** — кільцевий буфер логів + лічильник за весь час переживають перезавантаження.
- **Двоядерна архітектура** — пастки на Core 0, адмінка/сповіщення/монітори на Core 1.
- **Zero-config і serverless** — прошив, задав Wi-Fi + Telegram-токен, готово. mDNS `.local`, без хмари й бази даних.

---

## Як це працює

Завдяки двоядерному процесору Xtensa LX7 проєкт розділено на два ізольованих світи:

| Ядро | Роль | Задачі |
|------|------|--------|
| **Core 0** — Hacker World | Приймає атаки | RTSP :554 · HTTP :80 · Telnet :23 · SSH :22 · FTP :21 |
| **Core 1** — Admin World  | Управління та сповіщення | Admin Panel :9999 · Telegram · SPIFFS |

```
Зловмисник / бот
     │
     ├─ Port 554  (RTSP)   → Fake Hikvision DS-2CD camera  ─┐
     ├─ Port  80  (HTTP)   → Fake Hikvision NVR login page  │
     ├─ Port  23  (Telnet) → Fake Ubuntu 20.04 server       ├──► log_store → SPIFFS
     ├─ Port  22  (SSH)    → Fake OpenSSH 8.9p1             │         │
     └─ Port  21  (FTP)    → Fake vsFTPd 3.0.5             ─┘         ▼
                                                                Telegram Alert
                                                                       │
                                                              Admin Panel :9999
                                                             (Dark-mode Dashboard)
```

### Що захоплюється

| Протокол | Перехоплюється | Приклад |
|----------|---------------|---------|
| RTSP | Username + Password | `admin:12345` з Basic Auth заголовку |
| HTTP | Username + Password + **path + User-Agent** | POST-форма логіну NVR; кожен запит (GET/POST/інше) фінгерпринтиться за шляхом і User-Agent сканера |
| Telnet | Username + Password **+ команди після входу** | Login prompt, далі фейкова інтерактивна оболонка, що логує кожну команду |
| SSH | Username + Password **+ команди після входу** | Справжній SSH-2.0 сервер (wolfSSH) — `root:hunter2`, далі інтерактивна оболонка |
| FTP | Username + Password | `USER admin` / `PASS password` (RFC 959) |

> **Справжній SSH-сервер (wolfSSH).** Порт 22 — це повноцінний SSH-2.0 сервер, а не банер: wolfSSH проводить повний обмін ключами (curve25519) і презентує ECDSA host-key, тож пристрій термінує крипту і **захоплює відкритий логін та пароль** атакуючого — чого банер-only пастка не вміє. Логін потім приймається (будь-який пароль; це декой), і атакуючий потрапляє в ту саму інтерактивну оболонку, що й у Telnet, з логуванням кожної команди. Одне застереження: wolfSSH повідомляє власний version string, тож fingerprint-клієнт зрозуміє, що це не OpenSSH — цінність тут у захопленні кредів і команд, а не в мімікрії банера.

> **Інтерактивна фейкова оболонка (у стилі Cowrie).** Замість вічного «Login incorrect» Telnet- та SSH-honeypot *приймають* логін і кидають атакуючого у правдоподібну оболонку Ubuntu 20.04, яка відповідає на типові recon-команди (`ls`, `cat /etc/passwd`, `uname -a`, `ps`, `ifconfig`, `wget`, …) і **логує кожну введену команду** як подію `Shell`. Захоплення набору команд після входу розкриває TTP та IOC атакуючого — які payload'и він качає, які бінарники намагається запустити — чого honeypot, що збирає лише креди, ніколи не побачить. Команди завантаження/запуску (`wget`/`curl`/`tftp`/`chmod +x`/`./…`) позначаються й ескалюються в Telegram-сповіщення. Нічого ніколи не виконується: відповіді захардкоджені, файлова система вигадана, завантаження фейкові. Налаштовується через `TELNET_SHELL_ENABLE` / `TELNET_LOGIN_GRANT_ATTEMPT` у `config.h`.

> **MAC-адреса для всіх протоколів.** Оскільки атакуючий у тій самій локальній мережі, для кожної події ShadowSentry резолвить його MAC через ARP-таблицю lwIP і показує його разом зі здогадом про виробника (OUI). Рандомізований MAC (приватний, типовий для смартфонів) позначається окремо. MAC видно і в дашборді, і в Telegram-сповіщенні.

> **Threat-intel збагачення.** Фоновий воркер резолвить кожен IP атакуючого у країну, ISP/ASN і репутаційний тег (`hosting` / `proxy` / `mobile`) через [ip-api.com](https://ip-api.com) — безкоштовно й без API-ключа, тож працює одразу після прошивки. Результат (з прапором країни) показується в дашборді та Telegram-алерті; приватні/LAN IP позначаються `Private LAN` без зовнішнього запиту. Запити йдуть поза гарячим шляхом і кешуються за IP. Налаштовується через `GEOIP_ENABLE` / `GEOIP_CACHE_SIZE` у `config.h`.

> **Wi-Fi threat monitor (радіо-рівень).** ESP32 — це не лише TCP-стек, а Wi-Fi радіо, тож вона ловить **802.11 deauth / disassoc атаки**, яких **не бачить жоден** софтовий honeypot — зокрема одиночний deauth-фрейм, яким змушують переконектитись, щоб перехопити WPA2-хендшейк. Два сигнали: (1) *примусові розриви* — deauth скидає плату з ефіру, тож вона завжди фіксує власний розрив, і кожен класифікується за 802.11 reason-кодом (deauth-розрив несе низький код 1–9; звичайний обрив радіо рапортує 200+ і ігнорується), тому навіть **один** deauth-розрив піднімає алерт без хибних спрацювань від нестабільного звʼязку; (2) *broadcast deauth-флуди*, пійймані в promiscuous-режимі, з MAC передавача атакуючого та цільовим BSSID. Будь-який сигнал піднімає подію `WiFi`. Працює на каналі, до якого підключена плата — без channel-hopping. (Детекція rogue/evil-twin AP потребувала б стрибків по каналах — поки поза межами.) Налаштовується через `WIFI_MON_ENABLE` / `WIFI_MON_DEAUTH_DISC_THRESHOLD` у `config.h`.

> **Детектор ARP-spoof / MITM.** Фонова задача періодично сканує ARP-кеш lwIP на ознаки отруєння — зміну MAC шлюзу після того, як вивчено стабільний baseline, або один MAC, що претендує на кілька IP — і піднімає подію `ARP` (стрічка дашборду + Telegram). Це ловить L2 man-in-the-middle атаки, до яких порт-пастки сліпі (вони ніколи не завершують TCP-handshake). Межі: детектиться спуфінг, націлений на цей хост або broadcast по всій мережі (типове для bettercap/ettercap); строго point-to-point спуфінг між двома іншими хостами — поза межами. Налаштовується через `ARP_MONITOR_ENABLE` / `ARP_SCAN_INTERVAL_S` / `ARP_ALERT_COOLDOWN_S` у `config.h`.

**Детекція в дії.** Перевірено на реальній платі ESP32-S3 проти живого `bettercap` ARP-спуфу — щойно атакуючий отруїв запис шлюзу в кеші плати, монітор залогував це й надіслав Telegram-алерт (значення нижче анонімізовані):

```
ARP-MON: Gateway 192.168.1.1 MAC changed
         aa:bb:cc:dd:ee:01  ->  de:ad:be:ef:13:37   (MITM redirect)
```

---

## Вимоги

### Апаратне забезпечення

- **ESP32-S3** DevKit (будь-яка плата з ≥ 4 MB Flash)
- USB-кабель для прошивки
- Wi-Fi мережа 2.4 GHz

### Програмне забезпечення

| Компонент | Версія |
|-----------|--------|
| [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/stable/esp32s3/) | **v5.2+** |
| Python | 3.8+ |
| CMake | 3.16+ |

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

```bash
# Скопіювати шаблон конфігурації
cp main/config.h.example main/config.h

# Відредагувати під свої параметри
nano main/config.h
```

Усі параметри знаходяться в **одному файлі** — `main/config.h`:

```c
// Мережева ідентичність (що видно в списку пристроїв роутера)
#define DEVICE_HOSTNAME     "Hikvision-NVR"

// Wi-Fi
#define WIFI_SSID           "YourWiFiSSID"
#define WIFI_PASSWORD       "YourWiFiPassword"

// Telegram (отримати через @BotFather)
#define TELEGRAM_BOT_TOKEN  "YOUR_BOT_TOKEN"
#define TELEGRAM_CHAT_ID    "YOUR_CHAT_ID"

// Admin panel  →  http://<ip>:9999
#define ADMIN_PASSWORD      "changeme1"
#define ADMIN_PORT          9999

// Honeypot ports
#define RTSP_PORT           554
#define HTTP_PORT           80
#define TELNET_PORT         23
#define SSH_PORT            22
#define FTP_PORT            21
```

> `main/config.h` додано до `.gitignore` — реальні credentials ніколи не потраплять до репозиторію.

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

# 2. Активувати ESP-IDF
. ~/esp/esp-idf/export.sh

# 3. Скопіювати та заповнити конфіг
cp main/config.h.example main/config.h
nano main/config.h

# 4. Зібрати і прошити (замінити /dev/ttyUSB0 на свій порт)
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
I (426) MAIN: ╔══════════════════════════════════════╗
I (428) MAIN: ║    ShadowSentry S3  v1.0             ║
I (434) MAIN: ║    Edge Deception HoneyPot           ║
I (439) MAIN: ║    ESP32-S3  |  ESP-IDF v5.x         ║
I (444) MAIN: ╚══════════════════════════════════════╝
I (1827) WIFI: IP acquired: 192.168.1.105
I (1830) WIFI: Admin panel → http://192.168.1.105:9999
I (1842) WIFI: mDNS started → http://hikvision-nvr.local:9999
I (1904) RTSP: Honeypot listening on port 554
I (1910) HTTP: Honeypot listening on port 80
I (1916) TELNET: Honeypot listening on port 23
I (1924) SSH: Honeypot listening on port 22
I (1930) FTP: Honeypot listening on port 21
I (1938) ADMIN: Admin panel on port 9999
```

Відкрити браузер → `http://192.168.1.105:9999`  
Логін: `admin` / пароль з `ADMIN_PASSWORD`.

> **Не треба запам'ятовувати IP.** Завдяки mDNS пристрій завжди доступний за стабільним іменем — `http://hikvision-nvr.local:9999` — незалежно від того, який адрес видасть DHCP. Працює з коробки на macOS, Linux (avahi), Windows 10+, iOS та Android. Ім'я налаштовується через `MDNS_HOSTNAME` у `config.h`.

---

## Admin Dashboard

Dark-mode веб-інтерфейс із WebSocket-стрічкою в реальному часі (нові атаки зʼявляються миттєво) + опитування раз на 10 секунд для звірки й оновлення threat-intel. Кожна картка статистики й рядок розподілу **клікабельні** — фільтрують стрічку/таблицю за типом:

- **6 карток статистики** — Total, Unique IPs, RTSP, HTTP, Telnet, SSH, FTP
- **Donut chart** — розбивка атак по протоколах у реальному часі
- **Таблиця атак** — timestamp, IP, **MAC + vendor**, протокол, перехоплені credentials, payload
- **Footer** — uptime пристрою, вільна heap-пам'ять, рівень Wi-Fi сигналу (RSSI)
- **Кнопка Clear** — очищення логів з flash-пам'яті

### REST API

| Метод | Ендпоінт | Опис |
|-------|----------|------|
| `GET` | `/api/attacks` | Лог атак + статистика (JSON) |
| `GET` | `/api/status` | Uptime / heap / RSSI (JSON) |
| `POST` | `/api/clear` | Очистити лог |

Всі ендпоінти захищені HTTP Basic Auth (`admin` / `ADMIN_PASSWORD`).

---

## Структура проєкту

```
ShadowSentryS3/
├── CMakeLists.txt              ESP-IDF root build file
├── sdkconfig.defaults          ESP32-S3 defaults (240 MHz, dual-core)
├── partitions.csv              NVS(24KB) + App(3MB) + SPIFFS(1MB)
└── main/
    ├── config.h.example        ← Шаблон конфігурації (копіювати в config.h)
    ├── config.h                ← Реальні налаштування (в .gitignore)
    ├── idf_component.yml        Managed-залежності (espressif/mdns)
    ├── main.c                  Точка входу, розподіл задач по ядрах
    ├── wifi_manager.c/h        Wi-Fi STA, DHCP hostname, SNTP, mDNS, ARP-хелпери
    ├── arp_monitor.c/h         Детектор ARP-spoof / MITM              (Core 1)
    ├── wifi_monitor.c/h        Детектор Wi-Fi deauth-флуду (promisc)  (Core 1)
    ├── geoip.c/h               Threat-intel збагачення (ip-api.com)   (Core 1)
    ├── index.html              Dashboard HTML (вбудовується в прошивку)
    ├── CMakeLists.txt
    ├── honeypot/               ── Core 0 — Hacker World ──────────────
    │   ├── rtsp_trap.c/h       Port 554, Fake Hikvision, Base64 creds
    │   ├── http_trap.c/h       Port 80, Fake NVR login page
    │   ├── telnet_trap.c/h     Port 23, Fake Ubuntu 20.04 login
    │   ├── fake_shell.c/h      Інтерактивна оболонка після входу (запис команд)
    │   ├── ssh_trap.c/h        Port 22, Справжній SSH-сервер (wolfSSH) — ловить креди
    │   ├── ssh_hostkey.h       Вшитий ECDSA host-key (декой)
    │   └── ftp_trap.c/h        Port 21, Fake vsFTPd 3.0.5, full creds
    ├── admin/                  ── Core 1 — Admin World ───────────────
    │   ├── admin_panel.c/h     Port 9999, HTTP Basic Auth, REST API
    │   ├── ws_server.c/h       Port 9998, live WebSocket push подій
    │   └── telegram.c/h        Async FreeRTOS queue → Telegram Bot API
    └── storage/
        └── log_store.c/h       RAM ring buffer (200 записів) + SPIFFS
```

---

## Як детектується атака

Жоден легітимний пристрій домашньої мережі (ноутбук, телефон, Smart TV) **ніколи** не звертається до портів 554, 80, 23, 22 або 21 на ESP32-плату.

> **Будь-яке підключення до ShadowSentry S3 = 100% аномалія.**

Типові сценарії виявлення:

| Загроза | Поведінка | Час виявлення |
|---------|-----------|---------------|
| Mirai / Mozi ботнет | Брутфорс RTSP/Telnet/FTP | < 5 сек |
| Вторгнення після входу | Команди у фейковій Telnet-оболонці (recon, завантаження payload) | на кожну команду |
| Ransomware lateral movement | Сканування підмережі | < 5 сек |
| SSH-сканер | Version fingerprint port 22 | < 1 сек |
| Веб-сканер | GET / на port 80 | < 1 сек |
| Ручний скан (nmap) | SYN на будь-який порт | < 1 сек |
| ARP-spoofing / MITM | Зміна MAC шлюзу або один MAC на кількох IP | ≤ інтервал скану (8 сек) |
| Wi-Fi deauth / disassoc атака | Примусовий розрив за reason-кодом (≥1) або broadcast-флуд (promiscuous) | ≤ вікно (2 сек) |

---

## Залежності ESP-IDF

Всі компоненти входять до ESP-IDF, нічого не потрібно встановлювати окремо:

- `lwIP` — TCP/IP стек, raw сокети
- `FreeRTOS` — мультизадачність, черги
- `esp_http_client` — Telegram Bot API
- `mbedTLS` — Base64 decode для Basic Auth
- `SPIFFS` — файлова система у flash
- `esp_netif_sntp` — синхронізація часу

Один компонент підтягується автоматично менеджером компонентів (описаний у `main/idf_component.yml`, завантажується при першій збірці):

- `espressif/mdns` — `.local` name resolution (доступ до адмінки за іменем)

---

## Вирішення проблем

**Не підключається до Wi-Fi**
```
ESP32-S3 підтримує лише 2.4 GHz. Перевір SSID/пароль в config.h.
```

**`idf.py: command not found`**
```bash
. ~/esp/esp-idf/export.sh
```

**Permission denied на /dev/ttyUSB0 (Linux)**
```bash
sudo usermod -a -G dialout $USER
# Перезайти в сесію
```

**Помилка `SPIFFS: mount failed`**
```bash
idf.py -p /dev/ttyUSB0 erase-flash
idf.py -p /dev/ttyUSB0 flash
```

**Telegram не надсилає сповіщення**
```
Перевір що бот не заблокований і написав йому /start.
TELEGRAM_CHAT_ID — число (може бути від'ємним для груп).
```

---

## Дорожня карта

**Реалізовано**
- [x] 5 протокольних honeypot-пасток (RTSP / HTTP / Telnet / SSH / FTP)
- [x] MAC + виробник (OUI) для кожної атаки
- [x] Фінгерпринт HTTP-запитів (метод / шлях / User-Agent)
- [x] Telegram-сповіщення зі стійкою доставкою + ретраї
- [x] Live веб-дашборд + REST API, клікабельне вікно деталей
- [x] mDNS `.local` резолюція
- [x] ARP-spoof / MITM монітор
- [x] Threat-intel / GeoIP збагачення (країна · ASN · репутація)
- [x] Wi-Fi монітор deauth/disassoc (класифікація за reason-кодом)
- [x] Інтерактивна фейкова оболонка з логуванням команд + IOC (Telnet)
- [x] Справжній SSH-сервер через wolfSSH — захоплення кредів + фейкова оболонка
- [x] Live WebSocket-дашборд — push подій у реальному часі (fallback на опитування)

**Заплановано**
- [ ] Підміна version-банера SSH (видавати за OpenSSH, не wolfSSH)
- [ ] Генерація SSH host-key на пристрої при першому буті (кеш у NVS)
- [ ] Виявлення rogue / evil-twin AP (потребує channel hopping)
- [ ] Додаткові протокольні пастки (SMB, MQTT, UPnP)

---

## Ліцензія

MIT — використовуй, модифікуй, розповсюджуй вільно.
