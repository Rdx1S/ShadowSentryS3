#include "fake_shell.h"
#include "telnet_trap.h"   // TELNET_RECV_TIMEOUT_S (restore timeout after \r drain)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h" // uxTaskGetStackHighWaterMark() — verify stack headroom
#include "log_store.h"
#include "telegram.h"
#include "wifi_manager.h"
#include "config.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

static const char *TAG = "SHELL";

#define HOSTNAME "myserver"

// ── Canned reconnaissance output ────────────────────────────────────────────────
// Fictional data — believable enough to keep an attacker typing, real enough that
// automated scrapers store it. None of it touches the actual device.

static const char OUT_UNAME_A[] =
    "Linux " HOSTNAME " 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 20:42:41 "
    "UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n";

static const char OUT_ID_ROOT[] = "uid=0(root) gid=0(root) groups=0(root)\r\n";

static const char OUT_PASSWD[] =
    "root:x:0:0:root:/root:/bin/bash\r\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\r\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin\r\n"
    "mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false\r\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\r\n";

static const char OUT_CPUINFO[] =
    "processor\t: 0\r\n"
    "vendor_id\t: GenuineIntel\r\n"
    "cpu family\t: 6\r\n"
    "model\t\t: 62\r\n"
    "model name\t: Intel(R) Xeon(R) CPU E5-2670 v2 @ 2.50GHz\r\n"
    "stepping\t: 4\r\n"
    "cpu MHz\t\t: 2499.998\r\n"
    "cache size\t: 25600 KB\r\n"
    "processor\t: 1\r\n"
    "vendor_id\t: GenuineIntel\r\n"
    "model name\t: Intel(R) Xeon(R) CPU E5-2670 v2 @ 2.50GHz\r\n"
    "cpu MHz\t\t: 2499.998\r\n"
    "cache size\t: 25600 KB\r\n";

static const char OUT_OSRELEASE[] =
    "NAME=\"Ubuntu\"\r\n"
    "VERSION=\"20.04.6 LTS (Focal Fossa)\"\r\n"
    "ID=ubuntu\r\n"
    "ID_LIKE=debian\r\n"
    "PRETTY_NAME=\"Ubuntu 20.04.6 LTS\"\r\n"
    "VERSION_ID=\"20.04\"\r\n";

static const char OUT_LS_LONG[] =
    "total 32\r\n"
    "drwx------  4 root root 4096 Jan 12 09:14 .\r\n"
    "drwxr-xr-x 19 root root 4096 Oct 30 11:02 ..\r\n"
    "-rw-------  1 root root  812 Jan 12 09:21 .bash_history\r\n"
    "-rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc\r\n"
    "-rw-r--r--  1 root root  161 Oct 15  2021 .profile\r\n"
    "drwx------  2 root root 4096 Jan 12 09:14 .ssh\r\n"
    "-rw-r--r--  1 root root 1240 Jan 12 09:18 backup.sql\r\n";

static const char OUT_LS_SHORT[] = "backup.sql\r\n";

static const char OUT_PS[] =
    "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
    "root           1  0.0  0.3 168140 11460 ?        Ss   Oct30   0:14 /sbin/init\r\n"
    "root         412  0.0  0.2  92800  8120 ?        Ss   Oct30   0:02 /lib/systemd/systemd-journald\r\n"
    "root         658  0.0  0.1  16124  6900 ?        Ss   Oct30   0:00 /usr/sbin/sshd -D\r\n"
    "mysql       901  0.1  4.1 1820400 165200 ?       Ssl  Oct30   3:21 /usr/sbin/mysqld\r\n"
    "www-data   1102  0.0  0.6 213880 24600 ?         S    Oct30   0:05 nginx: worker process\r\n"
    "root       2210  0.0  0.1  10072  3360 pts/0     Ss   09:14   0:00 -bash\r\n"
    "root       2244  0.0  0.1  11220  3540 pts/0     R+   09:21   0:00 ps aux\r\n";

static const char OUT_IFCONFIG[] =
    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
    "        inet 10.0.0.23  netmask 255.255.255.0  broadcast 10.0.0.255\r\n"
    "        ether 52:54:00:a1:b2:c3  txqueuelen 1000  (Ethernet)\r\n"
    "        RX packets 184220  bytes 198443120 (198.4 MB)\r\n"
    "        TX packets 92110  bytes 12044210 (12.0 MB)\r\n"
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
    "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
    "        loop  txqueuelen 1000  (Local Loopback)\r\n";

static const char OUT_FREE[] =
    "               total        used        free      shared  buff/cache   available\r\n"
    "Mem:         4039184      812340     2403120        1024      823724     2984120\r\n"
    "Swap:        1048572           0     1048572\r\n";

static const char OUT_DF[] =
    "Filesystem     1K-blocks    Used Available Use% Mounted on\r\n"
    "/dev/sda1       41020640 8123400  30794120  21% /\r\n"
    "tmpfs            2019592       0   2019592   0% /dev/shm\r\n";

// ── Socket helpers ──────────────────────────────────────────────────────────────

static void put(int sock, const char *s) { send(sock, s, strlen(s), 0); }

// Read a single command line. Consumes telnet IAC options, handles backspace,
// and treats Ctrl-D (EOT) on an empty line as logout. Returns line length, 0 for
// a blank line, or -1 on disconnect/timeout.
static int read_cmd(int sock, char *out, size_t outlen)
{
    size_t pos = 0;
    char c;
    while (pos < outlen - 1) {
        if (recv(sock, &c, 1, 0) <= 0) return -1;
        unsigned char u = (unsigned char)c;

        if (u == 0xFF) {                 // telnet IAC: skip the 2 option bytes
            char opt[2];
            recv(sock, opt, 2, 0);
            continue;
        }
        if (u == 0x04 && pos == 0) return -1;   // Ctrl-D on empty line → logout
        if (u == 0x7F || u == 0x08) {           // backspace / delete
            if (pos) pos--;
            continue;
        }
        if (c == '\r' || c == '\n') {
            if (c == '\r') {                     // swallow a trailing \n
                char peek;
                struct timeval tv = {.tv_sec = 0, .tv_usec = 50 * 1000};
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                recv(sock, &peek, 1, 0);
                tv.tv_sec = TELNET_RECV_TIMEOUT_S; tv.tv_usec = 0;
                setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            }
            break;
        }
        out[pos++] = c;
    }
    out[pos] = '\0';
    return (int)pos;
}

// ── Logging ─────────────────────────────────────────────────────────────────────

// A command is an IOC if it tries to fetch a remote payload or run a dropped
// binary — the high-signal actions worth a dedicated Telegram alert.
static bool is_ioc(const char *cmd)
{
    static const char *needles[] = {
        "wget", "curl", "tftp", "ftpget", "nc ", "ncat", "scp ",
        "chmod +x", "chmod 777", "./", "/tmp/", "busybox", "base64 -d",
    };
    for (size_t i = 0; i < sizeof(needles) / sizeof(needles[0]); i++)
        if (strstr(cmd, needles[i])) return true;
    return false;
}

static void log_event(struct sockaddr_in *addr, const uint8_t mac[6],
                      const char *user, const char *detail, bool telegram)
{
    attack_log_t e = {
        .type      = ATTACK_SHELL,
        .src_ip    = addr->sin_addr.s_addr,
        .timestamp = (uint32_t)time(NULL),
    };
    memcpy(e.src_mac, mac, 6);
    strlcpy(e.username, user, sizeof(e.username));
    strlcpy(e.payload, detail, sizeof(e.payload));
    log_store_append(&e);
    if (telegram) telegram_notify(&e);
}

// ── Command dispatch ──────────────────────────────────────────────────────────

// Collapse the home directory to ~ for the prompt, like a real shell.
static const char *display_cwd(const char *cwd, const char *home)
{
    static char buf[80];
    size_t hl = strlen(home);
    if (strncmp(cwd, home, hl) == 0 && (cwd[hl] == '\0' || cwd[hl] == '/')) {
        snprintf(buf, sizeof(buf), "~%s", cwd + hl);
        return buf;
    }
    strlcpy(buf, cwd, sizeof(buf));
    return buf;
}

// Naive `cd` path resolution — no validation, the filesystem is fictional anyway.
static void do_cd(char *cwd, size_t cwdlen, const char *arg, const char *home)
{
    if (!arg || !arg[0] || strcmp(arg, "~") == 0) { strlcpy(cwd, home, cwdlen); return; }
    if (strcmp(arg, "..") == 0) {
        char *slash = strrchr(cwd, '/');
        if (slash && slash != cwd) *slash = '\0';
        else strlcpy(cwd, "/", cwdlen);
        return;
    }
    if (arg[0] == '/') { strlcpy(cwd, arg, cwdlen); return; }
    size_t cl = strlen(cwd);
    if (cl == 1 && cwd[0] == '/') snprintf(cwd + cl, cwdlen - cl, "%s", arg);
    else                         snprintf(cwd + cl, cwdlen - cl, "/%s", arg);
}

// Handle one command line. Returns true if the session should end (exit/logout).
static bool dispatch(int sock, const char *line, const char *user,
                     char *cwd, size_t cwdlen, const char *home, bool is_root)
{
    // First token = command; remainder = args (preserved verbatim for echo etc.)
    char cmd[FAKE_SHELL_CMD_MAXLEN];
    strlcpy(cmd, line, sizeof(cmd));
    char *args = cmd;
    while (*args && !isspace((unsigned char)*args)) args++;
    char *rest = args;
    while (*rest && isspace((unsigned char)*rest)) rest++;
    if (*args) *args = '\0';        // terminate the command token

    if (!cmd[0]) return false;      // blank line

    if (!strcmp(cmd, "exit") || !strcmp(cmd, "logout") || !strcmp(cmd, "quit")) {
        put(sock, "logout\r\n");
        return true;
    }
    if (!strcmp(cmd, "whoami")) { put(sock, user); put(sock, "\r\n"); return false; }
    if (!strcmp(cmd, "id")) {
        if (is_root) put(sock, OUT_ID_ROOT);
        else {
            char b[128];
            snprintf(b, sizeof(b),
                     "uid=1000(%s) gid=1000(%s) groups=1000(%s)\r\n", user, user, user);
            put(sock, b);
        }
        return false;
    }
    if (!strcmp(cmd, "pwd")) { put(sock, cwd); put(sock, "\r\n"); return false; }
    if (!strcmp(cmd, "hostname")) { put(sock, HOSTNAME "\r\n"); return false; }
    if (!strcmp(cmd, "uname")) {
        if (strstr(rest, "-a")) put(sock, OUT_UNAME_A);
        else if (strstr(rest, "-r")) put(sock, "5.15.0-89-generic\r\n");
        else put(sock, "Linux\r\n");
        return false;
    }
    if (!strcmp(cmd, "uptime")) {
        put(sock, " 09:21:44 up 47 days,  3:12,  1 user,  load average: 0.08, 0.03, 0.01\r\n");
        return false;
    }
    if (!strcmp(cmd, "cd")) { do_cd(cwd, cwdlen, rest, home); return false; }
    if (!strcmp(cmd, "ls") || !strcmp(cmd, "dir")) {
        put(sock, strstr(rest, "-l") ? OUT_LS_LONG : OUT_LS_SHORT);
        return false;
    }
    if (!strcmp(cmd, "ps")) { put(sock, OUT_PS); return false; }
    if (!strcmp(cmd, "ifconfig") || !strcmp(cmd, "ip")) { put(sock, OUT_IFCONFIG); return false; }
    if (!strcmp(cmd, "free")) { put(sock, OUT_FREE); return false; }
    if (!strcmp(cmd, "df")) { put(sock, OUT_DF); return false; }
    if (!strcmp(cmd, "echo")) { put(sock, rest); put(sock, "\r\n"); return false; }
    if (!strcmp(cmd, "cat")) {
        if (strstr(rest, "/etc/passwd"))           put(sock, OUT_PASSWD);
        else if (strstr(rest, "/proc/cpuinfo"))    put(sock, OUT_CPUINFO);
        else if (strstr(rest, "/etc/os-release"))  put(sock, OUT_OSRELEASE);
        else if (rest[0]) {
            char b[160];
            snprintf(b, sizeof(b), "cat: %s: No such file or directory\r\n", rest);
            put(sock, b);
        }
        return false;
    }
    if (!strcmp(cmd, "wget") || !strcmp(cmd, "curl") || !strcmp(cmd, "tftp") ||
        !strcmp(cmd, "ftpget")) {
        // Pretend the fetch works but the file never lands — keeps the bot moving
        // while the URL it tried to pull is captured in the command log.
        put(sock, "Connecting... connected.\r\n");
        put(sock, "HTTP request sent, awaiting response... 200 OK\r\n");
        return false;
    }
    if (!strcmp(cmd, "clear")) { put(sock, "\033[H\033[2J"); return false; }
    if (!strcmp(cmd, "history") || !strcmp(cmd, "w") || !strcmp(cmd, "who") ||
        !strcmp(cmd, "last")) {
        return false;   // empty output, like a freshly-provisioned box
    }
    if (!strcmp(cmd, "chmod") || !strcmp(cmd, "cp") || !strcmp(cmd, "mv") ||
        !strcmp(cmd, "rm") || !strcmp(cmd, "kill") || !strcmp(cmd, "mkdir") ||
        !strcmp(cmd, "touch") || !strcmp(cmd, "export") || !strcmp(cmd, "unset")) {
        return false;   // succeed silently, like the real coreutils on success
    }

    // Unknown command — bash's not-found message.
    char b[FAKE_SHELL_CMD_MAXLEN + 32];
    snprintf(b, sizeof(b), "-bash: %s: command not found\r\n", cmd);
    put(sock, b);
    return false;
}

// ── Session ─────────────────────────────────────────────────────────────────────

void fake_shell_run(int sock, struct sockaddr_in *addr, const char *user)
{
    uint8_t mac[6] = {0};
    wifi_manager_lookup_mac(addr->sin_addr.s_addr, mac);

    bool is_root = (strcmp(user, "root") == 0);
    char home[64];
    snprintf(home, sizeof(home), is_root ? "/root" : "/home/%s", user);
    char cwd[80];
    strlcpy(cwd, home, sizeof(cwd));

    const char *ip = inet_ntoa(addr->sin_addr);
    ESP_LOGW(TAG, "[%s] shell opened as '%s'", ip, user);

    // Motd, then the session-open event (one Telegram alert).
    char motd[256];
    snprintf(motd, sizeof(motd),
        "\r\nWelcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-89-generic x86_64)\r\n\r\n"
        "Last login: Fri Jan 12 09:14:02 2024 from %s\r\n", ip);
    put(sock, motd);
    log_event(addr, mac, user, "shell session opened", true);

    char prompt[128];
    char line[FAKE_SHELL_CMD_MAXLEN];

    for (int n = 0; n < FAKE_SHELL_MAX_COMMANDS; n++) {
        snprintf(prompt, sizeof(prompt), "%s@" HOSTNAME ":%s%s ",
                 user, display_cwd(cwd, home), is_root ? "#" : "$");
        put(sock, prompt);

        int len = read_cmd(sock, line, sizeof(line));
        if (len < 0) break;             // disconnect / Ctrl-D / timeout
        if (len == 0) continue;         // blank line — just re-prompt

        // Log the command (dashboard transcript); escalate to Telegram on IOCs.
        char detail[128];
        snprintf(detail, sizeof(detail), "$ %.120s", line);
        bool ioc = is_ioc(line);
        log_event(addr, mac, user, detail, ioc);
        ESP_LOGW(TAG, "[%s] cmd: %s%s", ip, line, ioc ? "  <IOC>" : "");

        if (dispatch(sock, line, user, cwd, sizeof(cwd), home, is_root)) break;
    }

    ESP_LOGI(TAG, "[%s] shell session ended (telnet task stack free: %u B)",
             ip, (unsigned)(uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t)));
}
