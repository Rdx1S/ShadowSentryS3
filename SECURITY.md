# Security Policy

## About this project

ShadowSentry S3 is a **defensive** security research tool — a hardware honeypot
that lures and logs attackers on a network you own. It is intended for
education, threat research, and protecting your own infrastructure.

⚠️ **Deploy it only on networks you own or are explicitly authorized to test.**
Capturing credentials, payloads, and traffic on networks you do not control may
be illegal in your jurisdiction.

## Supported versions

Security fixes are applied to the latest release and the `main` branch.

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

If you discover a vulnerability in ShadowSentry S3 itself (for example, a way to
crash the device, bypass the admin panel, or extract data from it), please
report it privately rather than opening a public issue by opening a
[private security advisory](https://github.com/Rdx1S/ShadowSentryS3/security/advisories/new).

Please include:

- affected version / commit,
- a description of the issue and its impact,
- steps to reproduce (or a proof of concept).

You can expect an initial response within a few days. Once a fix is available it
will be released and the reporter credited (unless anonymity is requested).

## Hardening notes

- Change `ADMIN_PASSWORD` in `main/config.h` before deploying — never ship the
  default.
- Keep `main/config.h` out of version control (it is git-ignored) — it embeds
  your Wi-Fi credentials, Telegram token, and admin password into the firmware.
- The admin panel and WebSocket feed are intended for a trusted LAN, not the
  public internet.
