# HA LAN Canary & TCP Tarpit (patched)

Home Assistant custom component + package that opens decoy ports (FTP 2121, SSH 2222,
Telnet 2323, VNC 5900, DSM-HTTP 8088, optional MySQL 3306) on your HA host, alerts your
phone when a device on the LAN probes them, and holds the scanner in a slow-drip tarpit.

Patched fork of [robainbinder/ha-lan-canary-tarpit](https://github.com/robainbinder/ha-lan-canary-tarpit) 1.0.0 (MIT). Main fixes:

- A second hit no longer toggles the alert off/on, which triggered the reset automation and released every trapped socket.
- Webhook is LAN-only, POST-only, with a secret ID from `secrets.yaml`.
- Alerts are rate limited (per-IP cooldown + global per-minute cap); the tarpit cap is enforced first.
- Reverse DNS has a timeout and cache; hostnames are sanitised.
- Health-check bypass requires a secret token; ports / ignore list are configurable; IPv4 + IPv6; clean shutdown.

Installation guide (Vietnamese): [HUONG_DAN_TRIEN_KHAI.md](HUONG_DAN_TRIEN_KHAI.md)
