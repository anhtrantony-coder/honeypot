"""Home Assistant LAN Canary Honeypot & Active TCP Tarpit (patched fork).

Based on https://github.com/robainbinder/ha-lan-canary-tarpit (MIT).

Fixes vs. upstream 1.0.0:
- No more off->on toggling of the alert boolean (it triggered the reset
  automation and released every trapped socket on the 2nd hit).
- Alerts are rate limited (per source IP cooldown + global per-minute cap),
  so a port scan cannot flood push notifications or the executor.
- The tarpit cap is enforced before anything else; reverse DNS has a timeout
  and a cache; hostnames are sanitised (PTR names can be attacker-controlled).
- Health check only with a secret token from configuration (no public bypass).
- Configurable ports / bind host / ignore list; binds IPv4 + IPv6 by default.
- Listeners and trapped sockets are closed cleanly on Home Assistant stop.
"""
from __future__ import annotations

import asyncio
from collections import deque
import functools
import ipaddress
import logging
import re
import socket
import time

import voluptuous as vol

from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import Event, HomeAssistant, ServiceCall
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.typing import ConfigType
from homeassistant.util import dt as dt_util

_LOGGER = logging.getLogger(__name__)

DOMAIN = "lan_canary"
EVENT_HIT = "lan_canary_hit"

ENT_ALERT = "input_boolean.canary_intrusion_alert"
ENT_LAST = "input_text.canary_last_event"
ENT_COUNT = "counter.canary_hit_count"

# port -> (service name, initial banner or None)
DECOYS: dict[int, tuple[str, bytes | None]] = {
    2121: ("FTP", b"220-DiskStation FTP server (Synology DSM 7.2) initializing...\r\n"),
    2222: ("SSH", b"Synology-DSM-7.2-Security-Banner: verifying host key...\r\n"),
    2323: ("Telnet", b"\r\nDiskStation-NAS login: "),
    3306: ("MySQL", b"\x4a\x00\x00\x00\x0a5.5.68-MariaDB-Synology\x00"),
    5900: ("VNC", b"RFB 003.008\n"),
    8088: ("Synology-DSM-HTTP", None),
}
# 3306 is opt-in: it collides with the MariaDB add-on.
DEFAULT_PORTS = [2121, 2222, 2323, 5900, 8088]

DRIP_INTERVAL_SEC = 10.0
TARPIT_MAX_DURATION_SEC = 900.0
FIRST_READ_TIMEOUT_SEC = 1.5
DNS_TIMEOUT_SEC = 2.0
DNS_CACHE_TTL_SEC = 3600.0
MAX_TRACKED_IPS = 1024

CONF_PORTS = "ports"
CONF_BIND_HOST = "bind_host"
CONF_IGNORE = "ignore_ips"
CONF_HEALTH_TOKEN = "healthcheck_token"
CONF_COOLDOWN = "per_ip_cooldown"
CONF_MAX_ALERTS = "max_alerts_per_minute"
CONF_MAX_TARPITS = "max_tarpits"


def _valid_network(value: str) -> str:
    try:
        ipaddress.ip_network(str(value), strict=False)
    except ValueError as err:
        raise vol.Invalid(f"invalid IP/CIDR: {value}") from err
    return str(value)


_INNER_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_PORTS, default=DEFAULT_PORTS): vol.All(
            cv.ensure_list, [vol.All(vol.Coerce(int), vol.In(list(DECOYS)))]
        ),
        vol.Optional(CONF_BIND_HOST): cv.string,
        vol.Optional(CONF_IGNORE, default=[]): vol.All(cv.ensure_list, [_valid_network]),
        vol.Optional(CONF_HEALTH_TOKEN): vol.All(cv.string, vol.Length(min=16)),
        vol.Optional(CONF_COOLDOWN, default=300): vol.All(
            vol.Coerce(int), vol.Range(min=10, max=86400)
        ),
        vol.Optional(CONF_MAX_ALERTS, default=6): vol.All(
            vol.Coerce(int), vol.Range(min=1, max=60)
        ),
        vol.Optional(CONF_MAX_TARPITS, default=64): vol.All(
            vol.Coerce(int), vol.Range(min=1, max=256)
        ),
    }
)

CONFIG_SCHEMA = vol.Schema(
    {DOMAIN: vol.All(lambda v: v or {}, _INNER_SCHEMA)}, extra=vol.ALLOW_EXTRA
)

_HOST_OK = re.compile(r"[^A-Za-z0-9._-]")


def _resolve_host(ip: str) -> str:
    """Blocking reverse DNS; runs in the executor."""
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except (OSError, UnicodeError):
        return "Unknown-Host"
    for suffix in (".lan", ".local", ".home", ".localdomain"):
        name = name.removesuffix(suffix)
    # PTR names often come from DHCP hostnames, which the scanning device chooses.
    return _HOST_OK.sub("", name)[:63] or "Unknown-Host"


def _clean_snippet(payload: bytes) -> str:
    if not payload:
        return ""
    lines = payload.decode("utf-8", errors="ignore").strip().splitlines()
    if not lines:
        return ""
    return "".join(ch for ch in lines[0] if 32 <= ord(ch) < 127)[:40].strip()


def _drip(port: int, step: int) -> bytes:
    if port == 2121:
        return f"220-DiskStation RAID check {step + 1}%...\r\n".encode("ascii")
    if port == 2222:
        return f"Synology-DSM-KeyCheck-{step + 1}: wait\r\n".encode("ascii")
    if port == 8088:
        return f"X-Synology-Auth-Wait-{step + 1}: {step * 10}\r\n".encode("ascii")
    return b"\x00"


class LanCanary:
    """Listeners, trapped sockets and alert throttling."""

    def __init__(self, hass: HomeAssistant, conf: dict) -> None:
        self.hass = hass
        self.conf = conf
        self.servers: dict[int, asyncio.base_events.Server] = {}
        self.writers: set[asyncio.StreamWriter] = set()
        self._ignore = [ipaddress.ip_network(n, strict=False) for n in conf[CONF_IGNORE]]
        token = conf.get(CONF_HEALTH_TOKEN)
        self._health_token = token.encode() if token else None
        self._last_alert_by_ip: dict[str, float] = {}
        self._alert_times: deque[float] = deque()
        self._suppressed = 0
        self._dns_cache: dict[str, tuple[str, float]] = {}

    # ---------- filtering / throttling ----------

    def _is_ignored(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_loopback:
            return True
        return any(addr in net for net in self._ignore)

    def _should_alert(self, ip: str) -> bool:
        """Return True if this hit may raise an alert; otherwise count it as suppressed."""
        now = time.monotonic()
        last = self._last_alert_by_ip.get(ip)
        if last is not None and now - last < self.conf[CONF_COOLDOWN]:
            self._suppressed += 1
            return False
        while self._alert_times and now - self._alert_times[0] > 60:
            self._alert_times.popleft()
        if len(self._alert_times) >= self.conf[CONF_MAX_ALERTS]:
            self._suppressed += 1
            return False
        self._alert_times.append(now)
        self._last_alert_by_ip[ip] = now
        if len(self._last_alert_by_ip) > MAX_TRACKED_IPS:
            oldest = sorted(self._last_alert_by_ip, key=self._last_alert_by_ip.get)
            for old_ip in oldest[: len(oldest) // 2]:
                del self._last_alert_by_ip[old_ip]
        return True

    async def _resolve(self, ip: str) -> str:
        now = time.monotonic()
        cached = self._dns_cache.get(ip)
        if cached and now - cached[1] < DNS_CACHE_TTL_SEC:
            return cached[0]
        try:
            name = await asyncio.wait_for(
                self.hass.async_add_executor_job(_resolve_host, ip), DNS_TIMEOUT_SEC
            )
        except asyncio.TimeoutError:
            name = "Unknown-Host"
        if len(self._dns_cache) > MAX_TRACKED_IPS:
            self._dns_cache.clear()
        self._dns_cache[ip] = (name, now)
        return name

    # ---------- recording a hit ----------

    async def _call(self, domain: str, service: str, data: dict) -> None:
        try:
            await self.hass.services.async_call(domain, service, data, blocking=True)
        except Exception as err:  # noqa: BLE001 - entity may be missing; keep going
            _LOGGER.error("LAN Canary: %s.%s failed: %s", domain, service, err)

    async def _record_hit(
        self, src_ip: str, svc: str, port: int, payload: bytes, trapped: int
    ) -> None:
        host = await self._resolve(src_ip)
        snippet = _clean_snippet(payload)
        suppressed, self._suppressed = self._suppressed, 0

        msg = f"{dt_util.now().strftime('%H:%M:%S')} — {src_ip} ({host}) on {svc} :{port}"
        if snippet:
            msg += f" [{snippet}]"
        msg += f" ({trapped} trapped"
        if suppressed:
            msg += f", +{suppressed} suppressed"
        msg += ")"
        msg = msg[:250]
        _LOGGER.warning("LAN CANARY TRIPPED: %s", msg)

        self.hass.bus.async_fire(
            EVENT_HIT,
            {
                "message": msg,
                "src_ip": src_ip,
                "host": host,
                "service": svc,
                "port": port,
                "payload": snippet,
                "trapped": trapped,
                "suppressed": suppressed,
            },
        )

        await self._call("input_text", "set_value", {"entity_id": ENT_LAST, "value": msg})
        counter = self.hass.states.get(ENT_COUNT)
        if counter is not None:
            try:
                current = int(float(counter.state))
            except ValueError:
                current = 0
            await self._call(
                "counter",
                "set_value",
                {"entity_id": ENT_COUNT, "value": current + 1 + suppressed},
            )
        alert = self.hass.states.get(ENT_ALERT)
        if alert is not None and alert.state != "on":
            await self._call("input_boolean", "turn_on", {"entity_id": ENT_ALERT})

    # ---------- connection handler ----------

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, port: int
    ) -> None:
        svc, banner = DECOYS[port]
        peer = writer.get_extra_info("peername")
        src_ip = str(peer[0]) if peer else "unknown"
        tracked = False
        try:
            if banner is not None:
                writer.write(banner)
                await writer.drain()
            try:
                payload = await asyncio.wait_for(reader.read(512), FIRST_READ_TIMEOUT_SEC)
            except asyncio.TimeoutError:
                payload = b""

            if self._health_token and self._health_token in payload:
                writer.write(b"CANARY_TARPIT_OK\n")
                await writer.drain()
                return
            if self._is_ignored(src_ip):
                return

            over_cap = len(self.writers) >= self.conf[CONF_MAX_TARPITS]
            if self._should_alert(src_ip):
                trapped = len(self.writers) + (0 if over_cap else 1)
                self.hass.async_create_background_task(
                    self._record_hit(src_ip, svc, port, payload, trapped),
                    f"{DOMAIN}_record_hit",
                )
            if over_cap:
                return  # cap reached: drop immediately, do not hold the socket

            self.writers.add(writer)
            tracked = True

            async with asyncio.timeout(TARPIT_MAX_DURATION_SEC + 30):
                if port == 8088:
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Server: nginx (Synology DSM 7.2)\r\n"
                        b"Cache-Control: no-cache, no-store\r\n"
                    )
                    await writer.drain()
                for step in range(int(TARPIT_MAX_DURATION_SEC // DRIP_INTERVAL_SEC)):
                    await asyncio.sleep(DRIP_INTERVAL_SEC)
                    if writer.is_closing():
                        break
                    writer.write(_drip(port, step))
                    await writer.drain()
        except (OSError, TimeoutError, asyncio.IncompleteReadError) as err:
            _LOGGER.debug("LAN Canary %s:%d connection ended: %r", src_ip, port, err)
        finally:
            if tracked:
                self.writers.discard(writer)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 5)
            except (OSError, TimeoutError, asyncio.TimeoutError):
                pass

    # ---------- lifecycle ----------

    async def async_start(self) -> None:
        host = self.conf.get(CONF_BIND_HOST)  # None = every IPv4 + IPv6 interface
        for port in self.conf[CONF_PORTS]:
            if port in self.servers:
                continue
            handler = functools.partial(self._handle_client, port=port)
            try:
                srv = await asyncio.start_server(handler, host=host, port=port)
            except OSError as err:
                if host is None:
                    # e.g. IPv6 present but unusable: fall back to IPv4 only
                    try:
                        srv = await asyncio.start_server(handler, host="0.0.0.0", port=port)
                    except OSError as err2:
                        _LOGGER.error(
                            "LAN Canary: cannot bind port %d (%s): %s",
                            port, DECOYS[port][0], err2,
                        )
                        continue
                else:
                    _LOGGER.error(
                        "LAN Canary: cannot bind %s:%d (%s): %s",
                        host, port, DECOYS[port][0], err,
                    )
                    continue
            self.servers[port] = srv
            addrs = ", ".join(str(s.getsockname()[0]) for s in srv.sockets)
            _LOGGER.info("LAN Canary listening on port %d (%s) [%s]", port, DECOYS[port][0], addrs)

    def release_all(self) -> int:
        released = len(self.writers)
        for writer in list(self.writers):
            writer.close()
        self.writers.clear()
        return released

    async def async_stop(self) -> None:
        self.release_all()
        servers = list(self.servers.values())
        self.servers.clear()
        for srv in servers:
            srv.close()
        for srv in servers:
            try:
                await asyncio.wait_for(srv.wait_closed(), 5)
            except (asyncio.TimeoutError, TimeoutError):
                pass

    async def async_reset(self) -> None:
        """Release trapped sockets and disarm the alert. Idempotent.

        Turning the boolean off re-triggers the reset automation, which calls
        this again; the second call sees alert=off and 0 sockets and does nothing.
        """
        released = self.release_all()
        alert = self.hass.states.get(ENT_ALERT)
        was_on = alert is not None and alert.state == "on"
        if not was_on and released == 0:
            return
        now_str = dt_util.now().strftime("%b %d %H:%M")
        await self._call(
            "input_text",
            "set_value",
            {"entity_id": ENT_LAST, "value": f"Re-armed {now_str} (released {released} sockets)"},
        )
        if was_on:
            await self._call("input_boolean", "turn_off", {"entity_id": ENT_ALERT})


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up LAN Canary from configuration.yaml."""
    canary = LanCanary(hass, config[DOMAIN])
    hass.data[DOMAIN] = canary
    await canary.async_start()

    async def _on_stop(_event: Event) -> None:
        await canary.async_stop()

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _on_stop)

    async def handle_start(_call: ServiceCall) -> None:
        await canary.async_start()

    async def handle_reset(_call: ServiceCall) -> None:
        await canary.async_reset()

    hass.services.async_register(DOMAIN, "start_canary", handle_start)
    hass.services.async_register(DOMAIN, "reset_canary", handle_reset)
    return True
