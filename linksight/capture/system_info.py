"""Adapter's own IP configuration, read from the OS.

Netool shows the network the box is plugged into — IP, subnet, gateway, DNS,
DHCP server. When the adapter already holds an address (static or a previous
lease), no DHCP traffic occurs on plug-in, so passive sniffing shows nothing.
This module reads the current configuration straight from the OS instead,
so the Network tab is populated whether or not DHCP traffic was observed.

Sources per platform:
  - IP + netmask: psutil.net_if_addrs (cross-platform)
  - Windows:      ipconfig /all  (also yields DHCP server + DNS of current lease)
  - macOS:        ipconfig getpacket <iface>  (DHCP lease details)
  - Linux:        /proc/net/route (gateway), /etc/resolv.conf (DNS)
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class InterfaceConfig:
    name: str = ""
    mac: str = ""
    ip: str = ""
    netmask: str = ""
    gateway: str = ""
    dns_servers: list[str] = field(default_factory=list)
    dhcp_server: str = ""
    dhcp_enabled: bool | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "mac": self.mac,
            "ip": self.ip,
            "netmask": self.netmask,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "dhcp_server": self.dhcp_server,
            "dhcp_enabled": self.dhcp_enabled,
        }


def _run(cmd: list[str], timeout: int = 8) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except Exception:
        return ""


def get_interface_config(iface_name: str) -> InterfaceConfig:
    """Best-effort current configuration for one interface."""
    cfg = InterfaceConfig(name=iface_name)
    _fill_from_psutil(cfg, iface_name)
    if sys.platform == "win32":
        _fill_windows(cfg, iface_name)
    elif sys.platform == "darwin":
        _fill_macos(cfg, iface_name)
    else:
        _fill_linux(cfg)
    return cfg


def _fill_from_psutil(cfg: InterfaceConfig, iface_name: str) -> None:
    try:
        import psutil
    except ImportError:
        return
    try:
        for name, addrs in psutil.net_if_addrs().items():
            if name != iface_name:
                continue
            for addr in addrs:
                fam = addr.family.name
                if "MAC" in fam or fam == "AF_LINK":
                    cfg.mac = addr.address
                elif fam == "AF_INET" and addr.address:
                    cfg.ip = addr.address
                    if addr.netmask:
                        cfg.netmask = addr.netmask
    except Exception:
        pass


def _fill_windows(cfg: InterfaceConfig, iface_name: str) -> None:
    """Parse ipconfig /all — authoritative for DHCP server + DNS of the lease."""
    out = _run(["ipconfig", "/all"])
    lines = [l.rstrip() for l in out.splitlines()]

    # find the adapter block
    start = None
    for i, line in enumerate(lines):
        if iface_name.lower() in line.lower() and "adapter" in line.lower():
            start = i
            break
    if start is None:
        return
    block: list[str] = []
    for line in lines[start:]:
        if "adapter" in line.lower() and block:
            break
        block.append(line)

    for i, line in enumerate(block):
        low = line.lower()
        val = line.split(":", 1)[1].strip() if ":" in line else ""
        if "dhcp enabled" in low:
            cfg.dhcp_enabled = val.lower().startswith("yes")
        elif "ipv4 address" in low or "ip address" in low:
            cfg.ip = val.split("(")[0].strip()
        elif "subnet mask" in low:
            cfg.netmask = val.split("(")[0].strip()
        elif "default gateway" in low:
            cfg.gateway = val.split("(")[0].strip()
        elif "dhcp server" in low:
            cfg.dhcp_server = val.split("(")[0].strip()
        elif "dns servers" in low or "dns server" in low:
            cfg.dns_servers.append(val.split("(")[0].strip())
            # ipconfig lists additional DNS servers on continuation lines:
            # "                                       1.1.1.1"
            for cont in block[i + 1 :]:
                cval = cont.split(":", 1)[1].strip() if ":" in cont else cont.strip()
                if not cval or ":" not in cont:
                    # continuation line looks like whitespace + IP, no label
                    if cval and cval[0].isdigit():
                        cfg.dns_servers.append(cval.split("(")[0].strip())
                        continue
                break


def _fill_macos(cfg: InterfaceConfig, iface_name: str) -> None:
    """ipconfig getpacket gives DHCP lease facts (gateway, DNS, server)."""
    out = _run(["ipconfig", "getpacket", iface_name])
    for line in out.splitlines():
        low = line.lower()
        if "yiaddr" in low:
            cfg.ip = line.split("=")[-1].strip()
        elif "subnet mask" in low:
            cfg.netmask = line.split("=")[-1].strip()
        elif "router" in low and "=" in line:
            cfg.gateway = line.split("=")[-1].strip()
        elif "domain name server" in low:
            cfg.dns_servers = [s.strip() for s in line.split("=")[-1].split(",") if s.strip()]
        elif "server identifier" in low:
            cfg.dhcp_server = line.split("=")[-1].strip()
        elif "dhcp" in low and "message type" in low:
            cfg.dhcp_enabled = True


def _fill_linux(cfg: InterfaceConfig) -> None:
    # gateway from /proc/net/route
    try:
        for line in open(_PROC_ROUTE):
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "00000000" and parts[2] != "00000000":
                gw = parts[2]
                cfg.gateway = ".".join(str(int(gw[i : i + 2], 16)) for i in (6, 4, 2, 0))
                break
    except Exception:
        pass
    # DNS from resolv.conf
    try:
        for line in open(_RESOLV_CONF):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                cfg.dns_servers.append(parts[1])
    except Exception:
        pass


_PROC_ROUTE = "/proc/net/route"
_RESOLV_CONF = "/etc/resolv.conf"
