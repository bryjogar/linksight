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
    unavailable_reason: str = ""

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
            "unavailable_reason": self.unavailable_reason,
        }


def _safe_run(
    cmd: list[str],
    timeout: int = 8,
    check_returncode: bool = True,
) -> subprocess.CompletedProcess[str] | None:
    """Run a subprocess detached from invalid console handles on Windows."""
    kwargs: dict = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "stdin": subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        result = subprocess.run(cmd, **kwargs)
        if check_returncode and result.returncode != 0:
            cmd_name = cmd[0] if cmd else "command"
            print(f"Command '{cmd_name}' failed with exit code {result.returncode}")
            return None
        return result
    except Exception as exc:
        cmd_name = cmd[0] if cmd else "command"
        print(f"Command '{cmd_name}' failed: {exc}")
        return None


def _run(cmd: list[str], timeout: int = 8) -> str | None:
    res = _safe_run(cmd, timeout=timeout, check_returncode=True)
    if res is None:
        return None
    return res.stdout


def get_quick_interface_config(iface_name: str) -> InterfaceConfig:
    """Fast, non-blocking interface config from psutil only (no subprocesses)."""
    cfg = InterfaceConfig(name=iface_name)
    _fill_from_psutil(cfg, iface_name)
    return cfg


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
            if name.lower() != iface_name.lower():
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


def _prefix_to_netmask(prefix: int | str) -> str:
    try:
        import ipaddress
        p = int(prefix)
        if 0 <= p <= 32:
            return str(ipaddress.IPv4Network(f"0.0.0.0/{p}").netmask)
    except Exception:
        pass
    return ""


def _parse_powershell_json(json_str: str, iface_name: str) -> dict | None:
    import json
    try:
        data = json.loads(json_str)
    except Exception:
        return None

    # Parse defensively: single object vs list
    item = None
    if isinstance(data, list):
        for candidate in data:
            if isinstance(candidate, dict):
                alias = candidate.get("InterfaceAlias", "")
                if str(alias).lower() == iface_name.lower():
                    item = candidate
                    break
        if item is None and len(data) == 1 and isinstance(data[0], dict):
            item = data[0]
    elif isinstance(data, dict):
        item = data

    if item is None or not isinstance(item, dict):
        return None

    res: dict = {}

    # IPv4 address & netmask
    ipv4_info = item.get("IPv4Address")
    if isinstance(ipv4_info, list):
        for entry in ipv4_info:
            if isinstance(entry, dict) and entry.get("IPAddress"):
                res["ip"] = str(entry.get("IPAddress"))
                if entry.get("PrefixLength") is not None:
                    res["netmask"] = _prefix_to_netmask(entry.get("PrefixLength"))
                break
            elif isinstance(entry, str) and "." in entry:
                res["ip"] = entry
                break
    elif isinstance(ipv4_info, dict):
        if ipv4_info.get("IPAddress"):
            res["ip"] = str(ipv4_info.get("IPAddress"))
        if ipv4_info.get("PrefixLength") is not None:
            res["netmask"] = _prefix_to_netmask(ipv4_info.get("PrefixLength"))
    elif isinstance(ipv4_info, str) and "." in ipv4_info:
        res["ip"] = ipv4_info

    # Default gateway -> NextHop
    gw_info = item.get("IPv4DefaultGateway")
    if isinstance(gw_info, list):
        for entry in gw_info:
            if isinstance(entry, dict) and entry.get("NextHop"):
                res["gateway"] = str(entry.get("NextHop"))
                break
            elif isinstance(entry, str) and "." in entry:
                res["gateway"] = entry
                break
    elif isinstance(gw_info, dict):
        if gw_info.get("NextHop"):
            res["gateway"] = str(gw_info.get("NextHop"))
        elif gw_info.get("IPAddress"):
            res["gateway"] = str(gw_info.get("IPAddress"))
    elif isinstance(gw_info, str) and "." in gw_info:
        res["gateway"] = gw_info

    # DNS servers -> ServerAddresses
    dns_info = item.get("DNSServer")
    dns_list: list[str] = []
    if isinstance(dns_info, list):
        for entry in dns_info:
            if isinstance(entry, dict):
                addrs = entry.get("ServerAddresses")
                if isinstance(addrs, list):
                    dns_list.extend(str(a) for a in addrs if a)
                elif isinstance(addrs, str) and addrs:
                    dns_list.append(addrs)
            elif isinstance(entry, str) and entry:
                dns_list.append(entry)
    elif isinstance(dns_info, dict):
        addrs = dns_info.get("ServerAddresses")
        if isinstance(addrs, list):
            dns_list.extend(str(a) for a in addrs if a)
        elif isinstance(addrs, str) and addrs:
            dns_list.append(addrs)
    elif isinstance(dns_info, str) and dns_info:
        dns_list.append(dns_info)
    if dns_list:
        res["dns_servers"] = [d for d in dns_list if "." in d or ":" in d]

    # DHCP server
    dhcp_info = item.get("DhcpServer") or item.get("DHCPServer")
    if isinstance(dhcp_info, dict):
        res["dhcp_server"] = str(dhcp_info.get("ServerAddress") or dhcp_info.get("IPAddress") or "")
    elif isinstance(dhcp_info, str) and dhcp_info:
        res["dhcp_server"] = dhcp_info

    # DHCP enabled
    net_ipv4 = item.get("NetIPv4Interface")
    if isinstance(net_ipv4, dict):
        dhcp_val = net_ipv4.get("DHCP") or net_ipv4.get("Dhcp")
        if isinstance(dhcp_val, str):
            res["dhcp_enabled"] = dhcp_val.lower().startswith("enable")
        elif isinstance(dhcp_val, bool):
            res["dhcp_enabled"] = dhcp_val
    elif "Dhcp" in item or "DHCP" in item:
        dhcp_val = item.get("Dhcp") or item.get("DHCP")
        if isinstance(dhcp_val, str):
            res["dhcp_enabled"] = dhcp_val.lower().startswith("enable")
        elif isinstance(dhcp_val, bool):
            res["dhcp_enabled"] = dhcp_val

    return res


def _fill_windows(cfg: InterfaceConfig, iface_name: str) -> None:
    """Read Windows interface configuration using PowerShell or ipconfig fallback."""
    # 1. PowerShell: Get-NetIPConfiguration
    ps_alias = iface_name.replace("'", "''")
    ps_cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        f"Get-NetIPConfiguration -InterfaceAlias '{ps_alias}' | ConvertTo-Json",
    ]
    ps_out = _run(ps_cmd, timeout=8)
    if ps_out:
        parsed = _parse_powershell_json(ps_out, iface_name)
        if parsed:
            if parsed.get("ip"):
                cfg.ip = parsed["ip"]
            if parsed.get("netmask"):
                cfg.netmask = parsed["netmask"]
            if parsed.get("gateway"):
                cfg.gateway = parsed["gateway"]
            if parsed.get("dns_servers"):
                cfg.dns_servers = parsed["dns_servers"]
            if parsed.get("dhcp_server"):
                cfg.dhcp_server = parsed["dhcp_server"]
            if parsed.get("dhcp_enabled") is not None:
                cfg.dhcp_enabled = parsed["dhcp_enabled"]
            if parsed.get("gateway") and parsed.get("dns_servers"):
                cfg.unavailable_reason = ""
                return

    # 2. Fallback: ipconfig /all
    out = _run(["ipconfig", "/all"])
    if out is None:
        if not (cfg.gateway or cfg.dns_servers or cfg.dhcp_server):
            cfg.unavailable_reason = "command failed"
        else:
            cfg.unavailable_reason = ""
        return
    if not out.strip():
        if not (cfg.gateway or cfg.dns_servers or cfg.dhcp_server):
            cfg.unavailable_reason = "no output"
        else:
            cfg.unavailable_reason = ""
        return

    lines = [l.rstrip() for l in out.splitlines()]

    # Collect adapter blocks
    blocks: list[tuple[str, list[str]]] = []
    current_name = ""
    current_lines: list[str] = []
    for line in lines:
        low = line.lower()
        if "adapter" in low and ":" in line:
            if current_name and current_lines:
                blocks.append((current_name, current_lines))
            idx = low.find("adapter")
            header_after = line[idx + len("adapter") :].strip().rstrip(":")
            current_name = header_after
            current_lines = [line]
        elif current_name:
            current_lines.append(line)
    if current_name and current_lines:
        blocks.append((current_name, current_lines))

    # Match block: exact match first
    target_block: list[str] | None = None
    for name, blk in blocks:
        if name.strip().lower() == iface_name.strip().lower():
            target_block = blk
            break

    # Fallback to substring match, without taking the first hit blindly
    if target_block is None:
        candidates = []
        for name, blk in blocks:
            if iface_name.lower() in name.lower():
                is_disconnected = any("media disconnected" in l.lower() for l in blk)
                has_ip = any("ipv4 address" in l.lower() or "ip address" in l.lower() for l in blk)
                candidates.append((not is_disconnected, has_ip, blk))
        if candidates:
            candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
            target_block = candidates[0][2]

    if target_block is None:
        if not (cfg.gateway or cfg.dns_servers or cfg.dhcp_server):
            cfg.unavailable_reason = "adapter not found"
        else:
            cfg.unavailable_reason = ""
        return

    dhcp_enabled = None
    ip = ""
    netmask = ""
    gateway = ""
    dhcp_server = ""
    dns_servers: list[str] = []

    for i, line in enumerate(target_block):
        low = line.lower()
        val = line.split(":", 1)[1].strip() if ":" in line else ""
        if "dhcp enabled" in low:
            dhcp_enabled = val.lower().startswith("yes")
        elif "ipv4 address" in low or "ip address" in low:
            ip = val.split("(")[0].strip()
        elif "subnet mask" in low:
            netmask = val.split("(")[0].strip()
        elif "default gateway" in low:
            gateway = val.split("(")[0].strip()
        elif "dhcp server" in low:
            dhcp_server = val.split("(")[0].strip()
        elif "dns servers" in low or "dns server" in low:
            if val:
                dns_servers.append(val.split("(")[0].strip())
            for cont in target_block[i + 1 :]:
                cval = cont.split(":", 1)[1].strip() if ":" in cont else cont.strip()
                if not cval or ":" not in cont:
                    if cval and (cval[0].isdigit() or ":" in cval):
                        dns_servers.append(cval.split("(")[0].strip())
                        continue
                break

    # Fill ONLY non-empty results — keep what psutil already provided
    if ip:
        cfg.ip = ip
    if netmask:
        cfg.netmask = netmask
    if gateway:
        cfg.gateway = gateway
    if dhcp_server:
        cfg.dhcp_server = dhcp_server
    if dns_servers:
        cfg.dns_servers = dns_servers
    if dhcp_enabled is not None:
        cfg.dhcp_enabled = dhcp_enabled
    cfg.unavailable_reason = ""


def _fill_macos(cfg: InterfaceConfig, iface_name: str) -> None:
    """ipconfig getpacket gives DHCP lease facts (gateway, DNS, server)."""
    out = _run(["ipconfig", "getpacket", iface_name])
    if out is None or not out.strip():
        return
    for line in out.splitlines():
        low = line.lower()
        if "yiaddr" in low:
            val = line.split("=")[-1].strip()
            if val:
                cfg.ip = val
        elif "subnet mask" in low:
            val = line.split("=")[-1].strip()
            if val:
                cfg.netmask = val
        elif "router" in low and "=" in line:
            val = line.split("=")[-1].strip()
            if val:
                cfg.gateway = val
        elif "domain name server" in low:
            vals = [s.strip() for s in line.split("=")[-1].split(",") if s.strip()]
            if vals:
                cfg.dns_servers = vals
        elif "server identifier" in low:
            val = line.split("=")[-1].strip()
            if val:
                cfg.dhcp_server = val
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
