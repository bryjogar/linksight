"""Network interface discovery — cross-platform.

Primary source is Scapy (already a dependency, uses Npcap on Windows and
BPF on macOS, and reports USB adapters properly). psutil and a Linux sysfs
fallback exist for dev environments without Scapy.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class NetInterface:
    name: str
    mac: str = ""
    ips: list[str] = field(default_factory=list)
    description: str = ""
    is_up: bool = True
    is_loopback: bool = False

    def label(self) -> str:
        extras = []
        if self.description:
            extras.append(self.description)
        if self.ips:
            extras.append(", ".join(self.ips))
        if self.is_loopback:
            extras.append("loopback")
        return f"{self.name} ({', '.join(extras)})" if extras else self.name


def list_interfaces(reload: bool = False) -> list[NetInterface]:
    """Enumerate network interfaces, best-effort across platforms."""
    if reload:
        try:
            from scapy.all import conf
            conf.ifaces.reload()
        except Exception:
            pass
    ifaces = _via_scapy()
    if ifaces:
        return ifaces
    ifaces = _via_psutil()
    if ifaces:
        return ifaces
    return _fallback_linux_sysfs()


def _iface_score(nic: NetInterface) -> int:
    """Score an interface for capture suitability.

    LLDP/CDP are wired protocols: Ethernet/USB adapters are the right target,
    Bluetooth never carries them, Wi-Fi rarely does. Prefer a live IP too
    (a connected adapter has a real one; 169.254.x is APIPA = nothing plugged in).
    """
    name = (nic.name or "").lower()
    desc = (nic.description or "").lower()
    blob = f"{name} {desc}"

    score = 0
    if "ethernet" in blob:
        score += 4
    if "usb" in blob or "lan" in blob:
        score += 2
    if "gigabit" in blob or "10/100" in blob or "1000" in blob:
        score += 1
    if "bluetooth" in blob or "bt " in blob or "pan" in blob:
        score -= 4
    if "wi-fi" in blob or "wlan" in blob or "wireless" in blob:
        score -= 1
    if nic.is_loopback:
        score -= 10

    for ip in nic.ips:
        if ip.startswith("169.254."):
            score -= 1
        elif ip.startswith("127.") or ip.startswith("::1"):
            pass
        elif ":" in ip or ip.count(".") == 3:
            score += 2
            break
    return score


def preferred_interface(ifaces: list[NetInterface] | None = None) -> NetInterface | None:
    """Pick the best interface for capture, or None if nothing suitable."""
    ifaces = ifaces if ifaces is not None else list_interfaces()
    if not ifaces:
        return None
    return max(ifaces, key=_iface_score)


def _via_scapy() -> list[NetInterface]:
    """Scapy's interface table — works on Windows (Npcap), macOS, Linux."""
    try:
        from scapy.all import conf
    except Exception:
        return []
    out: list[NetInterface] = []
    try:
        ps_stats = {}
        ps_addrs = {}
        try:
            import psutil
            ps_stats = psutil.net_if_stats()
            ps_addrs = psutil.net_if_addrs()
        except Exception:
            pass

        for iface in conf.ifaces.values():
            name = getattr(iface, "name", "") or ""
            if not name:
                continue
            mac = getattr(iface, "mac", "") or ""
            raw_ip = getattr(iface, "ip", "") or ""
            ips = [raw_ip] if isinstance(raw_ip, str) and raw_ip else []
            desc = getattr(iface, "description", "") or ""
            win_name = getattr(iface, "win_name", "") or ""

            # Check psutil for live link state and addresses
            matched_stats = (
                ps_stats.get(name)
                or ps_stats.get(desc)
                or (ps_stats.get(win_name) if win_name else None)
            )
            matched_addrs = (
                ps_addrs.get(name)
                or ps_addrs.get(desc)
                or (ps_addrs.get(win_name) if win_name else None)
            )

            is_up = True
            if matched_stats is not None:
                is_up = bool(matched_stats.isup)
            else:
                try:
                    from pathlib import Path
                    oper_file = Path("/sys/class/net") / name / "operstate"
                    if oper_file.exists():
                        is_up = oper_file.read_text().strip() == "up"
                except Exception:
                    pass

            if matched_addrs:
                live_ips = []
                for addr in matched_addrs:
                    fam = addr.family.name
                    if fam in ("AF_INET", "AF_INET6") and addr.address:
                        live_ips.append(addr.address)
                    elif ("MAC" in fam or fam == "AF_LINK") and not mac:
                        mac = addr.address
                if live_ips:
                    ips = live_ips

            first_ip = ips[0] if ips else ""
            is_loopback = name.lower().startswith(("lo", "loopback")) or first_ip.startswith("127.")
            out.append(NetInterface(
                name=name,
                mac=mac,
                ips=ips,
                description=desc,
                is_up=is_up,
                is_loopback=is_loopback,
            ))
    except Exception:
        return []
    return out


def _via_psutil() -> list[NetInterface]:
    """psutil enumeration (dev environments)."""
    try:
        import psutil
    except ImportError:
        return []
    out: list[NetInterface] = []
    try:
        stats = psutil.net_if_stats()
    except Exception:
        stats = {}
    try:
        for name, snic in psutil.net_if_addrs().items():
            mac = ""
            ips: list[str] = []
            for addr in snic:
                fam = addr.family.name
                if "MAC" in fam or fam == "AF_LINK":
                    mac = addr.address
                elif fam in ("AF_INET", "AF_INET6") and addr.address:
                    ips.append(addr.address)
            first_ip = ips[0] if ips else ""
            is_loopback = name.lower().startswith(("lo", "loopback")) or first_ip.startswith("127.")
            is_up = stats[name].isup if name in stats else True
            out.append(NetInterface(name=name, mac=mac, ips=ips, is_up=is_up, is_loopback=is_loopback))
    except Exception:
        return []
    return out


def _fallback_linux_sysfs() -> list[NetInterface]:
    """Linux-only fallback via /sys/class/net (no Scapy, no psutil)."""
    from pathlib import Path

    out: list[NetInterface] = []
    net_dir = Path("/sys/class/net")
    if not net_dir.is_dir():
        return out
    for p in sorted(net_dir.iterdir()):
        name = p.name
        mac = (p / "address").read_text().strip() if (p / "address").exists() else ""
        try:
            flags = int((p / "flags").read_text().strip(), 16) if (p / "flags").exists() else 0
            is_up = bool(flags & 0x1)
        except ValueError:
            is_up = True
        out.append(NetInterface(name=name, mac=mac, ips=[], is_up=is_up, is_loopback=name == "lo"))
    return out
