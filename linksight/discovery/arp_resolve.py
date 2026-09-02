"""ARP management IP auto-resolution for switches without LLDP management address TLVs.

UniFi and certain other switch vendors omit the LLDP Management Address TLV (TLV 8).
However, LLDP frames always supply the switch's chassis MAC address. By sweeping
the local subnet(s) on the connected interface with ARP who-has requests and
mapping replies (MAC -> IP), LinkSight can resolve the switch's management IPv4
address automatically from its chassis MAC.
"""

from __future__ import annotations

import ipaddress
from typing import Callable

from ..capture.interfaces import NetInterface, list_interfaces, preferred_interface
from ..parse.model import NeighborDevice


def normalize_mac(mac: str) -> str | None:
    """Normalize a MAC address to 12 lowercase hexadecimal digits without separators.

    Returns None if input is empty, None, or does not represent a valid 6-byte MAC.
    Supports formats:
      - 00:1a:2b:3c:4d:5e
      - 00-1a-2b-3c-4d-5e
      - 001a.2b3c.4d5e
      - 001a2b3c4d5e
    """
    if not mac:
        return None
    cleaned = "".join(c.lower() for c in mac if c.isalnum())
    if len(cleaned) == 12 and all(c in "0123456789abcdef" for c in cleaned):
        return cleaned
    return None


def compute_subnets_for_interface(nic: NetInterface) -> list[ipaddress.IPv4Network]:
    """Determine sweepable IPv4 subnets for the given interface.

    Caps sweep to sane sizes:
      - Skips /8 networks (too large to sweep within timeout bounds)
      - Caps networks larger than /22 to /24 around the host IP
      - Uses the interface's configured prefix when determinable (/22 to /30)
      - Falls back to /24 for RFC 1918 private addresses when netmask is unknown
      - Skips public addresses and loopback (127.0.0.0/8)
    """
    ips = list(nic.ips)
    if not ips:
        try:
            from ..capture.system_info import get_interface_config
            cfg = get_interface_config(nic.name)
            if cfg.ip:
                ips.append(cfg.ip)
        except Exception:
            pass

    subnets: list[ipaddress.IPv4Network] = []
    for item in ips:
        if not item or ":" in item:
            # Skip empty or IPv6 entries
            continue

        try:
            if "/" in item:
                iface_net = ipaddress.IPv4Interface(item)
                ip_addr = iface_net.ip
                net = iface_net.network
            else:
                ip_addr = ipaddress.IPv4Address(item)
                net = None
        except ValueError:
            continue

        # Skip loopback and public addresses
        if ip_addr.is_loopback or not ip_addr.is_private:
            continue

        if net is None:
            # Try to read netmask from interface configuration
            try:
                from ..capture.system_info import get_interface_config
                cfg = get_interface_config(nic.name)
                if cfg.netmask:
                    net = ipaddress.IPv4Interface(f"{ip_addr}/{cfg.netmask}").network
            except Exception:
                pass

        if net is None:
            # Fall back to /24 for RFC 1918 private addresses
            net = ipaddress.IPv4Network(f"{ip_addr}/24", strict=False)

        # Cap sweep size to sane bounds
        if net.prefixlen <= 8:
            # Skip /8 networks (millions of hosts)
            continue
        if net.prefixlen < 22:
            # Cap large subnets (e.g. /16) to /24 around host IP
            net = ipaddress.IPv4Network(f"{ip_addr}/24", strict=False)

        if net not in subnets:
            subnets.append(net)

    return subnets


def arp_sweep(
    iface_name: str,
    subnets: list[str] | None = None,
    timeout: float = 2.0,
    transport: Callable | None = None,
    stop_check: Callable[[], bool] | None = None,
) -> dict[str, str]:
    """Perform a best-effort ARP sweep on the local subnet(s) of iface_name.

    Returns a dictionary mapping normalized MAC address -> IP address string.
    Degrades gracefully and returns {} on any error.

    Windows note: ARP sweep needs the Npcap/WinPcap scapy path — same requirement
    the capture engine already has; if sendp/srp fails, return {} and fall through
    to manual.
    """
    if stop_check is not None and stop_check():
        return {}

    if subnets is None:
        target_nic = None
        for nic in list_interfaces():
            if nic.name == iface_name:
                target_nic = nic
                break
        if target_nic:
            subnets = [str(s) for s in compute_subnets_for_interface(target_nic)]
        else:
            subnets = []

    if not subnets or (stop_check is not None and stop_check()):
        return {}

    results: dict[str, str] = {}

    for subnet_str in subnets:
        if stop_check is not None and stop_check():
            return {}
        try:
            if transport is not None:
                res = transport(iface_name, subnet_str, timeout)
                if isinstance(res, dict):
                    for k, v in res.items():
                        if stop_check is not None and stop_check():
                            return {}
                        norm = normalize_mac(k)
                        if norm:
                            results[norm] = str(v)
                    continue
                ans = res[0] if isinstance(res, tuple) else res
            else:
                from scapy.all import Ether, ARP, srp
                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet_str)
                ans, _ = srp(pkt, iface=iface_name, timeout=timeout, verbose=0, retry=0)

            for pair in ans:
                if stop_check is not None and stop_check():
                    return {}
                rcv = pair[1] if isinstance(pair, (tuple, list)) and len(pair) >= 2 else pair
                if hasattr(rcv, "haslayer"):
                    from scapy.all import ARP as ScapyARP
                    if rcv.haslayer(ScapyARP):
                        arp_layer = rcv.getlayer(ScapyARP)
                        raw_mac = getattr(arp_layer, "hwsrc", "")
                        raw_ip = getattr(arp_layer, "psrc", "")
                    else:
                        raw_mac = getattr(rcv, "src", "")
                        raw_ip = getattr(rcv, "psrc", "")
                else:
                    raw_mac = getattr(rcv, "hwsrc", None) or getattr(rcv, "src", "")
                    raw_ip = getattr(rcv, "psrc", None) or getattr(rcv, "ip", "")

                norm_mac = normalize_mac(raw_mac)
                if norm_mac and raw_ip:
                    results[norm_mac] = str(raw_ip)
        except Exception:
            # Degrade gracefully: return accumulated replies, never raise
            continue

    return results


def resolve_switch_mgmt_ip(
    dev: NeighborDevice,
    sweep_fn: Callable[..., dict[str, str]] | None = None,
    ifaces: list[NetInterface] | None = None,
    timeout: float = 2.0,
    stop_check: Callable[[], bool] | None = None,
) -> str | None:
    """Orchestrate switch management IP resolution from chassis MAC.

    1. If dev already has management IPs, return None (no sweep needed).
    2. Validate and normalize dev.chassis_id MAC.
    3. Pick interface (dev.source_interface if present and up, else preferred_interface).
    4. Compute subnets for interface.
    5. Sweep subnets using sweep_fn (defaults to arp_sweep).
    6. Return IP matching switch's chassis MAC, or None.
    """
    if stop_check is not None and stop_check():
        return None

    # 1. Device already has an LLDP/CDP management IP — no sweep attempted
    if dev.management_ips:
        return None

    # 2. Chassis ID must be a valid MAC
    target_mac = normalize_mac(dev.chassis_id)
    if not target_mac:
        return None

    # 3. Pick interface: use device's source_interface if present and up, else preferred
    ifaces_list = ifaces if ifaces is not None else list_interfaces()

    nic: NetInterface | None = None
    if dev.source_interface:
        for n in ifaces_list:
            if n.name == dev.source_interface and n.is_up:
                nic = n
                break

    if nic is None:
        nic = preferred_interface(ifaces_list)

    if nic is None:
        return None

    # 4. Compute subnets for interface
    subnets = compute_subnets_for_interface(nic)
    if not subnets or (stop_check is not None and stop_check()):
        return None

    # 5. Sweep subnets
    fn = sweep_fn or arp_sweep
    try:
        replies = fn(nic.name, subnets=[str(s) for s in subnets], timeout=timeout, stop_check=stop_check)
    except TypeError:
        try:
            replies = fn(nic.name, subnets=[str(s) for s in subnets], timeout=timeout)
        except TypeError:
            try:
                replies = fn(nic.name, timeout=timeout)
            except TypeError:
                replies = fn(nic.name)
    except Exception:
        return None

    if stop_check is not None and stop_check():
        return None

    if not isinstance(replies, dict):
        return None

    # 6. Match normalized switch chassis MAC
    for mac_key, ip_val in replies.items():
        if stop_check is not None and stop_check():
            return None
        if normalize_mac(mac_key) == target_mac:
            return str(ip_val)

    return None
