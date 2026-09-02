"""Upstream switch chain walker using the STP root direction rule.

Walks switch-by-switch upstream towards the spanning tree root bridge / default gateway,
extracting per-port diagnostics (PVID, allowed VLANs, STP state, speed, LLDP neighbor).
"""

from __future__ import annotations

import time
from typing import Any, Callable

from .classifier import classify_device, is_edge_device
from .models import Hop, PortDiagnostics, UpstreamPath
from .snmp_client import (
    SnmpClient,
    SnmpError,
    SnmpTimeoutError,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
)

# Standard SNMP OIDs
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"

# BRIDGE-MIB (RFC 1493 / RFC 4188)
OID_DOT1D_BASE_BRIDGE_ADDRESS = "1.3.6.1.2.1.17.1.1.0"
OID_DOT1D_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
OID_DOT1D_STP_ROOT_BRIDGE = "1.3.6.1.2.1.17.2.5.0"
OID_DOT1D_STP_ROOT_COST = "1.3.6.1.2.1.17.2.6.0"
OID_DOT1D_STP_ROOT_PORT = "1.3.6.1.2.1.17.2.7.0"
OID_DOT1D_STP_PORT_STATE = "1.3.6.1.2.1.17.2.15.1.3"
OID_DOT1D_TP_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"

# IF-MIB (RFC 2863)
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"

# Q-BRIDGE-MIB (RFC 2674)
OID_DOT1Q_PVID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS = "1.3.6.1.2.1.17.7.1.4.3.1.2"
OID_DOT1Q_VLAN_CURRENT_EGRESS_PORTS = "1.3.6.1.2.1.17.7.1.4.2.1.4"
OID_DOT1Q_VLAN_STATIC_UNTAGGED_PORTS = "1.3.6.1.2.1.17.7.1.4.3.1.3"
OID_DOT1Q_VLAN_CURRENT_UNTAGGED_PORTS = "1.3.6.1.2.1.17.7.1.4.2.1.5"

# LLDP-MIB (IEEE 802.1AB)
OID_LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
OID_LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
OID_LLDP_REM_PORT_DESC = "1.0.8802.1.1.2.1.4.1.1.8"
OID_LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_REM_SYS_DESC = "1.0.8802.1.1.2.1.4.1.1.10"
OID_LLDP_REM_MAN_ADDR_TABLE = "1.0.8802.1.1.2.1.4.2.1"

# CISCO-CDP-MIB
OID_CDP_CACHE_ADDRESS = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"
OID_CDP_CACHE_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
OID_CDP_CACHE_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
OID_CDP_CACHE_PLATFORM = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"

# IP Route Table (Default Gateway & Routes - RFC 1213 / RFC 2096)
OID_IP_ROUTE_IF_INDEX_DEFAULT = "1.3.6.1.2.1.4.21.1.2.0.0.0.0"
OID_IP_ROUTE_NEXT_HOP_DEFAULT = "1.3.6.1.2.1.4.21.1.7.0.0.0.0"
OID_IP_ROUTE_TABLE = "1.3.6.1.2.1.4.21.1"

# IP Address & Net-to-Media / ARP Tables (RFC 1213 / RFC 2011)
OID_IP_ADDR_TABLE_IF_INDEX = "1.3.6.1.2.1.4.20.1.2"
OID_IP_ADDR_TABLE_NET_MASK = "1.3.6.1.2.1.4.20.1.3"
OID_IP_NET_TO_MEDIA_TABLE = "1.3.6.1.2.1.4.22.1"

STP_STATE_MAP = {
    1: "disabled",
    2: "blocking",
    3: "listening",
    4: "learning",
    5: "forwarding",
    6: "broken",
}

IF_OPER_STATUS_MAP = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "notPresent",
    7: "lowerLayerDown",
}

IF_ADMIN_STATUS_MAP = {
    1: "up",
    2: "down",
    3: "testing",
}


def _format_mac(val: bytes | str | None) -> str:
    """Format MAC address octets into aa:bb:cc:dd:ee:ff."""
    if isinstance(val, (NoSuchObject, NoSuchInstance, EndOfMibView)) or val is None:
        return ""
    if isinstance(val, bytes):
        return ":".join(f"{b:02x}" for b in val)
    if isinstance(val, str):
        cleaned = val.replace("-", ":").replace(".", "").lower()
        if len(cleaned) == 12:
            return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
        return val
    return ""


def _ports_from_bitmask(bitmask: bytes | str) -> list[int]:
    """Decode Q-BRIDGE-MIB port bitmask to list of 1-based port numbers."""
    if isinstance(bitmask, str):
        bitmask = bitmask.encode("latin-1")
    ports: list[int] = []
    for byte_idx, b in enumerate(bitmask):
        for bit_idx in range(8):
            if b & (0x80 >> bit_idx):
                ports.append(byte_idx * 8 + bit_idx + 1)
    return ports


def _parse_last_oid_index(oid_str: str) -> int | None:
    """Extract trailing integer index from OID string."""
    parts = oid_str.strip(".").split(".")
    if parts and parts[-1].isdigit():
        return int(parts[-1])
    return None


def _is_stp_root_bridge(
    base_bridge_addr: str | bytes | None,
    stp_root_bridge_val: str | bytes | None,
    stp_root_port: int | None,
) -> bool:
    """Determine if a switch is the STP Root bridge.

    A switch is the STP Root if:
    1. dot1dStpRootPort == 0, or
    2. dot1dBaseBridgeAddress matches the MAC portion of dot1dStpRootBridge.
    """
    if stp_root_port == 0:
        return True

    if not base_bridge_addr or not stp_root_bridge_val:
        return False

    if isinstance(base_bridge_addr, (NoSuchObject, NoSuchInstance, EndOfMibView)) or isinstance(
        stp_root_bridge_val, (NoSuchObject, NoSuchInstance, EndOfMibView)
    ):
        return False

    if not isinstance(base_bridge_addr, (bytes, str)) or not isinstance(stp_root_bridge_val, (bytes, str)):
        return False

    base_mac = _format_mac(base_bridge_addr).replace(":", "").lower()
    root_mac = _format_mac(stp_root_bridge_val).replace(":", "").lower()

    if base_mac and root_mac and len(base_mac) >= 12 and (base_mac in root_mac or root_mac in base_mac):
        return True

    return False


class UpstreamWalker:
    """Executes the upstream discovery chain walk starting from a switch management IP."""

    def __init__(
        self,
        community: str = "public",
        port: int = 161,
        timeout: float = 1.5,
        retries: int = 1,
        client_factory: Callable[[str, str], SnmpClient] | None = None,
    ):
        # RAM-only community: stored in memory only
        self._community = community
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self._client_factory = client_factory

    def _get_client(self, host: str) -> SnmpClient:
        if self._client_factory is not None:
            return self._client_factory(host, self._community)
        return SnmpClient(
            host=host,
            community=self._community,
            port=self.port,
            timeout=self.timeout,
            retries=self.retries,
        )

    def walk(
        self,
        start_ip: str,
        progress_callback: Callable[[str], None] | None = None,
        endpoint_ip: str | None = None,
        stop_check: Callable[[], bool] | None = None,
        forced_next_ip: str | None = None,
        endpoint_mac: str | None = None,
    ) -> UpstreamPath:
        """Walk the upstream switch chain starting at start_ip."""
        hops: list[Hop] = []
        visited_ips: set[str] = set()
        curr_ip = start_ip
        hop_index = 1
        max_hops = 16
        edge_type = "unknown"
        edge_summary = ""

        norm_endpoint_mac: str | None = None
        if endpoint_mac:
            cleaned_mac = endpoint_mac.replace(":", "").replace("-", "").replace(".", "").lower().strip()
            if len(cleaned_mac) == 12:
                norm_endpoint_mac = cleaned_mac

        while hop_index <= max_hops:
            if stop_check is not None and stop_check():
                break

            if curr_ip in visited_ips:
                edge_type = "loop_detected"
                edge_summary = f"Loop detected: {curr_ip} already visited in path."
                break
            visited_ips.add(curr_ip)

            if progress_callback:
                progress_callback(f"Querying hop {hop_index}: {curr_ip}…")

            t0 = time.perf_counter()
            client = self._get_client(curr_ip)
            try:
                # 1. System Information & Device Classification
                try:
                    sys_data = client.get([OID_SYS_DESCR, OID_SYS_OBJECT_ID, OID_SYS_NAME])
                    sys_descr = str(sys_data.get(OID_SYS_DESCR) or "")
                    sys_obj_id = str(sys_data.get(OID_SYS_OBJECT_ID) or "")
                    sys_name = str(sys_data.get(OID_SYS_NAME) or "")
                except (SnmpTimeoutError, SnmpError) as e:
                    # Switch unreachable / timeout
                    hop = Hop(
                        hop_index=hop_index,
                        mgmt_ip=curr_ip,
                        status="timeout" if isinstance(e, SnmpTimeoutError) else "unreachable",
                        error_message=str(e),
                        response_time_ms=(time.perf_counter() - t0) * 1000,
                    )
                    hops.append(hop)
                    edge_type = "timeout"
                    edge_summary = f"Walk stopped at hop {hop_index} ({curr_ip}): {e}"
                    break

                device_type = classify_device(sys_descr, sys_name, sys_obj_id)

                # Check if device is a router/firewall edge device
                if is_edge_device(device_type):
                    if progress_callback:
                        progress_callback(f"Querying edge {device_type} {sys_name or curr_ip} interfaces & routes…")

                    # Edge SNMP pass: query IF-MIB and route table for WAN/LAN details
                    if_names: dict[int, str] = {}
                    if_descrs: dict[int, str] = {}
                    if_speeds: dict[int, int] = {}
                    if_oper: dict[int, int] = {}
                    if_admin: dict[int, int] = {}

                    try:
                        for oid, val in client.walk(OID_IF_NAME):
                            idx = _parse_last_oid_index(oid)
                            if idx is not None and val:
                                if_names[idx] = str(val)
                    except Exception:
                        pass

                    try:
                        for oid, val in client.walk(OID_IF_DESCR):
                            idx = _parse_last_oid_index(oid)
                            if idx is not None and val:
                                if_descrs[idx] = str(val)
                    except Exception:
                        pass

                    try:
                        for oid, val in client.walk(OID_IF_HIGH_SPEED):
                            idx = _parse_last_oid_index(oid)
                            if idx is not None and isinstance(val, int) and val > 0:
                                if_speeds[idx] = val
                    except Exception:
                        pass

                    try:
                        for oid, val in client.walk(OID_IF_SPEED):
                            idx = _parse_last_oid_index(oid)
                            if idx is not None and idx not in if_speeds and isinstance(val, int) and val > 0:
                                if_speeds[idx] = val // 1_000_000
                    except Exception:
                        pass

                    try:
                        for oid, val in client.walk(OID_IF_OPER_STATUS):
                            idx = _parse_last_oid_index(oid)
                            if idx is not None and isinstance(val, int):
                                if_oper[idx] = val
                    except Exception:
                        pass

                    try:
                        for oid, val in client.walk(OID_IF_ADMIN_STATUS):
                            idx = _parse_last_oid_index(oid)
                            if idx is not None and isinstance(val, int):
                                if_admin[idx] = val
                    except Exception:
                        pass

                    # Default route lookup (0.0.0.0/0 next-hop and outgoing ifIndex)
                    isp_gateway: str | None = None
                    default_route_if_index: int | None = None

                    try:
                        route_data = client.get([OID_IP_ROUTE_NEXT_HOP_DEFAULT, OID_IP_ROUTE_IF_INDEX_DEFAULT])
                        gw_val = route_data.get(OID_IP_ROUTE_NEXT_HOP_DEFAULT)
                        if_idx_val = route_data.get(OID_IP_ROUTE_IF_INDEX_DEFAULT)

                        if gw_val and isinstance(gw_val, (str, bytes)):
                            ip_str = gw_val if isinstance(gw_val, str) else ".".join(str(b) for b in gw_val)
                            if ip_str and ip_str != "0.0.0.0":
                                isp_gateway = ip_str
                        if isinstance(if_idx_val, int) and if_idx_val > 0:
                            default_route_if_index = if_idx_val
                    except Exception:
                        pass

                    # Fallback: walk ipRouteTable if exact GET was not conclusive
                    if isp_gateway is None or default_route_if_index is None:
                        try:
                            for oid, val in client.walk(OID_IP_ROUTE_TABLE):
                                if oid.endswith(".0.0.0.0"):
                                    if ".4.21.1.2." in oid or oid.startswith("1.3.6.1.2.1.4.21.1.2."):
                                        if isinstance(val, int) and val > 0 and default_route_if_index is None:
                                            default_route_if_index = val
                                    elif ".4.21.1.7." in oid or oid.startswith("1.3.6.1.2.1.4.21.1.7."):
                                        if val and isinstance(val, (str, bytes)) and isp_gateway is None:
                                            ip_str = val if isinstance(val, str) else ".".join(str(b) for b in val)
                                            if ip_str and ip_str != "0.0.0.0":
                                                isp_gateway = ip_str
                        except Exception:
                            pass

                    # Previous hop info for LAN interface identification
                    prev_hop = hops[-1] if hops else None
                    prev_hop_ip = prev_hop.mgmt_ip if prev_hop else ""

                    # LAN interface identification
                    lan_if_index: int | None = None

                    # 1. LLDP neighbor check
                    if prev_hop_ip:
                        try:
                            for oid, val in client.walk(OID_LLDP_REM_MAN_ADDR_TABLE):
                                parts = oid.strip(".").split(".")
                                if len(parts) >= 10:
                                    p_cand = int(parts[-8]) if parts[-8].isdigit() else None
                                    subtype = int(parts[-6]) if parts[-6].isdigit() else None
                                    count = int(parts[-5]) if parts[-5].isdigit() else None
                                    if subtype == 1 and count == 4 and p_cand is not None:
                                        ip_str = ".".join(parts[-4:])
                                        if ip_str == prev_hop_ip:
                                            lan_if_index = p_cand
                                            break
                        except Exception:
                            pass

                    # 2. ARP table check (ipNetToMedia)
                    if lan_if_index is None and prev_hop_ip:
                        try:
                            for oid, val in client.walk(OID_IP_NET_TO_MEDIA_TABLE):
                                parts = oid.strip(".").split(".")
                                if len(parts) >= 6 and ".".join(parts[-4:]) == prev_hop_ip:
                                    cand_idx = int(parts[-5]) if parts[-5].isdigit() else None
                                    if cand_idx is not None:
                                        lan_if_index = cand_idx
                                        break
                                elif isinstance(val, (str, bytes)):
                                    ip_str = val if isinstance(val, str) else ".".join(str(b) for b in val)
                                    if ip_str == prev_hop_ip:
                                        cand_idx = _parse_last_oid_index(oid)
                                        if cand_idx is not None:
                                            lan_if_index = cand_idx
                                            break
                        except Exception:
                            pass

                    # 3. Subnet match check via ipAddrTable
                    if lan_if_index is None and prev_hop_ip:
                        try:
                            import ipaddress
                            ip_ifindex: dict[str, int] = {}
                            ip_mask: dict[str, str] = {}
                            for oid, val in client.walk(OID_IP_ADDR_TABLE_IF_INDEX):
                                parts = oid.strip(".").split(".")
                                if len(parts) >= 4 and isinstance(val, int):
                                    ip_str = ".".join(parts[-4:])
                                    ip_ifindex[ip_str] = val
                            for oid, val in client.walk(OID_IP_ADDR_TABLE_NET_MASK):
                                parts = oid.strip(".").split(".")
                                if len(parts) >= 4:
                                    mask_str = val if isinstance(val, str) else ".".join(str(b) for b in val) if isinstance(val, bytes) else str(val)
                                    ip_str = ".".join(parts[-4:])
                                    ip_mask[ip_str] = mask_str

                            prev_ip_obj = ipaddress.IPv4Address(prev_hop_ip)
                            for if_ip, if_idx in ip_ifindex.items():
                                mask = ip_mask.get(if_ip, "255.255.255.0")
                                try:
                                    net = ipaddress.IPv4Network(f"{if_ip}/{mask}", strict=False)
                                    if prev_ip_obj in net and if_idx != default_route_if_index:
                                        lan_if_index = if_idx
                                        break
                                except Exception:
                                    pass
                        except Exception:
                            pass

                    # 4. Fallback name-based LAN interface check
                    if lan_if_index is None:
                        for idx, name in if_names.items():
                            if idx != default_route_if_index and name.lower() in ("lan", "internal", "lan1", "trust", "inside"):
                                lan_if_index = idx
                                break
                        if lan_if_index is None:
                            for idx, desc in if_descrs.items():
                                if idx != default_route_if_index and desc.lower() in ("lan", "internal", "lan1", "trust", "inside"):
                                    lan_if_index = idx
                                    break

                    # Build edge port diagnostics list
                    all_indices = sorted(set(if_names.keys()) | set(if_descrs.keys()) | set(if_speeds.keys()) | set(if_oper.keys()) | set(if_admin.keys()))
                    if default_route_if_index is not None and default_route_if_index not in all_indices:
                        all_indices.append(default_route_if_index)
                        all_indices.sort()

                    ports_list: list[PortDiagnostics] = []
                    wan_diag: PortDiagnostics | None = None
                    lan_diag: PortDiagnostics | None = None

                    for idx in all_indices:
                        p_name = if_names.get(idx) or if_descrs.get(idx) or f"port{idx}"
                        p_speed = if_speeds.get(idx)
                        p_oper_num = if_oper.get(idx)
                        p_oper = IF_OPER_STATUS_MAP.get(p_oper_num, "unknown") if p_oper_num is not None else "unknown"
                        p_admin_num = if_admin.get(idx)
                        p_admin = IF_ADMIN_STATUS_MAP.get(p_admin_num, "unknown") if p_admin_num is not None else "unknown"

                        is_wan = bool(default_route_if_index is not None and idx == default_route_if_index)
                        is_lan = bool(lan_if_index is not None and idx == lan_if_index)

                        n_name = ""
                        n_ip = ""
                        n_port = ""

                        if is_wan:
                            n_name = "ISP Gateway" if isp_gateway else ""
                            n_ip = isp_gateway or ""
                        elif is_lan and prev_hop:
                            n_name = prev_hop.hostname
                            n_ip = prev_hop.mgmt_ip
                            if prev_hop.uplink_port:
                                n_port = prev_hop.uplink_port.port_name

                        diag = PortDiagnostics(
                            port_id=idx,
                            port_name=p_name,
                            link_speed_mbps=p_speed,
                            stp_state="unknown",
                            oper_status=p_oper,
                            admin_status=p_admin,
                            is_uplink=is_wan,
                            is_downlink=is_lan,
                            neighbor_name=n_name,
                            neighbor_ip=n_ip,
                            neighbor_port=n_port,
                        )
                        ports_list.append(diag)
                        if is_wan:
                            wan_diag = diag
                        if is_lan:
                            lan_diag = diag

                    # If default_route_if_index didn't match any port but isp_gateway was found and we have a wan-named interface
                    if wan_diag is None:
                        for p in ports_list:
                            if "wan" in p.port_name.lower():
                                wan_diag = p
                                p.is_uplink = True
                                if isp_gateway and not p.neighbor_ip:
                                    p.neighbor_ip = isp_gateway
                                    p.neighbor_name = "ISP Gateway"
                                break

                    hop = Hop(
                        hop_index=hop_index,
                        hostname=sys_name or curr_ip,
                        mgmt_ip=curr_ip,
                        sys_descr=sys_descr,
                        device_type=device_type,
                        is_stp_root=False,
                        default_gateway=isp_gateway,
                        status="router_reached",
                        ports=ports_list,
                        uplink_port=wan_diag,
                        downlink_port=lan_diag,
                        response_time_ms=(time.perf_counter() - t0) * 1000,
                        isp_gateway=isp_gateway,
                        wan_interface=wan_diag,
                        lan_interface=lan_diag,
                    )
                    hops.append(hop)
                    edge_type = device_type
                    if wan_diag and isp_gateway:
                        edge_summary = (
                            f"Edge {device_type} reached: {sys_name or curr_ip} ({curr_ip}) — "
                            f"WAN {wan_diag.port_name} via ISP gateway {isp_gateway}"
                        )
                    elif isp_gateway:
                        edge_summary = f"Edge {device_type} reached: {sys_name or curr_ip} ({curr_ip}) — ISP gateway {isp_gateway}"
                    elif wan_diag:
                        edge_summary = f"Edge {device_type} reached: {sys_name or curr_ip} ({curr_ip}) — WAN {wan_diag.port_name}"
                    else:
                        edge_summary = f"Edge {device_type} reached: {sys_name or curr_ip} ({curr_ip})"
                    break

                # 2. Bridge & STP Information
                bridge_addr = None
                stp_root_bridge = None
                stp_root_port = None
                try:
                    stp_data = client.get([
                        OID_DOT1D_BASE_BRIDGE_ADDRESS,
                        OID_DOT1D_STP_ROOT_BRIDGE,
                        OID_DOT1D_STP_ROOT_PORT,
                    ])
                    if isinstance(stp_data, dict):
                        b_val = stp_data.get(OID_DOT1D_BASE_BRIDGE_ADDRESS)
                        if isinstance(b_val, (bytes, str)) and not isinstance(b_val, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                            bridge_addr = b_val

                        r_val = stp_data.get(OID_DOT1D_STP_ROOT_BRIDGE)
                        if isinstance(r_val, (bytes, str)) and not isinstance(r_val, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                            stp_root_bridge = r_val

                        p_val = stp_data.get(OID_DOT1D_STP_ROOT_PORT)
                        if isinstance(p_val, int) and not isinstance(p_val, bool) and not isinstance(p_val, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                            stp_root_port = p_val
                except Exception:
                    pass

                # STP is present only if we have usable STP direction data (root port or root bridge).
                # A bare dot1dBaseBridgeAddress is just the bridge MAC (base BRIDGE-MIB), not a direction signal.
                stp_present = (stp_root_port is not None) or bool(stp_root_bridge)

                # 3. Tables: Port to ifIndex, STP Port State, Interface Speeds, Names
                port_ifindex_map: dict[int, int] = {}
                stp_port_states: dict[int, str] = {}
                try:
                    for oid, val in client.walk(OID_DOT1D_BASE_PORT_IFINDEX):
                        p_num = _parse_last_oid_index(oid)
                        if p_num is not None and isinstance(val, int):
                            port_ifindex_map[p_num] = val
                except Exception:
                    pass

                try:
                    for oid, val in client.walk(OID_DOT1D_STP_PORT_STATE):
                        p_num = _parse_last_oid_index(oid)
                        if p_num is not None and isinstance(val, int):
                            stp_port_states[p_num] = STP_STATE_MAP.get(val, "unknown")
                except Exception:
                    pass

                if_names: dict[int, str] = {}
                if_speeds: dict[int, int] = {}
                try:
                    for oid, val in client.walk(OID_IF_NAME):
                        idx = _parse_last_oid_index(oid)
                        if idx is not None and val:
                            if_names[idx] = str(val)
                except Exception:
                    pass

                try:
                    for oid, val in client.walk(OID_IF_DESCR):
                        idx = _parse_last_oid_index(oid)
                        if idx is not None and idx not in if_names and val:
                            if_names[idx] = str(val)
                except Exception:
                    pass

                try:
                    for oid, val in client.walk(OID_IF_HIGH_SPEED):
                        idx = _parse_last_oid_index(oid)
                        if idx is not None and isinstance(val, int) and val > 0:
                            if_speeds[idx] = val
                except Exception:
                    pass

                try:
                    for oid, val in client.walk(OID_IF_SPEED):
                        idx = _parse_last_oid_index(oid)
                        if idx is not None and idx not in if_speeds and isinstance(val, int) and val > 0:
                            if_speeds[idx] = val // 1_000_000
                except Exception:
                    pass

                # 4. VLAN Information (Q-BRIDGE-MIB)
                port_pvids: dict[int, int] = {}
                port_egress_vlans: dict[int, set[int]] = {}
                port_untagged_vlans: dict[int, set[int]] = {}
                untagged_tables_readable = False

                try:
                    for oid, val in client.walk(OID_DOT1Q_PVID):
                        p_num = _parse_last_oid_index(oid)
                        if p_num is not None and isinstance(val, int) and not isinstance(val, bool):
                            port_pvids[p_num] = val
                except Exception:
                    pass

                # Configured membership: static egress table
                try:
                    for oid, val in client.walk(OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS):
                        vlan_id = _parse_last_oid_index(oid)
                        if vlan_id is not None and isinstance(val, (bytes, str)) and not isinstance(val, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                            for p_num in _ports_from_bitmask(val):
                                port_egress_vlans.setdefault(p_num, set()).add(vlan_id)
                except Exception:
                    pass

                # Operational membership: current egress table
                try:
                    for oid, val in client.walk(OID_DOT1Q_VLAN_CURRENT_EGRESS_PORTS):
                        vlan_id = _parse_last_oid_index(oid)
                        if vlan_id is not None and isinstance(val, (bytes, str)) and not isinstance(val, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                            for p_num in _ports_from_bitmask(val):
                                port_egress_vlans.setdefault(p_num, set()).add(vlan_id)
                except Exception:
                    pass

                # Untagged membership: static untagged table
                try:
                    for oid, val in client.walk(OID_DOT1Q_VLAN_STATIC_UNTAGGED_PORTS):
                        vlan_id = _parse_last_oid_index(oid)
                        if vlan_id is not None and isinstance(val, (bytes, str)) and not isinstance(val, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                            untagged_tables_readable = True
                            for p_num in _ports_from_bitmask(val):
                                port_untagged_vlans.setdefault(p_num, set()).add(vlan_id)
                except Exception:
                    pass

                # Untagged membership: current untagged table
                try:
                    for oid, val in client.walk(OID_DOT1Q_VLAN_CURRENT_UNTAGGED_PORTS):
                        vlan_id = _parse_last_oid_index(oid)
                        if vlan_id is not None and isinstance(val, (bytes, str)) and not isinstance(val, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                            untagged_tables_readable = True
                            for p_num in _ports_from_bitmask(val):
                                port_untagged_vlans.setdefault(p_num, set()).add(vlan_id)
                except Exception:
                    pass

                # 5. LLDP & CDP Neighbor Tables
                port_neighbors: dict[int, dict[str, str]] = {}
                try:
                    for oid, val in client.walk(OID_LLDP_REM_SYS_NAME):
                        parts = oid.strip(".").split(".")
                        # ... <localPort>.<remIndex>
                        if len(parts) >= 2 and parts[-2].isdigit():
                            p_num = int(parts[-2])
                            port_neighbors.setdefault(p_num, {})["name"] = str(val)
                except Exception:
                    pass

                try:
                    for oid, val in client.walk(OID_LLDP_REM_PORT_ID):
                        parts = oid.strip(".").split(".")
                        if len(parts) >= 2 and parts[-2].isdigit():
                            p_num = int(parts[-2])
                            port_neighbors.setdefault(p_num, {})["port"] = str(val)
                except Exception:
                    pass

                try:
                    for oid, val in client.walk(OID_LLDP_REM_CHASSIS_ID):
                        parts = oid.strip(".").split(".")
                        if len(parts) >= 2 and parts[-2].isdigit():
                            p_num = int(parts[-2])
                            c_mac = _format_mac(val)
                            if c_mac:
                                port_neighbors.setdefault(p_num, {})["chassis"] = c_mac
                except Exception:
                    pass

                # LLDP Management Address table: OID contains IP or value contains IP
                try:
                    for oid, val in client.walk(OID_LLDP_REM_MAN_ADDR_TABLE):
                        parts = oid.strip(".").split(".")
                        # OID suffix: [..., localPort, remIndex, addrSubtype, addrCount, a, b, c, d]
                        if len(parts) >= 10:
                            p_cand = int(parts[-8]) if parts[-8].isdigit() else None
                            subtype = int(parts[-6]) if parts[-6].isdigit() else None
                            count = int(parts[-5]) if parts[-5].isdigit() else None
                            if subtype == 1 and count == 4 and p_cand is not None:
                                ip_str = ".".join(parts[-4:])
                                port_neighbors.setdefault(p_cand, {})["ip"] = ip_str
                except Exception:
                    pass

                # CDP table fallback
                try:
                    for oid, val in client.walk(OID_CDP_CACHE_DEVICE_ID):
                        if_idx = _parse_last_oid_index(oid)
                        if if_idx is not None:
                            port_neighbors.setdefault(if_idx, {})["name"] = str(val)
                    for oid, val in client.walk(OID_CDP_CACHE_DEVICE_PORT):
                        if_idx = _parse_last_oid_index(oid)
                        if if_idx is not None:
                            port_neighbors.setdefault(if_idx, {})["port"] = str(val)
                    for oid, val in client.walk(OID_CDP_CACHE_ADDRESS):
                        if_idx = _parse_last_oid_index(oid)
                        if if_idx is not None:
                            ip_str = val if isinstance(val, str) else (
                                ".".join(str(b) for b in val) if isinstance(val, bytes) and len(val) == 4 else ""
                            )
                            if ip_str:
                                port_neighbors.setdefault(if_idx, {})["ip"] = ip_str
                except Exception:
                    pass

                # 6. Default Route (L3 Edge fallback)
                default_gw = None
                try:
                    gw_val = client.get(OID_IP_ROUTE_NEXT_HOP_DEFAULT)
                    if gw_val and isinstance(gw_val, str) and gw_val != "0.0.0.0":
                        default_gw = gw_val
                except Exception:
                    pass

                # 7. DIRECTION RULE & STP Root Check
                is_root = _is_stp_root_bridge(bridge_addr, stp_root_bridge, stp_root_port)

                # Assemble port diagnostics
                ports_list: list[PortDiagnostics] = []
                all_port_ids = (
                    set(port_pvids.keys())
                    | set(stp_port_states.keys())
                    | set(port_neighbors.keys())
                    | set(port_egress_vlans.keys())
                    | set(port_untagged_vlans.keys())
                )
                if stp_root_port and stp_root_port > 0:
                    all_port_ids.add(stp_root_port)

                for p_num in sorted(all_port_ids):
                    if_idx = port_ifindex_map.get(p_num, p_num)
                    p_name = if_names.get(if_idx) or if_names.get(p_num) or f"Port {p_num}"
                    p_speed = if_speeds.get(if_idx) or if_speeds.get(p_num)
                    p_state = stp_port_states.get(p_num, "forwarding" if is_root else "unknown")
                    p_pvid = port_pvids.get(p_num)

                    egress_set = port_egress_vlans.get(p_num, set())
                    untagged_set = port_untagged_vlans.get(p_num, set())

                    if untagged_tables_readable:
                        p_untagged = sorted(untagged_set)
                        p_tagged = sorted(egress_set - untagged_set)
                        p_allowed = sorted(set(p_untagged) | set(p_tagged))
                        if not p_allowed and p_pvid is not None:
                            p_allowed = [p_pvid]
                    else:
                        p_untagged = []
                        p_tagged = []
                        p_allowed = sorted(egress_set) if egress_set else ([p_pvid] if p_pvid is not None else [])

                    p_neigh = port_neighbors.get(p_num) or port_neighbors.get(if_idx) or {}

                    is_this_root_port = bool(stp_root_port and p_num == stp_root_port)

                    diag = PortDiagnostics(
                        port_id=p_num,
                        port_name=p_name,
                        pvid=p_pvid,
                        allowed_vlans=p_allowed,
                        tagged_vlans=p_tagged,
                        untagged_vlans=p_untagged,
                        stp_state=p_state,
                        link_speed_mbps=p_speed,
                        is_root_port=is_this_root_port,
                        neighbor_name=p_neigh.get("name", ""),
                        neighbor_ip=p_neigh.get("ip", ""),
                        neighbor_port=p_neigh.get("port", ""),
                        neighbor_chassis=p_neigh.get("chassis", ""),
                        is_uplink=is_this_root_port,
                    )
                    ports_list.append(diag)

                # Uplink and Downlink determination
                uplink_port_diag = None
                if stp_root_port and stp_root_port > 0:
                    for p in ports_list:
                        if p.port_id == stp_root_port:
                            uplink_port_diag = p
                            p.is_uplink = True
                            break

                # Downlink determination for switch hops:
                # Matches against previous hop in chain (or endpoint on hop 1)
                prev_hop = hops[-1] if hops else None
                prev_hop_ip = prev_hop.mgmt_ip if prev_hop else (endpoint_ip or "")
                prev_hop_name = prev_hop.hostname if prev_hop else ""

                downlink_port_diag: PortDiagnostics | None = None

                if prev_hop_ip or prev_hop_name:
                    # 1. Exact mgmt IP match on neighbor_ip
                    if prev_hop_ip:
                        for p in ports_list:
                            if p is not uplink_port_diag and p.neighbor_ip == prev_hop_ip:
                                downlink_port_diag = p
                                break

                    # 2. Hostname match on neighbor_name
                    if downlink_port_diag is None and prev_hop_name:
                        for p in ports_list:
                            if p is not uplink_port_diag and p.neighbor_name:
                                p_n = p.neighbor_name.strip().lower()
                                h_n = prev_hop_name.strip().lower()
                                if p_n == h_n or h_n in p_n or p_n in h_n:
                                    downlink_port_diag = p
                                    break

                    # 3. ARP table check (ipNetToMedia)
                    if downlink_port_diag is None and prev_hop_ip:
                        try:
                            for oid, val in client.walk(OID_IP_NET_TO_MEDIA_TABLE):
                                parts = oid.strip(".").split(".")
                                if len(parts) >= 6 and ".".join(parts[-4:]) == prev_hop_ip:
                                    cand_idx = int(parts[-5]) if parts[-5].isdigit() else None
                                    if cand_idx is not None:
                                        for p in ports_list:
                                            if p is not uplink_port_diag and (p.port_id == cand_idx or port_ifindex_map.get(p.port_id) == cand_idx):
                                                downlink_port_diag = p
                                                break
                                        if downlink_port_diag:
                                            break
                                elif isinstance(val, (str, bytes)):
                                    ip_str = val if isinstance(val, str) else ".".join(str(b) for b in val)
                                    if ip_str == prev_hop_ip:
                                        cand_idx = _parse_last_oid_index(oid)
                                        if cand_idx is not None:
                                            for p in ports_list:
                                                if p is not uplink_port_diag and (p.port_id == cand_idx or port_ifindex_map.get(p.port_id) == cand_idx):
                                                    downlink_port_diag = p
                                                    break
                                            if downlink_port_diag:
                                                break
                        except Exception:
                            pass

                    # 4. Subnet match via ipAddrTable or neighbor_ip
                    if downlink_port_diag is None and prev_hop_ip:
                        try:
                            import ipaddress
                            for p in ports_list:
                                if p is not uplink_port_diag and p.neighbor_ip:
                                    try:
                                        if ipaddress.IPv4Network(f"{p.neighbor_ip}/24", strict=False) == ipaddress.IPv4Network(f"{prev_hop_ip}/24", strict=False):
                                            downlink_port_diag = p
                                            break
                                    except Exception:
                                        pass
                        except Exception:
                            pass

                # 5. Hop 1 fallback: match neighbor_name indicating endpoint
                if downlink_port_diag is None and hop_index == 1:
                    for p in ports_list:
                        if p is not uplink_port_diag and p.neighbor_name:
                            if any(k in p.neighbor_name.lower() for k in ("local-host", "endpoint", "host", "localhost")):
                                downlink_port_diag = p
                                break

                # 6. Hop 1 FDB fallback (BRIDGE-MIB dot1dTpFdbTable) for LLDP-silent endpoints
                if downlink_port_diag is None and hop_index == 1 and norm_endpoint_mac:
                    try:
                        matched_bridge_port: int | None = None
                        # 1. Exact GET optimization
                        try:
                            m_octets = [str(int(norm_endpoint_mac[i : i + 2], 16)) for i in range(0, 12, 2)]
                            exact_oid = f"{OID_DOT1D_TP_FDB_PORT}.{'.'.join(m_octets)}"
                            exact_val = client.get(exact_oid)
                            if isinstance(exact_val, int) and not isinstance(exact_val, bool) and exact_val > 0:
                                matched_bridge_port = exact_val
                        except Exception:
                            pass

                        # 2. Walk dot1dTpFdbPort
                        if matched_bridge_port is None:
                            for oid, val in client.walk(OID_DOT1D_TP_FDB_PORT):
                                parts = oid.strip(".").split(".")
                                if len(parts) >= 6 and all(p.isdigit() for p in parts[-6:]):
                                    mac_hex = "".join(f"{int(p):02x}" for p in parts[-6:])
                                    if mac_hex == norm_endpoint_mac:
                                        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
                                            matched_bridge_port = val
                                            break
                                        elif isinstance(val, str) and val.isdigit() and int(val) > 0:
                                            matched_bridge_port = int(val)
                                            break

                        if matched_bridge_port is not None:
                            target_if_idx = port_ifindex_map.get(matched_bridge_port, matched_bridge_port)
                            for p in ports_list:
                                if p is not uplink_port_diag and (
                                    p.port_id == matched_bridge_port
                                    or p.port_id == target_if_idx
                                    or port_ifindex_map.get(p.port_id) == target_if_idx
                                    or port_ifindex_map.get(p.port_id) == matched_bridge_port
                                ):
                                    downlink_port_diag = p
                                    break

                            if downlink_port_diag is not None:
                                downlink_port_diag.is_downlink = True
                                if not downlink_port_diag.neighbor_name:
                                    downlink_port_diag.neighbor_name = "Endpoint"
                    except Exception:
                        pass

                if downlink_port_diag is not None:
                    downlink_port_diag.is_downlink = True

                candidate_uplinks: list[PortDiagnostics] = []
                if not stp_present or is_root:
                    if not stp_present and progress_callback:
                        progress_callback(
                            f"STP MIB not available on {sys_name or curr_ip} — using LLDP neighbor direction"
                        )

                    for p in ports_list:
                        if not (p.neighbor_name or p.neighbor_port or p.neighbor_chassis or p.neighbor_ip):
                            continue
                        if p is downlink_port_diag or p.is_downlink:
                            continue
                        if prev_hop_ip and p.neighbor_ip and p.neighbor_ip == prev_hop_ip:
                            continue
                        if prev_hop_name and p.neighbor_name:
                            p_n = p.neighbor_name.strip().lower()
                            h_n = prev_hop_name.strip().lower()
                            if p_n == h_n or h_n in p_n or p_n in h_n:
                                continue
                        if hop_index == 1:
                            if endpoint_ip and p.neighbor_ip and p.neighbor_ip == endpoint_ip:
                                continue
                            if p.neighbor_name and any(
                                k in p.neighbor_name.lower()
                                for k in ("local-host", "endpoint", "host", "localhost")
                            ):
                                continue
                        candidate_uplinks.append(p)

                    if forced_next_ip:
                        forced_port = None
                        for p in candidate_uplinks:
                            if p.neighbor_ip == forced_next_ip:
                                forced_port = p
                                break
                        if forced_port is None:
                            for p in ports_list:
                                if p.neighbor_ip == forced_next_ip:
                                    forced_port = p
                                    break
                        if forced_port is None:
                            try:
                                for oid, val in client.walk(OID_IP_NET_TO_MEDIA_TABLE):
                                    parts = oid.strip(".").split(".")
                                    if len(parts) >= 6 and ".".join(parts[-4:]) == forced_next_ip:
                                        mac_val = _format_mac(val)
                                        if mac_val:
                                            from .arp_resolve import normalize_mac
                                            n_mac = normalize_mac(mac_val)
                                            for p in candidate_uplinks:
                                                if normalize_mac(p.neighbor_chassis) == n_mac:
                                                    forced_port = p
                                                    break
                                        if forced_port:
                                            break
                            except Exception:
                                pass
                        if forced_port is None:
                            no_ip_cands = [p for p in candidate_uplinks if not p.neighbor_ip]
                            if len(no_ip_cands) == 1:
                                forced_port = no_ip_cands[0]
                            elif len(candidate_uplinks) == 1:
                                forced_port = candidate_uplinks[0]

                        if forced_port is not None:
                            if not forced_port.neighbor_ip:
                                forced_port.neighbor_ip = forced_next_ip
                            uplink_port_diag = forced_port
                            uplink_port_diag.is_uplink = True
                            forced_next_ip = None  # consumed
                    elif not is_root and len(candidate_uplinks) == 1 and candidate_uplinks[0].neighbor_ip:
                        uplink_port_diag = candidate_uplinks[0]
                        uplink_port_diag.is_uplink = True
                elif forced_next_ip:
                    forced_port = None
                    for p in ports_list:
                        if p.neighbor_ip == forced_next_ip:
                            forced_port = p
                            break
                    if forced_port is not None:
                        if not forced_port.neighbor_ip:
                            forced_port.neighbor_ip = forced_next_ip
                        uplink_port_diag = forced_port
                        uplink_port_diag.is_uplink = True
                        forced_next_ip = None

                is_verified_root_from_downstream = bool(
                    prev_hop is not None
                    and prev_hop.stp_root_port_num is not None
                    and prev_hop.stp_root_port_num > 0
                    and prev_hop.uplink_port is not None
                    and prev_hop.uplink_port.neighbor_ip == curr_ip
                )

                hop_status = "ok"
                if is_root:
                    if uplink_port_diag is not None:
                        hop_status = "ok"
                    elif candidate_uplinks and (hop_index == 1 or not is_verified_root_from_downstream):
                        hop_status = "root_claimed_but_uplinks_present"
                    else:
                        hop_status = "root_reached"
                elif not stp_present:
                    if not candidate_uplinks and uplink_port_diag is None:
                        hop_status = "no_upstream"
                    elif candidate_uplinks and uplink_port_diag is None:
                        hop_status = "ambiguous"

                hop = Hop(
                    hop_index=hop_index,
                    hostname=sys_name or curr_ip,
                    mgmt_ip=curr_ip,
                    sys_descr=sys_descr,
                    device_type="switch",
                    is_stp_root=is_root,
                    stp_root_bridge_id=_format_mac(stp_root_bridge or ""),
                    stp_bridge_id=_format_mac(bridge_addr or ""),
                    stp_root_port_num=stp_root_port if not is_root else 0,
                    default_gateway=default_gw,
                    status=hop_status,
                    ports=ports_list,
                    uplink_port=uplink_port_diag,
                    downlink_port=downlink_port_diag,
                    ambiguous_candidates=list(candidate_uplinks) if (
                        candidate_uplinks and (
                            uplink_port_diag is None
                            or len(candidate_uplinks) > 1
                            or hop_status in ("ambiguous", "root_claimed_but_uplinks_present")
                        )
                    ) else [],
                    response_time_ms=(time.perf_counter() - t0) * 1000,
                )
                hops.append(hop)

                # DIRECTION RULE CHECK:
                # If switch IS STP Root:
                # If forced uplink selected, continue. If unverified STP root with LLDP candidates,
                # distrust STP root (wireless mesh / BPDU drop boundary) and expose candidates.
                # Otherwise, clean L2 top reached.
                if is_root:
                    if uplink_port_diag is not None:
                        pass
                    elif candidate_uplinks and (hop_index == 1 or not is_verified_root_from_downstream):
                        edge_type = "root_claimed_but_uplinks_present"
                        edge_summary = (
                            f"{sys_name or curr_ip} reports itself as STP root but LLDP shows "
                            f"upstream neighbor(s) — mesh/wireless uplink can hide the true root; "
                            f"choose a path to continue."
                        )
                        break
                    else:
                        edge_type = "stp_root"
                        gw_text = f", Gateway: {default_gw}" if default_gw else ""
                        edge_summary = f"L2 STP Root reached: {sys_name or curr_ip} ({curr_ip}){gw_text}"
                        break

                if not stp_present:
                    if not candidate_uplinks and uplink_port_diag is None:
                        edge_type = "no_upstream"
                        edge_summary = (
                            f"No upstream neighbor visible from {sys_name or curr_ip} ({curr_ip}) "
                            f"via LLDP — this switch appears to be the network edge."
                        )
                        break
                    elif candidate_uplinks and uplink_port_diag is None:
                        edge_type = "ambiguous"
                        cand_list = [
                            f"{p.neighbor_name} ({p.neighbor_ip})" if (p.neighbor_name and p.neighbor_ip)
                            else (p.neighbor_name or (f"MAC {p.neighbor_chassis}" if p.neighbor_chassis else f"Port {p.port_id}"))
                            for p in candidate_uplinks
                        ]
                        cand_desc = ", ".join(cand_list)
                        if len(candidate_uplinks) == 1:
                            edge_summary = (
                                f"Walk stopped at hop {hop_index} ({sys_name or curr_ip}): "
                                f"upstream candidate neighbor found without management IP ({cand_desc}) — "
                                f"choose path to resolve."
                            )
                        else:
                            edge_summary = (
                                f"Walk stopped at hop {hop_index} ({sys_name or curr_ip}): "
                                f"multiple upstream LLDP candidate neighbors found ({cand_desc}) — "
                                f"verify upstream topology."
                            )
                        break

                # If switch is NOT root: look up neighbor on the root port ONLY
                if not uplink_port_diag or not uplink_port_diag.neighbor_ip:
                    # Check if neighbor name or port exists
                    neigh_info = f" neighbor {uplink_port_diag.neighbor_name}" if (uplink_port_diag and uplink_port_diag.neighbor_name) else ""
                    edge_type = "unreachable"
                    edge_summary = (
                        f"Walk stopped at hop {hop_index} ({sys_name or curr_ip}): "
                        f"root port {stp_root_port}{neigh_info} has no management IP."
                    )
                    break

                next_ip = uplink_port_diag.neighbor_ip
                curr_ip = next_ip
                hop_index += 1

            finally:
                client.close()

        success = bool(hops and hops[-1].status in ("ok", "root_reached", "router_reached", "no_upstream"))
        return UpstreamPath(
            start_ip=start_ip,
            hops=hops,
            edge_type=edge_type,
            edge_summary=edge_summary or (f"Completed {len(hops)} hop walk." if success else "Discovery incomplete."),
            success=success,
        )
