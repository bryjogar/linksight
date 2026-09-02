"""Unit tests for UpstreamWalker and STP root direction rule."""

from __future__ import annotations

import pytest

from linksight.discovery.classifier import classify_device, is_edge_device
from linksight.discovery.models import Hop, PortDiagnostics, UpstreamPath
from linksight.discovery.snmp_client import (
    SnmpClient,
    SnmpTimeoutError,
    EndOfMibView,
    NoSuchObject,
    oid_to_tuple,
    build_snmp_request,
    decode_tlv,
    decode_value,
    decode_oid,
    PDU_GET_REQUEST,
    PDU_GET_NEXT_REQUEST,
    PDU_GET_RESPONSE,
)
from linksight.discovery.walker import (
    UpstreamWalker,
    OID_SYS_DESCR,
    OID_SYS_OBJECT_ID,
    OID_SYS_NAME,
    OID_DOT1D_BASE_BRIDGE_ADDRESS,
    OID_DOT1D_STP_ROOT_BRIDGE,
    OID_DOT1D_STP_ROOT_PORT,
    OID_DOT1D_BASE_PORT_IFINDEX,
    OID_DOT1D_STP_PORT_STATE,
    OID_IF_NAME,
    OID_IF_DESCR,
    OID_IF_HIGH_SPEED,
    OID_IF_SPEED,
    OID_IF_OPER_STATUS,
    OID_IF_ADMIN_STATUS,
    OID_DOT1Q_PVID,
    OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS,
    OID_LLDP_REM_PORT_ID,
    OID_LLDP_REM_SYS_NAME,
    OID_LLDP_REM_MAN_ADDR_TABLE,
    OID_IP_ROUTE_NEXT_HOP_DEFAULT,
    OID_IP_ROUTE_IF_INDEX_DEFAULT,
    OID_IP_ROUTE_TABLE,
    OID_IP_NET_TO_MEDIA_TABLE,
)


def make_mock_client_factory(device_mibs: dict[str, dict[str, any]]):
    """Create a client factory that returns simulated responses for given IP addresses."""
    def factory(host: str, community: str) -> SnmpClient:
        if host not in device_mibs:
            # Unreachable host
            def timeout_transport(req: bytes) -> bytes:
                import socket
                raise socket.timeout(f"Host {host} timed out")
            return SnmpClient(host, community=community, retries=0, transport=timeout_transport)

        store = device_mibs[host]
        sorted_oids = sorted(store.keys(), key=oid_to_tuple)

        def mock_transport(req_bytes: bytes) -> bytes:
            tag, msg_bytes, _ = decode_tlv(req_bytes, 0)
            pos = 0
            _, vbytes, pos = decode_tlv(msg_bytes, pos)
            _, cbytes, pos = decode_tlv(msg_bytes, pos)
            comm = decode_value(0x04, cbytes)
            ptag, pbytes, _ = decode_tlv(msg_bytes, pos)

            ppos = 0
            _, rbytes, ppos = decode_tlv(pbytes, ppos)
            req_id = decode_value(0x02, rbytes)
            _, _, ppos = decode_tlv(pbytes, ppos)
            _, _, ppos = decode_tlv(pbytes, ppos)
            _, vbl_bytes, _ = decode_tlv(pbytes, ppos)

            requested_oids = []
            vb_pos = 0
            while vb_pos < len(vbl_bytes):
                _, vb_data, vb_pos = decode_tlv(vbl_bytes, vb_pos)
                item_pos = 0
                _, obytes, item_pos = decode_tlv(vb_data, item_pos)
                requested_oids.append(decode_oid(obytes))

            resp_varbinds = []
            if ptag == PDU_GET_REQUEST:
                for roid in requested_oids:
                    val = store.get(roid, NoSuchObject())
                    resp_varbinds.append((roid, val))
            elif ptag == PDU_GET_NEXT_REQUEST:
                roid = requested_oids[0]
                req_tuple = oid_to_tuple(roid)
                found = False
                for cand in sorted_oids:
                    if oid_to_tuple(cand) > req_tuple:
                        resp_varbinds.append((cand, store[cand]))
                        found = True
                        break
                if not found:
                    resp_varbinds.append((roid, EndOfMibView()))

            return build_snmp_request(
                community=comm,
                pdu_type=PDU_GET_RESPONSE,
                request_id=req_id,
                varbinds=resp_varbinds,
            )

        return SnmpClient(host, community=community, transport=mock_transport)

    return factory


def test_direction_rule_recursion_trap_9_idfs():
    """CRITICAL TEST: Fiber Core (MDF) with 9 IDFs (A-I).

    When starting discovery at IDF-D:
    1. Walk must go IDF-D -> Core-MDF.
    2. Core-MDF is STP root (dot1dStpRootPort == 0).
    3. Walk must STOP at Core-MDF.
    4. Walk must NEVER recurse into IDFs A, B, C, E, F, G, H, I (which sit on Core's designated ports).
    """
    mdf_core_ip = "10.0.0.1"
    idf_d_ip = "10.0.10.4"

    # IDF-D MIB data
    idf_d_mib = {
        OID_SYS_DESCR: "Cisco Catalyst 2960X-48TD-L",
        OID_SYS_NAME: "IDF-D-SW1",
        OID_SYS_OBJECT_ID: "1.3.6.1.4.1.9.1.1208",
        OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("001122334455"),
        OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000000000000001"),  # Core MAC is 00:00:00:00:00:01
        OID_DOT1D_STP_ROOT_PORT: 24,                                     # Uplink port to Core
        f"{OID_DOT1D_BASE_PORT_IFINDEX}.24": 24,
        f"{OID_DOT1D_STP_PORT_STATE}.24": 5,                             # Forwarding
        f"{OID_IF_NAME}.24": "TenGigabitEthernet1/0/24",
        f"{OID_IF_HIGH_SPEED}.24": 10000,                                # 10 Gbps uplink
        f"{OID_DOT1Q_PVID}.24": 1,
        f"{OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS}.1": bytes.fromhex("800000"), # port 1
        f"{OID_DOT1Q_VLAN_STATIC_EGRESS_PORTS}.100": bytes.fromhex("000080"), # port 24
        # LLDP Neighbor on Port 24 is MDF-Core (10.0.0.1)
        f"{OID_LLDP_REM_SYS_NAME}.0.24.1": "Core-MDF",
        f"{OID_LLDP_REM_PORT_ID}.0.24.1": "TenGigabitEthernet1/1/4",
        f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.24.1.1.4.10.0.0.1": 1,
    }

    # Core-MDF MIB data: has 9 downstream IDFs connected on ports 1 through 9
    core_mdf_mib = {
        OID_SYS_DESCR: "Cisco Catalyst 9500-48Y4C",
        OID_SYS_NAME: "Core-MDF",
        OID_SYS_OBJECT_ID: "1.3.6.1.4.1.9.1.2500",
        OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("000000000001"),
        OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000000000000001"),
        OID_DOT1D_STP_ROOT_PORT: 0,                                     # IS STP ROOT!
        OID_IP_ROUTE_NEXT_HOP_DEFAULT: "192.168.1.1",                   # Default gateway
    }

    # Populate 9 downstream IDFs in Core's LLDP table (ports 1..9)
    idf_letters = ["A", "B", "C", "D", "E", "F", "G", "H", "I"]
    for idx, letter in enumerate(idf_letters, start=1):
        core_mdf_mib[f"{OID_DOT1D_BASE_PORT_IFINDEX}.{idx}"] = idx
        core_mdf_mib[f"{OID_DOT1D_STP_PORT_STATE}.{idx}"] = 5
        core_mdf_mib[f"{OID_IF_NAME}.{idx}"] = f"TenGigabitEthernet1/1/{idx}"
        core_mdf_mib[f"{OID_IF_HIGH_SPEED}.{idx}"] = 10000
        core_mdf_mib[f"{OID_DOT1Q_PVID}.{idx}"] = 100
        core_mdf_mib[f"{OID_LLDP_REM_SYS_NAME}.0.{idx}.1"] = f"IDF-{letter}-SW1"
        core_mdf_mib[f"{OID_LLDP_REM_PORT_ID}.0.{idx}.1"] = "TenGigabitEthernet1/0/24"
        core_mdf_mib[f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.{idx}.1.1.4.10.0.10.{idx}"] = 1

    # Trap: if walker descends into other IDFs, these stores exist
    device_mibs = {
        idf_d_ip: idf_d_mib,
        mdf_core_ip: core_mdf_mib,
    }
    for idx, letter in enumerate(idf_letters, start=1):
        ip = f"10.0.10.{idx}"
        if ip != idf_d_ip:
            device_mibs[ip] = {
                OID_SYS_DESCR: f"IDF-{letter} Trap Switch",
                OID_SYS_NAME: f"IDF-{letter}-SW1",
                OID_DOT1D_STP_ROOT_PORT: 24,
            }

    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="test_community", client_factory=factory)

    result: UpstreamPath = walker.walk(start_ip=idf_d_ip)

    # Verification of the direction rule
    assert result.success is True
    assert len(result.hops) == 2, f"Expected exactly 2 hops (IDF-D -> Core-MDF), got {len(result.hops)}"

    hop1 = result.hops[0]
    assert hop1.mgmt_ip == idf_d_ip
    assert hop1.hostname == "IDF-D-SW1"
    assert hop1.is_stp_root is False
    assert hop1.stp_root_port_num == 24
    assert hop1.uplink_port is not None
    assert hop1.uplink_port.neighbor_ip == mdf_core_ip
    assert hop1.uplink_port.neighbor_name == "Core-MDF"

    hop2 = result.hops[1]
    assert hop2.mgmt_ip == mdf_core_ip
    assert hop2.hostname == "Core-MDF"
    assert hop2.is_stp_root is True
    assert hop2.default_gateway == "192.168.1.1"

    # Crucial assertion: None of the other 8 IDFs were visited!
    visited_ips = [h.mgmt_ip for h in result.hops]
    for idx in range(1, 10):
        ip = f"10.0.10.{idx}"
        if ip != idf_d_ip:
            assert ip not in visited_ips, f"Recursion trap failed: {ip} was erroneously visited!"

    assert result.edge_type == "stp_root"
    assert "Core-MDF" in result.edge_summary


def test_walker_multi_hop_to_firewall_edge():
    """Verify 3-hop chain ending at an edge firewall with downlink and uplink port identification."""
    # Access -> Core (Root) -> Edge Firewall
    access_ip = "10.0.0.3"
    core_ip = "10.0.0.2"
    fw_ip = "10.0.0.1"

    device_mibs = {
        access_ip: {
            OID_SYS_DESCR: "Cisco Catalyst 2960L",
            OID_SYS_NAME: "Access-SW2",
            OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("aabbcc001122"),
            OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000001a2b3c4d5e"),
            OID_DOT1D_STP_ROOT_PORT: 24,
            f"{OID_DOT1D_BASE_PORT_IFINDEX}.1": 1,
            f"{OID_DOT1D_STP_PORT_STATE}.1": 5,
            f"{OID_IF_NAME}.1": "Gi1/0/1",
            f"{OID_IF_HIGH_SPEED}.1": 1000,
            f"{OID_DOT1Q_PVID}.1": 200,
            f"{OID_LLDP_REM_SYS_NAME}.0.1.1": "Local-Host",
            f"{OID_LLDP_REM_PORT_ID}.0.1.1": "eth0",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.1.1.1.4.10.0.0.42": 1,
            f"{OID_DOT1D_BASE_PORT_IFINDEX}.24": 24,
            f"{OID_DOT1D_STP_PORT_STATE}.24": 5,
            f"{OID_IF_NAME}.24": "Gi1/0/24",
            f"{OID_IF_HIGH_SPEED}.24": 1000,
            f"{OID_DOT1Q_PVID}.24": 100,
            f"{OID_LLDP_REM_SYS_NAME}.0.24.1": "Core-SW1",
            f"{OID_LLDP_REM_PORT_ID}.0.24.1": "Gi0/24",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.24.1.1.4.10.0.0.2": 1,
        },
        core_ip: {
            OID_SYS_DESCR: "Cisco Catalyst 2960X",
            OID_SYS_NAME: "Core-SW1",
            OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("001a2b3c4d5e"),
            OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000001a2b3c4d5e"),
            OID_DOT1D_STP_ROOT_PORT: 0,  # Root bridge
            OID_IP_ROUTE_NEXT_HOP_DEFAULT: fw_ip,
            f"{OID_DOT1D_BASE_PORT_IFINDEX}.24": 24,
            f"{OID_DOT1D_STP_PORT_STATE}.24": 5,
            f"{OID_IF_NAME}.24": "Gi0/24",
            f"{OID_IF_HIGH_SPEED}.24": 1000,
            f"{OID_DOT1Q_PVID}.24": 100,
            f"{OID_LLDP_REM_SYS_NAME}.0.24.1": "Access-SW2",
            f"{OID_LLDP_REM_PORT_ID}.0.24.1": "Gi1/0/24",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.24.1.1.4.10.0.0.3": 1,
        },
    }

    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="public", client_factory=factory)
    result = walker.walk(start_ip=access_ip)

    assert result.success is True
    assert len(result.hops) == 2
    hop1 = result.hops[0]
    assert hop1.hostname == "Access-SW2"
    assert hop1.uplink_port is not None
    assert hop1.uplink_port.port_name == "Gi1/0/24"
    assert hop1.uplink_port.is_uplink is True
    assert hop1.downlink_port is not None
    assert hop1.downlink_port.port_name == "Gi1/0/1"
    assert hop1.downlink_port.is_downlink is True
    assert hop1.downlink_port.neighbor_name == "Local-Host"

    hop2 = result.hops[1]
    assert hop2.hostname == "Core-SW1"
    assert hop2.is_stp_root is True
    assert hop2.default_gateway == fw_ip
    assert hop2.downlink_port is not None
    assert hop2.downlink_port.port_name == "Gi0/24"
    assert hop2.downlink_port.is_downlink is True
    assert hop2.downlink_port.neighbor_ip == access_ip
    assert hop2.downlink_port.neighbor_name == "Access-SW2"


def test_walker_switch_hop_downlink_identification():
    """Verify that multi-hop switch walker accurately determines uplink and downlink on every hop."""
    access_ip = "10.0.0.3"
    core_ip = "10.0.0.2"

    device_mibs = {
        access_ip: {
            OID_SYS_DESCR: "Cisco Catalyst 2960L",
            OID_SYS_NAME: "Access-SW2",
            OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("aabbcc001122"),
            OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000001a2b3c4d5e"),
            OID_DOT1D_STP_ROOT_PORT: 24,
            f"{OID_DOT1D_BASE_PORT_IFINDEX}.1": 1,
            f"{OID_DOT1D_STP_PORT_STATE}.1": 5,
            f"{OID_IF_NAME}.1": "Gi1/0/1",
            f"{OID_IF_HIGH_SPEED}.1": 1000,
            f"{OID_DOT1Q_PVID}.1": 200,
            f"{OID_LLDP_REM_SYS_NAME}.0.1.1": "Local-Host",
            f"{OID_LLDP_REM_PORT_ID}.0.1.1": "eth0",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.1.1.1.4.10.0.0.42": 1,
            f"{OID_DOT1D_BASE_PORT_IFINDEX}.24": 24,
            f"{OID_DOT1D_STP_PORT_STATE}.24": 5,
            f"{OID_IF_NAME}.24": "Gi1/0/24",
            f"{OID_IF_HIGH_SPEED}.24": 1000,
            f"{OID_DOT1Q_PVID}.24": 100,
            f"{OID_LLDP_REM_SYS_NAME}.0.24.1": "Core-SW1",
            f"{OID_LLDP_REM_PORT_ID}.0.24.1": "Gi0/24",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.24.1.1.4.10.0.0.2": 1,
        },
        core_ip: {
            OID_SYS_DESCR: "Cisco Catalyst 2960X",
            OID_SYS_NAME: "Core-SW1",
            OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("001a2b3c4d5e"),
            OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000001a2b3c4d5e"),
            OID_DOT1D_STP_ROOT_PORT: 0,
            f"{OID_DOT1D_BASE_PORT_IFINDEX}.24": 24,
            f"{OID_DOT1D_STP_PORT_STATE}.24": 5,
            f"{OID_IF_NAME}.24": "Gi0/24",
            f"{OID_IF_HIGH_SPEED}.24": 1000,
            f"{OID_DOT1Q_PVID}.24": 100,
            f"{OID_LLDP_REM_SYS_NAME}.0.24.1": "Access-SW2",
            f"{OID_LLDP_REM_PORT_ID}.0.24.1": "Gi1/0/24",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.24.1.1.4.10.0.0.3": 1,
        },
    }

    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="public", client_factory=factory)
    result = walker.walk(start_ip=access_ip)

    assert result.success is True
    assert len(result.hops) == 2

    # Hop 1: Access switch
    hop1 = result.hops[0]
    assert hop1.uplink_port is not None
    assert hop1.uplink_port.port_name == "Gi1/0/24"
    assert hop1.uplink_port.is_uplink is True
    assert hop1.downlink_port is not None
    assert hop1.downlink_port.port_name == "Gi1/0/1"
    assert hop1.downlink_port.is_downlink is True
    assert hop1.downlink_port.neighbor_name == "Local-Host"

    # Hop 2: Core switch (downlink faces Access switch hop 1)
    hop2 = result.hops[1]
    assert hop2.downlink_port is not None
    assert hop2.downlink_port.port_name == "Gi0/24"
    assert hop2.downlink_port.is_downlink is True
    assert hop2.downlink_port.neighbor_ip == "10.0.0.3"
    assert hop2.downlink_port.neighbor_name == "Access-SW2"


def test_walker_firewall_edge_snmp_pass():
    """Verify full SNMP pass on edge firewall (interfaces, default route, WAN/LAN mapping)."""
    access_ip = "10.0.0.3"
    core_ip = "10.0.0.2"
    fw_ip = "10.0.0.1"

    device_mibs = {
        access_ip: {
            OID_SYS_DESCR: "Cisco Catalyst 2960L",
            OID_SYS_NAME: "Access-SW2",
            OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("aabbcc001122"),
            OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000001a2b3c4d5e"),
            OID_DOT1D_STP_ROOT_PORT: 24,
            f"{OID_DOT1D_BASE_PORT_IFINDEX}.24": 24,
            f"{OID_DOT1D_STP_PORT_STATE}.24": 5,
            f"{OID_IF_NAME}.24": "Gi1/0/24",
            f"{OID_IF_HIGH_SPEED}.24": 1000,
            f"{OID_DOT1Q_PVID}.24": 100,
            f"{OID_LLDP_REM_SYS_NAME}.0.24.1": "Core-SW1",
            f"{OID_LLDP_REM_PORT_ID}.0.24.1": "Gi0/24",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.24.1.1.4.10.0.0.2": 1,
        },
        core_ip: {
            OID_SYS_DESCR: "Cisco Catalyst 2960X",
            OID_SYS_NAME: "Core-SW1",
            OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("001a2b3c4d5e"),
            OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000000000000001"),  # Firewall is root in STP
            OID_DOT1D_STP_ROOT_PORT: 1,
            f"{OID_DOT1D_BASE_PORT_IFINDEX}.1": 1,
            f"{OID_DOT1D_STP_PORT_STATE}.1": 5,
            f"{OID_IF_NAME}.1": "Gi0/1",
            f"{OID_IF_HIGH_SPEED}.1": 1000,
            f"{OID_DOT1Q_PVID}.1": 100,
            f"{OID_LLDP_REM_SYS_NAME}.0.1.1": "FW-Edge01",
            f"{OID_LLDP_REM_PORT_ID}.0.1.1": "port1",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.1.1.1.4.10.0.0.1": 1,
            f"{OID_DOT1D_BASE_PORT_IFINDEX}.24": 24,
            f"{OID_DOT1D_STP_PORT_STATE}.24": 5,
            f"{OID_IF_NAME}.24": "Gi0/24",
            f"{OID_IF_HIGH_SPEED}.24": 1000,
            f"{OID_DOT1Q_PVID}.24": 100,
            f"{OID_LLDP_REM_SYS_NAME}.0.24.1": "Access-SW2",
            f"{OID_LLDP_REM_PORT_ID}.0.24.1": "Gi1/0/24",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.24.1.1.4.10.0.0.3": 1,
        },
        fw_ip: {
            OID_SYS_DESCR: "FortiGate-60F v7.2.5,build1517,230612 (GA.M)",
            OID_SYS_NAME: "FW-Edge01",
            OID_SYS_OBJECT_ID: "1.3.6.1.4.1.12356.101.1",
            # Interfaces (ifTable / ifXTable)
            f"{OID_IF_NAME}.2": "lan",
            f"{OID_IF_HIGH_SPEED}.2": 1000,
            f"{OID_IF_OPER_STATUS}.2": 1,
            f"{OID_IF_ADMIN_STATUS}.2": 1,
            f"{OID_IF_NAME}.3": "dmz",
            f"{OID_IF_OPER_STATUS}.3": 2,
            f"{OID_IF_ADMIN_STATUS}.3": 2,
            f"{OID_IF_NAME}.5": "wan1",
            f"{OID_IF_HIGH_SPEED}.5": 1000,
            f"{OID_IF_OPER_STATUS}.5": 1,
            f"{OID_IF_ADMIN_STATUS}.5": 1,
            # Default route (0.0.0.0/0 -> ifIndex 5, next hop 203.0.113.1)
            OID_IP_ROUTE_NEXT_HOP_DEFAULT: "203.0.113.1",
            OID_IP_ROUTE_IF_INDEX_DEFAULT: 5,
            # ARP table entry for incoming Core switch (10.0.0.2)
            f"{OID_IP_NET_TO_MEDIA_TABLE}.1.2.10.0.0.2": 2,
            f"{OID_IP_NET_TO_MEDIA_TABLE}.3.2.10.0.0.2": "10.0.0.2",
        },
    }

    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="public", client_factory=factory)
    result = walker.walk(start_ip=access_ip)

    assert result.success is True
    assert len(result.hops) == 3, f"Expected 3 hops, got {len(result.hops)}"

    # Check edge hop (FW-Edge01)
    hop = result.hops[2]
    assert hop.mgmt_ip == fw_ip
    assert hop.hostname == "FW-Edge01"
    assert hop.device_type == "firewall"
    assert hop.status == "router_reached"
    assert result.edge_type == "firewall"

    # WAN interface identification
    assert hop.wan_interface is not None
    assert hop.wan_interface.port_name == "wan1"
    assert hop.wan_interface.link_speed_mbps == 1000
    assert hop.wan_interface.oper_status == "up"
    assert hop.wan_interface.is_uplink is True
    assert hop.isp_gateway == "203.0.113.1"

    # LAN interface identification
    assert hop.lan_interface is not None
    assert hop.lan_interface.port_name == "lan"
    assert hop.lan_interface.is_downlink is True
    assert hop.lan_interface.neighbor_ip == core_ip

    # Full interface list
    assert len(hop.ports) == 3
    port_names = [p.port_name for p in hop.ports]
    assert "wan1" in port_names
    assert "lan" in port_names
    assert "dmz" in port_names

    # Summary
    assert "FW-Edge01" in result.edge_summary
    assert "203.0.113.1" in result.edge_summary
    assert "wan1" in result.edge_summary


def test_walker_firewall_edge_degradation():
    """Verify graceful fallback when firewall refuses or times out on IF/route tables."""
    access_ip = "10.0.0.3"
    fw_ip = "10.0.0.1"

    device_mibs = {
        access_ip: {
            OID_SYS_DESCR: "Cisco Catalyst 2960L",
            OID_SYS_NAME: "Access-SW",
            OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("aabbcc001122"),
            OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000001a2b3c4d5e"),
            OID_DOT1D_STP_ROOT_PORT: 1,
            f"{OID_DOT1D_BASE_PORT_IFINDEX}.1": 1,
            f"{OID_DOT1D_STP_PORT_STATE}.1": 5,
            f"{OID_IF_NAME}.1": "Gi0/1",
            f"{OID_LLDP_REM_SYS_NAME}.0.1.1": "FW-Locked",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.1.1.1.4.10.0.0.1": 1,
        },
        fw_ip: {
            # Answers sysDescr/sysName/sysObjectID, but no IF or route tables
            OID_SYS_DESCR: "FortiGate-100F v7.0.0",
            OID_SYS_NAME: "FW-Locked",
            OID_SYS_OBJECT_ID: "1.3.6.1.4.1.12356.101.1",
        },
    }

    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="public", client_factory=factory)
    result = walker.walk(start_ip=access_ip)

    assert result.success is True
    assert len(result.hops) == 2
    fw_hop = result.hops[1]
    assert fw_hop.mgmt_ip == fw_ip
    assert fw_hop.hostname == "FW-Locked"
    assert fw_hop.device_type == "firewall"
    assert fw_hop.status == "router_reached"
    assert result.edge_type == "firewall"
    assert fw_hop.wan_interface is None
    assert fw_hop.isp_gateway is None
    assert "Edge firewall reached: FW-Locked (10.0.0.1)" in result.edge_summary


def test_walker_unreachable_next_hop():
    """Verify graceful handling when next hop is unreachable."""
    start_ip = "10.0.0.3"
    unreachable_ip = "10.0.0.99"

    device_mibs = {
        start_ip: {
            OID_SYS_DESCR: "Edge Switch",
            OID_SYS_NAME: "Access-SW",
            OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("aabbcc001122"),
            OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000999999999999"),
            OID_DOT1D_STP_ROOT_PORT: 1,
            f"{OID_DOT1D_STP_PORT_STATE}.1": 5,
            f"{OID_IF_NAME}.1": "Gi0/1",
            f"{OID_LLDP_REM_SYS_NAME}.0.1.1": "Dead-Core",
            f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.1.1.1.4.10.0.0.99": 1,
        }
    }

    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="public", client_factory=factory)
    result = walker.walk(start_ip=start_ip)

    assert len(result.hops) == 2
    assert result.hops[0].status == "ok"
    assert result.hops[1].mgmt_ip == unreachable_ip
    assert result.hops[1].status == "timeout"
    assert result.edge_type == "timeout"


def test_classifier():
    """Verify device classification rules."""
    assert classify_device("FortiGate-60F v7.2.5", "FW-01") == "firewall"
    assert classify_device("Palo Alto Networks PA-3220", "pan-gw") == "firewall"
    assert classify_device("Cisco IOS Software, C2960X", "Core-SW1") == "switch"
    assert classify_device("Cisco IOS Software, ISR4331/K9", "Branch-Router") == "router"
    assert classify_device("UniFi Dream Machine Pro Gateway", "UDM-Pro") == "router"
    assert classify_device("UniFi Switch USW-Lite-16-PoE", "USW-Lite-16-PoE") == "switch"
    assert is_edge_device("firewall") is True
    assert is_edge_device("router") is True
    assert is_edge_device("switch") is False


def test_walker_stp_absent_single_lldp_neighbor():
    """Verify that when STP data is absent, a single upstream LLDP neighbor is followed."""
    unifi_ip = "192.168.1.20"
    core_ip = "10.0.0.2"

    unifi_mib = {
        OID_SYS_DESCR: "UniFi Switch USW-Lite-16-PoE, Linux 4.14.222-ui-5.2",
        OID_SYS_NAME: "USW-Lite-16-PoE",
        # NO dot1dStp* OIDs
        f"{OID_IF_NAME}.1": "Port 1",
        f"{OID_LLDP_REM_SYS_NAME}.0.1.1": "Local-Host",
        f"{OID_LLDP_REM_PORT_ID}.0.1.1": "eth0",
        f"{OID_IF_NAME}.16": "Port 16",
        f"{OID_LLDP_REM_SYS_NAME}.0.16.1": "Core-SW1",
        f"{OID_LLDP_REM_PORT_ID}.0.16.1": "Gi0/24",
        f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.16.1.1.4.10.0.0.2": 1,
    }
    core_mib = {
        OID_SYS_DESCR: "Cisco Catalyst 2960X",
        OID_SYS_NAME: "Core-SW1",
        OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("001a2b3c4d5e"),
        OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000001a2b3c4d5e"),
        OID_DOT1D_STP_ROOT_PORT: 0,
        f"{OID_IF_NAME}.24": "Gi0/24",
    }

    device_mibs = {
        unifi_ip: unifi_mib,
        core_ip: core_mib,
    }

    progress_messages = []
    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="public", client_factory=factory)
    result = walker.walk(start_ip=unifi_ip, progress_callback=progress_messages.append)

    assert result.success is True
    assert len(result.hops) == 2
    assert any("STP MIB not available on USW-Lite-16-PoE — using LLDP neighbor direction" in m for m in progress_messages)

    hop1 = result.hops[0]
    assert hop1.hostname == "USW-Lite-16-PoE"
    assert hop1.mgmt_ip == unifi_ip
    assert hop1.is_stp_root is False
    assert hop1.stp_root_port_num is None
    assert hop1.uplink_port is not None
    assert hop1.uplink_port.port_id == 16
    assert hop1.uplink_port.is_uplink is True
    assert hop1.uplink_port.is_root_port is False
    assert hop1.uplink_port.neighbor_ip == core_ip
    assert hop1.uplink_port.neighbor_name == "Core-SW1"
    assert hop1.status == "ok"

    hop2 = result.hops[1]
    assert hop2.hostname == "Core-SW1"
    assert hop2.is_stp_root is True
    assert result.edge_type == "stp_root"


def test_walker_stp_absent_but_base_bridge_present_uses_lldp_fallback():
    """Verify that when dot1dBaseBridgeAddress is present but dot1dStp* are NoSuchObject,
    the walk uses the LLDP fallback rather than dead-ending with 'root port None has no management IP'."""
    unifi_ip = "192.168.1.20"
    core_ip = "10.0.0.2"

    unifi_mib = {
        OID_SYS_DESCR: "UniFi Switch USW-Lite-16-PoE, Linux 4.14.222-ui-5.2",
        OID_SYS_NAME: "USW-Lite-16-PoE",
        # dot1dBaseBridgeAddress IS present (base bridge MIB implemented)
        OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("7483c2112233"),
        # dot1dStp* subtree returns NoSuchObject
        OID_DOT1D_STP_ROOT_BRIDGE: NoSuchObject(),
        OID_DOT1D_STP_ROOT_PORT: NoSuchObject(),
        f"{OID_IF_NAME}.1": "Port 1",
        f"{OID_LLDP_REM_SYS_NAME}.0.1.1": "Local-Host",
        f"{OID_LLDP_REM_PORT_ID}.0.1.1": "eth0",
        f"{OID_IF_NAME}.16": "Port 16",
        f"{OID_LLDP_REM_SYS_NAME}.0.16.1": "Core-SW1",
        f"{OID_LLDP_REM_PORT_ID}.0.16.1": "Gi0/24",
        f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.16.1.1.4.10.0.0.2": 1,
    }
    core_mib = {
        OID_SYS_DESCR: "Cisco Catalyst 2960X",
        OID_SYS_NAME: "Core-SW1",
        OID_DOT1D_BASE_BRIDGE_ADDRESS: bytes.fromhex("001a2b3c4d5e"),
        OID_DOT1D_STP_ROOT_BRIDGE: bytes.fromhex("8000001a2b3c4d5e"),
        OID_DOT1D_STP_ROOT_PORT: 0,
        f"{OID_IF_NAME}.24": "Gi0/24",
    }

    device_mibs = {
        unifi_ip: unifi_mib,
        core_ip: core_mib,
    }

    progress_messages = []
    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="public", client_factory=factory)
    result = walker.walk(start_ip=unifi_ip, progress_callback=progress_messages.append)

    assert result.success is True
    assert len(result.hops) == 2
    assert any("STP MIB not available on USW-Lite-16-PoE — using LLDP neighbor direction" in m for m in progress_messages)

    hop1 = result.hops[0]
    assert hop1.hostname == "USW-Lite-16-PoE"
    assert hop1.mgmt_ip == unifi_ip
    assert hop1.is_stp_root is False
    assert hop1.stp_bridge_id == "74:83:c2:11:22:33"
    assert hop1.stp_root_port_num is None
    assert hop1.uplink_port is not None
    assert hop1.uplink_port.port_id == 16
    assert hop1.uplink_port.is_uplink is True
    assert hop1.uplink_port.is_root_port is False
    assert hop1.uplink_port.neighbor_ip == core_ip
    assert hop1.uplink_port.neighbor_name == "Core-SW1"
    assert hop1.status == "ok"

    hop2 = result.hops[1]
    assert hop2.hostname == "Core-SW1"
    assert hop2.is_stp_root is True
    assert result.edge_type == "stp_root"
    assert "root port None has no management IP" not in result.edge_summary


def test_walker_stp_absent_zero_lldp_neighbors_edge_stop():
    """Verify that when STP data is absent and no LLDP upstream neighbor exists, walk stops cleanly as no_upstream."""
    unifi_ip = "192.168.1.20"

    unifi_mib = {
        OID_SYS_DESCR: "UniFi Switch USW-Lite-16-PoE, Linux 4.14.222-ui-5.2",
        OID_SYS_NAME: "USW-Lite-16-PoE",
        # NO dot1dStp* OIDs, only downlink to host without IP
        f"{OID_IF_NAME}.1": "Port 1",
        f"{OID_LLDP_REM_SYS_NAME}.0.1.1": "Local-Host",
        f"{OID_LLDP_REM_PORT_ID}.0.1.1": "eth0",
    }

    device_mibs = {unifi_ip: unifi_mib}
    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="public", client_factory=factory)
    result = walker.walk(start_ip=unifi_ip)

    assert result.success is True
    assert len(result.hops) == 1
    hop = result.hops[0]
    assert hop.hostname == "USW-Lite-16-PoE"
    assert hop.status == "no_upstream"
    assert hop.is_stp_root is False
    assert hop.uplink_port is None
    assert result.edge_type == "no_upstream"
    assert "No upstream neighbor visible from USW-Lite-16-PoE (192.168.1.20) via LLDP — this switch appears to be the network edge." in result.edge_summary
    assert "root port None has no management IP" not in result.edge_summary


def test_walker_stp_absent_multiple_lldp_neighbors_ambiguous():
    """Verify that when STP data is absent and multiple LLDP candidate uplinks exist, walk stops gracefully as ambiguous."""
    unifi_ip = "192.168.1.20"

    unifi_mib = {
        OID_SYS_DESCR: "UniFi Switch USW-Lite-16-PoE, Linux 4.14.222-ui-5.2",
        OID_SYS_NAME: "USW-Lite-16-PoE",
        # Downlink to host
        f"{OID_IF_NAME}.1": "Port 1",
        f"{OID_LLDP_REM_SYS_NAME}.0.1.1": "Local-Host",
        f"{OID_LLDP_REM_PORT_ID}.0.1.1": "eth0",
        # Uplink candidate 1
        f"{OID_IF_NAME}.15": "Port 15",
        f"{OID_LLDP_REM_SYS_NAME}.0.15.1": "SW-A",
        f"{OID_LLDP_REM_PORT_ID}.0.15.1": "Gi0/1",
        f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.15.1.1.4.10.0.0.10": 1,
        # Uplink candidate 2
        f"{OID_IF_NAME}.16": "Port 16",
        f"{OID_LLDP_REM_SYS_NAME}.0.16.1": "SW-B",
        f"{OID_LLDP_REM_PORT_ID}.0.16.1": "Gi0/2",
        f"{OID_LLDP_REM_MAN_ADDR_TABLE}.3.0.16.1.1.4.10.0.0.20": 1,
    }

    device_mibs = {
        unifi_ip: unifi_mib,
        "10.0.0.10": {OID_SYS_DESCR: "Switch A", OID_SYS_NAME: "SW-A"},
        "10.0.0.20": {OID_SYS_DESCR: "Switch B", OID_SYS_NAME: "SW-B"},
    }

    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="public", client_factory=factory)
    result = walker.walk(start_ip=unifi_ip)

    assert result.success is False
    assert len(result.hops) == 1
    hop = result.hops[0]
    assert hop.hostname == "USW-Lite-16-PoE"
    assert hop.status == "ambiguous"
    assert hop.uplink_port is None
    assert result.edge_type == "ambiguous"
    assert "multiple upstream LLDP candidate neighbors" in result.edge_summary
    assert "SW-A" in result.edge_summary
    assert "10.0.0.10" in result.edge_summary
    assert "SW-B" in result.edge_summary
    assert "10.0.0.20" in result.edge_summary


def test_walker_stp_absent_single_edge_router_neighbor():
    """Verify that when STP is absent and single LLDP neighbor is a router/firewall, walk continues and terminates as edge."""
    from linksight.discovery.demo import UNIFI_DEMO_MIB_WITH_UPSTREAM, UNIFI_GATEWAY_DEMO_MIB

    unifi_ip = "192.168.1.20"
    gateway_ip = "192.168.1.1"

    device_mibs = {
        unifi_ip: UNIFI_DEMO_MIB_WITH_UPSTREAM,
        gateway_ip: UNIFI_GATEWAY_DEMO_MIB,
    }

    factory = make_mock_client_factory(device_mibs)
    walker = UpstreamWalker(community="public", client_factory=factory)
    result = walker.walk(start_ip=unifi_ip)

    assert result.success is True
    assert len(result.hops) == 2
    assert result.edge_type == "router"

    hop1 = result.hops[0]
    assert hop1.hostname == "USW-Lite-16-PoE"
    assert hop1.uplink_port is not None
    assert hop1.uplink_port.neighbor_ip == gateway_ip
    assert hop1.uplink_port.is_root_port is False
    assert hop1.uplink_port.is_uplink is True

    hop2 = result.hops[1]
    assert hop2.hostname == "UDM-Pro"
    assert hop2.device_type == "router"
    assert hop2.status == "router_reached"
    assert hop2.wan_interface is not None
    assert hop2.wan_interface.port_name == "wan1"
    assert hop2.isp_gateway == "198.51.100.1"
    assert "Edge router reached: UDM-Pro" in result.edge_summary
    assert "198.51.100.1" in result.edge_summary
