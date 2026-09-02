# Vendor-Agnostic Data-Acquisition Audit
**LinkSight Upstream Discovery Engine**  
*Document Revision: 1.0 (Audit & Hardening)*  
*Target Branch: feature/upstream-discovery*  

---

## 1. Executive Summary & Audit Context

MSP field engineers deploy LinkSight across highly heterogeneous client networks comprising diverse switching and routing hardware: Cisco (IOS, IOS-XE, NX-OS), Aruba/HPE (ProCurve, ArubaOS-Switch, ArubaOS-CX), Ubiquiti UniFi, Netgear ProSAFE, MikroTik (RouterOS, SwOS), Fortinet FortiSwitch, SMB generic smart switches, and Linux bridges/hypervisors.

Prior field testing uncovered three distinct Cisco-shaped assumptions in earlier iterations of the discovery engine, each manifesting as a failure on Ubiquiti UniFi switches:
1. **LLDP Management Address TLV Assumed Present:** UniFi switches advertise chassis MACs but frequently omit the Management Address TLV (TLV 8). This broke starting-switch IP identification until resolved via ARP sweep against the chassis MAC.
2. **BRIDGE-MIB STP Subtree Assumed Present:** Direction logic relied unconditionally on `dot1dStp` root port and bridge IDs. UniFi (and Linux bridges) omit or disable the classic 802.1D BRIDGE-MIB subtree, leading to premature termination until fallback LLDP candidate direction and mesh root-distrust heuristics were introduced.
3. **LLDP Remote Neighbors Assumed to Advertise IPs:** Candidate uplink filtering discarded any neighbor missing an advertised IP, silently dropping UniFi upstream switches until unaddressed candidates were preserved for on-demand resolution.

This audit establishes an exhaustive inventory of all SNMP OIDs and LLDP/CDP TLVs utilized by LinkSight, catalogs vendor-class anomalies across nine switch families, details technical hardening applied to eliminate remaining single-vendor assumptions, and documents intentional architectural boundaries.

---

## 2. Complete OID & TLV Source Inventory

The following table itemizes every data item requested by LinkSight, its MIB/TLV source, its discovery role, observed vendor omissions or variations, fallback wiring status, and associated risk level.

| Data Item | OID / TLV Source | Purpose in LinkSight | Vendor Classes that Omit or Alter It | Fallback Wired? | Risk Level |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **System Description** | `1.3.6.1.2.1.1.1.0`<br>(SNMPv2-MIB `sysDescr`) | Device classification (switch vs router vs firewall vs AP) | Rarely omitted; SMB switches return brief strings; some foreign firmware uses non-ASCII bytes | **Yes**: Falls back to `sysName` or MIB structure heuristics (STP/LLDP presence) | **Low** |
| **System Object ID** | `1.3.6.1.2.1.1.2.0`<br>(SNMPv2-MIB `sysObjectID`) | Enterprise OID vendor classification | Whitebox switches return generic `enterprises.0`; Netgear SMB may return net-snmp OIDs | **Yes**: Falls back to regex matching on `sysDescr` and `sysName` | **Low** |
| **System Name** | `1.3.6.1.2.1.1.5.0`<br>(SNMPv2-MIB `sysName`) | Switch hostname display and hop labeling | Unconfigured switches return empty string or IP address | **Yes**: Falls back to target management IP address | **Low** |
| **Base Bridge Address** | `1.3.6.1.2.1.17.1.1.0`<br>(BRIDGE-MIB `dot1dBaseBridgeAddress`) | Switch bridge MAC address for STP root comparisons and loop detection | Absent on pure L3 switches, FortiGate switch-controllers without bridge MIB, and some UniFi firmwares | **Yes**: Falls back to LLDP chassis MAC or ARP table cache | **Medium** |
| **STP Root Bridge ID** | `1.3.6.1.2.1.17.2.5.0`<br>(BRIDGE-MIB `dot1dStpRootBridge`) | Identifying the Spanning Tree root bridge (hop termination) | Omitted on switches with STP disabled, RSTP/MSTP-only implementations omitting classic dot1d, UniFi, Linux bridges | **Yes**: Falls back to LLDP/CDP neighbor candidate direction | **High** |
| **STP Root Port** | `1.3.6.1.2.1.17.2.7.0`<br>(BRIDGE-MIB `dot1dStpRootPort`) | Primary upstream egress direction rule | Omitted when STP is off or when switch is root (returns 0); absent on UniFi and SMB switches | **Yes**: Falls back to LLDP candidate uplinks with mesh distrust verification | **High** |
| **STP Port State** | `1.3.6.1.2.1.17.2.15.1.3`<br>(BRIDGE-MIB `dot1dStpPortState`) | Port forwarding/blocking status | Omitted when STP disabled or in MSTP mode without classic MIB mapping | **Yes**: Defaults to `"forwarding"` if switch is STP root, else `"unknown"` | **Medium** |
| **Bridge Port to ifIndex Map** | `1.3.6.1.2.1.17.1.4.1.2`<br>(BRIDGE-MIB `dot1dBasePortIfIndex`) | Translating bridge port numbers to IF-MIB `ifIndex` | Sparse or completely absent on SMB switches (Netgear Plus, MikroTik SwOS, Linux bridge) | **Yes**: Assumes identity map (`dot1dBasePort == ifIndex`); includes `ifName`/`ifSpeed` keys | **Medium** |
| **Interface Name** | `1.3.6.1.2.1.31.1.1.1.1`<br>(IF-MIB `ifName`) | Human-readable port labels (e.g. `Gi1/0/1`) | Absent on older SNMPv1/v2 agents | **Yes**: Falls back to `ifDescr` (`1.3.6.1.2.1.2.2.1.2`), then `"Port {n}"` | **Low** |
| **Interface Description** | `1.3.6.1.2.1.2.2.1.2`<br>(IF-MIB `ifDescr`) | Secondary port label and edge device discovery | Universally supported across standard MIB-II implementations | **Yes**: Used as fallback for `ifName` | **Low** |
| **Interface High Speed** | `1.3.6.1.2.1.31.1.1.1.15`<br>(IF-MIB `ifHighSpeed`) | Port speed in Mbps (Gauge32, 64-bit friendly) | Absent on older switches, 100M-only devices, and some SMB models | **Yes**: Falls back to `ifSpeed` with clamp rejection and SMB direct-Mbps handling | **Medium** |
| **Interface Speed (32-bit)** | `1.3.6.1.2.1.2.2.1.5`<br>(IF-MIB `ifSpeed`) | Legacy port speed in bits/sec | Wraps or clamps to `4294967295` on >=10G interfaces; SMB smart switches report direct Mbps (<1,000,000) | **Yes**: Evaluated via `_parse_if_speed` helper (clamp ignored, SMB quirk detected) | **Medium** |
| **Interface Oper Status** | `1.3.6.1.2.1.2.2.1.8`<br>(IF-MIB `ifOperStatus`) | Link state (up/down/testing) on edge gateways | Universally supported across standard MIB-II implementations | **Yes**: Maps to integer status 1..7 | **Low** |
| **Interface Admin Status** | `1.3.6.1.2.1.2.2.1.7`<br>(IF-MIB `ifAdminStatus`) | Administrative state on edge gateways | Universally supported across standard MIB-II implementations | **Yes**: Maps to integer status 1..3 | **Low** |
| **Default Port VLAN ID (PVID)** | `1.3.6.1.2.1.17.7.1.4.5.1.1`<br>(Q-BRIDGE-MIB `dot1qPvid`) | Access/native VLAN on switch ports | ArubaOS-Switch/ProCurve reports `0` on hybrid/tagged trunks; Linux bridge omits; SMB switches omit | **Yes**: `pvid <= 0` converted to `None`; falls back to first untagged VLAN | **High** |
| **Static VLAN Egress Ports** | `1.3.6.1.2.1.17.7.1.4.3.1.2`<br>(Q-BRIDGE-MIB static egress) | Configured VLAN membership bitmask | ArubaOS-Switch / ProCurve omits static table; UniFi omits static tables; dynamic VLAN switches omit | **Yes**: Falls back to `dot1qVlanCurrentEgressPorts` operational table | **Medium** |
| **Current VLAN Egress Ports** | `1.3.6.1.2.1.17.7.1.4.2.1.4`<br>(Q-BRIDGE-MIB current egress) | Operational active VLAN membership bitmask | Netgear SMB and unmanaged switches omit entire Q-BRIDGE-MIB | **Yes**: Combines with static egress table; falls back to PVID | **Medium** |
| **Static Untagged Ports** | `1.3.6.1.2.1.17.7.1.4.3.1.4`<br>(Q-BRIDGE-MIB static untagged) | Untagged VLAN egress membership | Omitted on ArubaOS-Switch, UniFi, and simple L2 smart switches | **Yes**: Falls back to current untagged table, then PVID | **Medium** |
| **Current Untagged Ports** | `1.3.6.1.2.1.17.7.1.4.2.1.5`<br>(Q-BRIDGE-MIB current untagged) | Operational untagged VLAN membership | Omitted on SMB switches without Q-BRIDGE-MIB | **Yes**: Falls back to static untagged table; tagged calculated via set difference | **Medium** |
| **LLDP Remote Chassis ID** | `1.0.8802.1.1.2.1.4.1.1.5`<br>(LLDP-MIB `lldpRemChassisId`) | Identifying neighbor switch chassis | May be encoded as interface name, network address, or locally assigned string instead of MAC | **Yes**: Normalized via `normalize_mac`; labeled as `"Chassis {id}"` if non-MAC | **High** |
| **LLDP Remote Port ID** | `1.0.8802.1.1.2.1.4.1.1.7`<br>(LLDP-MIB `lldpRemPortId`) | Identifying connecting port on neighbor | Format varies (ifName, ifDescr, MAC, agent-circuit-id) | **Yes**: Stored as raw decoded string | **Low** |
| **LLDP Remote System Name** | `1.0.8802.1.1.2.1.4.1.1.9`<br>(LLDP-MIB `lldpRemSysName`) | Neighbor switch hostname display | Often blank on unconfigured access switches or IP phones | **Yes**: Falls back to neighbor chassis ID or port identifier | **Low** |
| **LLDP Remote Mgmt Address** | `1.0.8802.1.1.2.1.4.2.1.3`<br>(LLDP-MIB `lldpRemManAddrTable`) | Management IP for traversing to next hop | Omitted by Ubiquiti UniFi, MikroTik, FortiSwitch in standalone mode, and Linux bridges | **Yes**: ARP sweep from chassis MAC; surfaces as actionable candidate if unresolvable | **Critical** |
| **CDP Cache Device ID** | `1.3.6.1.4.1.9.9.23.1.2.1.1.6`<br>(CISCO-CDP-MIB `cdpCacheDeviceId`) | Cisco neighbor hostname when LLDP disabled | Absent on all non-Cisco equipment (unless CDP compatibility enabled) | **Yes**: Dual-protocol fallback (LLDP + CDP) | **High** |
| **CDP Cache Device Port** | `1.3.6.1.4.1.9.9.23.1.2.1.1.7`<br>(CISCO-CDP-MIB `cdpCacheDevicePort`) | Connecting neighbor port on Cisco switches | Absent on non-Cisco gear | **Yes**: Populates port neighbor diagnostics | **Medium** |
| **CDP Cache Address** | `1.3.6.1.4.1.9.9.23.1.2.1.1.4`<br>(CISCO-CDP-MIB `cdpCacheAddress`) | Neighbor IP on Cisco switches when LLDP off | Raw 4-byte OCTET STRING; absent on non-Cisco gear | **Yes**: Decoded via `_decode_ip_address`; parsed using 2-part index `parts[-2]` | **High** |
| **CDP Cache Platform** | `1.3.6.1.4.1.9.9.23.1.2.1.1.8`<br>(CISCO-CDP-MIB `cdpCachePlatform`) | Neighbor model/platform string | Absent on non-Cisco gear | **Yes**: Stored in port neighbor metadata | **Low** |
| **Default Route Next-Hop** | `1.3.6.1.2.1.4.21.1.7.0.0.0.0`<br>(RFC 1213 `ipRouteNextHop.0.0.0.0`) | L3 gateway IP on core switches & firewalls | Omitted on pure Layer-2 switches | **Yes**: Falls back to full `ipRouteTable` walk; absent on L2 is clean normal state | **Low** |
| **Default Route ifIndex** | `1.3.6.1.2.1.4.21.1.2.0.0.0.0`<br>(RFC 1213 `ipRouteIfIndex.0.0.0.0`) | Outgoing interface for default route | Omitted on pure Layer-2 switches | **Yes**: Falls back to full `ipRouteTable` walk | **Low** |
| **IP Net-To-Media (ARP Table)** | `1.3.6.1.2.1.4.22.1.2`<br>(RFC 1213 `ipNetToMediaPhysAddress`) | Hop 1 downlink port resolution & next-IP MAC lookup | Sparse on pure L2 switches without IP routing enabled | **Yes**: Falls back to FDB table walk and subnet heuristics | **Medium** |
| **FDB Port Table** | `1.3.6.1.2.1.17.4.3.1.2`<br>(BRIDGE-MIB `dot1dTpFdbPort`) | Identifying downlink port to endpoint by client MAC | Absent on routers; enormous on core switches (10,000+ entries) causing timeout | **Yes**: Exact GET tried first; walk capped at 200 rows and 2.0s time bound | **High** |

---

## 3. In-Depth Analysis of the 11 Risk Findings

### Finding 1: `dot1qPvid` Reported as 0 or Omitted on Hybrid/Tagged Ports
- **Real-World Behavior:** Under IEEE 802.1Q, VLAN ID 0 is reserved (priority-tagged frame without VLAN identification). ArubaOS-Switch/ProCurve (e.g. 2530, 2920, 2930F) reports `dot1qPvid == 0` for ports configured with tagged VLANs only or hybrid trunks without a native VLAN. Linux bridges and SMB switches often omit the OID entirely. Treating `0` as an active VLAN results in corrupt diagnostics (`VLAN 0 (Tagged)`).
- **Resolution Applied:** 
  - `walker.py`: Filtered out non-positive values when walking `OID_DOT1Q_PVID` (`val > 0`).
  - `walker.py`: In port assembly, `p_pvid <= 0` is normalized to `None`. In `p_allowed` calculations, `p_pvid` is only included if `p_pvid > 0`.
  - `models.py`: Hardened `PortDiagnostics.effective_pvid` to require `self.pvid is not None and self.pvid > 0`, falling back to `untagged_vlans[0]` if valid.

### Finding 2: LLDP `chassis_id` Not Being a MAC Address
- **Real-World Behavior:** IEEE 802.1AB defines seven chassis ID subtypes (1: Chassis Component, 2: Interface Alias, 3: Port Component, 4: MAC Address, 5: Network Address, 6: Interface Name, 7: Locally Assigned). Cisco switches advertise subtype 4 (MAC). However, Linux hosts, virtualization hypervisors, and routers often advertise subtype 6 or 7 (e.g. `b"eth0"` or `b"core-router-chassis"`). Passing a non-MAC chassis ID to hex-colon MAC formatters produces malformed strings like `63:6f:72:65:2d:72`. Attempting ARP resolution against a non-MAC chassis ID generates invalid ARP broadcasts.
- **Resolution Applied:**
  - `arp_resolve.py`: Enhanced `normalize_mac()` to strictly validate input length and hex characters. If length is not 12 hex chars (or 6 raw bytes), returns `None`.
  - `arp_resolve.py`: In `resolve_switch_mgmt_ip()`, added explicit check rejecting devices with `chassis_id_type is not None and chassis_id_type != 4`.
  - `walker.py`: In candidate uplink formatting, tested `normalize_mac(p.neighbor_chassis)`. If valid MAC, formatted as `MAC {chassis}`; otherwise formatted honestly as `Chassis {chassis}`.

### Finding 3: `dot1dBasePortIfIndex` Sparse or Absent
- **Real-World Behavior:** BRIDGE-MIB specifies `dot1dBasePortIfIndex` (`1.3.6.1.2.1.17.1.4.1.2`) to map bridge port numbers (1, 2, 3...) to MIB-II `ifIndex` values (which on chassis switches may be 10101, 10102...). On many SMB switches (Netgear ProSAFE Plus, TP-Link, MikroTik SwOS) and Linux bridges, this mapping table is omitted. Previous LinkSight code assembled ports strictly from `port_ifindex_map.keys()` and VLAN tables; when both were absent, the port list was completely empty.
- **Resolution Applied:**
  - `walker.py`: Hardened `all_port_ids` assembly. When `port_ifindex_map` is empty, `all_port_ids` automatically populates from `set(if_names.keys()) | set(if_speeds.keys())`.
  - `walker.py`: `inverse_ifindex_map` safely maps reverse lookups, ensuring port neighbors keyed by either bridge port or `ifIndex` match successfully.

### Finding 4: `ifHighSpeed` Absent but `ifSpeed` Present (>4Gbps Wraps, 32-bit Clamps, SMB Quirks)
- **Real-World Behavior:** RFC 2863 specifies `ifHighSpeed` in units of 1,000,000 bits/second (Mbps) as a 32-bit Gauge32. `ifSpeed` represents speed in bits/second as a 32-bit Gauge32. For speeds > 4.294 Gbps (e.g. 10Gbps, 40Gbps, 100Gbps), `ifSpeed` cannot represent the value and RFC 2863 requires it to clamp at `4294967295`. Simply dividing `4294967295 // 1_000_000` reports `4294 Mbps` (~4.3 Gbps) on a 10G port. Furthermore, some SMB switches (Netgear Plus, older Zyxel) report `ifSpeed` directly in Mbps (e.g. `1000` for 1 Gbps).
- **Resolution Applied:**
  - `walker.py`: Introduced dedicated `_parse_if_speed(val: Any) -> int | None`:
    - Rejects non-integers, booleans, and values `<= 0`.
    - Rejects `4294967295` (RFC 2863 32-bit gauge clamp).
    - If `val >= 1_000_000`: divides by `1_000_000` (bits/sec -> Mbps).
    - If `0 < val < 1_000_000`: treats as direct Mbps (SMB vendor quirk).
  - Applied uniformly across edge device interface sweeps and switch hop diagnostics.

### Finding 5: SNMP v1-Only Devices
- **Real-World Behavior:** Legacy industrial switches, older PDU/UPS network cards, and minimal embedded devices only implement SNMPv1 (RFC 1157). SNMPv1 uses different PDU framing (no `GetBulkRequest`, different error status definitions) and does not support 64-bit counters (`Counter64`). LinkSight's `SnmpClient` is built on SNMPv2c framing.
- **Status & Rationale:** **Skipped (Out of scope).** Supporting SNMPv1 requires protocol ASN.1 packet framing rewrites, which is out of scope for the vendor-agnostic data-acquisition hardening audit. LinkSight returns clear, actionable error summaries (`"SNMP request timed out (verify reachability, community string, or SNMPv2c enablement)"`) when connecting to v1-only devices. Recommend separate task if v1 support is mandated.

### Finding 6: Community String Differences Per Device
- **Real-World Behavior:** In MSP environments, access switches, distribution switches, and core firewalls may be maintained under differing administrative domains with distinct SNMP community strings (e.g. `client-access-ro`, `client-core-ro`). LinkSight's `UpstreamWalker` initiates walks using a single global `community` string parameter.
- **Resolution Applied:**
  - `snmp_client.py`: Added detection for SNMP `authorizationError` (error-status 16). Raises specific `SnmpAuthError`.
  - `walker.py`: Catches `SnmpAuthError` (and error string matching). Immediately records `Hop(status="auth_failed")` and sets `edge_type = "auth_failed"` with clear diagnostic summary: `"Walk stopped at hop {n} ({ip}): SNMP authentication failed (invalid community string)."`.
  - UI preserves the discovered chain up to the failed hop without discarding prior hops.

### Finding 7: IP Route Table: 0.0.0.0 Default Route Missing on Pure Layer-2 Switches
- **Real-World Behavior:** Pure Layer-2 access switches (e.g. Cisco Catalyst 2960 in L2 mode, UniFi USW, Aruba 2530) do not run routing protocols and often return an empty `ipRouteTable`. Searching for `OID_IP_ROUTE_NEXT_HOP_DEFAULT` (`1.3.6.1.2.1.4.21.1.7.0.0.0.0`) returns `noSuchName` or `NoSuchObject`.
- **Resolution Applied:**
  - `snmp_client.py`: Multi-get and single-get return `None` on missing route OIDs rather than raising.
  - `walker.py`: Evaluates `_decode_ip_address(gw_val)`. If `0.0.0.0` or missing, `default_gw` remains `None`.
  - Direction logic correctly continues upstream traversal via Spanning Tree or LLDP neighbor candidates; absence of a default route on a Layer-2 switch is treated as normal operational state.

### Finding 8: LLDP Disabled Globally but CDP Enabled (or Vice-Versa)
- **Real-World Behavior:** In Cisco environments, LLDP is disabled by default on older IOS releases (`no lldp run`), while CDP (`cdp run`) is universally enabled. Conversely, in non-Cisco networks, CDP is absent and LLDP is primary. If LinkSight only checked LLDP, Cisco switches with LLDP disabled appeared as dead-ends. Furthermore, previous LinkSight code suffered from a critical indexing bug: `CISCO-CDP-MIB` `cdpCacheTable` is indexed by `(cdpCacheIfIndex, cdpCacheDeviceIndex)`. LinkSight previously parsed `parts[-1]`, mapping all CDP neighbors to port 1 regardless of actual port. Additionally, CDP IP addresses were stored as unparsed raw 4-byte ASCII strings (`"\n\x00\x00\x01"`).
- **Resolution Applied:**
  - `walker.py`: Fixed CDP index parsing to extract `cdpCacheIfIndex` from `parts[-2]`.
  - `walker.py`: Integrated `_decode_ip_address()` to decode the 4-byte binary octets into dotted-decimal IPv4 strings.
  - `walker.py`: Wired `OID_CDP_CACHE_PLATFORM` into neighbor metadata.
  - `walker.py`: CDP neighbors populate `port_neighbors` and automatically feed `candidate_uplinks` when LLDP is absent, enabling seamless discovery across Cisco-only shops.

### Finding 9: FDB (`dot1dTpFdbTable`) Extremely Large on Core Switch
- **Real-World Behavior:** Core switches, distribution aggregates, and datacenter gateways maintain Forwarding Database (FDB) tables with 5,000 to 50,000+ MAC addresses. On Hop 1, when an endpoint is LLDP-silent, LinkSight attempts to identify the downlink port via `dot1dTpFdbTable` (`1.3.6.1.2.1.17.4.3.1.2`). A sequential SNMP walk of 10,000 entries across high-latency WAN links would take several minutes and hang the UI.
- **Resolution Applied:**
  - `walker.py`: Optimized exact OID GET first: queries `dot1dTpFdbPort.{mac_octets}` directly (single round-trip).
  - `walker.py`: If exact GET is unsupported by the agent, the sequential walk fallback is strictly capped: `max_rows=200` and a hard time bound of `2.0 seconds` (`(time.perf_counter() - fdb_start) > 2.0`). If the endpoint is not located within bounds, the walk aborts gracefully without freezing the application.

### Finding 10: `sysDescr` / `sysName` Empty or Foreign Language / Non-UTF8 Encoding
- **Real-World Behavior:** Legacy Asian or European firmware may encode `sysDescr` or `sysName` using Latin-1, EUC-JP, or GBK encodings, or return raw control bytes. Some whitebox devices return empty strings.
- **Resolution Applied:**
  - `snmp_client.py`: Added fallback decoding in `decode_value()`: tries `utf-8`, then `latin-1` with replacement characters, never raising `UnicodeDecodeError`.
  - `classifier.py`: Added empty string safety; accepts optional MIB presence flags (`has_bridge_or_stp`, `has_lldp_cdp`). If strings are uninformative or empty, classifies as `"switch"` if bridge/LLDP MIBs exist, else `"unknown"` (never crashes).
  - `walker.py`: Uses `sys_name or curr_ip` across all summaries and UI representations.

### Finding 11: WALK Returns Partial Data (Device Errors Mid-Table)
- **Real-World Behavior:** Faulty SNMP agent implementations (e.g. older SMB switches, overwhelmed CPU) may return an error PDU (e.g. `genErr`, `tooBig`, or TCP/UDP reset) in the middle of walking an interface or VLAN table after successfully returning the first N rows. Standard SNMP client implementations throw an unhandled exception and discard all previously gathered rows.
- **Resolution Applied:**
  - `snmp_client.py`: In `SnmpClient.walk()`, the iterative `get_next` loop is wrapped in a `try...except SnmpError` block. If an error or gap occurs mid-table, the loop logs a debug warning and breaks cleanly, returning all valid rows collected up to the failure point.

---

## 4. Dead OID Analysis

During the audit, all OID constants declared in `walker.py` were cross-referenced against the discovery logic:

1. **`OID_DOT1D_STP_ROOT_COST` (`1.3.6.1.2.1.17.2.6.0`):**
   - **Status:** **Dead constant.**
   - **Audit Finding:** Declared in `walker.py` header, but never queried or referenced in any function or test. Spanning Tree path cost is not utilized in LinkSight's hop traversal rules (which prioritize root bridge identity, root port number, and LLDP candidate verification). Kept for documentation reference; marked as unused.
2. **`OID_CDP_CACHE_PLATFORM` (`1.3.6.1.4.1.9.9.23.1.2.1.1.8`):**
   - **Status:** **Previously dead, now wired.**
   - **Audit Finding:** Declared in `walker.py` header, but never polled. Now actively queried during the CDP fallback walk and attached to port neighbor metadata to aid field engineers in identifying upstream Cisco hardware models.
3. **`OID_IF_DESCR` (`1.3.6.1.2.1.2.2.1.2`):**
   - **Status:** **Active.**
   - **Audit Finding:** Actively queried in edge device discovery to record interface names, and queried as a fallback on switches where `ifName` is absent.
4. **`OID_IP_ADDR_TABLE_NET_MASK` (`1.3.6.1.2.1.4.20.1.3`):**
   - **Status:** **Active.**
   - **Audit Finding:** Actively queried during edge device discovery to match interface subnets against LAN addresses.

---

## 5. Architectural Boundary: ARP Sweeps Across Different Subnets

### The Physical Constraint
LinkSight implements an automated ARP sweep (`arp_resolve.py`) to discover the management IP of switches that advertise a chassis MAC via LLDP but omit the Management Address TLV (notably Ubiquiti UniFi switches).

Field engineers must understand the physical networking boundary of ARP:
- **ARP operates strictly at OSI Layer 2 (Broadcast Domain).**
- LinkSight transmits raw ARP requests via `AF_PACKET` socket on the host machine's physical network interface.
- ARP requests **cannot cross a router or routed Layer 3 boundary**.
- Therefore, automated ARP resolution of an upstream switch's chassis MAC can **only succeed if the switch's management interface is on the same Layer 2 VLAN/subnet as the host running LinkSight**.

### Real-World MSP Scenarios:
1. **Host on Access VLAN, Switch Mgmt on Separate Management VLAN (Different Subnet):**
   - The switch does not respond to ARP requests broadcast on the access VLAN.
   - The ARP sweep times out after its bounded duration (default 5.0 seconds).
2. **Hop 2+ Upstream Switches on Separate Subnets:**
   - As LinkSight traverses upstream into distribution and core layers, switches reside on dedicated loopback or routed management subnets.

### LinkSight's Honest Degradation Architecture
Rather than hanging, crashing, or guessing bogus IP addresses, LinkSight handles this limitation honestly and transparently:
1. When an upstream switch is discovered via LLDP with a valid chassis MAC but no management IP, `walker.py` produces an `ambiguous` hop state:
   - `hop.status = "ambiguous"`
   - `hop.ambiguous_candidates = [cand]` (preserving `cand.neighbor_name` and `cand.neighbor_chassis`).
2. In the UI (`MainWindow._on_upstream_ambiguous_selected`), LinkSight attempts ARP resolution once.
3. If ARP resolution returns `None` (because the switch is on an isolated management VLAN), LinkSight displays an explicit, actionable prompt to the field engineer:
   > *"Switch did not advertise a management IP via LLDP/CDP and ARP resolution did not find it (it may be on a different VLAN/subnet). Enter the switch's management IP manually to continue the walk:"*
4. The engineer enters the IP, and `walker.walk(start_ip=..., forced_next_ip=manual_ip)` resumes traversal seamlessly.

---

## 6. Vendor-Class Test Matrix Summary

To guarantee CI catches future vendor regressions, `tests/test_walker.py` incorporates mock fixture test classes covering all major vendor behaviors:

| Vendor Test Class | Tested Characteristics | Verified Behavior & Assertions |
| :--- | :--- | :--- |
| **`cisco_full`** | STP present, root port 0, LLDP mgmt IPs present, dot1q static tables, 10G `ifHighSpeed` | Terminates bounded; identifies L2 STP Root; parses 10000 Mbps; populates static tagged/untagged VLANs |
| **`aruba_procurve`** | STP absent, current-table VLANs only, `dot1qPvid == 0` on trunk, `ifSpeed` only (bps) | Terminates bounded; handles `pvid=0` as `None` (never VLAN 0); parses 1000 Mbps from bits/sec; follows LLDP to core |
| **`unifi_thin`** | STP absent, no LLDP mgmt IP (chassis MAC only), no CDP, sparse IF-MIB | Terminates bounded; never crashes; produces actionable `ambiguous` candidate with normalized MAC |
| **`minimal_generic`** | Non-vendor sysDescr, no STP, no dot1q, no FDB, SMB direct-Mbps `ifSpeed`, text chassis ID | Terminates bounded; classifies as `switch` via LLDP evidence; parses direct Mbps; displays `"Chassis {id}"` |
| **`cisco_cdp_only`** | LLDP disabled globally, CDP active with 2-part index and binary IP, STP absent | Terminates bounded; parses CDP `ifIndex` from `parts[-2]`; decodes binary IP; follows CDP uplink |

All 130 tests in the test suite pass cleanly.
