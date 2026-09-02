"""Demo replay mode — feeds realistic LLDP/CDP frames on a timer.

Lets you see the full UI live without a switch: when LinkSight can't capture
(e.g. running in an unprivileged container), run with --demo and it simulates a small
network appearing over time.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from ..parse.model import NeighborDevice
from ..parse.frames import parse_frame
from ..parse.dhcp import parse_dhcp, MSG_OFFER, MSG_ACK, MSG_DISCOVER
from ..parse.builders import build_lldp_frame, build_cdp_frame, build_dhcp_frame

# A plausible little network: core switch, access switch, AP, printer, phone.
SCENARIO: list[tuple[str, bytes]] = [
    # (interface label, frame bytes)
    ("eth0", build_lldp_frame(
        chassis_mac="00:1a:2b:3c:4d:5e", system_name="Core-SW1",
        system_desc="Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E",
        port_id="Gi0/24", mgmt_ip="10.0.0.2", vlan=100)),
    ("eth0", build_cdp_frame(
        device_id="Core-SW1", port_id="Gi0/24", platform="cisco WS-C2960X-24TS-L",
        software="Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E",
        mgmt_ip="10.0.0.2", vlan=100)),
    ("eth0", build_lldp_frame(
        chassis_mac="aa:bb:cc:00:11:22", system_name="Access-SW2",
        system_desc="Cisco IOS Software, C2960L Software (C2960L-UNIVERSALK9-M), Version 15.2(7)E",
        port_id="Gi1/0/1", mgmt_ip="10.0.0.3", vlan=200)),
    ("eth0", build_lldp_frame(
        chassis_mac="02:00:00:00:00:64", system_name="lab-ap-2",
        system_desc="Ubiquiti UAP-AC-PRO", port_id="eth0", mgmt_ip="10.0.0.65", vlan=100)),
    ("eth0", build_lldp_frame(
        chassis_mac="00:24:9b:12:34:56", system_name="HPLaserJet-4350",
        system_desc="HP LaserJet 4350, firmware 08.110.3", port_id="wired", mgmt_ip="10.0.0.20", vlan=100)),
    ("eth0", build_cdp_frame(
        device_id="Cisco-IP-Phone-7942", port_id="Port 1", platform="Cisco IP Phone 7942",
        software="SCCP42.8-4-3S", mgmt_ip="10.0.0.50", vlan=100, caps=0x80)),
    ("eth0", build_lldp_frame(
        chassis_mac="74:83:c2:11:22:33", system_name="USW-Lite-16-PoE",
        system_desc="UniFi Switch Lite 16 PoE, 6.5.59.14777", port_id="Port 1",
        mgmt_ip="", vlan=1)),
    # DHCP transaction from a client on the wire (observed passively)
    ("eth0", build_dhcp_frame(
        message_type=MSG_DISCOVER, offered_ip="0.0.0.0", server_ip="0.0.0.0")),
    ("eth0", build_dhcp_frame(
        message_type=MSG_OFFER, offered_ip="10.0.0.42", server_ip="10.0.0.1",
        subnet_mask="255.255.255.0", gateways=["10.0.0.1"],
        dns_servers=["8.8.8.8", "1.1.1.1"], lease_seconds=86400,
        domain="example.lan")),
    ("eth0", build_dhcp_frame(
        message_type=MSG_ACK, offered_ip="10.0.0.42", server_ip="10.0.0.1",
        subnet_mask="255.255.255.0", gateways=["10.0.0.1"],
        dns_servers=["8.8.8.8", "1.1.1.1"], lease_seconds=86400,
        domain="example.lan")),
]


class DemoSource:
    """Emits scenario frames on a timer, one every N seconds, cycling."""

    def __init__(self, on_device: Callable[[NeighborDevice], None],
                 on_dhcp: Callable[[object], None] | None = None,
                 interval: float = 3.0):
        self.on_device = on_device
        self.on_dhcp = on_dhcp
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._idx = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="linksight-demo", daemon=True)
        self._thread.start()


    def stop(self) -> None:
        self._stop.set()

    def wait(self, timeout: float | None = 1.0) -> None:
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _run(self) -> None:
        while not self._stop.is_set():
            label, frame = SCENARIO[self._idx % len(SCENARIO)]
            if frame[12:14] == b"\x08\x00" and self.on_dhcp is not None:
                # DHCP frame: parse and emit directly
                src_ip = ".".join(str(b) for b in frame[14 + 12 : 14 + 16])
                payload = frame[14 + 20 + 8 :]
                obs = parse_dhcp(payload, src_ip=src_ip)
                if obs is not None:
                    self.on_dhcp(obs, frame)
            else:
                dev = parse_frame(frame, label)
                if dev is not None:
                    self.on_device(dev, frame)
            self._idx += 1
            self._stop.wait(self.interval)
