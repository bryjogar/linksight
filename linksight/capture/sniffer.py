"""Packet sniffing via Scapy, with graceful degradation.

LinkSight only needs LLDP (EtherType 0x88CC) and CDP (dst 01:00:0c:cc:cc:cc)
frames. We use a BPF filter so the kernel drops everything else — cheap even
on busy networks.

Privilege handling:
  - Windows: requires Npcap installed. Scapy raises a clear error; we surface it.
  - macOS: requires BPF access (admin).
  - Linux (container): requires CAP_NET_RAW (cap_add: NET_RAW).
"""

from __future__ import annotations

import threading
from typing import Callable

from ..parse.frames import parse_frame
from ..parse.model import NeighborDevice

BPF_FILTER = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc or udp port 67 or udp port 68"


class SnifferError(Exception):
    """Raised when the capture backend can't start (permissions, missing Npcap)."""


class Sniffer:
    """Runs Scapy sniff in a worker thread. Frames -> callbacks.

    on_device: NeighborDevice parsed from LLDP/CDP frames
    on_dhcp:   DhcpObservation parsed from DHCP OFFER/ACK frames
    """

    def __init__(
        self,
        interface: str,
        on_device: Callable[[NeighborDevice, bytes | None], None],
        on_error: Callable[[str], None] | None = None,
        on_dhcp: Callable[[object, bytes | None], None] | None = None,
    ):
        self.interface = interface
        self.on_device = on_device
        self.on_error = on_error or (lambda msg: print(f"[linksight] {msg}"))
        self.on_dhcp = on_dhcp
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="linksight-sniffer", daemon=True)
        self._thread.start()


    def stop(self) -> None:
        self._stop.set()

    def wait(self, timeout: float | None = 1.0) -> None:
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _run(self) -> None:
        try:
            from scapy.all import sniff
        except ImportError:
            self.on_error("Scapy is not installed. Run: pip install scapy")
            return

        def stop_filter(_pkt) -> bool:
            return self._stop.is_set()

        def handler(pkt) -> None:
            try:
                raw = bytes(pkt)
            except Exception:
                return
            # DHCP is IPv4/UDP on ports 67/68 — extract before LLDP/CDP dispatch
            if self.on_dhcp is not None and len(raw) >= 42 and raw[12:14] == b"\x08\x00":
                try:
                    ihl = (raw[14] & 0x0F) * 4
                    proto = raw[14 + 9]
                    if proto == 17:  # UDP
                        udp_off = 14 + ihl
                        sport = int.from_bytes(raw[udp_off : udp_off + 2], "big")
                        dport = int.from_bytes(raw[udp_off + 2 : udp_off + 4], "big")
                        if sport in (67, 68) or dport in (67, 68):
                            src_ip = ".".join(str(b) for b in raw[14 + 12 : 14 + 16])
                            payload = raw[udp_off + 8 :]
                            from ..parse.dhcp import parse_dhcp

                            obs = parse_dhcp(payload, src_ip=src_ip)
                            if obs is not None:
                                self.on_dhcp(obs, raw)
                except Exception:
                    pass
            dev = parse_frame(raw, self.interface)
            if dev is not None:
                self.on_device(dev, raw)

        try:
            sniff(
                iface=self.interface,
                filter=BPF_FILTER,
                prn=handler,
                stop_filter=stop_filter,
                store=False,
            )
        except PermissionError as e:
            self.on_error(self._permission_message())
        except Exception as e:  # Scapy wraps OS errors in many ways
            msg = str(e).lower()
            if "permission" in msg or "operation not permitted" in msg or "npcap" in msg:
                self.on_error(self._permission_message())
            else:
                self.on_error(f"Capture failed on {self.interface}: {e}")

    @staticmethod
    def _permission_message() -> str:
        return (
            "Packet capture needs privileges this process doesn't have.\n\n"
            "  • Windows: install Npcap (https://npcap.com) and run as Administrator.\n"
            "  • macOS: allow the terminal/application BPF access (System Settings > Privacy & Security).\n"
            "  • Linux: run with CAP_NET_RAW (docker: cap_add: [NET_RAW], or sudo)."
        )
