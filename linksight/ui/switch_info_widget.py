"""Switch info panel — the LLDP/CDP neighbor readout."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QLabel,
                               QGroupBox, QSizePolicy, QHBoxLayout, QPushButton)

from ..capture.oui_lookup import lookup_vendor
from .theme import FG, FG_DIM, FG_FAINT, ACCENT, MONO


def _row(label: str, value: str):
    lbl = QLabel(label)
    lbl.setStyleSheet(f"color: {FG_DIM}; font-weight: 500;")
    val = QLabel(value if value else "—")
    val.setTextInteractionFlags(Qt.TextSelectableByMouse)
    val.setObjectName("mono")
    val.setWordWrap(True)
    if value:
        val.setStyleSheet(f"color: {ACCENT}; font-family: {MONO}; font-weight: 600;")
    else:
        val.setStyleSheet(f"color: {FG_FAINT}; font-family: {MONO};")
    return lbl, val


class SwitchInfoWidget(QWidget):
    ssh_requested = Signal(str)            # management IP the user clicked
    upstream_requested = Signal(str)       # start management IP for upstream walk

    def __init__(self, parent=None):
        super().__init__(parent)
        self.group = QGroupBox("Switch Info")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.group)
        # hug content vertically — no dead space below the rows
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)

        self._current_mgmt_ip: str = ""
        self._mgmt_ip_row_idx: int | None = None

        self.panel_layout = QVBoxLayout(self.group)
        self.panel_layout.setContentsMargins(4, 4, 4, 6)
        self.panel_layout.setSpacing(6)

        self.grid_widget = QWidget()
        self.grid = QGridLayout(self.grid_widget)
        self.grid.setHorizontalSpacing(24)
        self.grid.setVerticalSpacing(2)
        self.grid.setContentsMargins(2, 0, 2, 4)
        self.panel_layout.addWidget(self.grid_widget)

        # Action bar with Upstream Discovery trigger
        action_bar = QHBoxLayout()
        action_bar.setContentsMargins(2, 2, 2, 2)
        self.upstream_btn = QPushButton("Discover Upstream Path")
        self.upstream_btn.setObjectName("tool")
        self.upstream_btn.setToolTip("Walk the LAN switch chain upstream via SNMP towards the STP root / gateway")
        self.upstream_btn.setEnabled(False)
        self.upstream_btn.clicked.connect(self._on_upstream_clicked)
        action_bar.addWidget(self.upstream_btn)
        action_bar.addStretch(1)
        self.panel_layout.addLayout(action_bar)

        self.clear()

    def _on_upstream_clicked(self) -> None:
        self.upstream_requested.emit(self._current_mgmt_ip)

    def set_management_ip(self, ip: str) -> None:
        """Update the management IP (e.g. if entered manually by the user)."""
        self._current_mgmt_ip = ip
        if ip:
            self.upstream_btn.setEnabled(True)
            self.upstream_btn.setToolTip(f"Walk upstream switches starting from {ip}")
            self._update_mgmt_ip_row(ip, is_arp=False)
        else:
            self.upstream_btn.setEnabled(True)
            self.upstream_btn.setToolTip(
                "No management IP advertised by switch — click to enter the switch management IP"
            )
            self._update_mgmt_ip_row("", is_arp=False)

    def set_resolved_mgmt_ip(self, ip: str) -> None:
        """Update the management IP with an auto-resolved ARP address."""
        if not ip:
            return
        self._current_mgmt_ip = ip
        self.upstream_btn.setEnabled(True)
        self.upstream_btn.setToolTip(
            f"Walk upstream switches starting from {ip} (auto-resolved via ARP)"
        )
        self._update_mgmt_ip_row(ip, is_arp=True)

    def show_device(self, dev) -> None:
        raw = dev.raw_tlvs or {}
        # Human-readable port: Port Description TLV wins (HP/Aruba style)
        port = raw.get("port_description") or dev.port_id or ""
        vendor = lookup_vendor(dev.chassis_id or "") if dev.chassis_id else ""
        chassis = dev.chassis_id or ""
        if vendor:
            chassis = f"{chassis}  ({vendor})"
        rows = [
            ("Hostname", dev.system_name or ""),
            ("Model / Platform", dev.platform or ""),
            ("System description", dev.system_description or ""),
            ("Switch port", port),
            ("VLAN ID", str(dev.vlan) if dev.vlan is not None else ""),
            ("Mgmt IP address", ", ".join(dev.management_ips)),
            ("Protocol", dev.protocol.upper()),
            ("Chassis ID", chassis),
        ]
        self._render(rows)

        if dev.management_ips:
            # Prefer IPv4 management addresses for the upstream walk (SNMP/ARP
            # are IPv4-first); only fall back to IPv6 when no IPv4 is advertised.
            # Skip IPv6 link-local (fe80::) — unreachable without a zone/scope ID.
            ipv4_ips = [ip for ip in dev.management_ips if ":" not in ip]
            if ipv4_ips:
                self._current_mgmt_ip = ipv4_ips[0]
            else:
                self._current_mgmt_ip = ""
            if self._current_mgmt_ip:
                self.upstream_btn.setEnabled(True)
                self.upstream_btn.setToolTip(f"Walk upstream switches starting from {self._current_mgmt_ip}")
            else:
                self.upstream_btn.setEnabled(True)
                self.upstream_btn.setToolTip(
                    "No IPv4 management IP advertised by switch — click to enter the switch management IP"
                )
        else:
            self._current_mgmt_ip = ""
            self.upstream_btn.setEnabled(True)
            self.upstream_btn.setToolTip(
                "No management IP advertised by switch — click to enter the switch management IP"
            )

    def clear(self) -> None:
        self._current_mgmt_ip = ""
        self._mgmt_ip_row_idx = None
        self.upstream_btn.setEnabled(False)
        self.upstream_btn.setToolTip("No switch detected")
        self._render([
            ("Hostname", ""),
            ("Model / Platform", ""),
            ("System description", ""),
            ("Switch port", ""),
            ("VLAN ID", ""),
            ("Mgmt IP address", ""),
            ("Protocol", ""),
        ])

    def _render(self, rows) -> None:
        self._clear_grid()
        self._mgmt_ip_row_idx = None
        for i, (label, value) in enumerate(rows):
            lbl, val = _row(label, value)
            if label == "Mgmt IP address":
                self._mgmt_ip_row_idx = i
                val = self._mgmt_ip_widget(value)
            self.grid.addWidget(lbl, i, 0)
            self.grid.addWidget(val, i, 1)
        self.grid.setColumnStretch(1, 1)

    def _update_mgmt_ip_row(self, ip: str, is_arp: bool = False) -> None:
        if getattr(self, "_mgmt_ip_row_idx", None) is None:
            return
        item = self.grid.itemAtPosition(self._mgmt_ip_row_idx, 1)
        if item is not None:
            w = item.widget()
            if w is not None:
                self.grid.removeWidget(w)
                w.deleteLater()
        new_w = self._mgmt_ip_widget(ip, is_arp=is_arp)
        self.grid.addWidget(new_w, self._mgmt_ip_row_idx, 1)

    def _mgmt_ip_widget(self, value: str, is_arp: bool = False) -> QWidget:
        """A row of clickable management-IP links."""
        wrap = QWidget()
        lay = QHBoxLayout(wrap)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        ips = [ip.strip() for ip in value.replace(",", " ").split() if ip.strip()]
        if not ips:
            lbl = QLabel("—")
            lbl.setStyleSheet(f"color: {FG_FAINT}; font-family: {MONO};")
            lay.addWidget(lbl)
            return wrap
        for ip in ips:
            link = QLabel(f'<a href="ssh://{ip}" style="color: {ACCENT}; '
                          f'text-decoration: underline;">{ip}</a>')
            link.setOpenExternalLinks(False)
            link.setToolTip(f"Click to SSH to {ip}")
            link.linkActivated.connect(lambda _=None, target=ip: self.ssh_requested.emit(target))
            lay.addWidget(link)
        if is_arp:
            tag = QLabel("(ARP)")
            tag.setStyleSheet(f"color: {FG_DIM}; font-family: {MONO}; font-size: 11px;")
            lay.addWidget(tag)
        lay.addStretch(1)
        return wrap

    def _clear_grid(self) -> None:
        while self.grid.count():
            item = self.grid.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
