"""Switch info panel — the LLDP/CDP neighbor readout."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QLabel,
                               QGroupBox, QSizePolicy, QHBoxLayout)

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
    ssh_requested = Signal(str)  # management IP the user clicked

    def __init__(self, parent=None):
        super().__init__(parent)
        self.group = QGroupBox("Switch Info")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.group)
        # hug content vertically — no dead space below the rows
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)

        self.grid = QGridLayout(self.group)
        self.grid.setHorizontalSpacing(24)
        self.grid.setVerticalSpacing(2)
        self.grid.setContentsMargins(2, 0, 2, 4)

        self.clear()

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
            ("Port ID (raw)", dev.port_id or ""),
            ("VLAN ID", str(dev.vlan) if dev.vlan is not None else ""),
            ("Mgmt IP address", ", ".join(dev.management_ips)),
            ("Protocol", dev.protocol.upper()),
            ("Chassis ID", chassis),
        ]
        self._render(rows)

    def clear(self) -> None:
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
        for i, (label, value) in enumerate(rows):
            lbl, val = _row(label, value)
            if label == "Mgmt IP address":
                val = self._mgmt_ip_widget(value)
            self.grid.addWidget(lbl, i, 0)
            self.grid.addWidget(val, i, 1)
        self.grid.setColumnStretch(1, 1)

    def _mgmt_ip_widget(self, value: str) -> QWidget:
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
        lay.addStretch(1)
        return wrap

    def _clear_grid(self) -> None:
        while self.grid.count():
            item = self.grid.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
