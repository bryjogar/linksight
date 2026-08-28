"""LAN info panel — the attached network's identity (adapter config + DHCP)."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QLabel,
                               QGroupBox, QSizePolicy)

from ..capture.system_info import get_interface_config
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


class LanInfoWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._iface_name = ""
        self._mac_override = ""
        self.controller = None  # set by main_window for DHCP observation

        self.group = QGroupBox("LAN Info")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.group)
        # hug content vertically — no dead space below the rows
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Maximum)

        self.grid = QGridLayout(self.group)
        self.grid.setHorizontalSpacing(24)
        self.grid.setVerticalSpacing(2)
        self.grid.setContentsMargins(2, 0, 2, 4)

    def set_interface(self, iface_name: str, mac: str = "") -> None:
        self._iface_name = iface_name
        self._mac_override = mac
        self.refresh()

    def refresh(self) -> None:
        cfg = get_interface_config(self._iface_name) if self._iface_name else None
        net = self.controller.network if self.controller else {}

        mac = self._mac_override or (cfg.mac if cfg else "")
        vendor = lookup_vendor(mac) if mac else ""
        mac_display = mac if mac else ""
        if mac and vendor:
            mac_display = f"{mac}  ({vendor})"

        dhcp_server = cfg.dhcp_server if cfg and cfg.dhcp_server else net.get("server_ip", "")
        rows = [
            ("IP address", cfg.ip if cfg else ""),
            ("Subnet mask", cfg.netmask if cfg else ""),
            ("Default gateway", cfg.gateway if cfg else ""),
            ("DNS servers", ", ".join(cfg.dns_servers) if cfg else ""),
            ("DHCP server", dhcp_server),
            ("DHCP enabled", ("yes" if cfg.dhcp_enabled else "no") if cfg and cfg.dhcp_enabled is not None else ""),
            ("MAC address", mac_display),
        ]
        if net.get("last_message"):
            rows.append(("DHCP observed", net.get("last_message", "")))
        if net.get("domain"):
            rows.append(("Domain", net.get("domain", "")))

        self._render(rows)

    def _render(self, rows) -> None:
        self._clear_grid()
        for i, (label, value) in enumerate(rows):
            lbl, val = _row(label, value)
            self.grid.addWidget(lbl, i, 0)
            self.grid.addWidget(val, i, 1)
        self.grid.setColumnStretch(1, 1)

    def _clear_grid(self) -> None:
        while self.grid.count():
            item = self.grid.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
