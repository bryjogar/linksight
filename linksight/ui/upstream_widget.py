"""Upstream discovery readout widget — renders the upstream switch chain path and diagnostics."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QGroupBox,
    QPushButton,
    QScrollArea,
    QFrame,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QSizePolicy,
)

from ..discovery.models import Hop, PortDiagnostics, UpstreamPath
from .theme import (
    BG,
    BG_PANEL,
    BG_RAISED,
    BG_INPUT,
    BORDER,
    BORDER_STRONG,
    FG,
    FG_DIM,
    FG_FAINT,
    ACCENT,
    OK,
    WARN,
    DANGER,
    MONO,
)


class HopCardWidget(QFrame):
    """An expandable card displaying a single hop in the upstream chain."""

    def __init__(self, hop: Hop, parent=None):
        super().__init__(parent)
        self.hop = hop
        self.expanded = True
        self.setObjectName("panel")
        self.setStyleSheet(
            f"QFrame#panel {{ background-color: {BG_PANEL}; border: 1px solid {BORDER}; border-radius: 6px; margin-bottom: 6px; }}"
        )
        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 6, 8, 6)
        main_layout.setSpacing(6)

        # Header Row
        header = QHBoxLayout()
        header.setSpacing(8)

        # Hop index badge
        badge = QLabel(f" HOP {self.hop.hop_index} ")
        badge.setStyleSheet(
            f"background-color: {BG_INPUT}; color: {ACCENT}; font-weight: 700; "
            f"font-size: 11px; border: 1px solid {BORDER_STRONG}; border-radius: 4px; padding: 2px 4px;"
        )
        header.addWidget(badge)

        # Hostname and IP
        title_text = f"{self.hop.hostname or 'Unknown Switch'} ({self.hop.mgmt_ip})"
        title = QLabel(title_text)
        title.setStyleSheet(f"color: {FG}; font-weight: 600; font-size: 13px; font-family: {MONO};")
        header.addWidget(title)

        # STP / Role Status Tag
        if self.hop.is_stp_root:
            tag = QLabel(" STP ROOT BRIDGE ")
            tag.setStyleSheet(
                f"background-color: #064e3b; color: {OK}; font-weight: 700; "
                f"font-size: 10px; border-radius: 3px; padding: 2px 4px;"
            )
            header.addWidget(tag)
        elif self.hop.device_type in ("firewall", "router"):
            tag = QLabel(f" {self.hop.device_type.upper()} EDGE ")
            tag.setStyleSheet(
                f"background-color: #1e3a5f; color: {ACCENT}; font-weight: 700; "
                f"font-size: 10px; border-radius: 3px; padding: 2px 4px;"
            )
            header.addWidget(tag)
        elif self.hop.status in ("timeout", "unreachable"):
            tag = QLabel(f" {self.hop.status.upper()} ")
            tag.setStyleSheet(
                f"background-color: #450a0a; color: {DANGER}; font-weight: 700; "
                f"font-size: 10px; border-radius: 3px; padding: 2px 4px;"
            )
            header.addWidget(tag)

        if self.hop.wan_interface and not self.hop.is_stp_root:
            up_lbl = QLabel(f"WAN: {self.hop.wan_interface.port_name}")
            up_lbl.setStyleSheet(f"color: {FG_DIM}; font-size: 11px;")
            header.addWidget(up_lbl)
        elif self.hop.uplink_port and not self.hop.is_stp_root:
            up_lbl = QLabel(f"Root Port: {self.hop.uplink_port.port_name}")
            up_lbl.setStyleSheet(f"color: {FG_DIM}; font-size: 11px;")
            header.addWidget(up_lbl)

        header.addStretch(1)

        if self.hop.response_time_ms is not None:
            lat = QLabel(f"{self.hop.response_time_ms:.1f} ms")
            lat.setStyleSheet(f"color: {FG_FAINT}; font-size: 11px; font-family: {MONO};")
            header.addWidget(lat)

        self.toggle_btn = QPushButton("Hide" if self.expanded else "Show")
        self.toggle_btn.setObjectName("tool")
        self.toggle_btn.setFixedWidth(50)
        self.toggle_btn.clicked.connect(self._toggle_expand)
        header.addWidget(self.toggle_btn)

        main_layout.addLayout(header)

        # Body Container
        self.body = QWidget()
        body_layout = QVBoxLayout(self.body)
        body_layout.setContentsMargins(0, 4, 0, 0)
        body_layout.setSpacing(6)

        # Info line (platform / sys_descr)
        if self.hop.sys_descr or self.hop.platform:
            desc_text = self.hop.platform or self.hop.sys_descr
            desc_lbl = QLabel(f"System: {desc_text}")
            desc_lbl.setStyleSheet(f"color: {FG_DIM}; font-size: 11px;")
            desc_lbl.setWordWrap(True)
            body_layout.addWidget(desc_lbl)

        # WAN Handoff Block (Prominent WAN Interface + Speed + Oper Status + ISP Gateway)
        if self.hop.wan_interface or self.hop.isp_gateway:
            wan_frame = QFrame()
            wan_frame.setObjectName("wan_handoff")
            wan_frame.setStyleSheet(
                f"QFrame#wan_handoff {{ background-color: {BG_INPUT}; border: 1px solid {BORDER_STRONG}; border-radius: 4px; padding: 4px 8px; }}"
            )
            wan_layout = QHBoxLayout(wan_frame)
            wan_layout.setContentsMargins(6, 4, 6, 4)
            wan_layout.setSpacing(14)

            badge_wan = QLabel("WAN HANDOFF")
            badge_wan.setStyleSheet(f"color: {ACCENT}; font-weight: 700; font-size: 11px; font-family: {MONO};")
            wan_layout.addWidget(badge_wan)

            wan_name = self.hop.wan_interface.port_name if self.hop.wan_interface else "WAN"
            wan_lbl = QLabel(f"Interface: <span style='color:{FG}; font-family:{MONO}; font-weight:600;'>{wan_name}</span>")
            wan_lbl.setStyleSheet(f"color: {FG_DIM}; font-size: 11px;")
            wan_layout.addWidget(wan_lbl)

            if self.hop.wan_interface and self.hop.wan_interface.link_speed_mbps is not None:
                spd = self.hop.wan_interface.link_speed_mbps
                spd_str = f"{spd // 1000} Gbps" if spd >= 1000 and spd % 1000 == 0 else f"{spd} Mbps"
                spd_color = OK if spd >= 1000 else WARN
                spd_lbl = QLabel(f"Speed: <span style='color:{spd_color}; font-family:{MONO}; font-weight:600;'>{spd_str}</span>")
            else:
                spd_lbl = QLabel("Speed: <span style='color:#808080;'>—</span>")
            spd_lbl.setStyleSheet(f"color: {FG_DIM}; font-size: 11px;")
            wan_layout.addWidget(spd_lbl)

            oper_status = self.hop.wan_interface.oper_status if (self.hop.wan_interface and self.hop.wan_interface.oper_status != "unknown") else ("up" if self.hop.wan_interface else "unknown")
            if oper_status.lower() == "up":
                oper_color = OK
            elif oper_status.lower() == "down":
                oper_color = DANGER
            else:
                oper_color = WARN
            oper_lbl = QLabel(f"Status: <span style='color:{oper_color}; font-family:{MONO}; font-weight:600;'>{oper_status.upper()}</span>")
            oper_lbl.setStyleSheet(f"color: {FG_DIM}; font-size: 11px;")
            wan_layout.addWidget(oper_lbl)

            if self.hop.isp_gateway:
                gw_lbl = QLabel(f"ISP Gateway: <span style='color:{ACCENT}; font-family:{MONO}; font-weight:700; font-size:12px;'>{self.hop.isp_gateway}</span>")
                gw_lbl.setStyleSheet(f"color: {FG_DIM}; font-size: 11px;")
                wan_layout.addWidget(gw_lbl)

            wan_layout.addStretch(1)
            body_layout.addWidget(wan_frame)
        elif self.hop.default_gateway:
            gw_lbl = QLabel(f"Default Gateway (L3): {self.hop.default_gateway}")
            gw_lbl.setStyleSheet(f"color: {ACCENT}; font-size: 11px; font-weight: 600; font-family: {MONO};")
            body_layout.addWidget(gw_lbl)

        if self.hop.error_message:
            err_lbl = QLabel(f"Error: {self.hop.error_message}")
            err_lbl.setStyleSheet(f"color: {DANGER}; font-size: 11px;")
            body_layout.addWidget(err_lbl)

        # Per-port diagnostics table
        if self.hop.ports:
            table = QTableWidget()
            table.setColumnCount(6)
            table.setHorizontalHeaderLabels([
                "PORT",
                "PVID",
                "ALLOWED VLANS",
                "STP / STATUS",
                "LINK SPEED",
                "CONNECTED NEIGHBOR",
            ])
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            table.horizontalHeader().setStretchLastSection(True)
            table.verticalHeader().setVisible(False)
            table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            table.setRowCount(len(self.hop.ports))
            table.setShowGrid(True)

            for row_idx, port in enumerate(self.hop.ports):
                # 1. Port
                p_text = port.port_name or f"Port {port.port_id}"
                if port.is_root_port:
                    p_text += " [ROOT/UPLINK]"
                elif self.hop.wan_interface and (port == self.hop.wan_interface or port.port_id == self.hop.wan_interface.port_id):
                    p_text += " [WAN/UPLINK]"
                elif self.hop.lan_interface and (port == self.hop.lan_interface or port.port_id == self.hop.lan_interface.port_id):
                    p_text += " [LAN/DOWNLINK]"
                elif port.is_uplink:
                    p_text += " [UPLINK]"
                elif port.is_downlink:
                    p_text += " [DOWNLINK]"
                it_port = QTableWidgetItem(p_text)
                it_port.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                if port.is_root_port or port.is_uplink or (self.hop.wan_interface and port.port_id == self.hop.wan_interface.port_id):
                    it_port.setForeground(Qt.GlobalColor.cyan)
                elif self.hop.lan_interface and port.port_id == self.hop.lan_interface.port_id:
                    it_port.setForeground(Qt.GlobalColor.green)
                table.setItem(row_idx, 0, it_port)

                # 2. PVID
                pvid_str = str(port.pvid) if port.pvid is not None else "—"
                it_pvid = QTableWidgetItem(pvid_str)
                it_pvid.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                table.setItem(row_idx, 1, it_pvid)

                # 3. Allowed VLANs
                vlans_str = ", ".join(str(v) for v in port.allowed_vlans) if port.allowed_vlans else "—"
                it_vlans = QTableWidgetItem(vlans_str)
                it_vlans.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                table.setItem(row_idx, 2, it_vlans)

                # 4. STP / Oper Status
                st = port.stp_state.upper()
                if st != "UNKNOWN":
                    status_text = st
                    if port.is_forwarding:
                        color = Qt.GlobalColor.green
                    elif st in ("BLOCKING", "BROKEN"):
                        color = Qt.GlobalColor.red
                    else:
                        color = Qt.GlobalColor.yellow
                elif port.oper_status and port.oper_status.lower() != "unknown":
                    status_text = port.oper_status.upper()
                    if port.oper_status.lower() == "up":
                        color = Qt.GlobalColor.green
                    elif port.oper_status.lower() == "down":
                        color = Qt.GlobalColor.red
                    else:
                        color = Qt.GlobalColor.yellow
                else:
                    status_text = "—"
                    color = Qt.GlobalColor.gray

                it_stp = QTableWidgetItem(status_text)
                it_stp.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                it_stp.setForeground(color)
                table.setItem(row_idx, 3, it_stp)

                # 5. Link Speed
                if port.link_speed_mbps is not None:
                    if port.link_speed_mbps >= 1000:
                        speed_str = f"{port.link_speed_mbps // 1000} Gbps" if port.link_speed_mbps % 1000 == 0 else f"{port.link_speed_mbps} Mbps"
                    else:
                        speed_str = f"{port.link_speed_mbps} Mbps"
                else:
                    speed_str = "—"
                it_speed = QTableWidgetItem(speed_str)
                it_speed.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                if port.link_speed_mbps is not None and port.link_speed_mbps < 1000:
                    it_speed.setForeground(Qt.GlobalColor.yellow)
                elif port.link_speed_mbps is not None:
                    it_speed.setForeground(Qt.GlobalColor.green)
                table.setItem(row_idx, 4, it_speed)

                # 6. Neighbor
                neigh_parts = []
                if port.neighbor_name:
                    neigh_parts.append(port.neighbor_name)
                if port.neighbor_ip:
                    neigh_parts.append(f"({port.neighbor_ip})")
                if port.neighbor_port:
                    neigh_parts.append(f"on {port.neighbor_port}")
                neigh_str = " ".join(neigh_parts) if neigh_parts else "—"
                it_neigh = QTableWidgetItem(neigh_str)
                it_neigh.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                table.setItem(row_idx, 5, it_neigh)

            # Sizing
            table.resizeColumnsToContents()
            table.setMinimumHeight(min(220, 32 + len(self.hop.ports) * 26))
            body_layout.addWidget(table)

        main_layout.addWidget(self.body)

    def _toggle_expand(self):
        self.expanded = not self.expanded
        self.body.setVisible(self.expanded)
        self.toggle_btn.setText("Hide" if self.expanded else "Show")


class UpstreamWidget(QWidget):
    """Panel displaying the full upstream discovery chain path and hop diagnostics."""

    refresh_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.group = QGroupBox("Upstream Discovery — Path to Edge")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.group)

        self._setup_ui()
        self.clear()

    def _setup_ui(self):
        self.group_layout = QVBoxLayout(self.group)
        self.group_layout.setContentsMargins(6, 6, 6, 6)
        self.group_layout.setSpacing(6)

        # Top Control & Breadcrumb Summary Bar
        top_bar = QHBoxLayout()
        top_bar.setSpacing(8)

        self.summary_label = QLabel("No upstream path discovered yet.")
        self.summary_label.setStyleSheet(f"color: {FG_DIM}; font-weight: 500;")
        top_bar.addWidget(self.summary_label, stretch=1)

        self.refresh_btn = QPushButton("Re-Walk")
        self.refresh_btn.setObjectName("tool")
        self.refresh_btn.clicked.connect(self.refresh_requested.emit)
        top_bar.addWidget(self.refresh_btn)

        self.group_layout.addLayout(top_bar)

        # Path Breadcrumb Strip
        self.breadcrumb_bar = QLabel("")
        self.breadcrumb_bar.setStyleSheet(
            f"background-color: {BG_INPUT}; color: {FG}; font-family: {MONO}; "
            f"font-size: 12px; padding: 6px 10px; border: 1px solid {BORDER}; border-radius: 4px;"
        )
        self.breadcrumb_bar.setWordWrap(True)
        self.breadcrumb_bar.hide()
        self.group_layout.addWidget(self.breadcrumb_bar)

        # Scrollable Hop Cards List
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setStyleSheet(f"background-color: {BG_PANEL};")

        self.cards_container = QWidget()
        self.cards_layout = QVBoxLayout(self.cards_container)
        self.cards_layout.setContentsMargins(0, 0, 0, 0)
        self.cards_layout.setSpacing(4)
        self.cards_layout.addStretch(1)

        self.scroll.setWidget(self.cards_container)
        self.group_layout.addWidget(self.scroll, stretch=1)

    def set_status(self, text: str) -> None:
        """Update discovery status text while in progress."""
        self.summary_label.setText(text)
        self.summary_label.setStyleSheet(f"color: {ACCENT}; font-weight: 600;")

    def show_path(self, path: UpstreamPath) -> None:
        """Render the complete upstream discovery path."""
        self._clear_cards()

        if not path.hops:
            self.summary_label.setText("No upstream hops found.")
            self.summary_label.setStyleSheet(f"color: {FG_FAINT};")
            self.breadcrumb_bar.hide()
            return

        # Summary text
        self.summary_label.setText(path.edge_summary or f"Walk completed ({len(path.hops)} hops)")
        self.summary_label.setStyleSheet(f"color: {OK if path.success else WARN}; font-weight: 600;")

        # Breadcrumb trail
        trail = ["Endpoint"]
        for hop in path.hops:
            trail.append(f"{hop.hostname or hop.mgmt_ip}")
        if path.hops and path.hops[-1].isp_gateway:
            trail.append(f"ISP Gateway ({path.hops[-1].isp_gateway})")
        elif path.hops and path.hops[-1].default_gateway and not (path.edge_type in ("firewall", "router") and path.hops[-1].device_type in ("firewall", "router")):
            trail.append(f"Gateway ({path.hops[-1].default_gateway})")

        self.breadcrumb_bar.setText(" ──▶ ".join(trail))
        self.breadcrumb_bar.show()

        # Add Hop Cards
        for hop in path.hops:
            card = HopCardWidget(hop)
            self.cards_layout.insertWidget(self.cards_layout.count() - 1, card)

    def clear(self) -> None:
        """Reset the widget."""
        self._clear_cards()
        self.summary_label.setText("Click 'Discover Upstream Path' to walk upstream switches via SNMP.")
        self.summary_label.setStyleSheet(f"color: {FG_FAINT};")
        self.breadcrumb_bar.hide()

    def _clear_cards(self) -> None:
        while self.cards_layout.count() > 1:
            item = self.cards_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
