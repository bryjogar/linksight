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


def _format_speed(speed_mbps: int | None) -> tuple[str, str]:
    """Return (text, hex_color) for link speed."""
    if speed_mbps is None:
        return ("—", FG_FAINT)
    if speed_mbps >= 1000 and speed_mbps % 1000 == 0:
        speed_str = f"{speed_mbps // 1000} Gbps"
    else:
        speed_str = f"{speed_mbps} Mbps"
    color = OK if speed_mbps >= 1000 else WARN
    return (speed_str, color)


def _format_port_status(port: PortDiagnostics) -> tuple[str, str]:
    """Return (status_text, hex_color) for port STP/oper status."""
    st = port.stp_state.upper()
    if st != "UNKNOWN":
        if port.is_forwarding:
            return (st, OK)
        elif st in ("BLOCKING", "BROKEN"):
            return (st, DANGER)
        else:
            return (st, WARN)
    elif port.oper_status and port.oper_status.lower() != "unknown":
        op = port.oper_status.upper()
        if port.oper_status.lower() == "up":
            return (op, OK)
        elif port.oper_status.lower() == "down":
            return (op, DANGER)
        else:
            return (op, WARN)
    return ("—", FG_FAINT)


def _format_port_details_html(port: PortDiagnostics) -> str:
    """Format line 2 for compact path port block: PVID, allowed VLANs, STP state, link speed."""
    parts = []

    # 1. PVID & Allowed VLANs
    pvid_str = f"PVID {port.pvid}" if port.pvid is not None else ""
    if port.allowed_vlans:
        vlans_str = ", ".join(str(v) for v in port.allowed_vlans)
        vlan_part = f"VLANs {vlans_str}"
        if pvid_str:
            parts.append(
                f"<span style='color:{ACCENT}; font-weight:600;'>{pvid_str}</span> · "
                f"<span style='color:{FG}; font-weight:600;'>{vlan_part}</span>"
            )
        else:
            parts.append(f"<span style='color:{FG}; font-weight:600;'>{vlan_part}</span>")
    elif pvid_str:
        parts.append(f"<span style='color:{ACCENT}; font-weight:600;'>{pvid_str}</span>")

    # 2. STP state
    st = port.stp_state.lower() if port.stp_state else "unknown"
    if st != "unknown":
        stp_col = OK if port.is_forwarding else (DANGER if st in ("blocking", "broken") else WARN)
        parts.append(f"<span style='color:{stp_col}; font-weight:600;'>STP {st}</span>")
    elif port.oper_status and port.oper_status.lower() != "unknown":
        op = port.oper_status.lower()
        op_col = OK if op == "up" else (DANGER if op == "down" else WARN)
        parts.append(f"<span style='color:{op_col}; font-weight:600;'>Status {op}</span>")

    # 3. Speed
    if port.link_speed_mbps is not None:
        spd_str, spd_col = _format_speed(port.link_speed_mbps)
        parts.append(f"<span style='color:{spd_col}; font-weight:600;'>{spd_str}</span>")

    if not parts:
        return ""
    joined = " · ".join(parts)
    return f"<span style='color:{FG_DIM}; font-family:{MONO}; font-size:11px;'>{joined}</span>"


class HopCardWidget(QFrame):
    """An expandable card displaying a single hop in the upstream chain."""

    continue_from = Signal(str)

    def __init__(self, hop: Hop, parent=None):
        super().__init__(parent)
        self.hop = hop
        self.expanded = True
        self.ports_expanded = False
        self.ports_toggle_btn: QPushButton | None = None
        self.table: QTableWidget | None = None
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
        elif self.hop.status == "no_upstream":
            tag = QLabel(" NETWORK EDGE ")
            tag.setStyleSheet(
                f"background-color: #064e3b; color: {OK}; font-weight: 700; "
                f"font-size: 10px; border-radius: 3px; padding: 2px 4px;"
            )
            header.addWidget(tag)
        elif self.hop.status == "ambiguous":
            tag = QLabel(" AMBIGUOUS UPLINK ")
            tag.setStyleSheet(
                f"background-color: #422006; color: {WARN}; font-weight: 700; "
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
            prefix = "Root Port" if self.hop.uplink_port.is_root_port else "Uplink"
            up_lbl = QLabel(f"{prefix}: {self.hop.uplink_port.port_name}")
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

        # Determine path ports: downlink, uplink
        downlink = self.hop.downlink_port or self.hop.lan_interface
        uplink = self.hop.uplink_port or self.hop.wan_interface

        # For hop 1 if downlink is unknown, check if any port has neighbor indicating endpoint
        if downlink is None and self.hop.hop_index == 1:
            for p in self.hop.ports:
                if p is not uplink and p.neighbor_name:
                    if any(k in p.neighbor_name.lower() for k in ("local-host", "endpoint", "host", "localhost")):
                        downlink = p
                        break

        # WAN Handoff Block (Prominent WAN Interface + Speed + Oper Status + ISP Gateway for Edge devices)
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
                spd_str, spd_color = _format_speed(self.hop.wan_interface.link_speed_mbps)
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
        elif downlink or uplink:
            # Compact Path Summary Block (K'Nex style trace: Downlink -> Switch -> Uplink)
            path_frame = QFrame()
            path_frame.setObjectName("path_summary")
            path_frame.setStyleSheet(
                f"QFrame#path_summary {{ background-color: {BG_INPUT}; border: 1px solid {BORDER_STRONG}; border-radius: 4px; padding: 6px 10px; }}"
            )
            path_layout = QHBoxLayout(path_frame)
            path_layout.setContentsMargins(8, 6, 8, 6)
            path_layout.setSpacing(12)

            badge_path = QLabel("PATH")
            badge_path.setStyleSheet(f"color: {ACCENT}; font-weight: 700; font-size: 11px; font-family: {MONO};")
            path_layout.addWidget(badge_path)

            if downlink:
                down_widget = QWidget()
                down_vbox = QVBoxLayout(down_widget)
                down_vbox.setContentsMargins(0, 0, 0, 0)
                down_vbox.setSpacing(2)

                d_name = downlink.port_name or f"Port {downlink.port_id}"
                d_spd_str, d_spd_col = _format_speed(downlink.link_speed_mbps)
                d_st_str, d_st_col = _format_port_status(downlink)

                d_parts = []
                if downlink.neighbor_name:
                    d_parts.append(downlink.neighbor_name)
                if downlink.neighbor_ip:
                    d_parts.append(f"({downlink.neighbor_ip})")
                if downlink.neighbor_port:
                    d_parts.append(f"on {downlink.neighbor_port}")
                d_neigh_str = " ".join(d_parts)
                d_neigh_html = f" <span style='color:{FG_DIM}; font-size:11px;'>◀ {d_neigh_str}</span>" if d_neigh_str else ""

                d_top_html = (
                    f"<span style='color:{OK}; font-weight:700; font-size:10px; font-family:{MONO};'>▼ DOWNLINK</span> "
                    f"<span style='color:{FG}; font-family:{MONO}; font-weight:700; font-size:12px;'>{d_name}</span> "
                    f"<span style='color:{d_spd_col}; font-family:{MONO}; font-weight:600; font-size:11px;'>{d_spd_str}</span> "
                    f"<span style='color:{d_st_col}; font-family:{MONO}; font-weight:600; font-size:11px;'>{d_st_str}</span>"
                    f"{d_neigh_html}"
                )
                d_top_lbl = QLabel(d_top_html)
                down_vbox.addWidget(d_top_lbl)

                d_detail_html = _format_port_details_html(downlink)
                if d_detail_html:
                    d_detail_lbl = QLabel(d_detail_html)
                    down_vbox.addWidget(d_detail_lbl)

                path_layout.addWidget(down_widget)

            # Center Switch indicator
            switch_name = self.hop.hostname or self.hop.mgmt_ip or "Switch"
            if downlink and uplink:
                center_lbl = QLabel(f"──▶ [ {switch_name} ] ──▶")
                center_lbl.setStyleSheet(f"color: {ACCENT}; font-family: {MONO}; font-weight: 600; font-size: 11px;")
                path_layout.addWidget(center_lbl)
            elif downlink and not uplink:
                root_str = " (STP Root)" if self.hop.is_stp_root else (" (Network Edge)" if self.hop.status == "no_upstream" else "")
                center_lbl = QLabel(f"──▶ [ {switch_name}{root_str} ]")
                center_lbl.setStyleSheet(f"color: {OK if (self.hop.is_stp_root or self.hop.status == 'no_upstream') else ACCENT}; font-family: {MONO}; font-weight: 600; font-size: 11px;")
                path_layout.addWidget(center_lbl)
            elif uplink and not downlink:
                center_lbl = QLabel(f"[ {switch_name} ] ──▶")
                center_lbl.setStyleSheet(f"color: {ACCENT}; font-family: {MONO}; font-weight: 600; font-size: 11px;")
                path_layout.addWidget(center_lbl)

            if uplink:
                up_widget = QWidget()
                up_vbox = QVBoxLayout(up_widget)
                up_vbox.setContentsMargins(0, 0, 0, 0)
                up_vbox.setSpacing(2)

                u_tag = "ROOT / UPLINK" if uplink.is_root_port else "UPLINK"
                u_name = uplink.port_name or f"Port {uplink.port_id}"
                u_spd_str, u_spd_col = _format_speed(uplink.link_speed_mbps)
                u_st_str, u_st_col = _format_port_status(uplink)

                u_parts = []
                if uplink.neighbor_name:
                    u_parts.append(uplink.neighbor_name)
                if uplink.neighbor_ip:
                    u_parts.append(f"({uplink.neighbor_ip})")
                if uplink.neighbor_port:
                    u_parts.append(f"on {uplink.neighbor_port}")
                u_neigh_str = " ".join(u_parts)
                u_neigh_html = f" <span style='color:{FG_DIM}; font-size:11px;'>▶ {u_neigh_str}</span>" if u_neigh_str else ""

                u_top_html = (
                    f"<span style='color:{ACCENT}; font-weight:700; font-size:10px; font-family:{MONO};'>▲ {u_tag}</span> "
                    f"<span style='color:{FG}; font-family:{MONO}; font-weight:700; font-size:12px;'>{u_name}</span> "
                    f"<span style='color:{u_spd_col}; font-family:{MONO}; font-weight:600; font-size:11px;'>{u_spd_str}</span> "
                    f"<span style='color:{u_st_col}; font-family:{MONO}; font-weight:600; font-size:11px;'>{u_st_str}</span>"
                    f"{u_neigh_html}"
                )
                u_top_lbl = QLabel(u_top_html)
                up_vbox.addWidget(u_top_lbl)

                u_detail_html = _format_port_details_html(uplink)
                if u_detail_html:
                    u_detail_lbl = QLabel(u_detail_html)
                    up_vbox.addWidget(u_detail_lbl)

                path_layout.addWidget(up_widget)

            path_layout.addStretch(1)
            body_layout.addWidget(path_frame)

        if self.hop.default_gateway and not (self.hop.wan_interface or self.hop.isp_gateway):
            gw_lbl = QLabel(f"Default Gateway (L3): {self.hop.default_gateway}")
            gw_lbl.setStyleSheet(f"color: {ACCENT}; font-size: 11px; font-weight: 600; font-family: {MONO};")
            body_layout.addWidget(gw_lbl)

        if self.hop.error_message:
            err_lbl = QLabel(f"Error: {self.hop.error_message}")
            err_lbl.setStyleSheet(f"color: {DANGER}; font-size: 11px;")
            body_layout.addWidget(err_lbl)

        # Ambiguous candidate continuation buttons
        candidates = list(self.hop.ambiguous_candidates)
        if not candidates and self.hop.status == "ambiguous":
            candidates = [p for p in self.hop.ports if p.neighbor_ip and not p.is_downlink]

        if self.hop.status == "ambiguous" and candidates:
            cand_frame = QFrame()
            cand_frame.setObjectName("ambiguous_candidates")
            cand_frame.setStyleSheet(
                f"QFrame#ambiguous_candidates {{ background-color: {BG_INPUT}; border: 1px solid {WARN}; "
                f"border-radius: 4px; padding: 6px 10px; }}"
            )
            cand_layout = QVBoxLayout(cand_frame)
            cand_layout.setContentsMargins(8, 6, 8, 6)
            cand_layout.setSpacing(6)

            cand_title = QLabel("Multiple upstream candidates found — choose a path to continue discovery:")
            cand_title.setStyleSheet(f"color: {WARN}; font-weight: 600; font-size: 11px;")
            cand_layout.addWidget(cand_title)

            btn_row = QHBoxLayout()
            btn_row.setSpacing(8)

            for cand in candidates:
                cand_name = cand.neighbor_name or "Neighbor"
                cand_ip = cand.neighbor_ip or ""
                cand_port = cand.port_name or (f"Port {cand.port_id}" if cand.port_id is not None else "")
                port_suffix = f" on {cand_port}" if cand_port else ""
                btn_text = f"▶ Try {cand_name} ({cand_ip}){port_suffix}"
                cand_btn = QPushButton(btn_text)
                cand_btn.setObjectName(f"candidate_btn_{cand_ip}")
                cand_btn.setStyleSheet(
                    f"QPushButton {{ background-color: {BG_PANEL}; border: 1px solid {BORDER_STRONG}; "
                    f"color: {ACCENT}; font-size: 11px; font-weight: 600; font-family: {MONO}; "
                    f"padding: 4px 10px; border-radius: 4px; text-align: left; }} "
                    f"QPushButton:hover {{ background-color: #1e3a5f; color: #ffffff; border-color: {ACCENT}; }}"
                )
                cand_btn.setCursor(Qt.CursorShape.PointingHandCursor)
                cand_btn.clicked.connect(lambda checked=False, target_ip=cand_ip: self.continue_from.emit(target_ip))
                btn_row.addWidget(cand_btn)

            btn_row.addStretch(1)
            cand_layout.addLayout(btn_row)
            body_layout.addWidget(cand_frame)

        # Per-port diagnostics table (collapsed by default behind "All N ports" toggle)
        if self.hop.ports:
            self.ports_expanded = False

            toggle_row = QHBoxLayout()
            toggle_row.setContentsMargins(0, 2, 0, 0)

            port_count = len(self.hop.ports)
            self.ports_toggle_btn = QPushButton(f"▶  All {port_count} ports")
            self.ports_toggle_btn.setObjectName("ports_toggle")
            self.ports_toggle_btn.setStyleSheet(
                f"QPushButton#ports_toggle {{ background-color: transparent; border: 1px solid {BORDER}; "
                f"color: {FG_DIM}; font-size: 11px; padding: 3px 8px; border-radius: 4px; text-align: left; }} "
                f"QPushButton#ports_toggle:hover {{ background-color: {BG_INPUT}; color: {FG}; border-color: {BORDER_STRONG}; }}"
            )
            self.ports_toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.ports_toggle_btn.clicked.connect(self._toggle_ports)
            toggle_row.addWidget(self.ports_toggle_btn)
            toggle_row.addStretch(1)
            body_layout.addWidget(QWidget())  # spacer
            body_layout.addLayout(toggle_row)

            self.table = QTableWidget()
            self.table.setColumnCount(6)
            self.table.setHorizontalHeaderLabels([
                "PORT",
                "PVID",
                "ALLOWED VLANS",
                "STP / STATUS",
                "LINK SPEED",
                "CONNECTED NEIGHBOR",
            ])
            self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            self.table.horizontalHeader().setStretchLastSection(True)
            self.table.verticalHeader().setVisible(False)
            self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            self.table.setRowCount(len(self.hop.ports))
            self.table.setShowGrid(True)

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
                elif (self.hop.lan_interface and port.port_id == self.hop.lan_interface.port_id) or port.is_downlink:
                    it_port.setForeground(Qt.GlobalColor.green)
                self.table.setItem(row_idx, 0, it_port)

                # 2. PVID
                pvid_str = str(port.pvid) if port.pvid is not None else "—"
                it_pvid = QTableWidgetItem(pvid_str)
                it_pvid.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                self.table.setItem(row_idx, 1, it_pvid)

                # 3. Allowed VLANs
                vlans_str = ", ".join(str(v) for v in port.allowed_vlans) if port.allowed_vlans else "—"
                it_vlans = QTableWidgetItem(vlans_str)
                it_vlans.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                self.table.setItem(row_idx, 2, it_vlans)

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
                self.table.setItem(row_idx, 3, it_stp)

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
                self.table.setItem(row_idx, 4, it_speed)

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
                self.table.setItem(row_idx, 5, it_neigh)

                # Row height compact
                self.table.setRowHeight(row_idx, 24)

            # Sizing
            self.table.resizeColumnsToContents()
            self.table.setMinimumHeight(min(220, 32 + len(self.hop.ports) * 26))
            self.table.setVisible(False)
            body_layout.addWidget(self.table)
        else:
            self.ports_expanded = False
            self.ports_toggle_btn = None
            self.table = None

        main_layout.addWidget(self.body)

    def _toggle_expand(self):
        self.expanded = not self.expanded
        self.body.setVisible(self.expanded)
        self.toggle_btn.setText("Hide" if self.expanded else "Show")

    def _toggle_ports(self):
        self.ports_expanded = not self.ports_expanded
        if self.table is not None:
            self.table.setVisible(self.ports_expanded)
        if self.ports_toggle_btn is not None:
            port_count = len(self.hop.ports)
            arrow = "▼" if self.ports_expanded else "▶"
            self.ports_toggle_btn.setText(f"{arrow}  All {port_count} ports")


class UpstreamWidget(QWidget):
    """Panel displaying the full upstream discovery chain path and hop diagnostics."""

    refresh_requested = Signal()
    continue_from = Signal(str)

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
            card.continue_from.connect(self.continue_from.emit)
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
