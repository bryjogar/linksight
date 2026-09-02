"""NIC status panel — table of network adapters with link state."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal, QAbstractTableModel
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QTableView, QHeaderView,
                               QLabel)

from ..capture.interfaces import list_interfaces, NetInterface
from .theme import MONO


class NicModel(QAbstractTableModel):
    HEADERS = ["ADAPTER", "STATE", "IP ADDRESS", "MAC ADDRESS"]

    def __init__(self, nics: list[NetInterface]):
        super().__init__()
        self._nics = nics

    def rowCount(self, parent=...):
        return len(self._nics)

    def update_nics(self, nics: list[NetInterface]) -> None:
        self.beginResetModel()
        self._nics = list(nics)
        self.endResetModel()

    def columnCount(self, parent=...):
        return len(self.HEADERS)

    def headerData(self, section, orientation=Qt.Horizontal, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._nics)):
            return None
        nic = self._nics[index.row()]
        col = index.column()
        if role == Qt.DisplayRole:
            if col == 0:
                return nic.name
            if col == 1:
                return "UP" if nic.is_up else "DOWN"
            if col == 2:
                return ", ".join(nic.ips) if nic.ips else "—"
            if col == 3:
                return nic.mac or "—"
        if role == Qt.ForegroundRole and col == 1:
            from PySide6.QtGui import QColor
            return QColor("#10b981") if nic.is_up else QColor("#ef4444")
        if role == Qt.FontRole and col in (2, 3):
            from PySide6.QtGui import QFont
            return QFont(MONO, 12)
        return None

    def nic_at(self, row: int) -> NetInterface | None:
        if 0 <= row < len(self._nics):
            return self._nics[row]
        return None


class NicStatusWidget(QWidget):
    selection_changed = Signal(object)  # NetInterface or None

    def __init__(self, parent=None):
        super().__init__(parent)
        self.nics = list_interfaces()
        self.model = NicModel(self.nics)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        hint = QLabel("Network adapters on this machine")
        hint.setObjectName("faint")
        layout.addWidget(hint)

        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(26)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        for i in range(1, 4):
            header.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.table.selectionModel().selectionChanged.connect(self._on_selection)
        layout.addWidget(self.table, 1)

    def _on_selection(self, selected, _deselected) -> None:
        idxs = selected.indexes()
        if not idxs:
            self.selection_changed.emit(None)
            return
        nic = self.model.nic_at(idxs[0].row())
        self.selection_changed.emit(nic)

    def refresh(self, nics: list[NetInterface] | None = None) -> None:
        """Update interface list while safely preserving selection if the adapter is still present."""
        if nics is None:
            nics = list_interfaces()

        selected_name = None
        current_idx = self.table.currentIndex()
        if current_idx.isValid():
            selected_nic = self.model.nic_at(current_idx.row())
            if selected_nic:
                selected_name = selected_nic.name

        self.nics = list(nics)
        self.model.update_nics(self.nics)

        if selected_name:
            for row, nic in enumerate(self.nics):
                if nic.name == selected_name:
                    from PySide6.QtCore import QItemSelectionModel
                    idx = self.model.index(row, 0)
                    self.table.selectionModel().setCurrentIndex(
                        idx,
                        QItemSelectionModel.SelectionFlag.ClearAndSelect | QItemSelectionModel.SelectionFlag.Rows
                    )
                    break

    def update_interfaces(self, nics: list[NetInterface]) -> None:
        self.refresh(nics)
