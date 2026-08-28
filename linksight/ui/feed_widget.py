"""Live feed widget — raw hex dump of every captured frame.

No parsed summaries here: parsed data lives in the Devices/Network tables.
This view exists so any frame can be inspected byte-for-byte against the
wire (copy into Wireshark/Scapy) — the debugging ground truth.
"""

from __future__ import annotations

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPlainTextEdit, QLabel)

from ..util import hexdump

SEP = "─" * 60


class FeedWidget(QWidget):
    MAX_FRAMES = 40

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        hint = QLabel("Raw frames from the wire. Select-all and copy to compare against Wireshark.")
        hint.setObjectName("faint")
        layout.addWidget(hint)

        self.feed = QPlainTextEdit()
        self.feed.setReadOnly(True)
        self.feed.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(self.feed, 1)

    def add_frame(self, raw: bytes) -> None:
        self.feed.appendPlainText(SEP)
        self.feed.appendPlainText(hexdump(raw))
        self._trim()

    def _trim(self) -> None:
        # keep the last MAX_FRAMES separators (each frame = separator + dump)
        blocks = self.feed.document().blockCount()
        if blocks > self.MAX_FRAMES * 12:
            cursor = self.feed.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.movePosition(cursor.Down, cursor.KeepAnchor, blocks - self.MAX_FRAMES * 12)
            cursor.removeSelectedText()
