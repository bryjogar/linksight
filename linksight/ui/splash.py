"""Launch splash for LinkSight — dark, engineered, status-driven.

A frameless launch window in the house palette (K'Nex, not Duplo): wordmark,
a thin accent rule, monospace status line and a hairline progress bar. No logo
assets, no bubbles — the window tells you what it is doing while the capture
engine boots, then closes when the main window is ready.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QFrame, QLabel, QProgressBar, QVBoxLayout, QWidget

from .theme import ACCENT, BG, BORDER_STRONG, FG, FG_DIM, FG_FAINT, MONO


class SplashScreen(QWidget):
    """Frameless launch window with a live status line and progress bar."""

    def __init__(self, subtitle: str = "", parent=None):
        super().__init__(parent, Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(480, 220)

        root = QFrame(self)
        root.setObjectName("splash")
        root.setStyleSheet(
            f"QFrame#splash {{ background-color: {BG}; border: 1px solid {BORDER_STRONG}; "
            f"border-radius: 10px; }}"
        )
        layout = QVBoxLayout(root)
        layout.setContentsMargins(26, 22, 26, 20)
        layout.setSpacing(10)

        title = QLabel("LinkSight")
        title.setStyleSheet(f"color: {FG}; font-size: 26px; font-weight: 700; letter-spacing: 1px;")
        layout.addWidget(title)

        rule = QFrame()
        rule.setFixedHeight(2)
        rule.setFixedWidth(64)
        rule.setStyleSheet(f"background-color: {ACCENT}; border: none;")
        layout.addWidget(rule)

        if subtitle:
            sub = QLabel(subtitle)
            sub.setStyleSheet(f"color: {FG_FAINT}; font-size: 12px;")
            layout.addWidget(sub)

        layout.addStretch(1)

        self.status_label = QLabel("Initializing…")
        self.status_label.setStyleSheet(
            f"color: {FG_DIM}; font-family: {MONO}; font-size: 12px;"
        )
        layout.addWidget(self.status_label)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        self.progress.setStyleSheet(
            f"QProgressBar {{ background-color: #1e2130; border: none; border-radius: 2px; }}"
            f"QProgressBar::chunk {{ background-color: {ACCENT}; border-radius: 2px; }}"
        )
        layout.addWidget(self.progress)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(root)

    def set_status(self, text: str, pct: int) -> None:
        """Update the status line and progress position."""
        self.status_label.setText(text)
        self.progress.setValue(max(0, min(100, pct)))

    def show_centered(self) -> None:
        """Show centered on the primary screen."""
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            geo = screen.availableGeometry()
            self.move(
                geo.x() + (geo.width() - self.width()) // 2,
                geo.y() + (geo.height() - self.height()) // 2,
            )
        self.show()
