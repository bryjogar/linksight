"""Application-wide stylesheet — matches the wifi-explorer house style.

Palette, radii, and accent are deliberately identical to WiFi Explorer so
NetProbe reads as part of the same family of tools. Clean engineering blue
(#3b82f6), not blurple. Restrained 6-8px radii, no bubble buttons.
"""

from __future__ import annotations

# Palette (shared with wifi-explorer)
BG = "#0f1117"
BG_RAISED = "#161822"
BG_PANEL = "#13151f"
BG_ALT = "#181b26"
BG_INPUT = "#1a1d2e"
FG = "#e0e0e0"
FG_DIM = "#a0a0a0"
FG_FAINT = "#808080"
ACCENT = "#3b82f6"          # engineering blue (wifi-explorer accent)
ACCENT_HOVER = "#2563eb"
ACCENT_PRESSED = "#1d4ed8"
BORDER = "#252836"
BORDER_STRONG = "#353848"
OK = "#10b981"              # green
WARN = "#f59e0b"            # amber
DANGER = "#ef4444"          # red
MONO = "Consolas, 'SF Mono', Menlo, monospace"

STYLESHEET = f"""
QMainWindow {{
    background-color: {BG};
}}
QWidget {{
    background-color: {BG};
    color: {FG};
    font-family: 'Segoe UI', 'Inter', 'Helvetica Neue', sans-serif;
    font-size: 13px;
}}
QMenuBar {{
    background-color: {BG_RAISED};
    color: {FG_DIM};
    border-bottom: 1px solid {BORDER};
    padding: 2px 0;
}}
QMenuBar::item:selected {{
    background-color: {BORDER};
    border-radius: 4px;
}}
QMenu {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER_STRONG};
    border-radius: 6px;
    padding: 4px;
}}
QMenu::item {{
    padding: 6px 28px 6px 12px;
    border-radius: 4px;
}}
QMenu::item:selected {{
    background-color: {ACCENT};
}}
QToolBar {{
    background-color: {BG_RAISED};
    border-bottom: 1px solid {BORDER};
    spacing: 4px;
    padding: 4px;
}}
QToolButton {{
    background-color: transparent;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 6px 12px;
    color: {FG_DIM};
}}
QToolButton:hover {{
    background-color: {BORDER};
    border-color: {ACCENT};
    color: #ffffff;
}}
QToolButton:pressed {{
    background-color: {ACCENT_PRESSED};
}}
QStatusBar {{
    background-color: {BG_RAISED};
    color: {FG_FAINT};
    border-top: 1px solid {BORDER};
    font-size: 12px;
}}
QStatusBar::item {{
    border: none;
}}
QTableView, QTableWidget {{
    background-color: {BG_PANEL};
    alternate-background-color: {BG_ALT};
    border: 1px solid {BORDER};
    border-radius: 8px;
    gridline-color: #1e2130;
    selection-background-color: #1e3a5f;
    selection-color: #ffffff;
}}
QHeaderView::section {{
    background-color: {BG_INPUT};
    color: {FG_DIM};
    border: none;
    border-right: 1px solid {BORDER};
    border-bottom: 2px solid {ACCENT};
    padding: 8px 12px;
    font-weight: 600;
    font-size: 12px;
}}
QTableCornerButton::section {{
    background-color: {BG_INPUT};
    border-bottom: 2px solid {ACCENT};
}}
QPushButton {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER_STRONG};
    border-radius: 6px;
    padding: 6px 16px;
    color: {FG};
    font-weight: 500;
}}
QPushButton:hover {{
    background-color: {BORDER};
    border-color: {ACCENT};
}}
QPushButton:pressed {{
    background-color: {ACCENT_PRESSED};
}}
QPushButton:disabled {{
    background-color: {BG_INPUT};
    color: {FG_FAINT};
    border-color: {BORDER};
}}
QPushButton#primary {{
    background-color: {ACCENT};
    border-color: {ACCENT};
    color: white;
    font-weight: 600;
    font-size: 14px;
    padding: 10px 24px;
}}
QPushButton#primary:hover {{
    background-color: {ACCENT_HOVER};
    border-color: {ACCENT_HOVER};
}}
QPushButton#primary:pressed {{
    background-color: {ACCENT_PRESSED};
}}
QPushButton#danger {{
    border-color: {DANGER};
    color: {DANGER};
}}
QPushButton#tool {{
    background-color: {BG_RAISED};
    color: {FG};
    padding: 4px 10px;
    border: 1px solid #3b3f55;
    border-radius: 4px;
    font-size: 12px;
}}
QPushButton#tool:hover {{
    background-color: #3b3f55;
}}
QLineEdit, QComboBox, QSpinBox {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER_STRONG};
    border-radius: 6px;
    padding: 5px 10px;
    color: {FG};
    selection-background-color: #1e3a5f;
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
    border-color: {ACCENT};
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox QAbstractItemView {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER_STRONG};
    border-radius: 6px;
    selection-background-color: {ACCENT};
    color: {FG};
}}
QPlainTextEdit, QTextEdit {{
    background-color: {BG_PANEL};
    border: 1px solid {BORDER};
    border-radius: 6px;
    font-family: {MONO};
    font-size: 12px;
    color: {FG};
}}
QGroupBox {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 8px;
    font-weight: 600;
    color: {FG_DIM};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
}}
QCheckBox {{
    spacing: 8px;
}}
QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 2px solid #505060;
    background-color: transparent;
}}
QCheckBox::indicator:checked {{
    background-color: {ACCENT};
    border-color: {ACCENT};
}}
QCheckBox::indicator:hover {{
    border-color: {ACCENT};
}}
QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: 8px;
    background-color: {BG_PANEL};
}}
QTabBar::tab {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER};
    padding: 8px 20px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    color: {FG_FAINT};
}}
QTabBar::tab:selected {{
    background-color: {BG_PANEL};
    border-bottom-color: {BG_PANEL};
    color: {ACCENT};
    font-weight: 600;
}}
QTabBar::tab:hover:!selected {{
    background-color: {BORDER};
    color: {FG_DIM};
}}
QScrollBar:vertical {{
    background: {BG};
    width: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: #353848;
    border-radius: 4px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{
    background: #4a4d60;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: {BG};
    height: 8px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal {{
    background: #353848;
    border-radius: 4px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{
    background: #4a4d60;
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}
QSplitter::handle {{
    background-color: {BORDER};
    width: 2px;
    height: 2px;
}}
QLabel#mono {{
    font-family: {MONO};
    font-size: 12px;
    color: {FG};
}}
QLabel#dim {{
    color: {FG_DIM};
}}
QLabel#faint {{
    color: {FG_FAINT};
    font-size: 12px;
}}
QLabel#accent {{
    color: {ACCENT};
}}
QLabel#ok {{
    color: {OK};
}}
QLabel#warn {{
    color: {WARN};
}}
QLabel#danger {{
    color: {DANGER};
}}
QFrame#panel {{
    background-color: {BG_PANEL};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
QFrame#header {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER};
    border-radius: 8px;
}}
QToolTip {{
    background-color: {BG_INPUT};
    border: 1px solid {BORDER_STRONG};
    color: {FG};
    padding: 4px 8px;
}}
"""


def apply(app) -> None:
    app.setStyleSheet(STYLESHEET)
