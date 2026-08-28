"""Update-notification event — QtCore only, so it's testable headless.

Regression guard: PySide6's QEvent constructor requires a QEvent.Type enum.
Passing a raw int (wifi-explorer's pattern) throws and silently kills the
update link in packaged builds.
"""

from __future__ import annotations

from PySide6.QtCore import QEvent


class UpdateAvailableEvent(QEvent):
    """Custom event posted from the background update-check thread."""
    _event_type = QEvent.Type.User + 1

    def __init__(self, update_info):
        # PySide6 requires a QEvent.Type enum, not a raw int
        super().__init__(QEvent.Type(self._event_type))
        self.update_info = update_info
