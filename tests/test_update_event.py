"""Tests for the update-notification event (headless-safe)."""

from PySide6.QtCore import QEvent

from linksight.ui.update_event import UpdateAvailableEvent



def test_event_constructs_with_enum_type():
    """PySide6 QEvent needs a Type enum — raw ints throw and kill the link."""
    info = object()
    evt = UpdateAvailableEvent(info)
    assert evt.type() == QEvent.Type.User + 1
    assert evt.update_info is info
