"""Tests for OUI vendor lookup — offline-friendly."""

from netprobe.capture.oui_lookup import lookup_vendor


def test_lookup_unknown_returns_empty():
    """Unknown/short MACs return '' without network calls."""
    assert lookup_vendor("") == ""
    assert lookup_vendor("00:11") == ""
    assert lookup_vendor("ff:ff:ff:ff:ff:ff") == ""
