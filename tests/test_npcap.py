"""Tests for Npcap detection (Windows-only behavior; safe on other platforms)."""

import sys

from linksight.capture import npcap



def test_npcap_installed_none_on_non_windows():
    """On non-Windows, npcap_installed() must return None (not applicable)."""
    if sys.platform != "win32":
        assert npcap.npcap_installed() is None


def test_npcap_detection_returns_bool_or_none():
    """On Windows it must return a bool; elsewhere None."""
    result = npcap.npcap_installed()
    if sys.platform == "win32":
        assert isinstance(result, bool)
    else:
        assert result is None


def test_constants_present():
    assert npcap.NPCAP_DIST_URL.startswith("https://")
    assert npcap.NPCAP_DOWNLOAD_PAGE.startswith("https://")
