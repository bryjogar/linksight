"""Tests for Windows UAC elevation check, relaunch mechanism, and loop guard."""

from __future__ import annotations

import ctypes
import os
import sys
from unittest.mock import MagicMock

import pytest

from app import ensure_elevated


@pytest.fixture
def mock_windll(monkeypatch):
    """Provide a mock ctypes.windll for Windows API calls."""
    windll = MagicMock()
    monkeypatch.setattr(ctypes, "windll", windll, raising=False)
    return windll


def test_elevation_already_admin(monkeypatch, mock_windll):
    """When already running as admin on Windows, ensure_elevated returns cleanly without relaunch."""
    monkeypatch.setattr(sys, "platform", "win32")
    mock_windll.shell32.IsUserAnAdmin.return_value = 1

    ensure_elevated(["--demo"])

    assert mock_windll.shell32.IsUserAnAdmin.call_count == 1
    assert mock_windll.shell32.ShellExecuteW.call_count == 0


def test_elevation_not_admin_relaunch_succeeds(monkeypatch, mock_windll):
    """When not running as admin on Windows, ensure_elevated relaunches via ShellExecuteW and exits 0."""
    monkeypatch.setattr(sys, "platform", "win32")
    mock_windll.shell32.IsUserAnAdmin.return_value = 0
    mock_windll.shell32.ShellExecuteW.return_value = 42

    with pytest.raises(SystemExit) as exc_info:
        ensure_elevated(["--demo"])

    assert exc_info.value.code == 0
    assert mock_windll.shell32.ShellExecuteW.call_count == 1

    args = mock_windll.shell32.ShellExecuteW.call_args[0]
    assert args[0] is None
    assert args[1] == "runas"
    assert args[2] == sys.executable
    assert "--demo" in args[3]
    assert "--no-relaunch" in args[3]
    assert args[4] is None
    assert args[5] == 1


def test_elevation_not_admin_uac_declined(monkeypatch, mock_windll, capsys):
    """When UAC elevation is declined (ret <= 32), ensure_elevated exits with error code 1."""
    monkeypatch.setattr(sys, "platform", "win32")
    mock_windll.shell32.IsUserAnAdmin.return_value = 0
    mock_windll.shell32.ShellExecuteW.return_value = 5  # SE_ERR_ACCESSDENIED

    with pytest.raises(SystemExit) as exc_info:
        ensure_elevated([])

    assert exc_info.value.code == 1
    assert mock_windll.shell32.ShellExecuteW.call_count == 1

    captured = capsys.readouterr()
    assert "administrator privileges" in captured.err.lower()


def test_elevation_loop_guard_with_no_relaunch(monkeypatch, mock_windll, capsys):
    """If --no-relaunch is present and still not admin, do not attempt to relaunch again."""
    monkeypatch.setattr(sys, "platform", "win32")
    mock_windll.shell32.IsUserAnAdmin.return_value = 0

    with pytest.raises(SystemExit) as exc_info:
        ensure_elevated(["--no-relaunch"])

    assert exc_info.value.code == 1
    assert mock_windll.shell32.ShellExecuteW.call_count == 0

    captured = capsys.readouterr()
    assert "administrator privileges" in captured.err.lower()


def test_elevation_non_windows(monkeypatch, mock_windll):
    """On non-Windows platforms, ensure_elevated is a no-op."""
    monkeypatch.setattr(sys, "platform", "linux")

    ensure_elevated(["--demo"])

    assert mock_windll.shell32.IsUserAnAdmin.call_count == 0
    assert mock_windll.shell32.ShellExecuteW.call_count == 0


def test_elevation_frozen_relaunch(monkeypatch, mock_windll):
    """In frozen build mode, relaunch does not prepend the script path."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    mock_windll.shell32.IsUserAnAdmin.return_value = 0
    mock_windll.shell32.ShellExecuteW.return_value = 42

    with pytest.raises(SystemExit) as exc_info:
        ensure_elevated(["--demo"])

    assert exc_info.value.code == 0
    params = mock_windll.shell32.ShellExecuteW.call_args[0][3]
    assert params == "--demo --no-relaunch"


def test_elevation_shellexecute_raises_exception(monkeypatch, mock_windll, capsys):
    """If ShellExecuteW raises an exception, exits with code 1 and prints an ASCII error."""
    monkeypatch.setattr(sys, "platform", "win32")
    mock_windll.shell32.IsUserAnAdmin.return_value = 0
    mock_windll.shell32.ShellExecuteW.side_effect = OSError("Access is denied")

    with pytest.raises(SystemExit) as exc_info:
        ensure_elevated([])

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "failed to elevate privileges" in captured.err.lower()
