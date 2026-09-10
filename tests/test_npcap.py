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


def test_npcap_installed_tool_failure_returns_none(monkeypatch):
    """When sc query tool execution fails and dirs don't exist, must return None, never False."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr("linksight.capture.npcap._safe_run", lambda *a, **k: None)
    monkeypatch.setattr("pathlib.Path.exists", lambda self: False)
    assert npcap.npcap_installed() is None


def test_npcap_installed_service_found(monkeypatch):
    """When sc query succeeds and reports npcap service, returns True."""
    import subprocess
    monkeypatch.setattr(sys, "platform", "win32")
    proc = subprocess.CompletedProcess(
        ["sc", "query", "npcap"], returncode=0, stdout="SERVICE_NAME: npcap\nSTATE: RUNNING", stderr=""
    )
    monkeypatch.setattr("linksight.capture.npcap._safe_run", lambda *a, **k: proc)
    assert npcap.npcap_installed() is True


def test_npcap_installed_service_not_found(monkeypatch):
    """When sc query cleanly reports service absent (exit code 1060), returns False."""
    import subprocess
    monkeypatch.setattr(sys, "platform", "win32")
    proc = subprocess.CompletedProcess(
        ["sc", "query", "npcap"], returncode=1060, stdout="", stderr="The specified service does not exist"
    )
    monkeypatch.setattr("linksight.capture.npcap._safe_run", lambda *a, **k: proc)
    monkeypatch.setattr("pathlib.Path.exists", lambda self: False)
    assert npcap.npcap_installed() is False


def test_safe_run_passes_windows_flags(monkeypatch):
    """_safe_run must pass stdin=DEVNULL and CREATE_NO_WINDOW on Windows."""
    import subprocess
    from linksight.capture.system_info import _safe_run

    captured_kwargs = {}

    def fake_run(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return subprocess.CompletedProcess(args[0], returncode=0, stdout="output", stderr="")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "run", fake_run)

    res = _safe_run(["dummy_cmd"], timeout=5)
    assert res is not None
    assert captured_kwargs.get("stdin") == subprocess.DEVNULL
    assert captured_kwargs.get("creationflags") == getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


def test_system_info_run_distinguishes_failure(monkeypatch):
    """_run must return None on tool failure and empty string on empty output."""
    from linksight.capture.system_info import _run, _safe_run

    monkeypatch.setattr("linksight.capture.system_info._safe_run", lambda *a, **k: None)
    assert _run(["fail_cmd"]) is None

    import subprocess
    empty_proc = subprocess.CompletedProcess(["empty_cmd"], returncode=0, stdout="", stderr="")
    monkeypatch.setattr("linksight.capture.system_info._safe_run", lambda *a, **k: empty_proc)
    assert _run(["empty_cmd"]) == ""
