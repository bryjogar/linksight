"""Global pytest configuration for LinkSight test suite."""

import os
import subprocess
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(autouse=True)
def _mock_ping_subprocess(monkeypatch):
    """Ensure no real ping commands are run during the test suite."""
    from linksight.capture import system_info
    orig_safe_run = system_info._safe_run

    def safe_run_stub(cmd, timeout=8, check_returncode=True):
        if cmd and cmd[0] == "ping":
            return subprocess.CompletedProcess(
                cmd,
                returncode=0,
                stdout="64 bytes from 8.8.8.8: icmp_seq=1 ttl=116 time=10.0 ms\n",
                stderr="",
            )
        return orig_safe_run(cmd, timeout=timeout, check_returncode=check_returncode)

    monkeypatch.setattr("linksight.capture.system_info._safe_run", safe_run_stub)
    monkeypatch.setattr("linksight.capture.link_checks._safe_run", safe_run_stub)

