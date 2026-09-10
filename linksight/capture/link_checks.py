"""Internet, DNS, and ISP gateway reachability checks.

Executes low-overhead single-probe ping checks through the hardened Windows/Unix
subprocess runner to confirm internet access, distinguishing DNS resolution
failures from ISP/gateway reachability and ICMP timeout/blocking.
"""

from __future__ import annotations

import re
import sys
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from .system_info import _safe_run


@dataclass
class LinkCheckResult:
    target: str | None
    status: str  # "reachable", "unreachable", "timeout", "unavailable", "not_checked"
    message: str
    latency_ms: float | None = None

    @property
    def is_success(self) -> bool:
        return self.status == "reachable"

    @property
    def display_text(self) -> str:
        if self.status == "reachable" and self.latency_ms is not None:
            if self.latency_ms < 1.0:
                return "reachable (<1 ms)"
            return f"reachable ({self.latency_ms:.0f} ms)"
        return self.message


def build_ping_cmd(target: str, platform: str | None = None) -> list[str]:
    """Build platform-specific single-ping command.

    - Windows: -n 1 -w 1000 (1 ping, 1000ms timeout)
    - macOS / Linux: -c 1 -W 1 (1 ping, 1s timeout)
    """
    plat = platform if platform is not None else sys.platform
    if plat == "win32":
        return ["ping", "-n", "1", "-w", "1000", target]
    return ["ping", "-c", "1", "-W", "1", target]


def parse_ping_result(
    target: str | None,
    proc: subprocess.CompletedProcess[str] | None,
) -> LinkCheckResult:
    """Parse ping process outcome into a LinkCheckResult."""
    if not target or not target.strip() or target.strip() == "0.0.0.0":
        return LinkCheckResult(
            target=target,
            status="not_checked",
            message="not checked (no gateway known)",
        )

    if proc is None:
        return LinkCheckResult(
            target=target,
            status="unavailable",
            message="command unavailable",
        )

    if proc.returncode == 124:
        return LinkCheckResult(
            target=target,
            status="timeout",
            message="no reply (ICMP may be blocked)",
        )

    out = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    out_lower = out.lower()

    # 1. Unreachable / name resolution failure indicators
    unreachable_tokens = [
        "destination host unreachable",
        "destination net unreachable",
        "destination unreachable",
        "host unreachable",
        "net unreachable",
        "network unreachable",
        "no route to host",
        "name or service not known",
        "unknown host",
        "could not find host",
        "temporary failure in name resolution",
        "transmit failed",
        "general failure",
    ]
    for token in unreachable_tokens:
        if token in out_lower:
            return LinkCheckResult(
                target=target,
                status="unreachable",
                message="unreachable",
            )

    # 2. Success (returncode == 0 AND reply token)
    has_reply_token = (
        ("bytes from" in out_lower)
        or ("reply from" in out_lower and "bytes=" in out_lower)
    )
    if proc.returncode == 0 and has_reply_token:
        latency_ms: float | None = None
        match = re.search(r"time[=<]([0-9.]+)\s*ms", out_lower)
        if match:
            try:
                latency_ms = float(match.group(1))
            except ValueError:
                pass
        return LinkCheckResult(
            target=target,
            status="reachable",
            message="reachable",
            latency_ms=latency_ms,
        )

    # 3. Timeout indicators
    timeout_tokens = [
        "request timed out",
        "100% packet loss",
        "100.0% packet loss",
        "100% loss",
        "0 packets received",
        "0 received",
        "timed out",
    ]
    for token in timeout_tokens:
        if token in out_lower:
            return LinkCheckResult(
                target=target,
                status="timeout",
                message="no reply (ICMP may be blocked)",
            )

    # 4. Fallback for non-zero exit code
    if proc.returncode != 0:
        if proc.returncode == 127:
            return LinkCheckResult(
                target=target,
                status="unavailable",
                message="command unavailable",
            )
        if not out.strip():
            return LinkCheckResult(
                target=target,
                status="timeout",
                message="no reply (ICMP may be blocked)",
            )
        return LinkCheckResult(
            target=target,
            status="unreachable",
            message="unreachable",
        )

    # Fallback for returncode 0 but missing reply token
    return LinkCheckResult(
        target=target,
        status="timeout",
        message="no reply (ICMP may be blocked)",
    )


def run_ping(
    target: str | None,
    platform: str | None = None,
    timeout: int = 3,
) -> LinkCheckResult:
    """Run a single ping check against target using the hardened subprocess runner."""
    if not target or not target.strip() or target.strip() == "0.0.0.0":
        return parse_ping_result(target, None)

    cmd = build_ping_cmd(target.strip(), platform=platform)
    proc = _safe_run(cmd, timeout=timeout, check_returncode=False)
    return parse_ping_result(target, proc)


def run_all_link_checks(
    gateway: str | None = None,
    platform: str | None = None,
    stop_event: threading.Event | None = None,
) -> dict[str, LinkCheckResult]:
    """Run reachability checks for DNS+internet, Internet, and ISP gateway in parallel."""
    gw_target = gateway.strip() if (gateway and gateway.strip() and gateway.strip() != "0.0.0.0") else None
    targets: dict[str, str | None] = {
        "DNS + internet": "google.com",
        "Internet": "8.8.8.8",
        "ISP": gw_target,
    }

    results: dict[str, LinkCheckResult] = {}
    if stop_event is not None and stop_event.is_set():
        return results

    def _check(name: str, tgt: str | None) -> tuple[str, LinkCheckResult]:
        if stop_event is not None and stop_event.is_set():
            return name, LinkCheckResult(target=tgt, status="not_checked", message="cancelled")
        res = run_ping(tgt, platform=platform)
        return name, res

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(_check, name, tgt) for name, tgt in targets.items()]
        for f in futures:
            try:
                name, res = f.result()
                results[name] = res
            except Exception:
                pass

    return results
