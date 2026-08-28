"""Update checker — polls GitHub for newer commits (same pattern as wifi-explorer)."""

from __future__ import annotations

import json
import ssl
import urllib.request
from dataclasses import dataclass


@dataclass
class UpdateInfo:
    latest_sha: str
    current_sha: str
    message: str
    url: str


def check_for_updates(current_sha: str) -> UpdateInfo | None:
    """Check GitHub for newer commits. Returns info if an update is available.

    Non-blocking — caller should run in a background thread.
    Timeout: 5 seconds. Returns None on network/API errors.
    """
    if not current_sha or current_sha == "unknown":
        return None

    url = (
        "https://api.github.com/repos/bryjogar/"
        "self-hosted-and-hyper-personal/commits/main"
    )
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "NetProbe-UpdateCheck/0.1",
            },
        )
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            data = json.loads(resp.read())

        latest = data["sha"]
        if latest[:7] == current_sha[:7]:
            return None  # up to date

        return UpdateInfo(
            latest_sha=latest[:7],
            current_sha=current_sha[:7],
            message=data["commit"]["message"].split("\n")[0][:80],
            url="https://github.com/bryjogar/self-hosted-and-hyper-personal/releases/latest",
        )
    except Exception:
        return None
