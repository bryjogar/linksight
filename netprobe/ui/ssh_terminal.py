"""Launch an interactive SSH session to a device in the OS terminal.

Security model: the app passes ONLY the username and IP on the command line.
The password is never touched by NetProbe — the terminal's own `ssh` prompt
collects it interactively, so nothing is stored or logged.
"""

from __future__ import annotations

import shutil
import subprocess
import sys


def launch_ssh_terminal(ip: str, username: str) -> tuple[bool, str]:
    """Open a new terminal window running `ssh <username>@<ip>`.

    Returns (ok, message). The ssh process inherits the terminal, so host-key
    confirmation and the password prompt happen in that window.
    """
    target = f"{username}@{ip}" if username else ip

    if sys.platform == "win32":
        return _launch_windows(target)
    if sys.platform == "darwin":
        return _launch_macos(target)
    return _launch_linux(target)


def _launch_windows(target: str) -> tuple[bool, str]:
    # Prefer Windows Terminal, fall back to a plain cmd window.
    if shutil.which("wt"):
        cmd = ["wt", "ssh", target]
    else:
        cmd = ["cmd", "/c", "start", "cmd", "/k", "ssh", target]
    try:
        subprocess.Popen(cmd)
        return True, f"Opened terminal: ssh {target}"
    except Exception as e:  # pragma: no cover
        return False, f"Failed to open terminal: {e}"


def _launch_macos(target: str) -> tuple[bool, str]:
    script = f'tell application "Terminal" to do script "ssh {target}"'
    try:
        subprocess.Popen(["osascript", "-e", script])
        return True, f"Opened Terminal: ssh {target}"
    except Exception as e:  # pragma: no cover
        return False, f"Failed to open Terminal: {e}"


def _launch_linux(target: str) -> tuple[bool, str]:
    # Try common terminal emulators; fall back to xterm if present.
    for term in ("x-terminal-emulator", "gnome-terminal", "konsole", "xterm"):
        exe = shutil.which(term)
        if not exe:
            continue
        try:
            if term == "gnome-terminal":
                subprocess.Popen([exe, "--", "bash", "-lc", f"ssh {target}"])
            else:
                subprocess.Popen([exe, "-e", f"bash -lc 'ssh {target}'"])
            return True, f"Opened {term}: ssh {target}"
        except Exception as e:  # pragma: no cover
            return False, f"Failed to open {term}: {e}"
    return False, "No terminal emulator found (install xterm or gnome-terminal)."
