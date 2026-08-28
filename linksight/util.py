"""Pure helpers with no Qt dependency (unit-testable anywhere)."""

from __future__ import annotations


def hexdump(data: bytes, max_bytes: int = 1024) -> str:
    """Classic hexdump: offset + 16 bytes hex + ASCII gutter. Truncates."""
    if len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True
    else:
        truncated = False
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        hexpart = f"{hexpart:<47}"
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04x}  {hexpart}  {asc}")
    if truncated:
        lines.append("... (truncated)")
    return "\n".join(lines)
