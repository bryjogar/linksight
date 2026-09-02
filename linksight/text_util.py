"""Safe text decoding utilities for SNMP and network discovery."""

from __future__ import annotations

import ast
from typing import Any


def is_printable_text(s: str) -> bool:
    """Check if string contains clean printable text.

    Rejects control characters other than tab, newline, and carriage return.
    Also rejects strings where more than 10% of characters are non-printable.
    """
    if not s:
        return True
    non_printable = 0
    for ch in s:
        if ch in ("\t", "\n", "\r"):
            continue
        code = ord(ch)
        # Control characters: ASCII < 32 or DEL (127) or C1 controls (128-159)
        if code < 32 or (127 <= code <= 159):
            return False
        if not ch.isprintable():
            non_printable += 1
    if (non_printable / len(s)) > 0.10:
        return False
    return True


_is_printable_text = is_printable_text


def decode_text(val: Any) -> str | None:
    """Safely decode SNMP or network value to clean printable text.

    - str: returns as-is (stripped). If it is a Python bytes repr (b'...'),
      unwraps and evaluates the inner bytes safely. If it contains control
      characters or >10% non-printable characters, returns None.
    - bytes: attempts UTF-8 decode; falls back to latin-1; if the decoded
      result contains control characters other than \\t\\n\\r or has a low
      printable ratio (>10% non-printable), returns None (not text; MAC/opaque).
    - clean scalar (int, float, but not bool): returns str(val).
    - anything else (None, MIB sentinels, lists, dicts, etc.): returns None.
    """
    if val is None:
        return None

    # Check for SNMP sentinel types by name to avoid tight coupling
    if hasattr(val, "__class__") and val.__class__.__name__ in (
        "NoSuchObject",
        "NoSuchInstance",
        "EndOfMibView",
    ):
        return None

    if isinstance(val, (bytes, bytearray)):
        b = bytes(val)
        if not b:
            return ""
        if all(x == 0 for x in b):
            return None
        try:
            s = b.decode("utf-8")
        except UnicodeDecodeError:
            try:
                s = b.decode("latin-1")
            except Exception:
                return None
        cleaned = s.rstrip("\x00").strip()
        if not cleaned:
            return ""
        if not is_printable_text(cleaned):
            return None
        return cleaned

    if isinstance(val, str):
        s = val.strip()
        if (s.startswith("b'") and s.endswith("'")) or (s.startswith('b"') and s.endswith('"')):
            try:
                evaluated = ast.literal_eval(s)
                if isinstance(evaluated, (bytes, bytearray)):
                    return decode_text(evaluated)
            except Exception:
                return None
        cleaned = s.rstrip("\x00").strip()
        if not cleaned:
            return ""
        if "b'" in cleaned or 'b"' in cleaned:
            idx = cleaned.find("b'")
            if idx != -1:
                return None
        if not is_printable_text(cleaned):
            return None
        return cleaned

    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return str(val)

    return None


_decode_text = decode_text


def decode_port_id(val: Any) -> str:
    """Decode a port identifier from SNMP/LLDP value.

    Returns printable text if valid, formatted MAC address if 6/8 bytes,
    hex string for other binary octets, or empty string. Never returns a bytes repr.
    """
    text = decode_text(val)
    if text:
        return text
    if isinstance(val, (bytes, bytearray)):
        b = bytes(val)
        if len(b) in (6, 8):
            return ":".join(f"{x:02x}" for x in b)
        return b.hex()
    return ""


_decode_port_id = decode_port_id


def format_mac(val: Any) -> str:
    """Format MAC address octets or string into aa:bb:cc:dd:ee:ff."""
    if val is None:
        return ""
    if hasattr(val, "__class__") and val.__class__.__name__ in (
        "NoSuchObject",
        "NoSuchInstance",
        "EndOfMibView",
    ):
        return ""
    if isinstance(val, (bytes, bytearray)):
        b = bytes(val)
        if len(b) in (6, 8):
            return ":".join(f"{x:02x}" for x in b)
        try:
            text = b.decode("utf-8")
            if text.isprintable() and len(text) <= 64:
                return text
        except (UnicodeDecodeError, Exception):
            pass
        return ":".join(f"{x:02x}" for x in b)
    if isinstance(val, str):
        s = val.strip()
        if (s.startswith("b'") and s.endswith("'")) or (s.startswith('b"') and s.endswith('"')):
            try:
                evaluated = ast.literal_eval(s)
                if isinstance(evaluated, (bytes, bytearray)):
                    return format_mac(evaluated)
            except Exception:
                return ""
        cleaned_hex = s.replace("-", "").replace(":", "").replace(".", "").lower()
        if len(cleaned_hex) in (12, 16) and all(c in "0123456789abcdef" for c in cleaned_hex):
            return ":".join(cleaned_hex[i : i + 2] for i in range(0, len(cleaned_hex), 2))
        if is_printable_text(s) and "b'" not in s:
            return s
        return ""
    return ""


_format_mac = format_mac


def decode_ip_address(val: Any) -> str | None:
    """Decode IP address from bytes, str, or OCTET STRING."""
    if not val:
        return None
    if hasattr(val, "__class__") and val.__class__.__name__ in (
        "NoSuchObject",
        "NoSuchInstance",
        "EndOfMibView",
    ):
        return None
    if isinstance(val, (bytes, bytearray)):
        b = bytes(val)
        if len(b) == 4:
            return ".".join(str(x) for x in b)
        try:
            val = b.decode("utf-8", "ignore")
        except Exception:
            return None
    if isinstance(val, str):
        s = val.strip()
        if (s.startswith("b'") and s.endswith("'")) or (s.startswith('b"') and s.endswith('"')):
            try:
                evaluated = ast.literal_eval(s)
                if isinstance(evaluated, (bytes, bytearray)):
                    return decode_ip_address(evaluated)
            except Exception:
                return None
        if "." in s and all(part.isdigit() for part in s.split(".") if part):
            return s
        if len(s) == 4:
            return ".".join(str(ord(c)) for c in s)
    return None


_decode_ip_address = decode_ip_address
