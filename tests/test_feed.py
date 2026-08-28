"""Tests for the hexdump helper (pure module — no Qt import needed)."""

from netprobe.util import hexdump


def test_hexdump_short():
    out = hexdump(b"\x01\x02\x03\x04")
    assert "0000" in out
    assert "01 02 03 04" in out


def test_hexdump_ascii_gutter():
    out = hexdump(b"hello world")
    assert "hello world" in out


def test_hexdump_nonprintable_dotted():
    out = hexdump(b"\x00\x01\xff")
    assert ".." in out


def test_hexdump_truncates():
    out = hexdump(b"\x00" * 1000, max_bytes=128)
    assert "truncated" in out


def test_hexdump_16_per_line():
    out = hexdump(bytes(range(32)))
    lines = out.splitlines()
    # 2 full lines of 16 bytes
    assert len(lines) == 2
    assert lines[0].startswith("0000")
    assert lines[1].startswith("0010")
