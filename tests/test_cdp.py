"""Tests for the CDP parser."""

from netprobe.parse.cdp import parse_cdp_frame
from netprobe.parse.frames import parse_frame
from tests.fixtures import build_cdp_frame, CDP_SAMPLE


def test_cdp_basic_fields():
    dev = parse_cdp_frame(CDP_SAMPLE, "eth0")
    assert dev is not None
    assert dev.protocol == "cdp"
    assert dev.system_name == "Core-SW1"
    assert dev.chassis_id == "Core-SW1"
    assert dev.port_id == "Gi0/24"
    assert dev.platform == "cisco WS-C2960X-24TS-L"
    assert "Cisco IOS" in dev.system_description
    assert dev.management_ips == ["10.0.0.2"]
    assert dev.vlan == 100
    assert "L2 Switch" in dev.capabilities
    assert dev.raw_tlvs.get("duplex") == 1


def test_cdp_dispatch_via_parse_frame():
    dev = parse_frame(CDP_SAMPLE, "eth0")
    assert dev is not None
    assert dev.protocol == "cdp"
    assert dev.platform.startswith("cisco")


def test_cdp_snap_variant():
    """CDP is SNAP-encapsulated; EtherType field shows 0x2000 directly in our
    fixture, but some captures expose the LLC/SNAP form. Verify we accept it."""
    frame = build_cdp_frame()
    # Rebuild with SNAP LLC form: dst/src + 0xaaaa + snap(00 00 0c 20 00) then CDP body
    import tests.fixtures as fx
    from netprobe.parse.cdp import CDP_SNAP
    body = frame[14:]
    snap_frame = fx.eth("01:00:0c:cc:cc:cc", "00:1a:2b:3c:4d:5e", 0xAAAA, CDP_SNAP + body)
    dev = parse_frame(snap_frame, "eth0")
    assert dev is not None
    assert dev.protocol == "cdp"
    assert dev.system_name == "Core-SW1"


def test_cdp_rejects_garbage():
    assert parse_cdp_frame(b"\x00" * 40, "eth0") is None
