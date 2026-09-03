"""Regression tests: IPv4-only mgmt selection, two-IP on-link preference,
and bytes-never-render guarantees (field-test feedback 2026-09-03)."""

import pytest

from linksight.discovery.models import (
    PortDiagnostics,
    _prefer_ipv4,
    _prefer_onlink_ip,
)


class TestPreferIpv4:
    def test_prefers_ipv4_over_ipv6(self):
        assert _prefer_ipv4(["2001:db8::1", "192.168.1.5"]) == "192.168.1.5"
        assert _prefer_ipv4(["fe80::1", "10.0.0.2", "2001:db8::1"]) == "10.0.0.2"

    def test_never_returns_ipv6(self):
        assert _prefer_ipv4(["fe80::1", "2001:db8::1"]) == ""
        assert _prefer_ipv4(["2001:db8::1"]) == ""

    def test_skips_apipa_link_local_v4(self):
        assert _prefer_ipv4(["169.254.1.1", "10.0.0.2"]) == "10.0.0.2"
        assert _prefer_ipv4(["169.254.1.1"]) == ""


class TestPortDiagnosticsIpv4Only:
    def test_resyncs_ipv4_even_when_ipv6_preset_and_in_list(self):
        # Field bug: a pre-set IPv6 survived because it was already in the list.
        diag = PortDiagnostics(
            port_id=1,
            neighbor_ip="2001:db8::1",
            neighbor_ips=["2001:db8::1", "10.0.0.2"],
        )
        assert diag.neighbor_ip == "10.0.0.2"

    def test_ipv6_only_list_clears_mgmt(self):
        diag = PortDiagnostics(
            port_id=1,
            neighbor_ip="fe80::1",
            neighbor_ips=["fe80::1", "2001:db8::1"],
        )
        assert diag.neighbor_ip == ""

    def test_single_ipv6_field_cleared(self):
        diag = PortDiagnostics(port_id=1, neighbor_ip="fe80::1", neighbor_ips=[])
        assert diag.neighbor_ip == ""


class TestPreferOnlinkIp:
    def test_prefers_same_24(self):
        ips = ["10.99.0.5", "192.168.10.20"]
        assert _prefer_onlink_ip(ips, "192.168.10.1") == "192.168.10.20"

    def test_falls_back_to_same_16(self):
        ips = ["10.1.1.1", "192.168.200.5"]
        assert _prefer_onlink_ip(ips, "192.168.10.1") == "192.168.200.5"

    def test_no_onlink_keeps_first_v4(self):
        ips = ["172.16.0.9", "10.1.1.1"]
        assert _prefer_onlink_ip(ips, "192.168.10.1") == "172.16.0.9"

    def test_never_returns_ipv6(self):
        assert _prefer_onlink_ip(["fe80::1", "2001:db8::1"], "192.168.10.1") == ""

    def test_v4_and_v6_mixed_prefers_onlink_v4(self):
        ips = ["2001:db8::1", "10.0.0.9", "10.0.1.9"]
        assert _prefer_onlink_ip(ips, "10.0.0.1") == "10.0.0.9"


class TestBytesNeverRender:
    """Bytes or bytes-reprs on any candidate field must never survive into
    display text (field repro: b't\\x83\\x19\\xa4' partial UniFi MAC)."""

    PATTERN_BYTES = b"t\x83\xc2\x19\xa4"
    PATTERN_REPR = "b't\\x83\\xc2\\x19\\xa4'"

    def test_port_id_bytes_normalized(self):
        diag = PortDiagnostics(port_id=self.PATTERN_BYTES)
        assert "b'" not in str(diag.port_id).lower() or "b'" not in str(diag.port_id)
        assert "b'" not in repr(diag.port_id)

    def test_port_id_str_repr_normalized(self):
        diag = PortDiagnostics(port_id=self.PATTERN_REPR)
        assert "b'" not in str(diag.port_id)
        assert "b'" not in repr(diag.port_id)

    def test_numeric_port_id_stays_int(self):
        assert PortDiagnostics(port_id="24").port_id == 24
        assert PortDiagnostics(port_id=24).port_id == 24

    def test_poisoned_fields_never_survive_anywhere(self):
        diag = PortDiagnostics(
            port_id=self.PATTERN_BYTES,
            port_name=self.PATTERN_REPR,
            neighbor_name=self.PATTERN_BYTES,
            neighbor_chassis=self.PATTERN_REPR,
            neighbor_port=self.PATTERN_BYTES,
            neighbor_ip=self.PATTERN_REPR,
            platform=self.PATTERN_REPR,
        )
        blob = str(diag.to_dict())
        assert "b'" not in blob

    def test_poisoned_multiline_name_falls_back_to_chassis(self):
        chassis = "74:83:c2:19:a4:00"
        diag = PortDiagnostics(
            port_id=1,
            neighbor_name=self.PATTERN_BYTES,
            neighbor_chassis=chassis,
        )
        assert diag.neighbor_name == chassis or diag.neighbor_name == ""
        assert "b'" not in diag.neighbor_name


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
