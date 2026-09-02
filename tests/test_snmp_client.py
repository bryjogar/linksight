"""Unit tests for pure-Python SNMP client and BER encoder/decoder."""

from __future__ import annotations

import pytest

from linksight.discovery.snmp_client import (
    SnmpClient,
    SnmpError,
    SnmpTimeoutError,
    EndOfMibView,
    NoSuchObject,
    NoSuchInstance,
    encode_int,
    encode_len,
    encode_oid,
    encode_str,
    encode_null,
    decode_oid,
    decode_tlv,
    decode_value,
    build_snmp_request,
    parse_snmp_response,
    oid_is_descendant,
    oid_to_tuple,
    PDU_GET_REQUEST,
    PDU_GET_NEXT_REQUEST,
    PDU_GET_RESPONSE,
)


def test_ber_encode_decode_int():
    """Verify BER integer encoding and decoding for zero, positive, negative, and multi-byte values."""
    test_cases = [0, 1, -1, 42, 127, 128, 255, 256, 65535, -32768, 1000000]
    for val in test_cases:
        enc = encode_int(val)
        tag, val_bytes, _ = decode_tlv(enc, 0)
        assert tag == 0x02
        dec = decode_value(tag, val_bytes)
        assert dec == val


def test_ber_encode_decode_oid():
    """Verify BER OID encoding and decoding."""
    oids = [
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.5.0",
        "1.3.6.1.2.1.17.2.7.0",
        "1.0.8802.1.1.2.1.4.1.1.9.0.24.1",
        "1.3.6.1.4.1.9.9.23.1.2.1.1.4.1.1",
    ]
    for oid in oids:
        enc = encode_oid(oid)
        tag, val_bytes, _ = decode_tlv(enc, 0)
        assert tag == 0x06
        dec = decode_oid(val_bytes)
        assert dec == oid


def test_ber_encode_decode_string_and_null():
    """Verify BER string and null encoding/decoding."""
    s = "public"
    enc_s = encode_str(s)
    tag, val_bytes, _ = decode_tlv(enc_s, 0)
    assert tag == 0x04
    assert decode_value(tag, val_bytes) == s

    enc_null = encode_null()
    tag, val_bytes, _ = decode_tlv(enc_null, 0)
    assert tag == 0x05
    assert decode_value(tag, val_bytes) is None


def test_oid_helpers():
    """Verify OID comparison and descendant checks."""
    assert oid_to_tuple("1.3.6.1.2.1.1.1.0") == (1, 3, 6, 1, 2, 1, 1, 1, 0)
    assert oid_is_descendant("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1")
    assert not oid_is_descendant("1.3.6.1.2.1.2.1.1.0", "1.3.6.1.2.1.1")
    assert not oid_is_descendant("1.3.6.1.2.1.1", "1.3.6.1.2.1.1")


def test_build_and_parse_snmp_packets():
    """Verify building an SNMP request and parsing an SNMP response."""
    req_id = 998877
    req_bytes = build_snmp_request(
        community="secret_comm",
        pdu_type=PDU_GET_REQUEST,
        request_id=req_id,
        varbinds=[("1.3.6.1.2.1.1.5.0", None)],
    )
    assert isinstance(req_bytes, bytes)
    assert len(req_bytes) > 0

    # Build a simulated response packet
    resp_bytes = build_snmp_request(
        community="secret_comm",
        pdu_type=PDU_GET_RESPONSE,
        request_id=req_id,
        varbinds=[("1.3.6.1.2.1.1.5.0", "Core-Switch-01")],
    )

    ver, comm, parsed_req_id, err_stat, err_idx, varbinds = parse_snmp_response(resp_bytes)
    assert ver == 1
    assert comm == "secret_comm"
    assert parsed_req_id == req_id
    assert err_stat == 0
    assert err_idx == 0
    assert len(varbinds) == 1
    assert varbinds[0] == ("1.3.6.1.2.1.1.5.0", "Core-Switch-01")


def test_snmp_client_mock_transport():
    """Verify SnmpClient GET, GETNEXT, and walk using a mock transport."""
    # Simulated MIB store
    mib_store = {
        "1.3.6.1.2.1.1.1.0": "Cisco IOS Switch",
        "1.3.6.1.2.1.1.5.0": "Dist-SW1",
        "1.3.6.1.2.1.17.2.7.0": 24,
        "1.3.6.1.2.1.31.1.1.1.1.1": "Gi0/1",
        "1.3.6.1.2.1.31.1.1.1.1.2": "Gi0/2",
        "1.3.6.1.2.1.31.1.1.1.1.24": "Gi0/24",
    }
    sorted_oids = sorted(mib_store.keys(), key=oid_to_tuple)

    def mock_transport(req_bytes: bytes) -> bytes:
        tag, msg_bytes, _ = decode_tlv(req_bytes, 0)
        pos = 0
        _, vbytes, pos = decode_tlv(msg_bytes, pos)
        _, cbytes, pos = decode_tlv(msg_bytes, pos)
        comm = decode_value(0x04, cbytes)
        ptag, pbytes, _ = decode_tlv(msg_bytes, pos)

        ppos = 0
        _, rbytes, ppos = decode_tlv(pbytes, ppos)
        req_id = decode_value(0x02, rbytes)
        _, _, ppos = decode_tlv(pbytes, ppos)
        _, _, ppos = decode_tlv(pbytes, ppos)
        _, vbl_bytes, _ = decode_tlv(pbytes, ppos)

        # decode requested OIDs
        requested_oids = []
        vb_pos = 0
        while vb_pos < len(vbl_bytes):
            _, vb_data, vb_pos = decode_tlv(vbl_bytes, vb_pos)
            item_pos = 0
            _, obytes, item_pos = decode_tlv(vb_data, item_pos)
            requested_oids.append(decode_oid(obytes))

        resp_varbinds = []
        if ptag == PDU_GET_REQUEST:
            for roid in requested_oids:
                val = mib_store.get(roid, NoSuchObject())
                resp_varbinds.append((roid, val))
        elif ptag == PDU_GET_NEXT_REQUEST:
            roid = requested_oids[0]
            req_tuple = oid_to_tuple(roid)
            found = False
            for cand in sorted_oids:
                if oid_to_tuple(cand) > req_tuple:
                    resp_varbinds.append((cand, mib_store[cand]))
                    found = True
                    break
            if not found:
                resp_varbinds.append((roid, EndOfMibView()))

        return build_snmp_request(
            community=comm,
            pdu_type=PDU_GET_RESPONSE,
            request_id=req_id,
            varbinds=resp_varbinds,
        )

    client = SnmpClient("10.0.0.1", community="test_comm", transport=mock_transport)

    # Test single GET
    sysname = client.get("1.3.6.1.2.1.1.5.0")
    assert sysname == "Dist-SW1"

    # Test multi GET
    multi = client.get(["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.17.2.7.0"])
    assert multi["1.3.6.1.2.1.1.1.0"] == "Cisco IOS Switch"
    assert multi["1.3.6.1.2.1.17.2.7.0"] == 24

    # Test GETNEXT
    nxt = client.get_next("1.3.6.1.2.1.1.1.0")
    assert nxt is not None
    assert nxt[0] == "1.3.6.1.2.1.1.5.0"
    assert nxt[1] == "Dist-SW1"

    # Test Walk
    walked = client.walk("1.3.6.1.2.1.31.1.1.1.1")
    assert len(walked) == 3
    assert walked[0] == ("1.3.6.1.2.1.31.1.1.1.1.1", "Gi0/1")
    assert walked[1] == ("1.3.6.1.2.1.31.1.1.1.1.2", "Gi0/2")
    assert walked[2] == ("1.3.6.1.2.1.31.1.1.1.1.24", "Gi0/24")

    client.close()


def test_snmp_client_timeout():
    """Verify SnmpClient raises SnmpTimeoutError on timeout."""
    def timeout_transport(req: bytes) -> bytes:
        import socket
        raise socket.timeout("timed out")

    client = SnmpClient("192.0.2.1", community="public", retries=0, transport=timeout_transport)
    with pytest.raises(SnmpTimeoutError):
        client.get("1.3.6.1.2.1.1.1.0")
