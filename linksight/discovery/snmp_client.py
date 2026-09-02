"""Pure-Python SNMP v2c client with zero native dependencies.

Handles SNMP v2c GET, GETNEXT, and subtree walks over UDP with BER encoding/decoding.
Community strings are held strictly in memory for the process lifetime.
"""

from __future__ import annotations

import random
import socket
import time
from typing import Any, Callable

# ASN.1 / BER Universal Tags
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30

# SNMP Application Tags (RFC 1157 / RFC 1902)
TAG_IPADDRESS = 0x40
TAG_COUNTER32 = 0x41
TAG_GAUGE32 = 0x42
TAG_TIMETICKS = 0x43
TAG_OPAQUE = 0x44
TAG_COUNTER64 = 0x46

# SNMP Context-Specific / Exception Tags
TAG_NOSUCHOBJECT = 0x80
TAG_NOSUCHINSTANCE = 0x81
TAG_ENDOFMIBVIEW = 0x82

# SNMP PDU Tags
PDU_GET_REQUEST = 0xA0
PDU_GET_NEXT_REQUEST = 0xA1
PDU_GET_RESPONSE = 0xA2
PDU_SET_REQUEST = 0xA3
PDU_GET_BULK_REQUEST = 0xA5


class SnmpError(Exception):
    """Base exception for SNMP operations."""
    pass


class SnmpTimeoutError(SnmpError):
    """Raised when an SNMP request times out."""
    pass


class SnmpAuthError(SnmpError):
    """Raised when SNMP community is invalid or authentication fails."""
    pass


SNMP_ERROR_STATUS_MAP = {
    0: "noError",
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}


class EndOfMibView:
    def __repr__(self) -> str:
        return "EndOfMibView"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, EndOfMibView)


class NoSuchObject:
    def __repr__(self) -> str:
        return "NoSuchObject"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, NoSuchObject)


class NoSuchInstance:
    def __repr__(self) -> str:
        return "NoSuchInstance"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, NoSuchInstance)


def encode_len(length: int) -> bytes:
    """Encode BER length octets."""
    if length < 128:
        return bytes([length])
    num_bytes = (length.bit_length() + 7) // 8
    return bytes([0x80 | num_bytes]) + length.to_bytes(num_bytes, "big")


def encode_sequence(payload: bytes) -> bytes:
    """Encode a BER sequence."""
    return bytes([TAG_SEQUENCE]) + encode_len(len(payload)) + payload


def encode_int(val: int, tag: int = TAG_INTEGER) -> bytes:
    """Encode an integer in signed two's complement BER."""
    if val == 0:
        return bytes([tag, 1, 0])
    needed_bits = val.bit_length() + 1
    num_bytes = (needed_bits + 7) // 8
    val_bytes = val.to_bytes(num_bytes, "big", signed=True)
    return bytes([tag, len(val_bytes)]) + val_bytes


def encode_str(s: str | bytes, tag: int = TAG_OCTET_STRING) -> bytes:
    """Encode an octet string."""
    b = s.encode("utf-8") if isinstance(s, str) else s
    return bytes([tag]) + encode_len(len(b)) + b


def encode_null() -> bytes:
    """Encode a BER NULL."""
    return bytes([TAG_NULL, 0x00])


def encode_oid(oid_str: str) -> bytes:
    """Encode a dotted OID string into BER octets."""
    clean = oid_str.strip(".")
    if not clean:
        return bytes([TAG_OID, 0x00])
    parts = [int(p) for p in clean.split(".")]
    if len(parts) < 2:
        return bytes([TAG_OID, 0x00])
    first = 40 * parts[0] + parts[1]
    res = bytearray([first])
    for part in parts[2:]:
        if part == 0:
            res.append(0)
            continue
        chunks = []
        val = part
        while val > 0:
            chunks.append(val & 0x7F)
            val >>= 7
        chunks.reverse()
        for i, chunk in enumerate(chunks):
            if i < len(chunks) - 1:
                res.append(chunk | 0x80)
            else:
                res.append(chunk)
    return bytes([TAG_OID]) + encode_len(len(res)) + bytes(res)


def decode_oid(data: bytes) -> str:
    """Decode BER OID octets into a dotted string."""
    if not data:
        return ""
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if (b & 0x80) == 0:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def decode_tlv(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    """Decode a single TLV entry. Returns (tag, value_bytes, next_pos)."""
    if pos >= len(data):
        raise SnmpError("Unexpected end of data reading tag")
    tag = data[pos]
    pos += 1
    if pos >= len(data):
        raise SnmpError("Unexpected end of data reading length")
    length_byte = data[pos]
    pos += 1
    if length_byte < 128:
        length = length_byte
    else:
        num_octets = length_byte & 0x7F
        if pos + num_octets > len(data):
            raise SnmpError("Invalid multi-byte length in BER TLV")
        length = int.from_bytes(data[pos : pos + num_octets], "big")
        pos += num_octets
    if pos + length > len(data):
        raise SnmpError("TLV value length exceeds packet boundary")
    val_bytes = data[pos : pos + length]
    return tag, val_bytes, pos + length


def decode_value(tag: int, val_bytes: bytes) -> Any:
    """Decode ASN.1 value bytes to Python native types."""
    if tag == TAG_INTEGER:
        return int.from_bytes(val_bytes, "big", signed=True)
    elif tag == TAG_OCTET_STRING:
        try:
            return val_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return val_bytes
    elif tag == TAG_NULL:
        return None
    elif tag == TAG_OID:
        return decode_oid(val_bytes)
    elif tag == TAG_IPADDRESS:
        if len(val_bytes) == 4:
            return ".".join(str(b) for b in val_bytes)
        return val_bytes.hex()
    elif tag in (TAG_COUNTER32, TAG_GAUGE32, TAG_TIMETICKS, TAG_COUNTER64):
        return int.from_bytes(val_bytes, "big", signed=False)
    elif tag == TAG_NOSUCHOBJECT:
        return NoSuchObject()
    elif tag == TAG_NOSUCHINSTANCE:
        return NoSuchInstance()
    elif tag == TAG_ENDOFMIBVIEW:
        return EndOfMibView()
    else:
        return val_bytes


def build_snmp_request(
    community: str,
    pdu_type: int,
    request_id: int,
    varbinds: list[tuple[str, Any]],
    non_repeaters: int = 0,
    max_repetitions: int = 0,
) -> bytes:
    """Build a complete SNMP v2c request message."""
    vb_bytes = bytearray()
    for oid, val in varbinds:
        oid_encoded = encode_oid(oid)
        if val is None:
            val_encoded = encode_null()
        elif isinstance(val, int):
            val_encoded = encode_int(val)
        elif isinstance(val, (str, bytes)):
            val_encoded = encode_str(val)
        else:
            val_encoded = encode_null()
        vb_bytes.extend(encode_sequence(oid_encoded + val_encoded))
    varbind_list = encode_sequence(bytes(vb_bytes))

    if pdu_type == PDU_GET_BULK_REQUEST:
        err_stat = encode_int(non_repeaters)
        err_idx = encode_int(max_repetitions)
    else:
        err_stat = encode_int(0)
        err_idx = encode_int(0)

    pdu_payload = encode_int(request_id) + err_stat + err_idx + varbind_list
    pdu = bytes([pdu_type]) + encode_len(len(pdu_payload)) + pdu_payload

    # Version 1 = SNMPv2c (0 = v1, 1 = v2c)
    msg_payload = encode_int(1) + encode_str(community) + pdu
    return encode_sequence(msg_payload)


def parse_snmp_response(data: bytes) -> tuple[int, str, int, int, int, list[tuple[str, Any]]]:
    """Parse an SNMP response packet.

    Returns (version, community, request_id, error_status, error_index, varbinds).
    """
    tag, msg_bytes, _ = decode_tlv(data, 0)
    if tag != TAG_SEQUENCE:
        raise SnmpError(f"Invalid SNMP message wrapper tag: {tag:#x}")

    pos = 0
    vtag, vbytes, pos = decode_tlv(msg_bytes, pos)
    version = decode_value(vtag, vbytes)
    ctag, cbytes, pos = decode_tlv(msg_bytes, pos)
    community = decode_value(ctag, cbytes)
    ptag, pbytes, _ = decode_tlv(msg_bytes, pos)

    if ptag != PDU_GET_RESPONSE:
        raise SnmpError(f"Unexpected SNMP PDU tag in response: {ptag:#x}")

    ppos = 0
    rtag, rbytes, ppos = decode_tlv(pbytes, ppos)
    req_id = decode_value(rtag, rbytes)
    etag, ebytes, ppos = decode_tlv(pbytes, ppos)
    err_stat = decode_value(etag, ebytes)
    itag, ibytes, ppos = decode_tlv(pbytes, ppos)
    err_idx = decode_value(itag, ibytes)
    _, vbl_bytes, _ = decode_tlv(pbytes, ppos)

    varbinds: list[tuple[str, Any]] = []
    vb_pos = 0
    while vb_pos < len(vbl_bytes):
        _, vb_data, vb_pos = decode_tlv(vbl_bytes, vb_pos)
        item_pos = 0
        _, obytes, item_pos = decode_tlv(vb_data, item_pos)
        oid = decode_oid(obytes)
        val_tag, val_bytes, _ = decode_tlv(vb_data, item_pos)
        val = decode_value(val_tag, val_bytes)
        varbinds.append((oid, val))

    return version, community, req_id, err_stat, err_idx, varbinds


def oid_to_tuple(oid: str) -> tuple[int, ...]:
    """Convert dotted OID string to integer tuple for comparison."""
    parts = oid.strip(".").split(".")
    return tuple(int(p) for p in parts if p.isdigit())


def oid_is_descendant(oid: str, root_oid: str) -> bool:
    """Check if oid is within the subtree of root_oid."""
    o = oid_to_tuple(oid)
    r = oid_to_tuple(root_oid)
    return len(o) > len(r) and o[: len(r)] == r


class SnmpClient:
    """Pure-Python SNMP v2c client."""

    def __init__(
        self,
        host: str,
        community: str = "public",
        port: int = 161,
        timeout: float = 1.5,
        retries: int = 1,
        transport: Callable[[bytes], bytes] | None = None,
    ):
        self.host = host
        # RAM-only community: held only on this instance
        self._community = community
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self._transport = transport
        self._sock: socket.socket | None = None

    def _get_socket(self) -> socket.socket:
        if self._sock is None:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.settimeout(self.timeout)
        return self._sock

    def _send_recv(self, req_bytes: bytes, req_id: int) -> bytes:
        if self._transport is not None:
            try:
                return self._transport(req_bytes)
            except (socket.timeout, TimeoutError):
                raise SnmpTimeoutError(f"SNMP request to {self.host}:{self.port} timed out")
            except OSError as e:
                raise SnmpError(f"SNMP network error: {e}")

        sock = self._get_socket()
        for attempt in range(self.retries + 1):
            try:
                sock.sendto(req_bytes, (self.host, self.port))
                while True:
                    data, _ = sock.recvfrom(65535)
                    # Verify request ID matches
                    try:
                        _, _, resp_req_id, _, _, _ = parse_snmp_response(data)
                        if resp_req_id == req_id:
                            return data
                    except Exception:
                        continue
            except socket.timeout:
                if attempt == self.retries:
                    raise SnmpTimeoutError(f"SNMP request to {self.host}:{self.port} timed out")
            except OSError as e:
                if attempt == self.retries:
                    raise SnmpError(f"SNMP network error: {e}")
        raise SnmpTimeoutError(f"SNMP request to {self.host}:{self.port} timed out")

    def get(self, oids: str | list[str]) -> Any | dict[str, Any]:
        """Perform SNMP GET for one or multiple OIDs."""
        single = isinstance(oids, str)
        oid_list = [oids] if single else oids
        req_id = random.randint(1, 0x7FFFFFFF)
        varbinds_req = [(oid, None) for oid in oid_list]
        req_bytes = build_snmp_request(
            self._community, PDU_GET_REQUEST, req_id, varbinds_req
        )
        resp_data = self._send_recv(req_bytes, req_id)
        _, _, _, err_stat, _, varbinds = parse_snmp_response(resp_data)

        # RFC 1157 / RFC 1905 err_stat == 2 is noSuchName (OID missing on agent)
        if err_stat == 2:
            if single:
                return None
            res_dict = {oid: None for oid in oid_list}
            for oid, val in varbinds:
                if not isinstance(val, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                    res_dict[oid] = val
            return res_dict

        if err_stat == 16:
            raise SnmpAuthError("SNMP community authentication failed (authorizationError)")

        if err_stat != 0:
            err_name = SNMP_ERROR_STATUS_MAP.get(err_stat, f"status {err_stat}")
            raise SnmpError(f"SNMP GET returned error: {err_name} ({err_stat})")

        res_dict = {}
        for oid, val in varbinds:
            if isinstance(val, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                res_dict[oid] = None
            else:
                res_dict[oid] = val

        if single:
            return res_dict.get(oid_list[0])
        return res_dict

    def get_next(self, oid: str) -> tuple[str, Any] | None:
        """Perform SNMP GETNEXT for an OID."""
        req_id = random.randint(1, 0x7FFFFFFF)
        req_bytes = build_snmp_request(
            self._community, PDU_GET_NEXT_REQUEST, req_id, [(oid, None)]
        )
        try:
            resp_data = self._send_recv(req_bytes, req_id)
            _, _, _, err_stat, _, varbinds = parse_snmp_response(resp_data)
        except SnmpError:
            return None

        if err_stat != 0 or not varbinds:
            return None

        next_oid, val = varbinds[0]
        if isinstance(val, (EndOfMibView, NoSuchObject, NoSuchInstance)):
            return None
        return next_oid, val

    def walk(self, root_oid: str, max_rows: int = 1000) -> list[tuple[str, Any]]:
        """Perform a subtree walk under root_oid using GETNEXT."""
        results: list[tuple[str, Any]] = []
        curr_oid = root_oid
        curr_tuple = oid_to_tuple(curr_oid)

        for _ in range(max_rows):
            try:
                nxt = self.get_next(curr_oid)
            except SnmpError:
                break
            if nxt is None:
                break
            next_oid, val = nxt
            next_tuple = oid_to_tuple(next_oid)

            # Check if next_oid is strictly greater and within subtree
            if next_tuple <= curr_tuple:
                break
            if not oid_is_descendant(next_oid, root_oid):
                break

            results.append((next_oid, val))
            curr_oid = next_oid
            curr_tuple = next_tuple

        return results

    def walk_dict(self, root_oid: str) -> dict[str, Any]:
        """Subtree walk returning a dictionary of {oid: value}."""
        return {oid: val for oid, val in self.walk(root_oid)}

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def __enter__(self) -> SnmpClient:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
