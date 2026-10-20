"""Wire-format helpers for Trojan and the gRPC Hunk protobuf message."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import struct
from typing import Optional, Tuple


MAX_TROJAN_HEADER = 64 * 1024


class ProtocolError(ValueError):
    """The peer sent an invalid Trojan or gRPC frame."""


@dataclass(frozen=True)
class TrojanRequest:
    """The CONNECT portion of a Trojan request."""

    password: bytes
    host: str
    port: int
    payload: bytes


def password_to_hex(password: str) -> bytes:
    """Return the 56-byte SHA-224 hexadecimal Trojan password representation."""

    return hashlib.sha224(password.encode("utf-8")).hexdigest().encode("ascii")


def _decode_varint(data: bytes, offset: int) -> Optional[Tuple[int, int]]:
    value = 0
    for index in range(10):
        position = offset + index
        if position >= len(data):
            return None
        byte = data[position]
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return value, index + 1
    raise ProtocolError("protobuf varint is longer than 10 bytes")


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot encode a negative value")
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        encoded.append(byte | 0x80 if value else byte)
        if not value:
            return bytes(encoded)


def encode_grpc_message(payload: bytes) -> bytes:
    """Encode a v2ray-compatible gRPC ``Hunk { bytes data = 1; }`` message."""

    protobuf = b"\x0a" + _encode_varint(len(payload)) + payload
    return b"\x00" + struct.pack(">I", len(protobuf)) + protobuf


def pop_grpc_messages(buffer: bytearray, max_message_size: int) -> list[bytes]:
    """Remove complete uncompressed Hunk messages from *buffer*.

    HTTP/2 DATA boundaries do not correspond to gRPC message boundaries, so the
    caller keeps this buffer for the lifetime of an HTTP/2 stream.
    """

    messages: list[bytes] = []
    while len(buffer) >= 5:
        if buffer[0] != 0:
            raise ProtocolError("compressed gRPC messages are unsupported")
        protobuf_size = struct.unpack(">I", buffer[1:5])[0]
        if protobuf_size > max_message_size + 11:
            raise ProtocolError("gRPC message exceeds configured limit")
        frame_size = 5 + protobuf_size
        if len(buffer) < frame_size:
            break
        protobuf = bytes(buffer[5:frame_size])
        del buffer[:frame_size]
        if not protobuf or protobuf[0] != 0x0A:
            raise ProtocolError("expected Hunk.data protobuf field")
        decoded = _decode_varint(protobuf, 1)
        if decoded is None:
            raise ProtocolError("incomplete Hunk length")
        payload_size, length_size = decoded
        payload_offset = 1 + length_size
        if payload_offset + payload_size != len(protobuf):
            raise ProtocolError("Hunk payload length does not match gRPC frame")
        if payload_size > max_message_size:
            raise ProtocolError("Hunk payload exceeds configured limit")
        messages.append(protobuf[payload_offset:])
    return messages


def parse_trojan_request(buffer: bytes) -> Optional[Tuple[TrojanRequest, int]]:
    """Parse a complete Trojan CONNECT header, or return ``None`` if partial."""

    # password(56) + CRLF + command + ATYP is the smallest useful prefix.
    if len(buffer) < 60:
        return None
    if len(buffer) > MAX_TROJAN_HEADER:
        raise ProtocolError("Trojan request header exceeds 64 KiB")

    password = buffer[:56]
    if buffer[56:58] != b"\r\n":
        raise ProtocolError("missing CRLF after Trojan password")
    if buffer[58] != 1:
        raise ProtocolError("this compact server supports CONNECT only")
    atyp = buffer[59]
    cursor = 60

    if atyp == 1:
        end = cursor + 4
        if len(buffer) < end + 2:
            return None
        host = str(ipaddress.IPv4Address(bytes(buffer[cursor:end])))
        cursor = end
    elif atyp == 4:
        end = cursor + 16
        if len(buffer) < end + 2:
            return None
        host = str(ipaddress.IPv6Address(bytes(buffer[cursor:end])))
        cursor = end
    elif atyp == 3:
        if len(buffer) < cursor + 1:
            return None
        name_length = buffer[cursor]
        cursor += 1
        end = cursor + name_length
        if not name_length:
            raise ProtocolError("Trojan domain must not be empty")
        if len(buffer) < end + 2:
            return None
        try:
            host = buffer[cursor:end].decode("idna")
        except UnicodeError as exc:
            raise ProtocolError("invalid Trojan domain name") from exc
        cursor = end
    else:
        raise ProtocolError("unsupported Trojan address type")

    port = struct.unpack(">H", buffer[cursor : cursor + 2])[0]
    cursor += 2
    if buffer[cursor : cursor + 2] != b"\r\n":
        if len(buffer) < cursor + 2:
            return None
        raise ProtocolError("missing CRLF after Trojan address")
    cursor += 2
    return TrojanRequest(password, host, port, buffer[cursor:]), cursor


def build_trojan_connect(password: str, host: str, port: int, payload: bytes = b"") -> bytes:
    """Build a CONNECT request; useful for compatibility tests and examples."""

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded_host = host.encode("idna")
        if not 1 <= len(encoded_host) <= 255:
            raise ValueError("domain name must contain 1 to 255 encoded bytes")
        encoded_address = b"\x03" + bytes([len(encoded_host)]) + encoded_host
    else:
        encoded_address = (b"\x01" if address.version == 4 else b"\x04") + address.packed
    if not 1 <= port <= 65535:
        raise ValueError("port must be in 1..65535")
    return password_to_hex(password) + b"\r\n\x01" + encoded_address + struct.pack(">H", port) + b"\r\n" + payload
