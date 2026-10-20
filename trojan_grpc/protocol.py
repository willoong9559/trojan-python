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
    """The command header of a Trojan request."""

    password: bytes
    command: int
    host: str
    port: int
    payload: bytes


@dataclass(frozen=True)
class UdpPacket:
    """One Trojan UDP-over-TCP packet."""

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


def _parse_address(buffer: bytes, cursor: int) -> Optional[Tuple[str, int, int]]:
    """Parse a SOCKS-style address, returning ``(host, port, next_offset)``."""

    if len(buffer) < cursor + 1:
        return None
    atyp = buffer[cursor]
    cursor += 1
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
            host = bytes(buffer[cursor:end]).decode("idna")
        except UnicodeError as exc:
            raise ProtocolError("invalid Trojan domain name") from exc
        cursor = end
    else:
        raise ProtocolError("unsupported Trojan address type")
    port = struct.unpack(">H", bytes(buffer[cursor : cursor + 2]))[0]
    return host, port, cursor + 2


def _encode_address(host: str, port: int, *, allow_zero_port: bool = False) -> bytes:
    if not (0 if allow_zero_port else 1) <= port <= 65535:
        raise ValueError("port must be in 0..65535" if allow_zero_port else "port must be in 1..65535")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded_host = host.encode("idna")
        if not 1 <= len(encoded_host) <= 255:
            raise ValueError("domain name must contain 1 to 255 encoded bytes")
        return b"\x03" + bytes([len(encoded_host)]) + encoded_host + struct.pack(">H", port)
    return (b"\x01" if address.version == 4 else b"\x04") + address.packed + struct.pack(">H", port)


def parse_trojan_request(buffer: bytes) -> Optional[Tuple[TrojanRequest, int]]:
    """Parse a complete Trojan CONNECT or UDP ASSOCIATE header."""

    # password(56) + CRLF + command + ATYP is the smallest useful prefix.
    if len(buffer) < 60:
        return None
    if len(buffer) > MAX_TROJAN_HEADER:
        raise ProtocolError("Trojan request header exceeds 64 KiB")

    password = buffer[:56]
    if buffer[56:58] != b"\r\n":
        raise ProtocolError("missing CRLF after Trojan password")
    command = buffer[58]
    if command not in (1, 3):
        raise ProtocolError("unsupported Trojan command")
    address = _parse_address(buffer, 59)
    if address is None:
        return None
    host, port, cursor = address
    if buffer[cursor : cursor + 2] != b"\r\n":
        if len(buffer) < cursor + 2:
            return None
        raise ProtocolError("missing CRLF after Trojan address")
    cursor += 2
    return TrojanRequest(password, command, host, port, buffer[cursor:]), cursor


def build_trojan_connect(password: str, host: str, port: int, payload: bytes = b"") -> bytes:
    """Build a CONNECT request; useful for compatibility tests and examples."""

    return build_trojan_request(password, 1, host, port, payload)


def build_trojan_request(password: str, command: int, host: str, port: int, payload: bytes = b"") -> bytes:
    """Build either a CONNECT (1) or UDP ASSOCIATE (3) Trojan request."""

    if command not in (1, 3):
        raise ValueError("command must be CONNECT (1) or UDP ASSOCIATE (3)")
    return password_to_hex(password) + b"\r\n" + bytes([command]) + _encode_address(
        host, port, allow_zero_port=command == 3
    ) + b"\r\n" + payload


def encode_udp_packet(packet: UdpPacket) -> bytes:
    """Encode an individual Trojan UDP-over-TCP packet."""

    if len(packet.payload) > 65535:
        raise ValueError("UDP payload exceeds the Trojan 65535-byte limit")
    return _encode_address(packet.host, packet.port) + struct.pack(">H", len(packet.payload)) + b"\r\n" + packet.payload


def pop_udp_packets(buffer: bytearray, max_payload_size: int = 65535) -> list[UdpPacket]:
    """Remove all complete Trojan UDP packets currently available in *buffer*."""

    packets: list[UdpPacket] = []
    while buffer:
        address = _parse_address(buffer, 0)
        if address is None:
            break
        host, port, cursor = address
        if len(buffer) < cursor + 4:
            break
        payload_size = struct.unpack(">H", bytes(buffer[cursor : cursor + 2]))[0]
        if payload_size > max_payload_size:
            raise ProtocolError("UDP payload exceeds configured limit")
        if buffer[cursor + 2 : cursor + 4] != b"\r\n":
            raise ProtocolError("missing CRLF before UDP payload")
        frame_size = cursor + 4 + payload_size
        if len(buffer) < frame_size:
            break
        packets.append(UdpPacket(host, port, bytes(buffer[cursor + 4 : frame_size])))
        del buffer[:frame_size]
    return packets
