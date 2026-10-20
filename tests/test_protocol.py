import unittest

from trojan_grpc.protocol import (
    ProtocolError,
    build_trojan_connect,
    encode_grpc_message,
    parse_trojan_request,
    pop_grpc_messages,
)


class ProtocolTests(unittest.TestCase):
    def test_grpc_frame_can_arrive_in_pieces(self):
        frame = encode_grpc_message(b"hello")
        buffered = bytearray(frame[:4])
        self.assertEqual(pop_grpc_messages(buffered, 1024), [])
        buffered.extend(frame[4:])
        self.assertEqual(pop_grpc_messages(buffered, 1024), [b"hello"])
        self.assertEqual(buffered, b"")

    def test_trojan_connect_with_domain_and_early_payload(self):
        raw = build_trojan_connect("password", "example.com", 443, b"GET /")
        parsed = parse_trojan_request(raw)
        self.assertIsNotNone(parsed)
        request, consumed = parsed
        self.assertEqual(consumed, len(raw) - len(b"GET /"))
        self.assertEqual((request.host, request.port, request.payload), ("example.com", 443, b"GET /"))

    def test_rejects_compressed_grpc_message(self):
        with self.assertRaises(ProtocolError):
            pop_grpc_messages(bytearray(b"\x01\x00\x00\x00\x00"), 1024)
