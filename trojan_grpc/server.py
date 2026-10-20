"""Asyncio Trojan-over-gRPC server.

The implementation intentionally covers only the interoperable core: HTTP/2
(h2c or TLS), ``/<service>/Tun`` streams, Trojan TCP CONNECT, and Hunk framing.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hmac
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

import h2.config
import h2.connection
import h2.events
import h2.settings

from .protocol import (
    MAX_TROJAN_HEADER,
    ProtocolError,
    UdpPacket,
    encode_udp_packet,
    encode_grpc_message,
    parse_trojan_request,
    password_to_hex,
    pop_grpc_messages,
    pop_udp_packets,
)

LOG = logging.getLogger("trojan_grpc")


@dataclass
class ServerOptions:
    password: str
    service_name: Optional[str] = None
    max_streams: int = 128
    max_message_size: int = 16 * 1024
    max_pending_input: int = 256 * 1024
    connect_timeout: float = 10.0
    enable_udp: bool = True
    udp_idle_timeout: float = 60.0
    # Leave room for an IPv6 Trojan UDP packet header in one Hunk message.
    max_udp_payload: int = 16 * 1024 - 22


class UdpReceiver(asyncio.DatagramProtocol):
    """Places datagrams from one association socket into a bounded queue."""

    def __init__(self, queue: "asyncio.Queue[tuple[bytes, tuple]]") -> None:
        self.queue = queue

    def datagram_received(self, data: bytes, address: tuple) -> None:
        try:
            self.queue.put_nowait((data, address))
        except asyncio.QueueFull:
            LOG.debug("dropping UDP response because the association queue is full")

    def error_received(self, exc: Exception) -> None:
        LOG.debug("UDP socket error: %s", exc)


@dataclass
class Tunnel:
    stream_id: int
    connection: "H2ServerConnection"
    inbound: "asyncio.Queue[Optional[bytes]]" = field(default_factory=asyncio.Queue)
    grpc_buffer: bytearray = field(default_factory=bytearray)
    buffered_input: int = 0
    worker: Optional[asyncio.Task[None]] = None
    target_reader: Optional[asyncio.StreamReader] = None
    target_writer: Optional[asyncio.StreamWriter] = None
    command: Optional[int] = None
    udp_buffer: bytearray = field(default_factory=bytearray)
    udp_queue: "asyncio.Queue[tuple[bytes, tuple]]" = field(default_factory=lambda: asyncio.Queue(maxsize=64))
    udp_transports: Dict[int, asyncio.DatagramTransport] = field(default_factory=dict)
    udp_response_task: Optional[asyncio.Task[None]] = None
    last_udp_activity: float = field(default_factory=time.monotonic)
    closed: bool = False

    def start(self) -> None:
        self.worker = asyncio.create_task(self._run(), name=f"trojan-stream-{self.stream_id}")

    def queue_payload(self, payload: bytes) -> None:
        self.buffered_input += len(payload)
        if self.buffered_input > self.connection.options.max_pending_input:
            raise ProtocolError("per-stream pending input limit exceeded")
        self.inbound.put_nowait(payload)

    def input_ended(self) -> None:
        if not self.closed:
            self.inbound.put_nowait(None)

    async def _run(self) -> None:
        header_buffer = bytearray()
        target_task: Optional[asyncio.Task[None]] = None
        try:
            while True:
                try:
                    payload = (
                        await asyncio.wait_for(self.inbound.get(), self.connection.options.udp_idle_timeout)
                        if self.command == 3
                        else await self.inbound.get()
                    )
                except asyncio.TimeoutError:
                    if time.monotonic() - self.last_udp_activity >= self.connection.options.udp_idle_timeout:
                        LOG.info("stream %s UDP association timed out", self.stream_id)
                        break
                    continue
                if payload is None:
                    if self.command is None:
                        raise ProtocolError("stream ended before complete Trojan request")
                    if self.command == 1:
                        assert self.target_writer is not None
                        self.target_writer.write_eof()
                        await self.target_writer.drain()
                    break
                self.buffered_input -= len(payload)

                if self.command is None:
                    header_buffer.extend(payload)
                    if len(header_buffer) > MAX_TROJAN_HEADER:
                        raise ProtocolError("Trojan request header exceeds 64 KiB")
                    parsed = parse_trojan_request(header_buffer)
                    if parsed is None:
                        continue
                    request, _ = parsed
                    if not hmac.compare_digest(request.password, self.connection.password_hash):
                        raise AuthenticationError("incorrect Trojan password")
                    self.command = request.command
                    if request.command == 1:
                        self.target_reader, self.target_writer = await asyncio.wait_for(
                            asyncio.open_connection(request.host, request.port),
                            timeout=self.connection.options.connect_timeout,
                        )
                        LOG.info("stream %s connected to %s:%s", self.stream_id, request.host, request.port)
                        target_task = asyncio.create_task(self._target_to_grpc())
                        if request.payload:
                            self.target_writer.write(request.payload)
                            await self.target_writer.drain()
                    else:
                        if not self.connection.options.enable_udp:
                            raise ProtocolError("UDP support is disabled")
                        await self._start_udp()
                        await self._send_udp_packets(request.payload)
                    header_buffer.clear()
                elif self.command == 1:
                    assert self.target_writer is not None
                    self.target_writer.write(payload)
                    await self.target_writer.drain()
                else:
                    await self._send_udp_packets(payload)

            if target_task is not None:
                await target_task
        except AuthenticationError as exc:
            await self.connection.finish_stream(self.stream_id, 16, str(exc))
        except (ProtocolError, ValueError) as exc:
            await self.connection.finish_stream(self.stream_id, 3, str(exc))
        except (OSError, asyncio.TimeoutError) as exc:
            LOG.info("stream %s target connection failed: %s", self.stream_id, exc)
            await self.connection.finish_stream(self.stream_id, 14, "target connection failed")
        except asyncio.CancelledError:
            raise
        except Exception:
            LOG.exception("unexpected stream %s failure", self.stream_id)
            await self.connection.finish_stream(self.stream_id, 13, "internal server error")
        else:
            await self.connection.finish_stream(self.stream_id, 0)
        finally:
            self.closed = True
            if target_task and not target_task.done():
                target_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, OSError):
                    await target_task
            if self.target_writer is not None:
                self.target_writer.close()
                with contextlib.suppress(OSError):
                    await self.target_writer.wait_closed()
            if self.udp_response_task and not self.udp_response_task.done():
                self.udp_response_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self.udp_response_task
            for transport in self.udp_transports.values():
                transport.close()
            self.connection.tunnels.pop(self.stream_id, None)

    async def _target_to_grpc(self) -> None:
        assert self.target_reader is not None
        while data := await self.target_reader.read(self.connection.options.max_message_size):
            await self.connection.send_grpc_message(self.stream_id, data)

    async def _start_udp(self) -> None:
        await self._udp_transport(socket.AF_INET)
        self.udp_response_task = asyncio.create_task(
            self._udp_to_grpc(), name=f"trojan-udp-responses-{self.stream_id}"
        )
        self.last_udp_activity = time.monotonic()
        LOG.info("stream %s started UDP association", self.stream_id)

    async def _udp_transport(self, family: int) -> asyncio.DatagramTransport:
        transport = self.udp_transports.get(family)
        if transport is not None:
            return transport
        local_addr = ("0.0.0.0", 0) if family == socket.AF_INET else ("::", 0)
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: UdpReceiver(self.udp_queue), local_addr=local_addr, family=family
        )
        self.udp_transports[family] = transport
        return transport

    async def _send_udp_packets(self, data: bytes) -> None:
        self.udp_buffer.extend(data)
        if len(self.udp_buffer) > self.connection.options.max_pending_input:
            raise ProtocolError("UDP packet buffer exceeds configured limit")
        for packet in pop_udp_packets(self.udp_buffer, self.connection.options.max_udp_payload):
            addresses = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(
                    packet.host, packet.port, type=socket.SOCK_DGRAM
                ),
                timeout=self.connection.options.connect_timeout,
            )
            if not addresses:
                raise OSError("UDP target did not resolve to an address")
            family, _, _, _, sockaddr = addresses[0]
            transport = await self._udp_transport(family)
            transport.sendto(packet.payload, sockaddr)
            self.last_udp_activity = time.monotonic()

    async def _udp_to_grpc(self) -> None:
        while True:
            data, address = await self.udp_queue.get()
            if len(data) > self.connection.options.max_udp_payload:
                LOG.debug("dropping oversized UDP response on stream %s", self.stream_id)
                continue
            packet = encode_udp_packet(UdpPacket(address[0], address[1], data))
            if len(packet) > self.connection.options.max_message_size:
                LOG.debug("dropping UDP response that exceeds gRPC message limit on stream %s", self.stream_id)
                continue
            self.last_udp_activity = time.monotonic()
            await self.connection.send_grpc_message(self.stream_id, packet)

    async def close(self) -> None:
        self.closed = True
        if self.worker and not self.worker.done():
            self.worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.worker


class AuthenticationError(ProtocolError):
    pass


class H2ServerConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        options: ServerOptions,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.options = options
        self.password_hash = password_to_hex(options.password)
        self.h2 = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        )
        self.lock = asyncio.Lock()
        self.window_updated = asyncio.Event()
        self.tunnels: Dict[int, Tunnel] = {}
        self.closing = False

    async def run(self) -> None:
        self.h2.local_settings.max_concurrent_streams = self.options.max_streams
        self.h2.initiate_connection()
        await self._flush()
        try:
            while data := await self.reader.read(64 * 1024):
                async with self.lock:
                    events = self.h2.receive_data(data)
                    output = self.h2.data_to_send()
                if output:
                    self.writer.write(output)
                    await self.writer.drain()
                for event in events:
                    await self._handle_event(event)
                    if self.closing:
                        return
        except (OSError, h2.exceptions.H2Error) as exc:
            LOG.debug("HTTP/2 connection ended: %s", exc)
        finally:
            self.closing = True
            await asyncio.gather(*(tunnel.close() for tunnel in list(self.tunnels.values())), return_exceptions=True)
            self.writer.close()
            with contextlib.suppress(OSError):
                await self.writer.wait_closed()

    async def _handle_event(self, event: object) -> None:
        if isinstance(event, h2.events.RequestReceived):
            await self._request_received(event)
        elif isinstance(event, h2.events.DataReceived):
            await self._data_received(event)
        elif isinstance(event, h2.events.StreamEnded):
            tunnel = self.tunnels.get(event.stream_id)
            if tunnel:
                tunnel.input_ended()
        elif isinstance(event, h2.events.StreamReset):
            tunnel = self.tunnels.get(event.stream_id)
            if tunnel:
                await tunnel.close()
                self.tunnels.pop(event.stream_id, None)
        elif isinstance(event, h2.events.WindowUpdated):
            self.window_updated.set()
        elif isinstance(event, h2.events.ConnectionTerminated):
            self.closing = True

    async def _request_received(self, event: h2.events.RequestReceived) -> None:
        headers = dict(event.headers)
        path = headers.get(":path", "")
        expected_path = f"/{self.options.service_name}/Tun" if self.options.service_name else None
        valid_path = path.endswith("/Tun") if expected_path is None else path == expected_path
        if headers.get(":method") != "POST":
            await self._reject_http(event.stream_id, 405)
            return
        if not valid_path:
            await self._reject_http(event.stream_id, 404)
            return
        if len(self.tunnels) >= self.options.max_streams:
            async with self.lock:
                self.h2.reset_stream(event.stream_id, error_code=7)  # REFUSED_STREAM
            await self._flush()
            return

        async with self.lock:
            self.h2.send_headers(
                event.stream_id,
                [
                    (":status", "200"),
                    ("content-type", "application/grpc"),
                    ("grpc-encoding", "identity"),
                ],
                end_stream=False,
            )
        await self._flush()
        tunnel = Tunnel(event.stream_id, self)
        self.tunnels[event.stream_id] = tunnel
        tunnel.start()

    async def _data_received(self, event: h2.events.DataReceived) -> None:
        async with self.lock:
            self.h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
        await self._flush()
        tunnel = self.tunnels.get(event.stream_id)
        if tunnel is None:
            return
        try:
            tunnel.grpc_buffer.extend(event.data)
            for payload in pop_grpc_messages(tunnel.grpc_buffer, self.options.max_message_size):
                tunnel.queue_payload(payload)
        except ProtocolError as exc:
            await self.finish_stream(event.stream_id, 3, str(exc))
            await tunnel.close()
            self.tunnels.pop(event.stream_id, None)

    async def _reject_http(self, stream_id: int, status: int) -> None:
        async with self.lock:
            self.h2.send_headers(stream_id, [(":status", str(status)), ("content-length", "0")], end_stream=True)
        await self._flush()

    async def send_grpc_message(self, stream_id: int, payload: bytes) -> None:
        frame = encode_grpc_message(payload)
        offset = 0
        while offset < len(frame) and not self.closing:
            async with self.lock:
                try:
                    window = self.h2.local_flow_control_window(stream_id)
                except h2.exceptions.StreamClosedError:
                    return
                if window:
                    size = min(window, self.h2.max_outbound_frame_size, len(frame) - offset)
                    self.h2.send_data(stream_id, frame[offset : offset + size], end_stream=False)
                    offset += size
                    output = self.h2.data_to_send()
                else:
                    output = b""
                    self.window_updated.clear()
            if output:
                self.writer.write(output)
                await self.writer.drain()
            elif offset < len(frame):
                await self.window_updated.wait()

    async def finish_stream(self, stream_id: int, status: int, message: str = "") -> None:
        async with self.lock:
            try:
                trailers = [("grpc-status", str(status))]
                if message:
                    trailers.append(("grpc-message", message.replace("\n", " ")[:200]))
                self.h2.send_headers(stream_id, trailers, end_stream=True)
            except h2.exceptions.StreamClosedError:
                return
        await self._flush()

    async def _flush(self) -> None:
        async with self.lock:
            data = self.h2.data_to_send()
        if data:
            self.writer.write(data)
            await self.writer.drain()


def build_ssl_context(cert: str, key: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["h2"])
    return context


async def serve(host: str, port: int, options: ServerOptions, ssl_context: Optional[ssl.SSLContext] = None) -> asyncio.AbstractServer:
    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if ssl_context and writer.get_extra_info("ssl_object").selected_alpn_protocol() != "h2":
            writer.close()
            return
        await H2ServerConnection(reader, writer, options).run()

    return await asyncio.start_server(accept, host, port, ssl=ssl_context)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simplified Trojan-over-gRPC server")
    parser.add_argument("--password", required=True, help="Trojan plaintext password")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--service-name", help="require /<service-name>/Tun; defaults to any /.../Tun")
    parser.add_argument("--cert", help="PEM certificate; requires --key")
    parser.add_argument("--key", help="PEM private key; requires --cert")
    parser.add_argument("--max-streams", type=int, default=128)
    parser.add_argument("--max-message-size", type=int, default=16 * 1024)
    parser.add_argument("--disable-udp", action="store_true", help="reject Trojan UDP ASSOCIATE requests")
    parser.add_argument("--udp-idle-timeout", type=float, default=60.0)
    parser.add_argument("--log-level", default="INFO")
    return parser.parse_args()


async def _main_async(args: argparse.Namespace) -> None:
    if bool(args.cert) != bool(args.key):
        raise SystemExit("--cert and --key must be supplied together")
    if args.max_streams < 1 or args.max_message_size < 1 or args.udp_idle_timeout <= 0:
        raise SystemExit("stream and message limits must be positive")
    ssl_context = build_ssl_context(args.cert, args.key) if args.cert else None
    options = ServerOptions(
        password=args.password,
        service_name=args.service_name,
        max_streams=args.max_streams,
        max_message_size=args.max_message_size,
        enable_udp=not args.disable_udp,
        udp_idle_timeout=args.udp_idle_timeout,
        max_udp_payload=max(1, min(65535, args.max_message_size - 22)),
    )
    server = await serve(args.host, args.port, options, ssl_context)
    scheme = "TLS" if ssl_context else "h2c"
    LOG.info("listening on %s:%s (%s)", args.host, args.port, scheme)
    async with server:
        await server.serve_forever()


def main() -> None:
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(_main_async(args))


if __name__ == "__main__":
    main()
