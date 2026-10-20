import asyncio
import unittest

import h2.config
import h2.connection
import h2.events

from trojan_grpc.protocol import build_trojan_connect, encode_grpc_message, pop_grpc_messages
from trojan_grpc.server import ServerOptions, serve


class E2ETests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def echo(reader, writer):
            try:
                while data := await reader.read(65536):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()

        self.echo = await asyncio.start_server(echo, "127.0.0.1", 0)
        echo_port = self.echo.sockets[0].getsockname()[1]
        self.proxy = await serve("127.0.0.1", 0, ServerOptions(password="correct horse", service_name="GunService"))
        self.proxy_port = self.proxy.sockets[0].getsockname()[1]
        self.request = build_trojan_connect("correct horse", "127.0.0.1", echo_port, b"first-")

    async def asyncTearDown(self):
        self.proxy.close()
        self.echo.close()
        await self.proxy.wait_closed()
        await self.echo.wait_closed()

    async def test_h2c_tunnel_relays_initial_and_later_data(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
        client_h2 = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
        client_h2.initiate_connection()
        writer.write(client_h2.data_to_send())
        await writer.drain()

        stream_id = client_h2.get_next_available_stream_id()
        client_h2.send_headers(stream_id, [(":method", "POST"), (":scheme", "http"), (":authority", "localhost"), (":path", "/GunService/Tun"), ("content-type", "application/grpc"), ("te", "trailers")])
        client_h2.send_data(stream_id, encode_grpc_message(self.request), end_stream=False)
        client_h2.send_data(stream_id, encode_grpc_message(b"second"), end_stream=True)
        writer.write(client_h2.data_to_send())
        await writer.drain()

        received = bytearray()
        grpc_buffer = bytearray()
        trailers = {}
        while not trailers:
            data = await asyncio.wait_for(reader.read(65536), timeout=2)
            self.assertTrue(data)
            for event in client_h2.receive_data(data):
                if isinstance(event, h2.events.DataReceived):
                    grpc_buffer.extend(event.data)
                    received.extend(b"".join(pop_grpc_messages(grpc_buffer, 65536)))
                    client_h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.TrailersReceived):
                    trailers = dict(event.headers)
            writer.write(client_h2.data_to_send())
            await writer.drain()
        self.assertEqual(received, b"first-second", trailers)
        self.assertEqual(trailers.get("grpc-status"), "0")
        writer.close()
        await writer.wait_closed()
