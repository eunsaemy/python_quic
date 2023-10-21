# built-in modules
import os
from logging import getLogger
from rsa import PrivateKey, PublicKey
from socket import socket, AF_INET, SOCK_DGRAM
from typing import Any, Callable, Dict, List, Optional, Tuple

# implemented modules
from .buffer import (
    Buffer,
    int_from_bytes,
    int_to_bytes,
)
from .crypto import (
    AsymmetricContext,
    SymmetricContext,
)
from .frame_builder import (
    QuicFrameType,
    QuicFrameBuilder,
)
from .frame_parser import (
    QuicParsedFrame,
)
from .packet_builder import (
    QuicPacketBuilder,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ZERO_RTT,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_RETRY,
    PACKET_TYPE_ONE_RTT,
    PACKET_MAX_SIZE,
    PACKET_FIXED_BIT
)
from .packet_parser import (
    QuicPacketParser,
    QuicParsedPacket
)
from .quic_types import (
    QuicConnectionId,
    QuicProtocolVersion,
)

# logging module
logger = getLogger(__name__)


class QuicClient:
    def __init__(self, crypto: Optional[Tuple[PublicKey, PrivateKey]] = None) -> None:
        # socket
        self._sock = socket(AF_INET, SOCK_DGRAM)

        # authentication
        self._host_cid = QuicConnectionId(
            cid=os.urandom(8),
            sequence_number=0
        )
        self._peer_cid = QuicConnectionId(
            cid=os.urandom(8),
            sequence_number=0
        )

        self._version = QuicProtocolVersion.SAEM_QUIC

        # cryptography
        self._crypto = crypto
        self._crypto_bytes = [
            self._crypto[0].save_pkcs1(), self._crypto[1].save_pkcs1()]

        self._symmetric_context = SymmetricContext()
        self._host_asymmetric_context = AsymmetricContext(crypto[0], crypto[1])
        self._peer_asymmetric_context = AsymmetricContext()

        # packet builders and parsers
        self._qpb = QuicPacketBuilder(
            host_cid=self._host_cid.cid,
            peer_cid=self._peer_cid.cid,
            version=self._version,
            is_client=True,
            symm_context=self._symmetric_context
        )
        self._qfb = QuicFrameBuilder()
        self._packet_parser = QuicPacketParser(
            symm_context=self._symmetric_context
        )

        self._handler_dict: Dict[int, Callable] = dict()

        self._handler_dict[PACKET_TYPE_INITIAL] = self._handle_initial
        self._handler_dict[PACKET_TYPE_HANDSHAKE] = self._handle_handshake
        self._handler_dict[PACKET_TYPE_ONE_RTT] = self._handle_onertt
        self._handler_dict[PACKET_TYPE_RETRY] = self._handle_retry

        self._early_response = b""

        # states
        self._retry: bool = False
        self._retry_limit: int
        self._disconnected: bool = False
        self._reading: bool = True
        self._stream_data: Buffer = Buffer(
            capacity=PACKET_MAX_SIZE, no_write_limit=True, no_read_limit=True)

    def connect(self, address) -> None:
        self._sock.connect(address)
        self._key_exchange()

    def _key_exchange(self) -> None:
        # send initial and zero rtt packet
        # build initial packet
        self._qpb.create_packet(PACKET_TYPE_INITIAL)

        # crypto_frame_offset = self._qpb.pos
        crypto_frame_offset = 0
        crypto_frame = self._qfb.create_crypto(
            self._crypto_bytes[0],  # public key in bytes
            crypto_frame_offset
        )

        self._qpb.push_frame(crypto_frame)

        hello_frame_offset = self._qpb.pos
        hello_frame_offset = 0
        hello_payload = int_to_bytes(QuicProtocolVersion.SAEM_QUIC)
        hello_frame = self._qfb.create_hello(hello_payload, hello_frame_offset)

        self._qpb.push_frame(hello_frame)

        # build 0RTT packet
        self._qpb.create_packet(PACKET_TYPE_ZERO_RTT)

        stream_frame_offset = 0

        # change to stream frame
        stream_frame = self._qfb.create_stream(b"valid", stream_frame_offset)

        self._qpb.push_frame(stream_frame)

        buf = self._qpb.flush()

        # start key exchange
        logger.debug(f"send value: {buf.data.hex(sep=' ', bytes_per_sep=1)}")
        logger.debug(f"send value: {buf.data}")
        send = self._sock.send(buf.data)
        logger.debug(f"send value: {send}")

        # expect initial packet
        # while(True):
        data, addr = self._sock.recvfrom(PACKET_MAX_SIZE)

        buf = Buffer(capacity=len(data), data=data)
        logger.debug(f"received initial data {buf.data}")

        while (int_from_bytes(buf.peek(1)) & PACKET_FIXED_BIT) > 0:
            self._packet_parser.set_retry(self._retry)
            self._packet_parser.parse(buf)

            # process packet
            logger.debug(f"handle packets and frames")
            for packet in self._packet_parser.parsed_packets:
                logger.debug(
                    f"handling packets - packet type: {packet.packet_type}")
                logger.debug(
                    f"handling packets - {('short header', 'long header')[packet.is_long_header]}")

                self._handler_dict[packet.packet_type](packet, packet.frames)

                for frame in packet.frames:
                    logger.debug(f"handling frame - type: {frame.type}")
                    logger.debug(
                        f"handling frame - type name: {QuicFrameType(frame.type).name}")
                    logger.debug(f"handling frame - payload: {frame.payload}")

            self._packet_parser.reset()

        # create handshake and 1-rtt message
        data = self._qpb.flush()
        logger.debug(f"sending initial response data: {data.data}")
        self._sock.sendto(data.data, addr)

        # todo: create 0-rtt packet to be sent to the QuicServer
        # todo: encrypt application payload and send to the server

    def disconnect(self) -> None:
        self._qpb.create_packet(PACKET_TYPE_ONE_RTT)
        connection_close_frame = self._qfb.create_connection_close()
        self._qpb.push_frame(connection_close_frame)
        send_data = self._qpb.flush()

        self._sock.send(send_data.data)

    def send(self, data: bytes) -> None:
        self._qpb.create_packet(PACKET_TYPE_ONE_RTT)
        stream_data = self._qfb.create_stream(data, 0)
        self._qpb.push_frame(stream_data)

        send_data = self._qpb.flush()

        self._sock.send(send_data.data)

    def sendto(self, data: bytes, addr) -> None:
        self._qpb.create_packet(PACKET_TYPE_ONE_RTT)
        stream_data = self._qfb.create_stream(data, 0)
        self._qpb.push_frame(stream_data)

        send_data = self._qpb.flush()

        self._sock.sendto(send_data.data, addr)

    def recvfrom(self) -> (bytes, Any):
        self._reading = True
        while True:
            data, addr = self._sock.recvfrom(PACKET_MAX_SIZE)

            buf = Buffer(capacity=len(data), data=data)

            logger.debug(f"received: {buf.data}")

            # self.parse_long_header_packet(buf)
            while (int_from_bytes(buf.peek(1)) & PACKET_FIXED_BIT) > 0:
                self._packet_parser.set_retry(self._retry)
                self._packet_parser.parse(buf)

                # process packet
                logger.debug(f"handle packets and frames")
                for packet in self._packet_parser.parsed_packets:
                    logger.debug(
                        f"handling packets - packet type: {packet.packet_type}")
                    packet_type = packet.packet_type
                    if packet_type == PACKET_TYPE_INITIAL:
                        logger.debug(f"packet type: INITIAL")
                    elif packet_type == PACKET_TYPE_ZERO_RTT:
                        logger.debug(f"packet type: ZERO RTT")
                    elif packet_type == PACKET_TYPE_HANDSHAKE:
                        logger.debug(f"packet type: HANDSHAKE")
                    elif packet_type == PACKET_TYPE_RETRY:
                        logger.debug(f"packet type: RETRY")
                    elif packet_type == PACKET_TYPE_ONE_RTT:
                        logger.debug(f"packet type: ONE RTT")
                    logger.debug(
                        f"handling packets - packet type name: {packet.packet_type}")
                    logger.debug(
                        f"handling packets - {('short header', 'long header')[packet.is_long_header]}")

                    self._handler_dict[packet.packet_type](
                        packet, packet.frames)

                    for frame in packet.frames:
                        logger.debug(f"handling frame - type: {frame.type}")
                        logger.debug(
                            f"handling frame - type name: {QuicFrameType(frame.type).name}")
                        logger.debug(
                            f"handling frame - payload: {frame.payload}")

                # clear packet parser
                self._packet_parser.reset()

            if self._disconnected:
                logger.debug(f"socket disconnected")
                break

            if not self._reading:
                logger.debug(f"socket disconnected")
                output_data = self._stream_data.data[:self._stream_data.tell()]
                self._stream_data.clear()
                return output_data, addr

    def recv(self) -> bytes:
        self._reading = True
        while True:
            data, addr = self._sock.recvfrom(PACKET_MAX_SIZE)

            buf = Buffer(capacity=len(data), data=data)

            logger.debug(f"received: {buf.data}")

            # self.parse_long_header_packet(buf)
            while (int_from_bytes(buf.peek(1)) & PACKET_FIXED_BIT) > 0:
                self._packet_parser.set_retry(self._retry)
                self._packet_parser.parse(buf)

                # process packet
                logger.debug(f"handle packets and frames")
                for packet in self._packet_parser.parsed_packets:
                    logger.debug(
                        f"handling packets - packet type: {packet.packet_type}")
                    packet_type = packet.packet_type
                    if packet_type == PACKET_TYPE_INITIAL:
                        logger.debug(f"packet type: INITIAL")
                    elif packet_type == PACKET_TYPE_ZERO_RTT:
                        logger.debug(f"packet type: ZERO RTT")
                    elif packet_type == PACKET_TYPE_HANDSHAKE:
                        logger.debug(f"packet type: HANDSHAKE")
                    elif packet_type == PACKET_TYPE_RETRY:
                        logger.debug(f"packet type: RETRY")
                    elif packet_type == PACKET_TYPE_ONE_RTT:
                        logger.debug(f"packet type: ONE RTT")
                    logger.debug(
                        f"handling packets - packet type name: {packet.packet_type}")
                    logger.debug(
                        f"handling packets - {('short header', 'long header')[packet.is_long_header]}")

                    self._handler_dict[packet.packet_type](
                        packet, packet.frames)

                    for frame in packet.frames:
                        logger.debug(f"handling frame - type: {frame.type}")
                        logger.debug(
                            f"handling frame - type name: {QuicFrameType(frame.type).name}")
                        logger.debug(
                            f"handling frame - payload: {frame.payload}")

                # clear packet parser
                self._packet_parser.reset()

            if self._disconnected:
                logger.debug(f"socket disconnected")
                break

            if not self._reading:
                logger.debug(f"socket disconnected")
                output_data = output_data = self._stream_data.data[:self._stream_data.tell()]
                self._stream_data.clear()
                return output_data

    def _handle_initial(self, packet_info: QuicParsedPacket, frames: List[QuicParsedFrame]):
        for frame in frames:
            if frame.type == QuicFrameType.CRYPTO:
                # load send l2 crypto context
                # self._send_context.set_public_key(frame.payload)
                self._peer_asymmetric_context.set_public_key(frame.payload)

    def _handle_handshake(self, packet_info: QuicParsedPacket, frames: List[QuicParsedFrame]):
        logger.debug(f"handling handshake")
        for frame in frames:
            logger.debug(
                f"handling handshake frame {QuicFrameType(frame.type).name}")
            if frame.type == QuicFrameType.CRYPTO:
                logger.debug(
                    f"handling handshake frame 2 {QuicFrameType(frame.type).name}")

                logger.debug(f"frame payload[0]: {frame.payload[0]}")
                if frame.payload[0] == 0:
                    dec_key = self._host_asymmetric_context.decrypt(
                        frame.payload[1:])
                    logger.debug(f"loaded symm key {dec_key}")
                    self._symmetric_context.key = dec_key
                elif frame.payload[0] == 1:
                    dec_nonce = self._host_asymmetric_context.decrypt(
                        frame.payload[1:])
                    logger.debug(f"loaded nonce {dec_nonce}")
                    self._symmetric_context.nonce = dec_nonce
                elif frame.payload[0] == 2:
                    logger.debug(f"loaded early response {frame.payload[1:]}")
                    self._early_response = frame.payload[1:]

                self._qpb.create_packet(PACKET_TYPE_HANDSHAKE)
                stream_frame = self._qfb.create_crypto(b"ack", 0)
                self._qpb.push_frame(stream_frame)
                stream_frame = self._qfb.create_stream(b"ok", 0)
                self._qpb.push_frame(stream_frame)

    def _handle_retry(self, packet_info: QuicParsedPacket, frames: List[QuicParsedFrame]):
        for frame in frames:
            if frame.type == QuicFrameType.STREAM:
                # parse retry token
                pass

    def _handle_onertt(self, packet_info: QuicParsedPacket, frames: List[QuicParsedFrame]):
        for frame in frames:
            if frame.type == QuicFrameType.STREAM:
                # validate frame payload
                if frame.payload[0] == 2:
                    if frame.payload == self._early_response:
                        self._reading = False
                else:
                    self._stream_data.push_bytes(frame.payload)
                    self._reading = False
