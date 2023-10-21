# built-in modules
import os
from logging import getLogger
from rsa import PrivateKey, PublicKey
from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR
from typing import Any, Callable, Dict, List, Optional, Tuple

# implemented modules
from .buffer import (
    Buffer,
    int_from_bytes,
    int_to_bytes,
)
from .crypto import (
    AsymmetricContext,
    SymmetricContext
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
    PACKET_FIXED_BIT,
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


class QuicServer:
    def __init__(self, crypto: Optional[Tuple[PublicKey, PrivateKey]]) -> None:
        self._sock = socket(AF_INET, SOCK_DGRAM)
        self._sock.getsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        self._host_cids: List[QuicConnectionId] = [
            QuicConnectionId(
                cid=os.urandom(8),
                sequence_number=0,
                was_sent=True
            )
        ]

        self._version = QuicProtocolVersion.SAEM_QUIC
        self._symmetric_context = SymmetricContext()
        self._host_asymmetric_context = AsymmetricContext(crypto[0], crypto[1])
        self._peer_asymmetric_context = AsymmetricContext()

        self._qpb = QuicPacketBuilder(
            host_cid=self._host_cids[0].cid,
            peer_cid=b"",
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
        self._handler_dict[PACKET_TYPE_ZERO_RTT] = self._handle_zerortt
        self._handler_dict[PACKET_TYPE_HANDSHAKE] = self._handle_handshake
        self._handler_dict[PACKET_TYPE_ONE_RTT] = self._handle_onertt

        self._early_response = b""

        self._client_info: (str, int) = ("", 443)
        self._retry: bool = False
        self._disconnected: bool = False
        self._reading: bool = True
        self._key_exchange_done: bool = False
        self._stream_data: Buffer = Buffer(
            capacity=PACKET_MAX_SIZE,
            no_write_limit=True,
            no_read_limit=True
        )

    def bind(self, addr: tuple[str, int]) -> None:        
        self._sock.bind(addr)

    def recv(self) -> bytes:
        self._reading = True
        while True:
            data, addr = self._sock.recvfrom(PACKET_MAX_SIZE)
            self._client_info = addr

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
                self._client_info = None
                break

            if not self._reading:
                logger.debug(f"socket disconnected")
                output_data = output_data = self._stream_data.data[:self._stream_data.tell()]
                self._stream_data.clear()
                return output_data

            # create handshake and 1rtt message
            data = self._qpb.flush()
            logger.debug(f"sending initial response data: {data.data}")
            self._sock.sendto(data.data, addr)

    def recvfrom(self) -> (bytes, Any):
        self._reading = True
        while True:
            data, addr = self._sock.recvfrom(PACKET_MAX_SIZE)
            self._client_info = addr

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
                self._client_info = None
                break

            if not self._reading:
                logger.debug(f"socket disconnected")
                output_data = output_data = self._stream_data.data[:self._stream_data.tell()]
                self._stream_data.clear()
                return output_data, addr

            # create handshake and 1rtt message
            data = self._qpb.flush()
            logger.debug(f"sending initial response data: {data.data}")
            self._sock.sendto(data.data, addr)

    def send(self, data: bytes) -> None:
        self._qpb.create_packet(PACKET_TYPE_ONE_RTT)
        stream_data = self._qfb.create_stream(data, 0)
        self._qpb.push_frame(stream_data)

        send_data = self._qpb.flush()

        self._sock.sendto(send_data.data, self._client_info)

    def sendto(self, data: bytes, addr) -> None:
        self._qpb.create_packet(PACKET_TYPE_ONE_RTT)
        stream_data = self._qfb.create_stream(data, 0)
        self._qpb.push_frame(stream_data)

        send_data = self._qpb.flush()
        if addr is None:
            self._sock.sendto(send_data.data, self._client_info)
        else:
            self._sock.sendto(send_data.data, addr)

    def _handle_initial(self, packet_info: QuicParsedPacket, frames: List[QuicParsedFrame]):
        for frame in frames:
            if frame.type == QuicFrameType.CRYPTO:
                # load send l2 crypto context
                self._peer_asymmetric_context.set_public_key(frame.payload)

                self._qpb.create_packet(PACKET_TYPE_INITIAL)
                crypto_frame = self._qfb.create_crypto(
                    self._host_asymmetric_context.public_key, self._qpb.pos)
                self._qpb.push_frame(crypto_frame)

                hello_frame_offset = self._qpb.pos
                hello_frame_offset = 0
                hello_payload = int_to_bytes(QuicProtocolVersion.SAEM_QUIC)
                hello_frame = self._qfb.create_hello(
                    hello_payload, hello_frame_offset)

                self._qpb.push_frame(hello_frame)

                self._qpb.create_packet(PACKET_TYPE_HANDSHAKE)
                encrypted_sym_key = self._peer_asymmetric_context.encrypt(
                    self._symmetric_context.key)
                encrypted_sym_nonce = self._peer_asymmetric_context.encrypt(
                    self._symmetric_context.nonce)
                crypto_frame = self._qfb.create_crypto(
                    b"\x00" + encrypted_sym_key)
                self._qpb.push_frame(crypto_frame)
                crypto_frame = self._qfb.create_crypto(
                    b"\x01" + encrypted_sym_nonce)
                self._qpb.push_frame(crypto_frame)
                self._early_response = os.urandom(32)
                crypto_frame = self._qfb.create_crypto(
                    b"\x02" + self._early_response)
                self._qpb.push_frame(crypto_frame)

    def _handle_zerortt(self, packet_info: QuicParsedPacket, frames: List[QuicParsedFrame]):
        for frame in frames:
            if frame.type == QuicFrameType.STREAM:

                # validate frame payload
                if frame.payload != b"valid":
                    self._retry = True
                    self._qpb.create_packet(PACKET_TYPE_RETRY)
                    self._retry_token = os.urandom(32)
                    stream_frame = self._qfb.create_stream(
                        self._retry_token, type=0)
                    self._qpb.push_frame(stream_frame)
                else:
                    self._qpb.create_packet(PACKET_TYPE_ONE_RTT)
                    stream_frame = self._qfb.create_stream(
                        payload=(b"\x02" + self._early_response), type=0)
                    self._qpb.push_frame(stream_frame)

    def _handle_handshake(self, packet_info: QuicParsedPacket, frames: List[QuicParsedFrame]):
        for frame in frames:
            if frame.type == QuicFrameType.STREAM:

                if frame.payload == b"ok":
                    logger.debug(f"client handshake received and is valid")
                else:
                    logger.debug(f"client handshake received and is invalid")

    def _handle_onertt(self, packet_info: QuicParsedPacket, frames: List[QuicParsedFrame]):
        logger.debug("[ONE RTT] handling packet")
        for frame in frames:
            logger.debug(
                f"[ONE RTT] handling frame {QuicFrameType(frame.type).name}")
            if frame.type == QuicFrameType.STREAM:
                # validate frame payload
                if frame.payload[0] == 2:
                    if frame.payload == self._early_response:
                        pass
                else:
                    self._stream_data.push_bytes(frame.payload)
                    self._reading = False
            elif frame.type == QuicFrameType.CONNECTION_CLOSE:
                logger.debug("[ONE RTT] handling disconnect frame")
                self._disconnected = True

            # todo: create retry packet
            # if frame.type == QuicFrameType.STREAM:
            #   # validate frame payload
            #   if frame.payload == b"ok":
            #     pass
            #     # self._retry = True
            #     # self._qpb.create_packet(PACKET_TYPE_RETRY)
            #     # self._retry_token = os.urandom(32)
            #     # stream_frame= self._qfb.create_stream(self._retry_token)
            #     # self._qpb.push_frame(stream_frame)

            #   else:
            #     pass
            #     # self._qpb.create_packet(PACKET_TYPE_ONE_RTT)
            #     # stream_frame = self._qfb.create_stream(payload=b"ok", type=0)
            #     # self._qpb.push_frame(stream_frame)
