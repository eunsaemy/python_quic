# built-in modules
from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional

# implemented modules
from .buffer import (
    Buffer,
    int_to_bytes,
)
from .crypto import (
    SymmetricContext,
)
from .frame_parser import (
    QuicFrameParser,
    QuicParsedFrame,
)
from .packet_builder import (
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ZERO_RTT,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_RETRY,
    PACKET_TYPE_ONE_RTT,
    PACKET_TYPE_MASK,
    is_long_header
)
from .quic_types import (
    QuicProtocolVersion,
)

# logging module
from logging import getLogger
logger = getLogger(__name__)


class QuicPacketParserState(IntEnum):
    PARSING_PACKET = 0x01
    PARSING_PAYLOAD = 0x02


@dataclass
class QuicParsedPacket:
    is_long_header: bool
    packet_type: int
    dest_cid: bytes
    payload: bytes
    frames: List[QuicParsedFrame]
    src_cid: Optional[bytes] = b""
    version: Optional[int] = 0


class QuicPacketParser:
    def __init__(
        self,
        symm_context: SymmetricContext
    ) -> None:

        # todo: add packets parsed with frames
        self._parsing_state: QuicPacketParserState = QuicPacketParserState.PARSING_PACKET

        # frame parser
        self._frame_parser = QuicFrameParser()

        # parsed data
        self._parsed_packets: List[QuicParsedPacket] = []

        # retry
        self._retry: bool = False

        # symmetric context
        self._symmetric_context = symm_context

    @property
    def parsed_packets(self) -> List[QuicParsedPacket]:
        return self._parsed_packets

    def set_retry(self, value: bool) -> None:
        self._retry = value

    def reset(self) -> None:
        # clear parsed packets in list
        self._parsed_packets = []

    def parse(self, packet: Buffer) -> None:

        # datagram parse pseudo

        # read first byte
        first_byte: bytes = packet.pull_uint8()

        packet_type: int = first_byte & PACKET_TYPE_MASK
        long_header: bool = is_long_header(packet_type)
        logger.debug(
            f"packet type of {packet_type} is {('short header', 'long header')[long_header]}")

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

        # parse packet number length
        packet_num_length = (packet_type & 0x03) + 1
        logger.debug(f"packet number length: {packet_num_length}")

        if long_header:
            # parse long header packet
            logger.debug(f"parsing long header")

            # parse version
            version = packet.pull_uint32()
            logger.debug(f"version: {int_to_bytes(version).hex(' ', 2)}")
            logger.debug(f"version in bytes: {int_to_bytes(version)}")

            # validate version
            if version in (QuicProtocolVersion.NEGOTIATION,
                           QuicProtocolVersion.VERSION_1,
                           QuicProtocolVersion.SAEM_QUIC):
                logger.debug(f"version is valid")
            else:
                logger.debug(f"version is invalid")

            # parse dest CID
            dest_id_len = packet.pull_uint8()
            logger.debug(f"dest id len: {dest_id_len}")
            dest_id = packet.pull_bytes(dest_id_len)
            logger.debug(f"dest id: {dest_id}")

            # parse src CID
            src_id_len = packet.pull_uint8()
            logger.debug(f"peer id len: {src_id_len}")
            src_id = packet.pull_bytes(src_id_len)
            logger.debug(f"peer id: {src_id}")

            if packet_type == PACKET_TYPE_INITIAL:
                # parse token
                # TODO: implement tokens
                pass

            logger.debug(f"packet peek: {packet.peek(10).hex(' ', 1)}")

            # parse payload length

            if packet_type in (PACKET_TYPE_INITIAL, PACKET_TYPE_ZERO_RTT, PACKET_TYPE_HANDSHAKE):

                # parse payload
                payload_length = packet.pull_uint_var()

                logger.debug(f"payload length: {payload_length}")
                # parse packet number
                packet_number = packet.pull_bytes(packet_num_length)
                # packet_number = packet.pull_uint_var()
                logger.debug(f"packet number: {packet_number}")
                logger.debug(f"payload data: {packet.peek(payload_length)}")
                # parse packet payload
                payload_data = packet.pull_bytes(payload_length)
                logger.debug(f"payload data: {payload_data}")
                logger.debug(f"payload data: {payload_data.hex(' ', 1)}")

                # parse packet payload data
                parsed_frames = self._frame_parser.parse(
                    Buffer(data=payload_data))

                parsed_packet = QuicParsedPacket(
                    is_long_header=long_header,
                    packet_type=packet_type,
                    version=version,
                    dest_cid=dest_id,
                    src_cid=src_id,
                    payload=payload_data,
                    frames=parsed_frames
                )

                self._parsed_packets.append(parsed_packet)

        else:
            # parse short header packet
            logger.debug(f"parsing short header")

            # parse dest CID
            dest_id_len = 8
            logger.debug(f"dest id len: {dest_id_len}")
            dest_id = packet.pull_bytes(dest_id_len)
            logger.debug(f"dest id: {dest_id}")

            header_index = packet.tell()

            # parse payload
            payload_length = packet.pull_uint_var()

            logger.debug(f"payload length: {payload_length}")
            # parse packet number
            packet_number = packet.pull_bytes(packet_num_length)
            # packet_number = packet.pull_uint_var()
            logger.debug(f"packet number: {packet_number}")
            logger.debug(f"payload data: {packet.peek(payload_length)}")
            # parse packet payload
            payload_data = packet.pull_bytes(payload_length)
            logger.debug(f"payload data: {payload_data}")
            logger.debug(f"payload data: {payload_data.hex(' ', 1)}")

            dec_payload_data = self._symmetric_context.decrypt(
                payload_data, b"test_associated")
            logger.debug(f"decrypted short header payload: {dec_payload_data}")

            # parse packet payload data
            parsed_frames = self._frame_parser.parse(
                Buffer(data=dec_payload_data))

            parsed_packet = QuicParsedPacket(
                is_long_header=long_header,
                packet_type=packet_type,
                dest_cid=dest_id,
                payload=payload_data,
                frames=parsed_frames
            )

            self._parsed_packets.append(parsed_packet)
