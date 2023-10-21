# built-in modules
from dataclasses import dataclass
from typing import List

# implemented modules
from .buffer import (
    Buffer,
    int_to_bytes,
    to_bits,
)
from .crypto import (
    SymmetricContext,
)
from .frame_builder import (
    QuicFrame,
    QuicFrameType,
)

# logging module
from logging import getLogger
logger = getLogger(__name__)

PACKET_LONG_HEADER = 0x80
PACKET_FIXED_BIT = 0x40
PACKET_SPIN_BIT = 0x20

PACKET_TYPE_INITIAL = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x00
PACKET_TYPE_ZERO_RTT = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x10
PACKET_TYPE_HANDSHAKE = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x20
PACKET_TYPE_RETRY = PACKET_LONG_HEADER | PACKET_FIXED_BIT | 0x30
PACKET_TYPE_ONE_RTT = PACKET_FIXED_BIT
PACKET_TYPE_MASK = 0xF0

PACKET_MAX_SIZE = 1280
PACKET_LENGTH_SEND_SIZE = 2
PACKET_NUMBER_SEND_SIZE = 2

CONNECTION_ID_MAX_SIZE = 20
PACKET_NUMBER_MAX_SIZE = 4


@dataclass
class QuicPacketInfo:
    packet_number: int
    packet_type: int
    sent_bytes: int


def is_long_header(byte: int):
    return bool(byte & PACKET_LONG_HEADER)


class QuicPacketBuilder:
    def __init__(
        self,
        host_cid: bytes,
        peer_cid: bytes,
        version: int,
        is_client: bool,
        symm_context: SymmetricContext,
        packet_number: int = 0,
        peer_token: bytes = b"",
        spin_bit: bool = False,
    ) -> None:
        self._is_client: bool = is_client
        self._host_cid: bytes = host_cid
        self._peer_cid: bytes = peer_cid
        self._peer_token: bytes = peer_token
        self._spin_bit: bool = spin_bit
        self._version: int = version

        # assembled datagrams and packets
        self._datagrams: List[bytes] = []
        self._datagram_init = True
        self._packets: List[QuicPacketInfo] = []

        # current packet info
        self._header_size: int = 0
        self._frames: List[QuicFrame] = []

        self._long_header: bool = False
        self._packet_number: int = packet_number
        self._packet_type: int = 0

        self._buffer: Buffer = Buffer(
            capacity=PACKET_MAX_SIZE
        )
        self._flight_capacity = PACKET_MAX_SIZE

        self._symmetric_context = symm_context

    @property
    def pos(self) -> int:
        return self._buffer.tell()

    @property
    def remaining_flight_space(self) -> int:
        return (
            self._flight_capacity
            - self._buffer.tell()
        )

    def flush(self) -> Buffer:
        self._end_packet()

        # buf = Buffer(data=self._buffer.data)
        # self._buffer = Buffer(capacity=PACKET_MAX_SIZE)
        buf = Buffer(data=self._buffer.data)
        buf.seek(self._buffer.tell())
        self._buffer = Buffer(capacity=PACKET_MAX_SIZE)
        return buf

    def push_frame(self, frame: QuicFrame):

        self._frames.append(frame)

    def create_packet(self, packet_type: int):
        buf = self._buffer
        packet_start = buf.tell()

        packet_long_header = is_long_header(packet_type)

        if self._packet_type == PACKET_TYPE_RETRY:
            self._buffer.peek(0)

        if self._packet_type > 0:
            self._end_packet()

        # calculate header size
        header_size = 0

        if packet_long_header:
            header_size = 1 + 4 + 1 + len(self._peer_cid) + 1 + len(self._host_cid)

        # write long header
        if packet_long_header:
            buf.push_uint8(packet_type | (self._packet_number &
                           PACKET_NUMBER_MAX_SIZE & 0xFFFF))  # 1 byte
            buf.push_uint32(self._version)  # 4 bytes
            buf.push_uint8(len(self._peer_cid))  # 1 byte
            buf.push_bytes(self._peer_cid)  # 1 - 20 bytes
            buf.push_uint8(len(self._host_cid))  # 1 byte
            buf.push_bytes(self._host_cid)  # 1 - 20 bytes

        # write short header
        else:
            logger.debug(f"writing short header")
            first_byte = packet_type | (
                self._packet_number & PACKET_NUMBER_MAX_SIZE & 0xFFFF)
            logger.debug(
                f"writing first byte for short header: {to_bits(first_byte)}")
            buf.push_uint8(first_byte)
            buf.push_bytes(self._host_cid)  # 1 - 20 bytes

        # set current packet info
        self._header_size = header_size
        self._long_header = packet_long_header
        self._packet_type = packet_type

        # increment packet number for next packet
        self._packet_number += 1

    def _end_packet(self):
        buf = self._buffer

        if self._buffer.tell() == 0:
            return

        # check if long header
        if self._long_header:
            # write long header payload
            logger.debug(f"ending long header packet")

            # todo: check if packet may contain a payload

            packet_number_length = len(int_to_bytes(self._packet_number))

            payload_length = 0
            for frame in self._frames:
                payload_length += frame.length

            # push payload length
            buf.push_uint_var(payload_length)

            # push packet number
            buf.push_uint_var(self._packet_number)

            for i in range(len(self._frames)):
                frames = self._frames
                logger.debug(
                    f"pushing frame: {QuicFrameType(frames[i].frame_type).name} w/ length: {frames[i].length}")
                # push frame data
                buf.push_bytes(frames[i].data)

        # write short header payload
        else:
            logger.debug(f"ending short header packet")
            packet_number_length = len(int_to_bytes(self._packet_number))

            payload_length = 0
            for frame in self._frames:
                payload_length += frame.length

            logger.debug(
                f"[ending short header] - total payload length {payload_length}")

            full_frame = b""
            for i in range(len(self._frames)):
                frames = self._frames
                # push frame data
                logger.debug(
                    f"[ending short header] - pushing {frames[i].data}")
                logger.debug(
                    f"pushing frame: {QuicFrameType(frames[i].frame_type).name} w/ length: {frames[i].length}")
                full_frame += frames[i].data

            enc_full_payload = self._symmetric_context.encrypt(
                full_frame, b"test_associated")

            # push payload length
            buf.push_uint_var(len(enc_full_payload))

            # push packet number
            buf.push_uint_var(self._packet_number)

            logger.debug(f"pushing: {enc_full_payload}")

            # push encrypted packet
            buf.push_bytes(enc_full_payload)

        # clean up
        self._frames = []
        self._header_size = 0
        self._long_header = False
        self._packet_type = 0
