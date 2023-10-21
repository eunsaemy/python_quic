# built-in modules
from dataclasses import dataclass
from enum import IntEnum
from logging import getLogger
from typing import Optional

# logging module
logger = getLogger(__name__)


@dataclass
class QuicConnectionId:
    cid: bytes
    sequence_number: int
    was_sent: bool = False


class QuicProtocolVersion(IntEnum):
    NEGOTIATION = 0
    VERSION_1 = 0x00000001
    SAEM_QUIC = 0xFF000001


@dataclass
class QuicHeader:
    is_long_header: bool
    version: Optional[int]
    packet_type: int
    dest_cid: bytes
    src_cid: bytes
    token: bytes = b""
    integrity_tag: bytes = b""
    rest_length: int = 0


PACKET_MAX_SIZE = 1280
PACKET_LENGTH_SEND_SIZE = 2
PACKET_NUMBER_SEND_SIZE = 2

QuicRecv = [bytes, (str, int)]
