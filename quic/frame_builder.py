# built-in modules
from dataclasses import dataclass
from enum import IntEnum
from logging import getLogger
from typing import Optional

# implemented modules
from .buffer import (
    Buffer,
    int_from_bytes,
    int_to_bytes,
    encode_uint_var,
)

# logging module
logger = getLogger(__name__)


class QuicFrameType(IntEnum):
    PADDING = 0x00,
    PING = 0x01,
    ACK = 0x02,
    RESET_STREAM = 0x04,
    STOP_SENDING = 0x05
    CRYPTO = 0x06
    STREAM = 0x08
    CONNECTION_CLOSE = 0x1c

    CLIENT_HELLO = 0x1f
    SERVER_HELLO = 0x20
    # add other frames here


@dataclass
class QuicFrame:
    frame_type: QuicFrameType
    data: bytes
    length: int


class QuicFrameBuilder:
    def create_test(self, payload: bytes = b"helloworld") -> QuicFrame:
        _payload_len = len(payload)

        _frame_type = QuicFrameType.CRYPTO  # 0x06 = 1 byte

        # 00001010 = 8 bits = 1 byte = decimal 10
        _encoded_length = encode_uint_var(_payload_len)

        _total_frame_length = _payload_len + len(int_to_bytes(_frame_type)) + len(_encoded_length)

        output_frame = Buffer(capacity=_total_frame_length)
        output_frame.push_bytes(int_to_bytes(_frame_type))
        output_frame.push_bytes(_encoded_length)
        output_frame.push_bytes(payload)

        # return output frame
        return QuicFrame(
            frame_type=_frame_type,
            data=output_frame.data,
            length=_total_frame_length
        )

    def create_crypto(self, payload: bytes, offset: Optional[int] = 0) -> QuicFrame:
        # payload length
        _payload_len = len(payload)  # 251 bytes
        logger.debug(f"crypto payload len: {_payload_len}")

        # type
        _frame_type = QuicFrameType.CRYPTO  # 1 byte

        # offset
        logger.debug(f"offset value: {offset}")
        _out_offset = encode_uint_var(offset)
        logger.debug(f"out offset value: {_out_offset}")
        _out_offset_len = len(_out_offset)
        logger.debug(f"out offset len: {_out_offset_len}")  # 1 byte

        # payload length
        _encoded_length = encode_uint_var(_payload_len)
        _encoded_length_len = len(_encoded_length)
        logger.debug(f"payload len: {_payload_len}")  # 2 bytes

        logger.debug(f"int encoded len: {int_to_bytes(251)}")  # 2 bytes
        logger.debug(
            f"int encoded len: {int_from_bytes(_encoded_length)}")  # 2 bytes
        logger.debug(f"encoded length: {_encoded_length}")  # 2 bytes
        logger.debug(f"encoded length len: {_encoded_length_len}")  # 2 bytes

        # total frame length
        _total_frame_length: int = _payload_len + \
                                   len(int_to_bytes(_frame_type)) + \
                                   len(_out_offset) + len(_encoded_length)

        # 255 bytes
        logger.debug(
            f"crypto frame - total frame length: {_total_frame_length}")

        # initialize output frame
        output_frame = Buffer(capacity=_total_frame_length)

        output_frame.push_bytes(int_to_bytes(_frame_type))  # frame type
        output_frame.push_bytes(_out_offset)  # frame offset
        output_frame.push_uint_var(_payload_len)  # frame payload length
        output_frame.push_bytes(payload)  # frame payload

        # return output frame
        return QuicFrame(
            frame_type=_frame_type,
            data=output_frame.data,
            length=_total_frame_length
        )

    def create_hello(self, payload: bytes, offset: Optional[int] = 0) -> QuicFrame:
        # payload length
        _payload_len = len(payload)

        # type
        _frame_type = QuicFrameType.CLIENT_HELLO
        # offset
        _out_offset = encode_uint_var(offset)
        # payload length
        _encoded_length = encode_uint_var(_payload_len)

        # total frame length
        _total_frame_length: int = len(int_to_bytes(
            _frame_type)) + len(_out_offset) + len(_encoded_length) + _payload_len

        # initialize output frame
        output_frame = Buffer(capacity=_total_frame_length)

        output_frame.push_bytes(int_to_bytes(_frame_type))  # frame type
        output_frame.push_bytes(_out_offset)  # frame offset
        output_frame.push_uint_var(_payload_len)  # frame payload length
        output_frame.push_bytes(payload)  # frame payload

        logger.debug(f"client hello frame: {output_frame.data}")
        logger.debug(f"client hello frame length: {len(output_frame.data)}")

        # return output frame
        return QuicFrame(
            frame_type=_frame_type,
            data=output_frame.data,
            length=_total_frame_length
        )

    def create_stream(self, payload: bytes, type: int, offset: Optional[int] = 0):
        # payload length
        _payload_len = len(payload)

        # type
        _frame_type = QuicFrameType.STREAM

        # offset
        _out_offset = b"\x00"
        _out_offset = encode_uint_var(offset)
        # payload length
        _encoded_length = encode_uint_var(_payload_len)

        # total frame length
        _total_frame_length: int = len(int_to_bytes(
            _frame_type)) + len(_out_offset) + len(_encoded_length) + _payload_len

        # initialize output frame
        output_frame = Buffer(capacity=_total_frame_length)

        output_frame.push_bytes(int_to_bytes(_frame_type))  # frame type
        output_frame.push_bytes(_out_offset)  # frame offset
        output_frame.push_uint_var(_payload_len)  # frame payload length
        output_frame.push_bytes(payload)  # frame payload

        logger.debug(f"stream frame: {output_frame.data}")
        logger.debug(f"stream frame length: {len(output_frame.data)}")

        # return output frame
        return QuicFrame(
            frame_type=_frame_type,
            data=output_frame.data,
            length=_total_frame_length
        )

    def create_connection_close(self) -> QuicFrame:
        # type
        _frame_type = QuicFrameType.CONNECTION_CLOSE

        # total frame length
        _total_frame_length: int = len(int_to_bytes(_frame_type))
        logger.debug(
            f"connection close - total frame length: {_total_frame_length}")
        # + len(_out_offset) + len(_encoded_length) + _payload_len

        # initialize output frame
        output_frame = Buffer(capacity=_total_frame_length)

        output_frame.push_bytes(int_to_bytes(_frame_type))  # frame type

        logger.debug(f"connection close frame: {output_frame.data}")
        logger.debug(f"connection close length: {len(output_frame.data)}")

        # return output frame
        return QuicFrame(
            frame_type=_frame_type,
            data=output_frame.data,
            length=_total_frame_length
        )
