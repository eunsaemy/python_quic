# built-in modules
from dataclasses import dataclass
from logging import getLogger
from typing import Callable, List

# implemented modules
from .buffer import (
    Buffer,
    to_bits,
)
from .frame_builder import (
    QuicFrameType,
)

# logging module
logger = getLogger(__name__)


@dataclass
class QuicParsedFrame:
    type: int
    payload_length: int
    payload: bytes


class QuicFrameParser:
    def __init__(self) -> None:
        self._parse_table: dict[int, Callable] = dict()
        self._initialize_handle_table()

    def _initialize_handle_table(self) -> None:
        self._parse_table[QuicFrameType.PADDING] = self._handle_padding
        self._parse_table[QuicFrameType.CRYPTO] = self._handle_crypto
        self._parse_table[QuicFrameType.CLIENT_HELLO] = self._handle_clienthello
        self._parse_table[QuicFrameType.STREAM] = self._handle_stream
        self._parse_table[QuicFrameType.CONNECTION_CLOSE] = self._handle_connection_close

    def parse(self, buffer: Buffer) -> list[QuicParsedFrame]:
        output_frames: List[QuicParsedFrame] = []
        while True:
            # error handling
            if buffer.tell() == buffer.capacity:
                break

            # get frame type
            frame_type = buffer.pull_uint8()

            if frame_type & 0x0f == QuicFrameType.STREAM:
                frame_type = QuicFrameType.STREAM

            if QuicFrameType(frame_type) in QuicFrameType:
                logger.debug(f"frame {frame_type} is a valid frame")
                logger.debug(f"parsing: {buffer.data}")
                logger.debug(f"parsing: {buffer.data.hex(' ', 1)}")
                logger.debug(f"buffer tell: {buffer.tell()}")
                if self._parse_table.get(QuicFrameType(frame_type)) is not None:
                    parsed_frame = self._parse_table[QuicFrameType(
                        frame_type)](buffer)
                    output_frames.append(parsed_frame)
                else:
                    self._handle_frame(buffer=buffer)
            else:
                break

        return output_frames

    # generic frame handler
    def _handle_frame(self, buffer: Buffer) -> QuicParsedFrame:
        logger.debug(f"parsing: {buffer.data}")
        return buffer.data

    # frame type 0
    def _handle_padding(self, buffer: Buffer) -> QuicParsedFrame:
        logger.debug(f"parsing padding frame")
        pass

    # frame type 6
    def _handle_crypto(self, buffer: Buffer) -> QuicParsedFrame:
        logger.debug(f"parsing crypto frame")

        # parse offset
        frame_offset = buffer.pull_uint_var()
        logger.debug(f"frame offset {frame_offset}")

        # parse length
        logger.debug(f"frame peek length {buffer.peek(1)}")
        frame_length = buffer.pull_uint_var()
        logger.debug(f"frame length {frame_length}")
        logger.debug(f"frame length {to_bits(frame_length)}")

        # parse frame payload
        frame_payload = buffer.pull_bytes(frame_length)
        logger.debug(f"frame length {frame_payload}")

        return QuicParsedFrame(
            QuicFrameType.CRYPTO,
            frame_length,
            frame_payload
        )

    def _handle_clienthello(self, buffer: Buffer) -> QuicParsedFrame:
        logger.debug(f"parsing client hello frame")

        # parse offset
        frame_offset = buffer.pull_uint_var()
        logger.debug(f"frame offset {frame_offset}")

        # parse length
        frame_length = buffer.pull_uint_var()
        logger.debug(f"frame length {frame_length}")
        logger.debug(f"frame length {to_bits(frame_length)}")

        # parse frame payload
        frame_payload = buffer.pull_bytes(frame_length)
        logger.debug(f"frame length {frame_payload}")

        return QuicParsedFrame(
            QuicFrameType.CLIENT_HELLO,
            frame_length,
            frame_payload
        )

    def _handle_serverhello(self, buffer: Buffer) -> QuicParsedFrame:
        logger.debug(f"parsing server hello frame")

        # parse offset
        frame_offset = buffer.pull_uint_var()
        logger.debug(f"frame offset {frame_offset}")

        # parse length
        frame_length = buffer.pull_uint_var()
        logger.debug(f"frame length {frame_length}")
        logger.debug(f"frame length {to_bits(frame_length)}")

        # parse frame payload
        frame_payload = buffer.pull_bytes(frame_length)
        logger.debug(f"frame length {frame_payload}")

        return QuicParsedFrame(
            QuicFrameType.SERVER_HELLO,
            frame_length,
            frame_payload
        )

    def _handle_stream(self, buffer: Buffer) -> QuicParsedFrame:
        logger.debug(f"parsing stream frame")

        # parse offset
        frame_offset = buffer.pull_uint_var()
        logger.debug(f"frame offset {frame_offset}")

        # parse length
        frame_length = buffer.pull_uint_var()
        logger.debug(f"frame length {frame_length}")
        logger.debug(f"frame length {to_bits(frame_length)}")

        # parse frame payload
        frame_payload = buffer.pull_bytes(frame_length)
        logger.debug(f"frame length {frame_payload}")

        return QuicParsedFrame(
            QuicFrameType.STREAM,
            frame_length,
            frame_payload
        )

    def _handle_connection_close(self, buffer: Buffer) -> QuicParsedFrame:
        logger.debug(f"parsing connection close frame")

        return QuicParsedFrame(
            QuicFrameType.CONNECTION_CLOSE,
            1,
            b""
        )
