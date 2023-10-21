# built-in modules
from dataclasses import dataclass
from logging import getLogger
from typing import Optional

# logging module
logger = getLogger(__name__)


class BufferReadError(ValueError):
    pass


class BufferWriteError(ValueError):
    pass


@dataclass
class Buffer:
    def __init__(self, capacity: int = 0, data: Optional[bytes] = None, no_write_limit: Optional[bool] = False,
                 no_read_limit: Optional[bool] = False):
        self._pos: int = 0
        self._initial_capacity = capacity

        if data is None:
            self._base: bytearray = bytearray(capacity)
            self._end: int = capacity
        else:
            self._base: bytearray = bytearray(data)
            self._end: int = len(data)

        self._no_write_limit = no_write_limit
        self._no_read_limit = no_read_limit

    def __str__(self) -> str:
        return int.from_bytes(self._base, "big").__str__()

    @property
    def data(self) -> bytes:
        return bytes(self._base)

    @property
    def capacity(self) -> int:
        return self._end

    def tell(self) -> int:
        return self._pos

    def peekat(self, at: int, length: int = 1) -> int:
        self._check_read_bounds(length)

        ret_value: bytes = bytes(self._base[at:at + length])
        return ret_value

    def peek(self, length: int) -> int:
        self._check_read_bounds(length)

        ret_value: bytes = bytes(self._base[self._pos:self._pos + length])
        return ret_value

    def seek(self, pos: int) -> None:
        if pos < 0 or pos > self._end:
            raise BufferReadError("Seek out of bounds")
        self._pos = pos

    def clear(self) -> None:
        self._pos = 0
        self._end = self._initial_capacity
        self._base = bytearray(self._initial_capacity)

    def _check_read_bounds(self, length: int):
        if self._no_read_limit:
            if isinstance(length, int) and length > self.capacity:
                logger.debug(f"extending read bounds")
                self._base.extend(bytearray(length - self.capacity))
                self._end = len(self._base)

        if length < 0:
            logger.debug(f"check read bounds (length < 0): {length < 0}")
            raise BufferReadError("Read out of bounds")

        elif (self._pos + length) > self._end:
            logger.debug(
                f"check read bounds (((self._pos + length) > self._end)): {((self._pos + length) > self._end)}")
            raise BufferReadError("Read out of bounds")

    def _check_write_bounds(self, length: int):
        if self._no_write_limit:
            if isinstance(length, int) and length > self.capacity:
                logger.debug(f"extending write bounds")
                self._base.extend(bytearray(length - self.capacity))
                self._end = len(self._base)

        if self._pos + length > self._end:
            raise BufferWriteError("Write out of bounds")

    def pull_bytes(self, length: int) -> bytes:
        self._check_read_bounds(length)

        ret_value: bytes = bytes(self._base[self._pos:self._pos + length])
        self._pos += length
        return ret_value

    def pull_uint_var(self) -> int:
        # value = self._base[self._pos:self._pos + 1]
        v = self.pull_uint8()
        prefix = v >> 6
        length = 1 << prefix
        v = v & 0x3F

        for i in range(length - 1):
            v = (v << 8) + self.pull_uint8()

        return v
        # print(f"value is: {value}")
        # match (int_from_bytes(value) >> 6):
        #   case 0:
        #     return self.pull_uint8()
        #   case 1:
        #     return self.pull_uint16()
        #   case 2:
        #     return self.pull_uint32()
        #   case _:
        #     return self.pull_uint64()

    def pull_uint8(self) -> int:
        return int_from_bytes(self.pull_bytes(1))

    def pull_uint16(self) -> int:
        return int_from_bytes(self.pull_bytes(2))

    def pull_uint32(self) -> int:
        return int_from_bytes(self.pull_bytes(4))

    def pull_uint64(self) -> int:
        return int_from_bytes(self.pull_bytes(8))

    def push_bytes(self, data: bytes):
        self._check_write_bounds(len(data))
        for val in data:
            self._base[self._pos] = val
            self._pos += 1

    def push_uint8(self, data: int):
        self._check_write_bounds(1)
        byte_data = (bytearray(int_to_bytes(data))[0:1], b"\x00")[data == 0]
        logger.debug(f"byte_data is: {byte_data}")
        self.push_bytes(byte_data)

    def push_uint16(self, data: int):
        self._check_write_bounds(2)
        self.push_bytes(bytearray(int_to_bytes(data))[0:2])

    def push_uint32(self, data: int):
        self._check_write_bounds(4)
        self.push_bytes(bytearray(int_to_bytes(data))[0:4])

    def push_uint64(self, data: int):
        self._check_write_bounds(8)
        self.push_bytes(bytearray(int_to_bytes(data))[0:8])

    def push_uint_var(self, data: int):
        if data <= 0x3f:  # 64
            self._check_write_bounds(1)
            self.push_uint8(data)
        elif data <= 0x3fff:  # 16383
            self._check_write_bounds(2)
            logger.debug(f"pushing: {int_to_bytes(data | 0x4000)}")
            self.push_bytes(int_to_bytes(data | 0x4000))
        elif data <= 0x3ffffff:
            self._check_write_bounds(4)
            logger.debug(f"pushing: {int_to_bytes(data | 0x80000000)}")
            self.push_bytes(int_to_bytes(data | 0x80000000))
        elif data <= 0x3fffffffffffffff:
            self._check_write_bounds(8)
            logger.debug(
                f"pushing: {int_to_bytes(data | 0xc000000000000000)}")
            self.push_bytes(int_to_bytes(data | 0xc000000000000000))

        logger.debug(f"pushed data result: {self.data}")


UINT_VAR_MAX = 0x3fffffffffffffff
UINT_VAR_MAX_SIZE = 8


def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, "big")


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7)//8, "big")


def encode_uint_var(value: int) -> bytes:
    buf_capacity = size_uint_var(value=value)
    buf = Buffer(capacity=buf_capacity)
    buf.push_uint_var(value)
    return buf.data


def decode_uint_var(buf: Buffer, offset: Optional[int] = 0) -> int:

    temp_buf = Buffer(data=buf.data)
    temp_buf.seek(offset)

    v = temp_buf.pull_uint8()
    prefix = v >> 6
    length = 1 << prefix
    v = v & 0x3F

    for i in range(length - 1):
        v = (v << 8) + temp_buf.pull_uint8()

    return v


def size_uint_var(value: int) -> int:
    if value <= 0x3f:
        return 1
    elif value <= 0x3fff:
        return 2
    elif value <= 0x3fffffff:
        return 4
    elif value <= 0x3fffffffffffffff:
        return 8
    else:
        raise ValueError("Integer is too big for a variable-length integer")


def space_at(value: str, length: int) -> str:
    return " ".join([value[i:i+length] for i in range(0, len(value), length)])


def to_bits(value: int, spaced: Optional[bool] = True) -> str:
    num_bytes = len(int_to_bytes(value))
    output = format(value, f"0{num_bytes * 8}b")
    spaced_output = space_at(output, 8)
    return (output, spaced_output)[spaced]
