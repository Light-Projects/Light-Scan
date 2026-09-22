# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import ctypes
import ctypes.util
import os
import sys
from dataclasses import dataclass
from typing import Iterator, Optional

current_dir = os.path.dirname(os.path.abspath(__file__)).replace("Saving","lib")

if sys.platform == "win32":
    _lib = ctypes.CDLL(f"{current_dir}/libpcapng.dll")
elif sys.platform == "linux":
    _lib = ctypes.CDLL(f"{current_dir}/libpcapng.so")
elif sys.platform == "darwin":
    _lib = ctypes.CDLL(f"{current_dir}/libpcapng.dylib")
else:
    _lib = ctypes.CDLL(f"{current_dir}/libpcapng.so")

class _CPacket(ctypes.Structure):
    _fields_ = [
        ("interface_id",   ctypes.c_uint32),
        ("timestamp_high", ctypes.c_uint32),
        ("timestamp_low",  ctypes.c_uint32),
        ("captured_len",   ctypes.c_uint32),
        ("original_len",   ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


class _CInterface(ctypes.Structure):
    _fields_ = [
        ("link_type", ctypes.c_uint16),
        ("snaplen",   ctypes.c_uint32),
        ("name", ctypes.c_char_p),
    ]

PCAPNG_OK               = 0
PCAPNG_ERR_IO           = -1
PCAPNG_ERR_FORMAT       = -2
PCAPNG_ERR_EOF          = -3
PCAPNG_ERR_NOMEM        = -4
PCAPNG_ERR_UNSUPPORTED  = -5
PCAPNG_ERR_INVAL        = -6

_lib.pcapng_writer_open.argtypes = [ctypes.c_char_p]
_lib.pcapng_writer_open.restype = ctypes.c_void_p

_lib.pcapng_writer_add_interface.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint16,
    ctypes.c_uint32,
    ctypes.c_char_p,
]
_lib.pcapng_writer_add_interface.restype = ctypes.c_int

_lib.pcapng_writer_write_packet.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.c_uint64,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_uint32,
]
_lib.pcapng_writer_write_packet.restype = ctypes.c_int

_lib.pcapng_writer_close.argtypes = [ctypes.c_void_p]
_lib.pcapng_writer_close.restype = None

_lib.pcapng_reader_open.argtypes = [ctypes.c_char_p]
_lib.pcapng_reader_open.restype = ctypes.c_void_p

_lib.pcapng_reader_next_packet.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(_CPacket),
]
_lib.pcapng_reader_next_packet.restype = ctypes.c_int

_lib.pcapng_reader_interface_count.argtypes = [ctypes.c_void_p]
_lib.pcapng_reader_interface_count.restype = ctypes.c_uint32

_lib.pcapng_reader_get_interface.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.POINTER(_CInterface),
]
_lib.pcapng_reader_get_interface.restype = ctypes.c_int

_lib.pcapng_reader_close.argtypes = [ctypes.c_void_p]
_lib.pcapng_reader_close.restype = None

_lib.pcapng_strerror.argtypes = [ctypes.c_int]
_lib.pcapng_strerror.restype = ctypes.c_char_p


class PcapngError(Exception):

    def __init__(self, status: int, context: str = ""):
        self.status = status
        message = _lib.pcapng_strerror(status).decode("utf-8", errors="replace")
        if context:
            message = f"{context}: {message}"
        super().__init__(message)


def _check(status: int, context: str = "") -> int:
    if status < 0:
        raise PcapngError(status, context)
    return status

@dataclass
class Packet:
    interface_id: int
    timestamp_usecs: int
    captured_len: int
    original_len: int
    data: bytes

    @property
    def is_truncated(self) -> bool:
        return self.captured_len < self.original_len

@dataclass
class Interface:
    link_type: int
    snaplen: int
    name: str

def _packet_from_cstruct(c_pkt: _CPacket) -> Packet:
    ts = (c_pkt.timestamp_high << 32) | c_pkt.timestamp_low
    if c_pkt.captured_len > 0:
        data = ctypes.string_at(c_pkt.data, c_pkt.captured_len)
    else:
        data = b""
    return Packet(
        interface_id=c_pkt.interface_id,
        timestamp_usecs=ts,
        captured_len=c_pkt.captured_len,
        original_len=c_pkt.original_len,
        data=data,
    )

class PcapngWriter:
    def __init__(self, path: str):
        handle = _lib.pcapng_writer_open(path.encode("utf-8"))
        if not handle:
            raise PcapngError(PCAPNG_ERR_IO, f"failed to open '{path}' for writing")
        self._handle = handle
        self._closed = False

    def add_interface(self, link_type: int, snaplen: int = 0,
                       name: Optional[str] = None) -> int:
        self._check_open()
        name_bytes = name.encode("utf-8") if name else None
        result = _lib.pcapng_writer_add_interface(
            self._handle, link_type, snaplen, name_bytes
        )
        return _check(result, "add_interface failed")

    def write_packet(self, interface_id: int, ts_usecs: int, data: bytes) -> None:
        self._check_open()
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data must be bytes-like, got {type(data).__name__}")

        length = len(data)
        buf_type = ctypes.c_uint8 * length
        c_buf = buf_type.from_buffer_copy(data) if length > 0 else buf_type()
        c_ptr = ctypes.cast(c_buf, ctypes.POINTER(ctypes.c_uint8))

        status = _lib.pcapng_writer_write_packet(
            self._handle, interface_id, ts_usecs, c_ptr, length
        )
        _check(status, "write_packet failed")

    def close(self) -> None:
        if not self._closed:
            _lib.pcapng_writer_close(self._handle)
            self._closed = True
            self._handle = None

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("I/O operation on closed PcapngWriter")

    def __enter__(self) -> "PcapngWriter":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

class PcapngReader:

    def __init__(self, path: str):
        handle = _lib.pcapng_reader_open(path.encode("utf-8"))
        if not handle:
            raise PcapngError(PCAPNG_ERR_FORMAT, f"failed to open '{path}' for reading")
        self._handle = handle
        self._closed = False

    @property
    def interfaces(self) -> list:
        self._check_open()
        count = _lib.pcapng_reader_interface_count(self._handle)
        result = []
        c_iface = _CInterface()
        for i in range(count):
            status = _lib.pcapng_reader_get_interface(
                self._handle, i, ctypes.byref(c_iface)
            )
            _check(status, f"get_interface({i}) failed")
            name = c_iface.name.decode("utf-8", errors="replace") if c_iface.name else ""
            result.append(Interface(
                link_type=c_iface.link_type,
                snaplen=c_iface.snaplen,
                name=name,
            ))
        return result

    def read_packet(self) -> Optional[Packet]:
        self._check_open()
        c_pkt = _CPacket()
        status = _lib.pcapng_reader_next_packet(self._handle, ctypes.byref(c_pkt))
        if status == PCAPNG_ERR_EOF:
            return None
        _check(status, "read_packet failed")
        return _packet_from_cstruct(c_pkt)

    def close(self) -> None:
        if not self._closed:
            _lib.pcapng_reader_close(self._handle)
            self._closed = True
            self._handle = None

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("I/O operation on closed PcapngReader")

    def __iter__(self) -> Iterator[Packet]:
        return self

    def __next__(self) -> Packet:
        packet = self.read_packet()
        if packet is None:
            raise StopIteration
        return packet

    def __enter__(self) -> "PcapngReader":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


__all__ = [
    "PcapngWriter",
    "PcapngReader",
    "Packet",
    "Interface",
    "PcapngError",
    "PCAPNG_OK",
    "PCAPNG_ERR_IO",
    "PCAPNG_ERR_FORMAT",
    "PCAPNG_ERR_EOF",
    "PCAPNG_ERR_NOMEM",
    "PCAPNG_ERR_UNSUPPORTED",
    "PCAPNG_ERR_INVAL",
]