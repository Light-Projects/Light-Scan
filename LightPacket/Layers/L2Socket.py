# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Standalone LightPacket L2pcapSocket for Windows (Npcap) – used for layer 2 packets socket.
"""
import ctypes
from ctypes import (
    create_string_buffer, c_ubyte, c_int, c_char_p, c_uint,
    c_void_p, byref, POINTER, c_ulong
)
import os
import sys
import time
import select
from typing import Optional
from ..Interfaces.WinInterfaces import get_default_interface_npcap_name_windows


if sys.platform != "win32":
    raise RuntimeError("This module is designed for Windows with Npcap.")


_npcap_path = os.path.join(os.environ["WINDIR"], "System32", "Npcap", "wpcap.dll")
if not os.path.isfile(_npcap_path):
    _npcap_path = "wpcap.dll"

pcap_lib = ctypes.windll.LoadLibrary(_npcap_path)

class pcap_pkthdr(ctypes.Structure):
    _fields_ = [
        ('ts_sec', c_ulong),
        ('ts_usec', c_ulong),
        ('caplen', c_uint),
        ('len', c_uint),
    ]

class bpf_program(ctypes.Structure):
    _fields_ = [
        ('bf_len', c_uint),
        ('bf_insns', c_void_p),
    ]

PCAP_ERRBUF_SIZE = 256
PCAP_ERROR = -1

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
NULL_MAC = '00:00:00:00:00:00'
BROADCAST_MAC_RAW = 'ffffffffffff'
NULL_MAC_RAW = '000000000000'

pcap_create = pcap_lib.pcap_create
pcap_create.restype = c_void_p
pcap_create.argtypes = [c_char_p, c_char_p]

pcap_set_snaplen = pcap_lib.pcap_set_snaplen
pcap_set_snaplen.restype = c_int
pcap_set_snaplen.argtypes = [c_void_p, c_int]

pcap_set_promisc = pcap_lib.pcap_set_promisc
pcap_set_promisc.restype = c_int
pcap_set_promisc.argtypes = [c_void_p, c_int]

pcap_set_timeout = pcap_lib.pcap_set_timeout
pcap_set_timeout.restype = c_int
pcap_set_timeout.argtypes = [c_void_p, c_int]

pcap_lib.pcap_set_immediate_mode.argtypes = [c_void_p, c_int]
pcap_lib.pcap_set_immediate_mode.restype = c_int

pcap_lib.pcap_get_selectable_fd.argtypes = [c_void_p]
pcap_lib.pcap_get_selectable_fd.restype = c_int

pcap_set_rfmon = pcap_lib.pcap_set_rfmon
pcap_set_rfmon.restype = c_int
pcap_set_rfmon.argtypes = [c_void_p, c_int]

pcap_activate = pcap_lib.pcap_activate
pcap_activate.restype = c_int
pcap_activate.argtypes = [c_void_p]

pcap_setmintocopy = pcap_lib.pcap_setmintocopy
pcap_setmintocopy.restype = c_int
pcap_setmintocopy.argtypes = [c_void_p, c_int]

pcap_inject = pcap_lib.pcap_inject
pcap_inject.restype = c_int
pcap_inject.argtypes = [c_void_p, c_void_p, ctypes.c_size_t]

pcap_sendpacket = pcap_lib.pcap_sendpacket
pcap_sendpacket.restype = c_int
pcap_sendpacket.argtypes = [c_void_p, c_void_p, c_int]

pcap_next_ex = pcap_lib.pcap_next_ex
pcap_next_ex.restype = c_int
pcap_next_ex.argtypes = [c_void_p, POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_ubyte))]

pcap_compile = pcap_lib.pcap_compile
pcap_compile.restype = c_int
pcap_compile.argtypes = [c_void_p, c_void_p, c_char_p, c_int, c_uint]

pcap_setfilter = pcap_lib.pcap_setfilter
pcap_setfilter.restype = c_int
pcap_setfilter.argtypes = [c_void_p, c_void_p]

pcap_close = pcap_lib.pcap_close
pcap_close.argtypes = [c_void_p]

pcap_freecode = pcap_lib.pcap_freecode
pcap_freecode.argtypes = [c_void_p]

pcap_geterr = pcap_lib.pcap_geterr
pcap_geterr.restype = c_char_p
pcap_geterr.argtypes = [c_void_p]


class L2Socket:
    """Raw layer-2 socket for Windows (Npcap)."""

    def __init__(self, iface=get_default_interface_npcap_name_windows(), snaplen=65535, promisc=True, to_ms=100, monitor=False):
        self.iface = iface
        self.pcap = None
        self._filter = None
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)

        self.pcap = pcap_create(iface.encode("utf8"), errbuf)
        if not self.pcap:
            raise OSError(self._err(errbuf))

        if pcap_set_snaplen(self.pcap, snaplen) != 0:
            raise OSError(self._err(errbuf) or "Could not set snaplen")
        if pcap_set_promisc(self.pcap, 1 if promisc else 0) != 0:
            raise OSError(self._err(errbuf) or "Could not set promisc")
        if pcap_set_timeout(self.pcap, to_ms) != 0:
            raise OSError(self._err(errbuf) or "Could not set timeout")
        if pcap_lib.pcap_set_immediate_mode(self.pcap, 1) != 0:
            raise OSError(self._err(errbuf) or "Could not set immediate mode")
        if monitor:
            if pcap_set_rfmon(self.pcap, 1) != 0:
                raise OSError(self._err(errbuf) or "Could not set monitor mode")

        status = pcap_activate(self.pcap)
        if status < 0:
            raise OSError(self._err(errbuf) or f"pcap_activate failed with status {status}")

        pcap_setmintocopy(self.pcap, 0)

        self._errbuf = errbuf
        self.closed = False

    def _err(self, errbuf):
        """Extract error message from errbuf."""
        return errbuf.value.decode("utf-8", errors="ignore").strip("\x00") or None

    def sendl2(self, packet):

        if self.closed or not self.pcap:
            raise RuntimeError("Socket closed")

        if hasattr(packet, 'build') and callable(packet.build):
            packet = packet.build()

        data = (c_ubyte * len(packet)).from_buffer_copy(packet)
        return pcap_inject(self.pcap, data, len(packet))

    def set_filter(self, filter_str: str) -> bool:

        if not self.pcap:
            return False

        fp = bpf_program()
        filter_bytes = filter_str.encode('utf-8')

        result = pcap_compile(self.pcap, byref(fp), filter_bytes, 1, 0)
        if result != 0:
            return False

        result = pcap_setfilter(self.pcap, byref(fp))
        pcap_freecode(byref(fp))

        if result == 0:
            self._filter = filter_str
            return True
        return False

    def recvl2(self, count: int = 1, timeout: float = 1.0) -> list:
        """Receive Layer 2 packets."""
        if self.closed or not self.pcap:
            raise RuntimeError("Socket closed")

        fd = pcap_lib.pcap_get_selectable_fd(self.pcap)

        packets = []
        deadline = time.time() + timeout
        received = 0

        while True:
            remaining = deadline - time.time()
            if timeout > 0 and remaining <= 0:
                break

            if fd >= 0 and timeout > 0:
                ready, _, _ = select.select([fd], [], [], remaining)
                if not ready:
                    break

            header_ptr = POINTER(pcap_pkthdr)()
            data_ptr = POINTER(c_ubyte)()

            ret = pcap_lib.pcap_next_ex(self.pcap, byref(header_ptr), byref(data_ptr))

            if ret == 1:
                if header_ptr and data_ptr:
                    length = header_ptr.contents.len
                    data = bytearray(length)
                    for i in range(length):
                        data[i] = data_ptr[i]
                    packets.append(bytes(data))
                    received += 1

                    if count > 0 and received >= count:
                        break
            elif ret == -1:
                err = self.geterr()
                raise RuntimeError(f"pcap_next_ex error: {err}")

        return packets

    def srp1(self, packet, timeout: float = 3.0, filter_str: str = None) -> Optional[bytes]:
        """Send and receive one Layer 2 packet."""
        if self.closed or not self.pcap:
            raise RuntimeError("Socket closed")

        if hasattr(packet, 'build') and callable(packet.build):
            send_data = packet.build()
        else:
            send_data = packet

        data = (c_ubyte * len(send_data)).from_buffer_copy(send_data)
        sent = pcap_lib.pcap_inject(self.pcap, data, len(send_data))

        original_filter = self._filter
        if filter_str:
            self.set_filter(filter_str)

        fd = pcap_lib.pcap_get_selectable_fd(self.pcap)

        response = None
        deadline = time.time() + timeout

        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break

            if fd >= 0:
                ready, _, _ = select.select([fd], [], [], remaining)
                if not ready:
                    break

            header_ptr = POINTER(pcap_pkthdr)()
            data_ptr = POINTER(c_ubyte)()

            ret = pcap_lib.pcap_next_ex(self.pcap, byref(header_ptr), byref(data_ptr))

            if ret == 1:
                if header_ptr and data_ptr:
                    length = header_ptr.contents.len
                    buf = bytearray(length)
                    for i in range(length):
                        buf[i] = data_ptr[i]
                    response = bytes(buf)
                    break
            elif ret == -1:
                err = self.geterr()
                raise RuntimeError(f"pcap_next_ex error: {err}")

        if original_filter:
            self.set_filter(original_filter)
        elif filter_str:
            self.set_filter("")

        return response

    def srp(self, packet, timeout: float = 3.0, count: int = 1, filter_str: str = None) -> list:
        """Send and receive multiple Layer 2 packets."""
        responses = []

        if hasattr(packet, 'build') and callable(packet.build):
            send_data = packet.build()
        else:
            send_data = packet

        data = (c_ubyte * len(send_data)).from_buffer_copy(send_data)
        sent = pcap_lib.pcap_inject(self.pcap, data, len(send_data))

        original_filter = self._filter
        if filter_str:
            self.set_filter(filter_str)

        fd = pcap_lib.pcap_get_selectable_fd(self.pcap)

        deadline = time.time() + timeout
        received = 0

        while count == 0 or received < count:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            if fd >= 0:
                ready, _, _ = select.select([fd], [], [], remaining)
                if not ready:
                    break

            header_ptr = POINTER(pcap_pkthdr)()
            data_ptr = POINTER(c_ubyte)()

            ret = pcap_lib.pcap_next_ex(self.pcap, byref(header_ptr), byref(data_ptr))

            if ret == 1:
                if header_ptr and data_ptr:
                    length = header_ptr.contents.len
                    buf = bytearray(length)
                    for i in range(length):
                        buf[i] = data_ptr[i]
                    responses.append(bytes(buf))
                    received += 1
            elif ret == -1:
                err = self.geterr()
                raise RuntimeError(f"pcap_next_ex error: {err}")

        if original_filter:
            self.set_filter(original_filter)
        elif filter_str:
            self.set_filter("")

        return responses

    def geterr(self):
        if not self.pcap:
            return ""
        err = pcap_geterr(self.pcap)
        return err.decode("utf-8", errors="ignore") if err else ""

    def close(self):
        if self.pcap:
            pcap_close(self.pcap)
            self.pcap = None
            self.closed = True

    def __del__(self):
        self.close()

