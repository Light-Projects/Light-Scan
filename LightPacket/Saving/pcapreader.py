# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import ctypes
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__)).replace("Saving","lib")

if sys.platform == "linux":
    lib = ctypes.CDLL(f"{current_dir}/libpcap_reader.so")
elif sys.platform == "win32":
    lib = ctypes.CDLL(f"{current_dir}/libpcap_reader.dll")
elif sys.platform == "darwin":
    lib = ctypes.CDLL(f"{current_dir}/libpcap_reader.dylib")
else:
    lib = ctypes.CDLL(f"{current_dir}/libpcap_reader.so")

class PcapGlobalHeader(ctypes.Structure):
    _pack_ = 1  
    _fields_ = [
        ("magic_number", ctypes.c_uint32),
        ("version_major", ctypes.c_uint16),
        ("version_minor", ctypes.c_uint16),
        ("thiszone", ctypes.c_int32),
        ("sigfigs", ctypes.c_uint32),
        ("snaplen", ctypes.c_uint32),
        ("network", ctypes.c_uint32),
    ]


class PcapPacketHeader(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ts_sec", ctypes.c_uint32),
        ("ts_usec", ctypes.c_uint32),
        ("incl_len", ctypes.c_uint32),
        ("orig_len", ctypes.c_uint32),
    ]


class PacketEntry(ctypes.Structure):
    _fields_ = [
        ("header", PcapPacketHeader),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
    ]


class PcapResult(ctypes.Structure):
    _fields_ = [
        ("packets", ctypes.POINTER(PacketEntry)),
        ("count", ctypes.c_long),
        ("global_header", PcapGlobalHeader),
    ]


lib.read_pcap_file.argtypes = [ctypes.c_char_p]
lib.read_pcap_file.restype = PcapResult

lib.free_pcap_result.argtypes = [ctypes.POINTER(PcapResult)]
lib.free_pcap_result.restype = None

lib.print_packet_info.argtypes = [ctypes.POINTER(PcapResult)]
lib.print_packet_info.restype = None


class PcapReadStream:
    def __init__(self, filename):
        self.filename = filename
        self.header = None
        self.packets = []
        self._result = None

    def open(self):
        self._result = lib.read_pcap_file(self.filename.encode("utf-8"))
        if not self._result.packets or self._result.count == 0:
            return self

        self.header = [{
            'magic': hex(self._result.global_header.magic_number),
            'version_major': self._result.global_header.version_major,
            'version_minor': self._result.global_header.version_minor,
            'thiszone': self._result.global_header.thiszone,
            'sigfigs': self._result.global_header.sigfigs,
            'snaplen': self._result.global_header.snaplen,
            'network': self._result.global_header.network,
        }]

        for i in range(self._result.count):
            entry = self._result.packets[i]
            raw = ctypes.string_at(entry.data, entry.header.incl_len)
            self.packets.append({
                "ts_sec": entry.header.ts_sec,
                "ts_usec": entry.header.ts_usec,
                "incl_len": entry.header.incl_len,
                "orig_len": entry.header.orig_len,
                "data": raw,
            })
        return self

    def close(self):
        if self._result is not None:
            lib.free_pcap_result(ctypes.byref(self._result))
            self._result = None

    def __enter__(self):
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __getitem__(self, idx):
        if idx == 0:
            return self.header
        return self.packets

def PcapRead(filename):
    result = lib.read_pcap_file(filename.encode("utf-8"))

    if not result.packets or result.count == 0:
        return []

    packets = []
    header = [{
        'magic': hex(result.global_header.magic_number),
        'version_major':result.global_header.version_major,
        'version_minor':result.global_header.version_minor,
        'thiszone':result.global_header.thiszone,
        'sigfigs':result.global_header.sigfigs,
        'snaplen':result.global_header.snaplen,
        'network':result.global_header.network,
    }]
    for i in range(result.count):
        entry = result.packets[i]
        raw = ctypes.string_at(entry.data, entry.header.incl_len)
        packets.append({
            "ts_sec": entry.header.ts_sec,
            "ts_usec": entry.header.ts_usec,
            "incl_len": entry.header.incl_len,
            "orig_len": entry.header.orig_len,
            "data": raw,
        })

    lib.free_pcap_result(ctypes.byref(result))
    return header,packets


