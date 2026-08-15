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
else:
    raise OSError("Unsupported platform")

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


def PcapRead(filename):
    result = lib.read_pcap_file(filename.encode("utf-8"))

    if not result.packets or result.count == 0:
        return []

    packets = []
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
    return packets


