# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import ctypes
import os
import sys
import struct

current_dir = os.path.dirname(os.path.abspath(__file__)).replace("Saving","lib")

if sys.platform == "linux":
    lib = ctypes.CDLL(f"{current_dir}/libpcap_writer.so")
elif sys.platform == "win32":
    lib = ctypes.CDLL(f"{current_dir}/libpcap_writer.dll")
else:
    raise OSError("Unsupported platform")

class PcapPacketData(ctypes.Structure):
    _fields_ = [
        ("data_length", ctypes.c_uint32),
        ("payload", ctypes.POINTER(ctypes.c_ubyte))
    ]

lib.create_pcap_file.argtypes = [
    ctypes.c_char_p,           
    ctypes.POINTER(PcapPacketData),  
    ctypes.c_int              
]
lib.create_pcap_file.restype = ctypes.c_int

def create_pcap(Data):
    if isinstance(Data, list):
        pass
    else:
        Data = [Data]
    
    packet_array = (PcapPacketData * len(Data))()
    
    for i, data in enumerate(Data):
        packet_array[i].data_length = len(data)
        packet_array[i].payload = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    
    return packet_array, len(Data)

def PcapWrite(packets,filename):
    packetarr, totalpackets = create_pcap(packets)
    result = lib.create_pcap_file(filename.encode(),packetarr,totalpackets)
    return result
