# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import ctypes
import os
import sys

PCAP_LINKTYPE_ETHERNET = 1
PCAP_LINKTYPE_PPP = 9
PCAP_LINKTYPE_IEEE802_11 = 105
PCAP_LINKTYPE_RAW = 101

current_dir = os.path.dirname(os.path.abspath(__file__)).replace("Saving","lib")

if sys.platform == "linux":
    lib = ctypes.CDLL(f"{current_dir}/libpcap_writer.so")
elif sys.platform == "win32":
    lib = ctypes.CDLL(f"{current_dir}/libpcap_writer.dll")
elif sys.platform == "darwin":
    lib = ctypes.CDLL(f"{current_dir}/libpcap_writer.dylib")
else:
    lib = ctypes.CDLL(f"{current_dir}/libpcap_writer.so")

class PcapPacketData(ctypes.Structure):
    _fields_ = [
        ("data_length", ctypes.c_uint32),
        ("payload", ctypes.POINTER(ctypes.c_ubyte))
    ]

lib.create_pcap_file.argtypes = [
    ctypes.c_char_p,           
    ctypes.POINTER(PcapPacketData),  
    ctypes.c_int,
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

class PcapWriteStream:
    def __init__(self, filename, linktype=PCAP_LINKTYPE_ETHERNET):
        if linktype is None:
            raise ValueError(
                "linktype is required — pass sock.datalink() "
                "so the file declares the correct link-layer type"
            )

        self.filename = filename
        self.linktype = linktype
        self._closed = False
        self._packets_written = 0

    def write(self, packets):
        if self._closed:
            raise RuntimeError("PcapWrite is closed")

        if not packets:
            return True

        packetarr, totalpackets = create_pcap(packets)
        rc = lib.create_pcap_file(
            self.filename.encode(),
            packetarr,
            totalpackets,
            self.linktype,
        )
        if rc != 0:
            raise IOError(f"Failed to write pcap: rc={rc}")

        self._packets_written += totalpackets
        return True

    def write_one(self, packet):
        """Convenience: write a single packet."""
        return self.write([packet])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        self._closed = True

    def __len__(self):
        return self._packets_written

    def __repr__(self):
        state = "closed" if self._closed else "open"
        return (f"<PcapWrite file={self.filename!r} "
                f"linktype={self.linktype} "
                f"written={self._packets_written} {state}>")

def PcapWrite(packets,filename,linktype=PCAP_LINKTYPE_ETHERNET):
    packetarr, totalpackets = create_pcap(packets)
    result = lib.create_pcap_file(filename.encode(),packetarr,totalpackets,linktype)
    return result
