# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
LightPacket Npcap Active and Available Interfaces.
"""

import ctypes
from ctypes import wintypes, byref, POINTER, Structure, c_char_p, c_void_p, c_int

pcap = ctypes.windll.wpcap

PCAP_ERRBUF_SIZE = 256
PCAP_SRC_IF_STRING = b"rpcap://"

class pcap_if(Structure):
    pass

pcap_if._fields_ = [
    ('next', POINTER(pcap_if)),
    ('name', c_char_p),
    ('description', c_char_p),
    ('addresses', c_void_p),
    ('flags', wintypes.DWORD)
]
pcap.pcap_findalldevs_ex.argtypes = [
    c_char_p,
    c_void_p,
    POINTER(POINTER(pcap_if)),
    c_char_p
]
pcap.pcap_findalldevs_ex.restype = c_int
pcap.pcap_freealldevs.argtypes = [POINTER(pcap_if)]
pcap.pcap_freealldevs.restype = None

def get_npcap_devices_windows():
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    devices_pointer = POINTER(pcap_if)()

    result = pcap.pcap_findalldevs_ex(
        PCAP_SRC_IF_STRING,
        None,
        byref(devices_pointer),
        errbuf
    )

    if result != 0:
        print(f"Error: {errbuf.value.decode()}")
        return []

    dev_list = []
    dev = devices_pointer
    while dev:
        name = dev.contents.name.decode() if dev.contents.name else ""
        desc = dev.contents.description.decode() if dev.contents.description else ""
        dev_list.append({"name": name, "description": desc})
        dev = dev.contents.next

    pcap.pcap_freealldevs(devices_pointer)
    return dev_list

