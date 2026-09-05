# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
BPF Compilation Process
"""
import ctypes
from ctypes import (
    create_string_buffer, c_int, c_char_p, c_uint,
    c_void_p, byref
)

try:
    pcap_lib = ctypes.CDLL("libpcap.so.1")
except OSError:
    try:
        pcap_lib = ctypes.CDLL("libpcap.so")
    except OSError:
        pass


class bpf_program(ctypes.Structure):
    _fields_ = [
        ('bf_len', c_uint),
        ('bf_insns', c_void_p),
    ]


pcap_lib.pcap_create.argtypes = [c_char_p, c_char_p]
pcap_lib.pcap_create.restype = c_void_p

pcap_lib.pcap_activate.argtypes = [c_void_p]
pcap_lib.pcap_activate.restype = c_int

pcap_lib.pcap_compile.argtypes = [c_void_p, c_void_p, c_char_p, c_int, c_uint]
pcap_lib.pcap_compile.restype = c_int


pcap_lib.pcap_close.argtypes = [c_void_p]
pcap_lib.pcap_close.restype = None

pcap_lib.pcap_freecode.argtypes = [c_void_p]
pcap_lib.pcap_freecode.restype = None


def free_filter(bp: bpf_program) -> None:
    """
    Free a bpf_program created with compile_filter
    """
    pcap_lib.pcap_freecode(ctypes.byref(bp))


class bpf_insn(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class sock_fprog(ctypes.Structure):
    """"Structure for SO_ATTACH_FILTER"""
    _fields_ = [('len', ctypes.c_ushort),
                ('filter', ctypes.POINTER(bpf_insn))]

def compile_filter_pcap(filter_str: str, iface: str):
    """Compiles a BPF filter using libpcap."""
    errbuf = create_string_buffer(256)
    pcap = pcap_lib.pcap_create(iface.encode('utf-8'), errbuf)
    if not pcap:
        return None
    if pcap_lib.pcap_activate(pcap) != 0:
        pcap_lib.pcap_close(pcap)
        return None

    fp = bpf_program()
    filter_bytes = filter_str.encode('utf-8')

    result = pcap_lib.pcap_compile(pcap, byref(fp), filter_bytes, 1, -1)
    if result != 0:
        pcap_lib.pcap_close(pcap)
        return None

    pcap_lib.pcap_close(pcap)
    return fp

def get_bpf_bytes(filter_str, iface):
    """Get just the BPF instructions from libpcap directly ."""
    bp = compile_filter_pcap(filter_str, iface)
    if bp is None:
        return None, None

    # Cast the void pointer to a pointer to bpf_insn
    insns_ptr = ctypes.cast(bp.bf_insns, ctypes.POINTER(bpf_insn))
    fp = sock_fprog(bp.bf_len, insns_ptr)
    return fp,bp
