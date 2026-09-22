# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Comprehensive tests for LightBPF Compiler, covering:
1. Compilation of all AST node types produced by Parser/Lexer.
2. Bytecode assembly, backpatching, serialization, and disassembly.
3. Execution verification using BpfEmulator on real/synthetic packets.
4. Cross-verification with native libpcap C bpf_filter when available.
"""

import struct
import socket
import pytest
import ctypes
import ctypes.util

from LightPacket.LightBPF.Lexer import BpfLexer
from LightPacket.LightBPF.Parser import BpfParser
from LightPacket.LightBPF.Compiler import (
    BpfCompiler, Instruction, disassemble, BpfEmulator,
    BPF_RET, BPF_K, BPF_MAX_BUF_LEN, bpf_insn
)


# ----------------------------------------------------------------------
# Helper to build synthetic raw packets for testing
# ----------------------------------------------------------------------
def make_ethernet(dst_mac="aa:bb:cc:dd:ee:ff", src_mac="00:11:22:33:44:55", ethertype=0x0800):
    dst = bytes.fromhex(dst_mac.replace(":", ""))
    src = bytes.fromhex(src_mac.replace(":", ""))
    return dst + src + struct.pack("!H", ethertype)


def make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=b""):
    # IPv4 header: 20 bytes (IHL = 5 -> 0x45)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    total_len = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0x1234, 0x4000, 64, proto, 0, src, dst
    )
    return hdr + payload


def make_tcp(src_port=12345, dst_port=80, flags=0x02, payload=b"HELLO"):
    # TCP header: 20 bytes (data offset 5 -> 0x50)
    hdr = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, 1000, 0, 0x50, flags, 65535, 0, 0
    )
    return hdr + payload


def make_udp(src_port=54321, dst_port=53, payload=b"DNSDATA"):
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", src_port, dst_port, length, 0)
    return hdr + payload


def make_arp(src_ip="192.168.1.1", dst_ip="192.168.1.2",
             src_mac="00:11:22:33:44:55", dst_mac="aa:bb:cc:dd:ee:ff"):
    s_mac = bytes.fromhex(src_mac.replace(":", ""))
    d_mac = bytes.fromhex(dst_mac.replace(":", ""))
    s_ip = socket.inet_aton(src_ip)
    d_ip = socket.inet_aton(dst_ip)
    # HW=1, Proto=0x0800, HLen=6, PLen=4, Op=1 (Request)
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + s_mac + s_ip + d_mac + d_ip


def make_vlan(vid=100, inner_ethertype=0x0800, inner_payload=b""):
    # 802.1Q header: 4 bytes (EtherType 0x8100, TCI, inner EtherType)
    tci = vid & 0x0FFF
    return struct.pack("!HH", tci, inner_ethertype) + inner_payload


# Standard test packets
PKT_TCP_SYN = make_ethernet(ethertype=0x0800) + make_ipv4(src_ip="192.168.1.10", dst_ip="192.168.1.20", proto=6, payload=make_tcp(src_port=12345, dst_port=80, flags=0x02))
PKT_UDP_DNS = make_ethernet(ethertype=0x0800) + make_ipv4(src_ip="10.0.0.5", dst_ip="8.8.8.8", proto=17, payload=make_udp(src_port=40000, dst_port=53))
PKT_ARP = make_ethernet(ethertype=0x0806) + make_arp(src_ip="192.168.1.1", dst_ip="192.168.1.254")
PKT_BROADCAST = make_ethernet(dst_mac="ff:ff:ff:ff:ff:ff", ethertype=0x0800) + make_ipv4(dst_ip="255.255.255.255")
PKT_MULTICAST = make_ethernet(dst_mac="01:00:5e:00:00:01", ethertype=0x0800) + make_ipv4(dst_ip="224.0.0.1")
PKT_VLAN_100 = make_ethernet(ethertype=0x8100) + make_vlan(vid=100, inner_ethertype=0x0800, inner_payload=make_ipv4(src_ip="10.1.1.1"))


# ----------------------------------------------------------------------
# Optional native libpcap runner
# ----------------------------------------------------------------------
def _get_libpcap():
    name = ctypes.util.find_library("pcap")
    if name:
        try:
            lib = ctypes.CDLL(name)
            if hasattr(lib, "bpf_filter"):
                # u_int bpf_filter(const struct bpf_insn *, const u_char *, u_int, u_int)
                lib.bpf_filter.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]
                lib.bpf_filter.restype = ctypes.c_uint
                return lib
        except OSError:
            pass
    return None


LIBPCAP = _get_libpcap()


def verify_filter(filter_str: str, packet: bytes, should_match: bool):
    """Compiles filter, runs on BpfEmulator and libpcap (if available)."""
    insns = BpfCompiler.compile_str(filter_str)
    assert len(insns) >= 2
    # Verify last two are terminal returns
    assert insns[-2].code == (BPF_RET | BPF_K) and insns[-2].k == BPF_MAX_BUF_LEN
    assert insns[-1].code == (BPF_RET | BPF_K) and insns[-1].k == 0

    # 1. Emulator verification
    result = BpfEmulator.execute(insns, packet)
    if should_match:
        assert result > 0, f"Filter '{filter_str}' expected MATCH, but was REJECTED by emulator"
    else:
        assert result == 0, f"Filter '{filter_str}' expected REJECT, but MATCHED ({result}) in emulator"

    # 2. Native libpcap cross-verification
    if LIBPCAP is not None:
        insn_bytes = BpfCompiler.to_bytes(insns)
        pcap_result = LIBPCAP.bpf_filter(insn_bytes, packet, len(packet), len(packet))
        if should_match:
            assert pcap_result > 0, f"Filter '{filter_str}' matched emulator but was rejected by libpcap"
        else:
            assert pcap_result == 0, f"Filter '{filter_str}' rejected by emulator but matched by libpcap"


# ----------------------------------------------------------------------
# Test Suites
# ----------------------------------------------------------------------

class TestProtocolCompilation:
    def test_ip_filter(self):
        verify_filter("ip", PKT_TCP_SYN, True)
        verify_filter("ip", PKT_UDP_DNS, True)
        verify_filter("ip", PKT_ARP, False)

    def test_tcp_filter(self):
        verify_filter("tcp", PKT_TCP_SYN, True)
        verify_filter("tcp", PKT_UDP_DNS, False)
        verify_filter("tcp", PKT_ARP, False)

    def test_udp_filter(self):
        verify_filter("udp", PKT_UDP_DNS, True)
        verify_filter("udp", PKT_TCP_SYN, False)

    def test_arp_filter(self):
        verify_filter("arp", PKT_ARP, True)
        verify_filter("arp", PKT_TCP_SYN, False)

    def test_ether_filter(self):
        verify_filter("ether", PKT_TCP_SYN, True)
        verify_filter("ether", PKT_ARP, True)


class TestHostFilter:
    def test_ipv4_host(self):
        verify_filter("host 192.168.1.10", PKT_TCP_SYN, True)
        verify_filter("host 192.168.1.20", PKT_TCP_SYN, True)
        verify_filter("host 10.0.0.1", PKT_TCP_SYN, False)

    def test_src_dst_host(self):
        verify_filter("src host 192.168.1.10", PKT_TCP_SYN, True)
        verify_filter("dst host 192.168.1.10", PKT_TCP_SYN, False)
        verify_filter("dst host 192.168.1.20", PKT_TCP_SYN, True)
        verify_filter("src host 192.168.1.20", PKT_TCP_SYN, False)

    def test_mac_host(self):
        verify_filter("host 00:11:22:33:44:55", PKT_TCP_SYN, True)
        verify_filter("src host 00:11:22:33:44:55", PKT_TCP_SYN, True)
        verify_filter("dst host 00:11:22:33:44:55", PKT_TCP_SYN, False)
        verify_filter("dst host aa:bb:cc:dd:ee:ff", PKT_TCP_SYN, True)


class TestNetFilter:
    def test_cidr4(self):
        verify_filter("net 192.168.1.0/24", PKT_TCP_SYN, True)
        verify_filter("src net 192.168.0.0/16", PKT_TCP_SYN, True)
        verify_filter("dst net 10.0.0.0/8", PKT_TCP_SYN, False)
        verify_filter("net 10.0.0.0/8", PKT_UDP_DNS, True)

    def test_net_mask(self):
        verify_filter("net 192.168.0.0 mask 255.255.0.0", PKT_TCP_SYN, True)
        verify_filter("net 10.0.0.0 mask 255.0.0.0", PKT_TCP_SYN, False)


class TestPortFilter:
    def test_port(self):
        verify_filter("port 80", PKT_TCP_SYN, True)
        verify_filter("dst port 80", PKT_TCP_SYN, True)
        verify_filter("src port 80", PKT_TCP_SYN, False)
        verify_filter("src port 12345", PKT_TCP_SYN, True)
        verify_filter("port 53", PKT_TCP_SYN, False)
        verify_filter("port 53", PKT_UDP_DNS, True)

    def test_service_name_resolution(self):
        verify_filter("port http", PKT_TCP_SYN, True)
        verify_filter("port domain", PKT_UDP_DNS, True)

    def test_tcp_port_qualified(self):
        verify_filter("tcp port 80", PKT_TCP_SYN, True)
        verify_filter("udp port 80", PKT_TCP_SYN, False)
        verify_filter("udp port 53", PKT_UDP_DNS, True)
        verify_filter("tcp port 53", PKT_UDP_DNS, False)

    def test_portrange(self):
        verify_filter("portrange 70-90", PKT_TCP_SYN, True)
        verify_filter("portrange 100-200", PKT_TCP_SYN, False)
        verify_filter("src portrange 12000-13000", PKT_TCP_SYN, True)


class TestByteAccessAndArithmetic:
    def test_tcp_flags_syn(self):
        # TCP SYN flag: byte 13, bit 2
        verify_filter("tcp[13] & 2 != 0", PKT_TCP_SYN, True)
        verify_filter("tcp[13] & 1 != 0", PKT_TCP_SYN, False)  # FIN flag
        verify_filter("tcp[13] & 2 == 0", PKT_TCP_SYN, False)

    def test_pseudo_field_tcpflags(self):
        verify_filter("tcp[tcpflags] & tcp-syn != 0", PKT_TCP_SYN, True)
        verify_filter("tcp[tcpflags] & tcp-fin != 0", PKT_TCP_SYN, False)
        verify_filter("tcp[tcpflags] & (tcp-syn | tcp-ack) != 0", PKT_TCP_SYN, True)

    def test_ether_byte_access(self):
        # EtherType at offset 12 == 0x0800
        verify_filter("ether[12:2] == 0x0800", PKT_TCP_SYN, True)
        verify_filter("ether[12:2] == 0x0806", PKT_TCP_SYN, False)
        verify_filter("ether[12:2] == 0x0806", PKT_ARP, True)

    def test_ip_byte_access(self):
        # IP Version 4, IHL 5: ip[0] == 0x45
        verify_filter("ip[0] == 0x45", PKT_TCP_SYN, True)
        verify_filter("(ip[0] & 0xf) == 5", PKT_TCP_SYN, True)
        verify_filter("(ip[0] & 0xf) * 4 == 20", PKT_TCP_SYN, True)
        verify_filter("(ip[0] & 0xf) * 4 > 20", PKT_TCP_SYN, False)


class TestLogicalExpressions:
    def test_and_or_not(self):
        verify_filter("tcp and port 80", PKT_TCP_SYN, True)
        verify_filter("tcp and port 443", PKT_TCP_SYN, False)
        verify_filter("tcp or udp", PKT_TCP_SYN, True)
        verify_filter("tcp or udp", PKT_UDP_DNS, True)
        verify_filter("not udp", PKT_TCP_SYN, True)
        verify_filter("not tcp", PKT_TCP_SYN, False)

    def test_nested_compound(self):
        verify_filter("(tcp or udp) and not dst port 53", PKT_TCP_SYN, True)
        verify_filter("(tcp or udp) and not dst port 53", PKT_UDP_DNS, False)
        verify_filter("tcp and (port 80 or port 443)", PKT_TCP_SYN, True)


class TestPacketLength:
    def test_length_filters(self):
        pkt_len = len(PKT_TCP_SYN)
        verify_filter(f"len == {pkt_len}", PKT_TCP_SYN, True)
        verify_filter(f"len > {pkt_len - 1}", PKT_TCP_SYN, True)
        verify_filter(f"len < {pkt_len + 1}", PKT_TCP_SYN, True)
        verify_filter("greater 10", PKT_TCP_SYN, True)
        verify_filter("greater 500", PKT_TCP_SYN, False)
        verify_filter("less 500", PKT_TCP_SYN, True)
        verify_filter("less 10", PKT_TCP_SYN, False)


class TestSpecialFilters:
    def test_broadcast(self):
        verify_filter("broadcast", PKT_BROADCAST, True)
        verify_filter("broadcast", PKT_TCP_SYN, False)

    def test_multicast(self):
        verify_filter("multicast", PKT_MULTICAST, True)
        verify_filter("multicast", PKT_TCP_SYN, False)

    def test_vlan(self):
        verify_filter("vlan", PKT_VLAN_100, True)
        verify_filter("vlan 100", PKT_VLAN_100, True)
        verify_filter("vlan 200", PKT_VLAN_100, False)
        verify_filter("vlan", PKT_TCP_SYN, False)


class TestSerializationAndDisassembly:
    def test_serialization(self):
        insns = BpfCompiler.compile_str("tcp port 80")
        raw = BpfCompiler.to_bytes(insns)
        assert len(raw) == len(insns) * 8

        fprog = BpfCompiler.to_fprog(insns)
        assert fprog.len == len(insns)
        assert fprog.filter is not None

    def test_disassembly_output(self):
        insns = BpfCompiler.compile_str("tcp port 80")
        text = disassemble(insns)
        assert "(000)" in text
        assert "ret #" in text


def make_ipv6(src_ip="2001:db8::1", dst_ip="2001:db8::2", next_hdr=6, payload=b""):
    src = socket.inet_pton(socket.AF_INET6, src_ip)
    dst = socket.inet_pton(socket.AF_INET6, dst_ip)
    hdr = struct.pack("!IHBB", 0x60000000, len(payload), next_hdr, 64) + src + dst
    return hdr + payload


def make_mpls(label=500, tc=0, s=1, ttl=64, inner_payload=b""):
    entry = (label << 12) | (tc << 9) | (s << 8) | ttl
    return struct.pack("!I", entry) + inner_payload


PKT_IPV6_TCP = make_ethernet(ethertype=0x86DD) + make_ipv6(src_ip="2001:db8::1", dst_ip="2001:db8::2", next_hdr=6, payload=make_tcp(dst_port=80))
PKT_MPLS_500 = make_ethernet(ethertype=0x8847) + make_mpls(label=500, inner_payload=make_ipv4(src_ip="10.0.0.1"))


class TestIPv6AndMPLS:
    def test_ipv6_protocol(self):
        verify_filter("ip6", PKT_IPV6_TCP, True)
        verify_filter("ip6", PKT_TCP_SYN, False)

    def test_ipv6_host(self):
        verify_filter("host 2001:db8::1", PKT_IPV6_TCP, True)
        verify_filter("src host 2001:db8::1", PKT_IPV6_TCP, True)
        verify_filter("dst host 2001:db8::1", PKT_IPV6_TCP, False)
        verify_filter("dst host 2001:db8::2", PKT_IPV6_TCP, True)

    def test_ipv6_net(self):
        verify_filter("net 2001:db8::/32", PKT_IPV6_TCP, True)
        verify_filter("net 2001:db9::/32", PKT_IPV6_TCP, False)

    def test_mpls_filter(self):
        verify_filter("mpls", PKT_MPLS_500, True)
        verify_filter("mpls 500", PKT_MPLS_500, True)
        verify_filter("mpls 600", PKT_MPLS_500, False)
        verify_filter("mpls", PKT_TCP_SYN, False)


class TestProtoKeyword:
    def test_ip_proto(self):
        verify_filter("ip proto 6", PKT_TCP_SYN, True)
        verify_filter("ip proto tcp", PKT_TCP_SYN, True)
        verify_filter("ip proto 17", PKT_TCP_SYN, False)
        verify_filter("ip proto udp", PKT_UDP_DNS, True)


class TestComplexArithmetic:
    def test_comparisons_and_operators(self):
        # Relational operators <, <=, >, >=, ==, !=
        verify_filter("ip[0] < 100", PKT_TCP_SYN, True)
        verify_filter("ip[0] <= 0x45", PKT_TCP_SYN, True)
        verify_filter("ip[0] > 0x45", PKT_TCP_SYN, False)
        verify_filter("ip[0] >= 0x45", PKT_TCP_SYN, True)
        verify_filter("ip[0] != 0", PKT_TCP_SYN, True)

    def test_both_sides_expressions(self):
        # Complex expression on both sides (testing scratch memory allocation)
        verify_filter("(ip[0] & 0xf) * 4 == (ip[0] & 0xf) * 4", PKT_TCP_SYN, True)
        verify_filter("(ip[0] & 0xf) * 4 != (ip[0] & 0xf) * 4 + 1", PKT_TCP_SYN, True)

