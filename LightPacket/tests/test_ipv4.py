# LightPacket/tests/test_ipv4.py
"""
IPv4 layer tests: header, checksum self-consistency, options, frag.
"""

import struct
import pytest

from LightPacket.ipv4 import IPv4, IPv4Parser, PROTO_TCP, PROTO_UDP
from LightPacket.utils.Checksum import ipv4_header_checksum as _checksum
from LightPacket.helper.ipv4.IPOptions import IPOptions, IPOption, OPT_NOP
from LightPacket.tcp import TCP, SYN
from LightPacket.udp import UDP


class TestIPv4Header:

    def test_default_no_options(self):
        assert len(IPv4().build()) == 20

    def test_roundtrip(self):
        ip = IPv4(src='192.168.1.1', dst='192.168.1.2',
                  proto=PROTO_TCP, ttl=64)
        parsed = IPv4Parser.load_as_ip_layer(ip.build())
        assert parsed.src == '192.168.1.1'
        assert parsed.dst == '192.168.1.2'
        assert parsed.ttl == 64
        assert parsed.proto == PROTO_TCP
        assert parsed.version == 4
        assert parsed.ihl == 5

    def test_proto_inference_tcp(self):
        raw = (IPv4(src='1.1.1.1', dst='2.2.2.2')
               / TCP(sport=1, dport=2)).build()
        assert raw[9] == PROTO_TCP

    def test_proto_inference_udp(self):
        raw = (IPv4(src='1.1.1.1', dst='2.2.2.2')
               / UDP(sport=1, dport=2)).build()
        assert raw[9] == PROTO_UDP

    def test_checksum_self_consistent(self):
        ip = IPv4(src='10.0.0.1', dst='10.0.0.2',
                  proto=PROTO_TCP, ttl=64)
        raw = ip.build()
        header = bytearray(raw[:20])
        header[10:12] = b'\x00\x00'
        expected = _checksum(bytes(header))
        actual = struct.unpack('>H', raw[10:12])[0]
        assert actual == expected

    def test_total_len_includes_payload(self):
        pkt = IPv4(src='1.1.1.1', dst='2.2.2.2') / TCP(sport=1, dport=2)
        raw = pkt.build()
        total_len = struct.unpack('>H', raw[2:4])[0]
        assert total_len == len(raw)

    def test_flags_and_frag_offset(self):
        ip = IPv4(src='1.1.1.1', dst='2.2.2.2', flags=0x1, frag_offset=100)
        raw = ip.build()
        flags_frag = struct.unpack('>H', raw[6:8])[0]
        assert (flags_frag >> 13) & 0x7 == 0x1
        assert flags_frag & 0x1FFF == 100


class TestIPv4Options:

    def test_options_bump_ihl(self):
        # 4 NOPs = 4 bytes → IHL = 6 (24 bytes header)
        opts = IPOptions([IPOption(OPT_NOP)] * 4)
        ip = IPv4(src='1.1.1.1', dst='2.2.2.2', options=opts)
        raw = ip.build()
        ihl = raw[0] & 0x0F
        assert ihl == 6
        assert len(raw) == 24

    def test_options_roundtrip(self):
        opts = IPOptions([IPOption(OPT_NOP)] * 4)
        ip = IPv4(src='1.1.1.1', dst='2.2.2.2', options=opts)
        parsed = IPv4Parser.load_as_ip_layer(ip.build())
        assert parsed.ihl == 6
        assert len(parsed.options) == 4