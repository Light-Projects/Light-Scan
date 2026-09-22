# LightPacket/tests/test_ipv6.py
"""
IPv6 layer tests: header, next-header inference, extension headers.
"""

import struct
import pytest

from LightPacket.ipv6 import IPv6, IPv6Parser, PROTO_TCP, PROTO_UDP
from LightPacket.helper.ipv6.IPv6ExtHeader import (
    IPv6ExtHeader, EXT_HOP_BY_HOP, EXT_ROUTING,
)
from LightPacket.tcp import TCP, SYN
from LightPacket.udp import UDP


class TestIPv6Header:

    def test_default_size(self):
        assert len(IPv6().build()) == 40

    def test_roundtrip(self):
        ip = IPv6(src='2001:db8::1', dst='2001:db8::2',
                  next_header=PROTO_TCP, hop_limit=64)
        parsed = IPv6Parser.load_as_ip_layer(ip.build())
        assert parsed.src == '2001:db8::1'
        assert parsed.dst == '2001:db8::2'
        assert parsed.next_header == PROTO_TCP
        assert parsed.hop_limit == 64
        assert parsed.version == 6

    def test_next_header_inference_tcp(self):
        raw = (IPv6(src='::1', dst='::2') / TCP(sport=1, dport=2)).build()
        assert raw[6] == PROTO_TCP

    def test_next_header_inference_udp(self):
        raw = (IPv6(src='::1', dst='::2') / UDP(sport=1, dport=2)).build()
        assert raw[6] == PROTO_UDP

    def test_payload_len(self):
        pkt = IPv6(src='::1', dst='::2') / UDP(sport=1, dport=2)
        raw = pkt.build()
        payload_len = struct.unpack('>H', raw[4:6])[0]
        assert payload_len == len(raw) - 40

    def test_traffic_class_and_flow_label(self):
        ip = IPv6(src='::1', dst='::2',
                  traffic_class=0xAB, flow_label=0x12345)
        raw = ip.build()
        vtf = struct.unpack('>I', raw[:4])[0]
        assert (vtf >> 28) & 0xF == 6
        assert (vtf >> 20) & 0xFF == 0xAB
        assert vtf & 0xFFFFF == 0x12345


class TestIPv6ExtensionHeaders:

    def test_hop_by_hop_sets_next_header(self):
        ext = IPv6ExtHeader(type=EXT_HOP_BY_HOP,
                            data=b'\x01\x04\x00\x00\x00\x00')
        raw = (IPv6(src='::1', dst='::2') / ext / UDP(sport=1, dport=2)).build()
        # IPv6 next-header should be 0 (Hop-by-Hop)
        assert raw[6] == EXT_HOP_BY_HOP

    def test_extension_header_size(self):
        # 6 bytes of data → 8-byte total (hdr_ext_len = 0)
        ext = IPv6ExtHeader(type=EXT_HOP_BY_HOP, data=b'\x00' * 6)
        assert len(ext) == 8

    def test_extension_roundtrip(self):
        ext = IPv6ExtHeader(type=EXT_ROUTING, data=b'\x00' * 6)
        pkt = IPv6(src='::1', dst='::2') / ext / UDP(sport=1, dport=2)
        parsed = IPv6Parser.load_as_ip_layer(pkt.build())
        assert parsed.payload.__class__.__name__ == 'IPv6ExtHeader'