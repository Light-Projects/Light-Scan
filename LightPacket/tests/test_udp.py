# LightPacket/tests/test_udp.py
"""
UDP layer tests: header, auto length, checksum with v4/v6 pseudo-header.
"""

import struct
import pytest

from LightPacket.udp import UDP, UDPParser
from LightPacket.Raw import Raw


class TestUDPHeader:

    def test_default_size(self):
        assert len(UDP().build()) == 8

    def test_roundtrip(self):
        udp = UDP(sport=53, dport=12345, length=12)
        raw = udp.build() + b'\x00\x00\x00\x00'
        parsed = UDPParser.load_as_udp_layer(raw)
        assert parsed.sport == 53
        assert parsed.dport == 12345
        assert parsed.length == 12

    def test_length_auto_with_payload(self):
        udp = UDP(sport=1, dport=2) / Raw(b'\xaa' * 10)
        raw = udp.build()
        length = struct.unpack('>H', raw[4:6])[0]
        assert length == 8 + 10

    def test_unset_checksum_is_zero(self):
        raw = UDP(sport=1, dport=2).build()
        assert struct.unpack('>H', raw[6:8])[0] == 0


class TestUDPChecksum:

    def test_checksum_ipv4_pseudo_header(self):
        udp = UDP(sport=1, dport=2)
        c = udp.compute_checksum('192.168.1.1', '192.168.1.2', is_ipv6=False)
        assert c != 0
        assert c == udp.checksum

    def test_checksum_ipv6_pseudo_header(self):
        udp = UDP(sport=1, dport=2)
        c = udp.compute_checksum('::1', '::2', is_ipv6=True)
        assert c != 0
        assert c == udp.checksum

    def test_checksum_differs_between_v4_and_v6(self):
        c4 = UDP(sport=1, dport=2).compute_checksum(
            '127.0.0.1', '127.0.0.2', is_ipv6=False)
        c6 = UDP(sport=1, dport=2).compute_checksum(
            '::1', '::2', is_ipv6=True)
        assert c4 != c6