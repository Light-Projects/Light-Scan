# LightPacket/tests/test_ppp.py
"""
PPP / PPP2b / PPPoE tests.

Covers the proto auto-set for IPv6 payloads and round-trip through the
parsers. The registry lookup in PPP2bParser passes a tuple instead of an
int — harmless for registered protocols (they're keyed by int) but noted.
"""

import struct

from LightPacket.ppp import (
    PPP, PPPParser, PPP2b, PPP2bParser, PPPoE, PPPoEParser,
    v4, v6,
)
from LightPacket.ipv4 import IPv4
from LightPacket.ipv6 import IPv6


class TestPPP:

    def test_fixed_size(self):
        assert len(PPP().build()) == 4

    def test_roundtrip(self):
        p = PPP(address=0xFF, control=0x03, proto=0x0021)
        parsed = PPPParser.load_as_ppp_layer(p.build())
        assert parsed.address == 0xFF
        assert parsed.control == 0x03
        assert parsed.proto == 0x0021

    def test_ipv4_payload(self):
        p = PPP() / IPv4(src='1.1.1.1', dst='2.2.2.2')
        parsed = PPPParser.load_as_ppp_layer(p.build())
        assert parsed.payload.__class__.__name__ == 'IPv4'


class TestPPP2b:

    def test_fixed_size(self):
        assert len(PPP2b().build()) == 2

    def test_roundtrip(self):
        p = PPP2b(proto=0x0021)
        parsed = PPP2bParser.load_as_ppp2b_layer(p.build())
        assert parsed.proto == 0x0021

    def test_ipv4_payload(self):
        p = PPP2b() / IPv4(src='1.1.1.1', dst='2.2.2.2')
        parsed = PPP2bParser.load_as_ppp2b_layer(p.build())
        assert parsed.payload.__class__.__name__ == 'IPv4'

    def test_ipv6_auto_proto(self):
        p = PPP2b() / IPv6(src='::1', dst='::2')
        raw = p.build()
        assert struct.unpack('!H', raw[:2])[0] == 87
        assert p.proto == 87


class TestPPPoE:

    def test_fixed_size(self):
        assert len(PPPoE().build()) == 6

    def test_roundtrip(self):
        p = PPPoE(version=1, type=1, code=0, ssid=0x1234)
        parsed = PPPoEParser.load_as_pppoe_layer(p.build())
        assert parsed.version == 1
        assert parsed.type == 1
        assert parsed.code == 0
        assert parsed.ssid == 0x1234

    def test_length_zero_with_no_payload(self):
        raw = PPPoE().build()
        lenght = struct.unpack('!H', raw[4:6])[0]
        assert lenght == 0

    def test_version_type_packed_in_first_byte(self):
        raw = PPPoE(version=0x1, type=0x1).build()
        assert raw[0] == 0x11