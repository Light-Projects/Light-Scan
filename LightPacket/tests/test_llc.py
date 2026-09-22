# LightPacket/tests/test_llc.py
"""
LLC tests: 3-byte header, SAP defaults for SNAP/STP, dispatch.
"""

from LightPacket.LLC import LLC, LLCParser
from LightPacket.Snap import SNAP
from LightPacket.Stp import STP
from LightPacket.ipv4 import IPv4


class TestLLCHeader:

    def test_minimum_size(self):
        assert len(LLC().build()) == 3

    def test_roundtrip(self):
        llc = LLC(dsap=0xAA, ssap=0xAA, control=0x03)
        parsed = LLCParser.load_as_llc_layer(llc.build())
        assert parsed.dsap == 0xAA
        assert parsed.ssap == 0xAA
        assert parsed.control == 0x03

    def test_default_sap_for_snap(self):
        raw = (LLC() / SNAP() / IPv4(src='1.1.1.1', dst='2.2.2.2')).build()
        assert raw[0] == 0xAA
        assert raw[1] == 0xAA
        assert raw[2] == 0x03

    def test_default_sap_for_stp(self):
        raw = (LLC() / STP()).build()
        assert raw[0] == 0x42
        assert raw[1] == 0x42

    def test_snap_dispatch(self):
        llc = LLC() / SNAP() / IPv4(src='1.1.1.1', dst='2.2.2.2')
        parsed = LLCParser.load_as_llc_layer(llc.build())
        assert parsed.payload.__class__.__name__ == 'SNAP'
        assert parsed.payload.payload.__class__.__name__ == 'IPv4'

    def test_stp_dispatch(self):
        llc = LLC() / STP()
        parsed = LLCParser.load_as_llc_layer(llc.build())
        assert parsed.payload.__class__.__name__ == 'STP'

    def test_partial_dsap_defaults_ssap(self):
        # Providing only dsap should default ssap to 0xAA
        llc = LLC(dsap=0xAA)
        raw = llc.build()
        assert raw[0] == 0xAA
        assert raw[1] == 0xAA

    def test_partial_ssap_defaults_dsap(self):
        llc = LLC(ssap=0xAA)
        raw = llc.build()
        assert raw[0] == 0xAA
        assert raw[1] == 0xAA