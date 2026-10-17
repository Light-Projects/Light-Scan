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

    def test_dot3_llc_raw_roundtrip(self):
        from LightPacket.Dot3 import Dot3
        from LightPacket.Raw import Raw
        from LightPacket.Detect_layer import DetectLayer

        p = Dot3(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / LLC() / Raw(b"test-payload")
        raw = p.build()
        parsed = DetectLayer().start(raw, linktype=1)
        assert parsed.__class__.__name__ == 'Dot3'
        assert parsed.payload.__class__.__name__ == 'LLC'
        # Rebuilding parsed packet should succeed without error
        rebuilt = parsed.build()
        assert len(rebuilt) == len(raw)

    def test_dot3_llc_snap_roundtrip(self):
        from LightPacket.Dot3 import Dot3
        from LightPacket.Detect_layer import DetectLayer

        p = Dot3(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / LLC() / SNAP()
        raw = p.build()
        parsed = DetectLayer().start(raw, linktype=1)
        assert parsed.__class__.__name__ == 'Dot3'
        assert parsed.payload.__class__.__name__ == 'LLC'
        assert parsed.payload.payload.__class__.__name__ == 'SNAP'
        # Rebuilding parsed SNAP must succeed without AttributeError
        rebuilt = parsed.build()
        assert len(rebuilt) == len(raw)

    def test_snap_oui_types(self):
        # SNAP should support int, bytes, and hex string for oui
        s1 = SNAP(oui=0x000000, pid=0x0800)
        s2 = SNAP(oui=b'\x00\x00\x00', pid=0x0800)
        s3 = SNAP(oui="00:00:00", pid=0x0800)
        assert s1.build() == s2.build() == s3.build()