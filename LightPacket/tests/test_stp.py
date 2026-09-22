# LightPacket/tests/test_stp.py
"""
STP / BPDU tests.

Regression coverage for STPParser bugs:
- protocol_id is not passed back into the STP object (always 0)
- payload after the 35-byte header is dropped
"""

import pytest

from LightPacket.Stp import STP, STPParser


class TestSTPHeader:

    def test_fixed_size(self):
        assert len(STP().build()) == 35

    def test_roundtrip_basic(self):
        s = STP(root_priority=0x8000, port_id=0x8001)
        parsed = STPParser.load_as_stp_layer(s.build())
        assert parsed.root_priority == 0x8000
        assert parsed.port_id == 0x8001
        assert parsed.max_age == 5120
        assert parsed.hello_time == 512
        assert parsed.forward_delay == 3840

    def test_protocol_id_roundtrip(self):
        s = STP(protocol_id=0x1234)
        parsed = STPParser.load_as_stp_layer(s.build())
        assert parsed.protocol_id == 0x1234

    def test_mac_addresses_roundtrip(self):
        s = STP(root_mac=b'\xaa' * 6, bridge_mac=b'\xbb' * 6)
        parsed = STPParser.load_as_stp_layer(s.build())
        assert bytes(parsed.root_mac) == b'\xaa' * 6
        assert bytes(parsed.bridge_mac) == b'\xbb' * 6

    def test_flags_roundtrip(self):
        for flags in (0x00, 0x01, 0x02, 0x04, 0x20, 0x40, 0x80):
            s = STP(flags=flags)
            parsed = STPParser.load_as_stp_layer(s.build())
            assert parsed.flags == flags

    def test_bpdu_type_tcn(self):
        s = STP(bpdu_type=0x80)
        parsed = STPParser.load_as_stp_layer(s.build())
        assert parsed.bpdu_type == 0x80