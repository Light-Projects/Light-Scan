# LightPacket/tests/test_tcp.py
"""
TCP layer tests: header round-trip, options, flags, checksum.
"""

import struct
import pytest

from LightPacket.tcp import TCP, TCPParser, SYN, ACK, FIN, PSH, RST, URG
from LightPacket.helper.tcp.TCPOptions import (
    TCPOptions, OPT_MSS, OPT_WS, OPT_SACK_PERM,
)


class TestTCPHeader:

    def test_default_no_options(self):
        assert len(TCP().build()) == 20

    def test_roundtrip_basic(self):
        tcp = TCP(sport=12345, dport=80, seq=100, ack=200,
                  flags=SYN | ACK, window=8192)
        parsed = TCPParser.load_as_tcp_layer(tcp.build())
        assert parsed.sport == 12345
        assert parsed.dport == 80
        assert parsed.seq == 100
        assert parsed.ack == 200
        assert parsed.window == 8192
        assert parsed.is_syn()
        assert parsed.is_ack()

    def test_flags_str(self):
        assert TCP(flags=SYN | ACK).flags_str() == 'SA'
        assert TCP(flags=FIN | PSH | ACK).flags_str() == 'FPA'
        assert TCP(flags=0).flags_str() == ''

    def test_flag_helpers(self):
        tcp = TCP(flags=SYN | ACK)
        assert tcp.is_syn()
        assert tcp.is_ack()
        assert not tcp.is_fin()
        assert tcp.is_syn_ack()

    def test_set_flag(self):
        tcp = TCP(flags=0)
        tcp.set_flag('S')
        assert tcp.flags & SYN
        tcp.set_flag('A')
        assert tcp.flags & SYN and tcp.flags & ACK
        tcp.set_flag('S', enabled=False)
        assert not (tcp.flags & SYN)

    def test_data_offset_without_options(self):
        tcp = TCP(sport=1, dport=2)
        tcp.build()
        assert tcp.data_offset == 5


class TestTCPOptions:

    def test_mss_wire_encoding(self):
        raw = TCPOptions([TCPOptions.mss(1460)]).build()
        # kind=2, len=4, value=0x05b4
        assert raw == b'\x02\x04\x05\xb4'

    def test_options_padded_to_4_bytes(self):
        # MSS (4) + SACK-perm (2) = 6 → padded to 8
        opts = TCPOptions([TCPOptions.mss(1460), TCPOptions.sack_permitted()])
        assert len(opts.build()) == 8

    def test_roundtrip_with_options(self):
        opts = TCPOptions([
            TCPOptions.mss(1460),
            TCPOptions.sack_permitted(),
            TCPOptions.window_scale(7),
            TCPOptions.nop(),
            TCPOptions.nop(),
        ])
        tcp = TCP(sport=1, dport=2, flags=SYN, options=opts)
        parsed = TCPParser.load_as_tcp_layer(tcp.build())
        assert parsed.options.has(OPT_MSS)
        assert parsed.options.has(OPT_WS)
        assert parsed.options.has(OPT_SACK_PERM)
        mss = parsed.options.get(OPT_MSS)
        assert struct.unpack('>H', mss.data)[0] == 1460

    def test_data_offset_with_options(self):
        opts = TCPOptions([
            TCPOptions.mss(1460),
            TCPOptions.sack_permitted(),
            TCPOptions.window_scale(7),
            TCPOptions.nop(),
            TCPOptions.nop(),
        ])
        tcp = TCP(flags=SYN, options=opts)
        raw = tcp.build()
        # 20 + 12 = 32 bytes header → data_offset = 8
        assert tcp.data_offset == 8
        assert len(raw) == 32


class TestTCPChecksum:

    def test_unset_checksum_is_zero(self):
        raw = TCP(sport=1, dport=2).build()
        assert struct.unpack('>H', raw[16:18])[0] == 0

    def test_computed_checksum_is_stored(self):
        tcp = TCP(sport=12345, dport=80, flags=SYN, window=8192)
        tcp.compute_checksum('192.168.1.1', '192.168.1.2')
        raw = tcp.build()
        csum = struct.unpack('>H', raw[16:18])[0]
        assert csum != 0
        assert csum == tcp.checksum

    def test_checksum_deterministic(self):
        c1 = TCP(sport=1, dport=2, seq=3, flags=SYN).compute_checksum(
            '10.0.0.1', '10.0.0.2')
        c2 = TCP(sport=1, dport=2, seq=3, flags=SYN).compute_checksum(
            '10.0.0.1', '10.0.0.2')
        assert c1 == c2