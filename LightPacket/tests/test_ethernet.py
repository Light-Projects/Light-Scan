# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.EthernetII (Ethernet, Loopback, EthernetParser, LoopbackParser).
"""
import struct
import pytest

from LightPacket.EthernetII import Ethernet, Loopback, EthernetParser, EthertypeHex
from LightPacket.Arp import ARP
from LightPacket.Raw import Raw


def test_ethernet_default_dst_is_broadcast():
    eth = Ethernet(src="00:11:22:33:44:55")
    assert str(eth.dst).lower() == "ff:ff:ff:ff:ff:ff"


def test_ethernet_build_length_is_14_bytes_header_plus_payload():
    eth = Ethernet(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55", ethertype=0x0800)
    pkt = eth / Raw(b"HELLO")
    data = pkt.build()
    # 6 (dst) + 6 (src) + 2 (ethertype) + 5 (payload)
    assert len(data) == 19
    assert data[:6] == bytes.fromhex("aabbccddeeff")
    assert data[6:12] == bytes.fromhex("001122334455")
    assert struct.unpack(">H", data[12:14])[0] == 0x0800
    assert data[14:] == b"HELLO"


def test_ethernet_len_dunder_is_always_14():
    eth = Ethernet()
    assert len(eth) == 14


def test_ethernet_auto_ethertype_for_arp_payload():
    eth = Ethernet(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55")
    packet = eth / ARP(ipsrc="10.0.0.1", ipdst="10.0.0.2",
                        macsrc="00:11:22:33:44:55", macdst="ff:ff:ff:ff:ff:ff")
    data = packet.build()
    ethertype = struct.unpack(">H", data[12:14])[0]
    assert ethertype == 0x0806  # ARP_var


def test_ethernet_explicit_ethertype_is_respected():
    eth = Ethernet(src="00:11:22:33:44:55", ethertype=0x1234)
    packet = eth / Raw(b"x")
    data = packet.build()
    assert struct.unpack(">H", data[12:14])[0] == 0x1234


def test_ethernet_invalid_low_ethertype_logs_error(monkeypatch):
    """Ethertype < 0x0600 should trigger the logger's error path."""
    called = {}

    def fake_error(*args, **kwargs):
        called["fired"] = True

    from LightPacket.EthernetII import LLogger
    monkeypatch.setattr(LLogger, "error", fake_error)

    eth = Ethernet(src="00:11:22:33:44:55", ethertype=0x0100)
    packet = eth / Raw(b"x")
    packet.build()
    assert called.get("fired") is True


def test_ethernet_copy_is_independent():
    eth = Ethernet(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55", ethertype=0x0800)
    stacked = eth / Raw(b"payload")
    cloned = stacked.copy()
    assert cloned is not stacked
    assert cloned.build() == stacked.build()


def test_ethernet_repr_contains_key_fields():
    eth = Ethernet(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55", ethertype=0x0800)
    r = repr(eth)
    assert "aa:bb:cc:dd:ee:ff" in r.lower()
    assert "00:11:22:33:44:55" in r.lower()


def test_ethertype_hex_helper():
    assert EthertypeHex(0x0800) == "0x800"
    assert EthertypeHex(2048) == hex(2048)


# ---------------------------------------------------------------------------
# EthernetParser round-trip
# ---------------------------------------------------------------------------

def test_ethernet_parser_round_trip_raw_payload():
    original = Ethernet(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55",
                         ethertype=0x1234) / Raw(b"payload-data")
    raw_bytes = original.build()

    parsed = EthernetParser.load_as_ethernet_layer(raw_bytes)

    assert str(parsed.dst).lower() == "aa:bb:cc:dd:ee:ff"
    assert str(parsed.src).lower() == "00:11:22:33:44:55"
    assert parsed.ethertype == 0x1234


def test_ethernet_parser_round_trip_with_arp():
    original = (Ethernet(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
                ARP(ipsrc="10.0.0.1", ipdst="10.0.0.2",
                    macsrc="00:11:22:33:44:55", macdst="ff:ff:ff:ff:ff:ff"))
    raw_bytes = original.build()

    parsed = EthernetParser.load_as_ethernet_layer(raw_bytes)

    assert parsed.ethertype == 0x0806
    arp_layer = parsed[ARP]
    assert arp_layer.ipsrc == "10.0.0.1"
    assert arp_layer.ipdst == "10.0.0.2"


def test_ethernet_parser_rejects_short_packet():
    from LightPacket.Logger.LightLogger import Logger
    with pytest.raises(Exception):
        # Anything shorter than the mandatory 14-byte header should raise via
        # the logger's error() call (implementation-defined exception type).
        EthernetParser.load_as_ethernet_layer(b"\x00" * 10)


# ---------------------------------------------------------------------------
# Loopback layer
# ---------------------------------------------------------------------------

def test_loopback_default_build():
    lb = Loopback()
    data = lb.build()
    skip, func = struct.unpack("<HH", data[:4])
    assert skip == 1
    assert func == 1
    assert data[4:] == b"\x00\x00Ping"


def test_loopback_func_2_includes_fmac():
    lb = Loopback(func=2, fmac=b"\xaa" * 6, data=b"payload")
    data = lb.build()
    assert data[4:10] == b"\xaa" * 6
    assert data[10:] == b"payload"


def test_loopback_parser_round_trip_func1():
    original = Loopback(skipcount=3, func=1, data=b"abcdef")
    raw_bytes = original.build()

    from LightPacket.EthernetII import LoopbackParser
    parsed = LoopbackParser.load_as_loopback_layer(raw_bytes)

    assert parsed.skipcount == 3
    assert parsed.func == 1
    assert parsed.data == b"abcdef"


def test_loopback_parser_rejects_short_packet():
    from LightPacket.EthernetII import LoopbackParser
    with pytest.raises(Exception):
        LoopbackParser.load_as_loopback_layer(b"\x00\x00")