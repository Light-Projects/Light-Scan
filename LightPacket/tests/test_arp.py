# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.Arp (ARP, ArpParser).
"""
import struct
import pytest

from LightPacket.Arp import ARP, ArpParser


def make_arp(**overrides):
    defaults = dict(
        hwtype=1, ptype=0x0800, maclen=6, plen=4, opcode=1,
        macsrc="00:11:22:33:44:55", ipsrc="10.0.0.1",
        macdst="ff:ff:ff:ff:ff:ff", ipdst="10.0.0.254",
    )
    defaults.update(overrides)
    return ARP(**defaults)


def test_arp_build_length_is_28_bytes():
    arp = make_arp()
    assert len(arp.build()) == 28
    assert len(arp) == 28


def test_arp_build_field_layout():
    arp = make_arp(opcode=2)
    data = arp.build()

    hwtype, ptype, maclen, plen, opcode = struct.unpack("!HHBBH", data[:8])
    assert hwtype == 1
    assert ptype == 0x0800
    assert maclen == 6
    assert plen == 4
    assert opcode == 2

    macsrc = data[8:14]
    ipsrc = data[14:18]
    macdst = data[18:24]
    ipdst = data[24:28]

    assert macsrc == bytes.fromhex("001122334455")
    assert ipsrc == bytes([10, 0, 0, 1])
    assert macdst == bytes.fromhex("ffffffffffff")
    assert ipdst == bytes([10, 0, 0, 254])


def test_arp_defaults_are_applied_when_fields_omitted():
    # hwtype/ptype/maclen/plen/opcode should default sensibly even if
    # macsrc/ipsrc/macdst/ipdst are supplied explicitly.
    arp = ARP(macsrc="00:11:22:33:44:55", ipsrc="10.0.0.1",
              macdst="ff:ff:ff:ff:ff:ff", ipdst="10.0.0.2")
    assert arp.hwtype == 1
    assert arp.ptype == 0x0800
    assert arp.maclen == 6
    assert arp.plen == 4
    assert arp.opcode == 1


def test_arp_repr_contains_opcode_and_addresses():
    arp = make_arp()
    r = repr(arp)
    assert "opcode=1" in r
    assert "10.0.0.1" in r
    assert "10.0.0.254" in r


def test_arp_copy_is_independent_and_equal_bytes():
    arp = make_arp()
    cloned = arp.copy()
    assert cloned is not arp
    assert cloned.build() == arp.build()
    cloned.opcode = 2
    assert arp.opcode == 1  # original untouched


def test_arp_with_payload_appends_bytes():
    from LightPacket.Raw import Raw
    arp = make_arp() / Raw(b"extra")
    data = arp.build()
    assert len(data) == 28 + len(b"extra")
    assert data[28:] == b"extra"


# ---------------------------------------------------------------------------
# ArpParser round-trip
# ---------------------------------------------------------------------------

def test_arp_parser_round_trip_all_fields():
    original = make_arp(opcode=2, hwtype=1, ptype=0x0800)
    raw_bytes = original.build()

    parsed = ArpParser.load_as_arp_layer(raw_bytes)

    assert parsed.hwtype == 1
    assert parsed.ptype == 0x0800
    assert parsed.maclen == 6
    assert parsed.plen == 4
    assert parsed.opcode == 2
    assert str(parsed.macsrc).lower() == "00:11:22:33:44:55"
    assert parsed.ipsrc == "10.0.0.1"
    assert str(parsed.macdst).lower() == "ff:ff:ff:ff:ff:ff"
    assert parsed.ipdst == "10.0.0.254"


def test_arp_parser_rejects_short_packet():
    with pytest.raises(Exception):
        ArpParser.load_as_arp_layer(b"\x00" * 10)


@pytest.mark.parametrize("opcode", [1, 2, 3, 4, 5, 6, 7, 8, 9, 99])
def test_arp_parser_handles_all_known_and_unknown_opcodes(opcode):
    original = make_arp(opcode=opcode)
    raw_bytes = original.build()
    parsed = ArpParser.load_as_arp_layer(raw_bytes)
    assert parsed.opcode == opcode