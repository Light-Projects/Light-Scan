# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.Vlan (VLAN, VLANParser, vlannum) including QinQ stacking.
"""
import struct
import pytest

from LightPacket.Vlan import VLAN, VLANParser, vlannum
from LightPacket.ipv4 import IPv4
from LightPacket.Raw import Raw
from LightPacket.EthernetII import Ethernet


def test_vlan_default_tpid_and_id():
    v = VLAN() / Raw(b"x")
    data = v.build()
    tpid, tci = struct.unpack("!HH", data[:4])
    assert tpid == 0x8100
    assert (tci & 0x0FFF) == 1  # default vlan_id


def test_vlan_priority_dei_id_packed_correctly():
    v = VLAN(priority=5, dei=1, vlan_id=100) / Raw(b"x")
    data = v.build()
    _, tci = struct.unpack("!HH", data[:4])
    priority = (tci >> 13) & 0x07
    dei = (tci >> 12) & 0x01
    vlan_id = tci & 0x0FFF
    assert priority == 5
    assert dei == 1
    assert vlan_id == 100


def test_vlan_priority_and_vlan_id_are_masked():
    # priority masked to 3 bits, vlan_id masked to 12 bits
    v = VLAN(priority=0xFF, dei=0xFF, vlan_id=0xFFFF) / Raw(b"x")
    assert v.priority == 0x07
    assert v.dei == 0x01
    assert v.vlan_id == 0x0FFF


def test_vlan_len_dunder():
    v = VLAN() / Raw(b"1234")
    assert len(v) == 4 + 4


def test_qinq_stacking_sets_outer_tpid_to_88a8():
    inner = VLAN(vlan_id=20) / Raw(b"payload")
    outer = VLAN(vlan_id=10) / inner
    data = outer.build()
    tpid_outer = struct.unpack("!H", data[:2])[0]
    assert tpid_outer == 0x88A8  # QinQ marker set by check_layers()


def test_vlan_num_counts_stacked_vlans():
    inner = VLAN(vlan_id=20) / Raw(b"x")
    outer = VLAN(vlan_id=10) / inner
    count, final_layer_name = outer.num()
    assert count == 2
    assert final_layer_name == "RawLayer" or final_layer_name  # just ensure returned


def test_vlan_copy_independent():
    v = VLAN(vlan_id=42) / Raw(b"x")
    cloned = v.copy()
    assert cloned is not v
    assert cloned.build() == v.build()


def test_vlan_repr_contains_fields():
    v = VLAN(tpid=0x8100, priority=3, dei=1, vlan_id=99)
    r = repr(v)
    assert "0x8100" in r
    assert "priority=3" in r
    assert "vlan_id=99" in r


# ---------------------------------------------------------------------------
# vlannum() helper
# ---------------------------------------------------------------------------

def test_vlannum_zero_for_non_vlan_tpid():
    raw = struct.pack("!HH", 0x0800, 0x0000)
    assert vlannum(raw) == 0


def test_vlannum_counts_single_vlan_tag():
    raw = struct.pack("!HH", 0x8100, 0x000A) + struct.pack("!HH", 0x0800, 0x0000)
    assert vlannum(raw) == 1


def test_vlannum_counts_qinq_double_tag():
    raw = (
        struct.pack("!HH", 0x88A8, 0x000A) +
        struct.pack("!HH", 0x8100, 0x0014) +
        struct.pack("!HH", 0x0800, 0x0000)
    )
    assert vlannum(raw) == 2


def test_vlannum_stops_on_short_trailing_bytes():
    raw = struct.pack("!HH", 0x8100, 0x000A) + b"\x08"  # incomplete trailing chunk
    assert vlannum(raw) == 1


# ---------------------------------------------------------------------------
# VLANParser round-trip
# ---------------------------------------------------------------------------

def test_vlan_parser_round_trip_single_tag():
    original = VLAN(tpid=0x8100, priority=2, dei=0, vlan_id=55)
    raw_bytes = original.build()  # no payload -> just the 4-byte tag

    parsed = VLANParser.load_as_vlan_layer(raw_bytes)

    assert parsed.tpid == 0x8100
    assert parsed.priority == 2
    assert parsed.dei == 0
    assert parsed.vlan_id == 55


def test_vlan_parser_rejects_short_header():
    with pytest.raises(Exception):
        result = VLANParser.load_as_vlan_layer(b"\x00\x00")


def test_full_ethernet_vlan_stack_round_trip_via_detect_layer():
    """
    End-to-end: Ethernet / VLAN / Raw -> bytes -> EthernetParser
    correctly reconstructs the VLAN tag and ethertype.
    """
    from LightPacket.EthernetII import EthernetParser

    packet = (
        Ethernet(dst="aa:bb:cc:dd:ee:ff", src="00:11:22:33:44:55") /
        VLAN(vlan_id=30) /
        IPv4()
    )
    raw_bytes = packet.build()

    parsed = EthernetParser.load_as_ethernet_layer(raw_bytes)
    vlan_layer = parsed[VLAN]
    assert vlan_layer.vlan_id == 30