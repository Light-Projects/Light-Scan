# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.utils.VlanUtils.VlanUtils
"""
from LightPacket.Vlan import VLAN
from LightPacket.Raw import Raw
from LightPacket.utils.VlanUtils import VlanUtils


def test_get_all_vlans_empty_when_none_present():
    pkt = Raw(b"nothing here")
    assert VlanUtils.get_all_vlans(pkt) == []


def test_get_all_vlans_single():
    pkt = VLAN(vlan_id=10) / Raw(b"x")
    vlans = VlanUtils.get_all_vlans(pkt)
    assert len(vlans) == 1
    assert vlans[0].vlan_id == 10


def test_get_all_vlans_qinq_order_outer_to_inner():
    pkt = VLAN(vlan_id=10) / VLAN(vlan_id=20) / Raw(b"x")
    vlans = VlanUtils.get_all_vlans(pkt)
    assert [v.vlan_id for v in vlans] == [10, 20]


def test_get_vlan_by_index_valid_and_invalid():
    pkt = VLAN(vlan_id=10) / VLAN(vlan_id=20) / Raw(b"x")
    assert VlanUtils.get_vlan_by_index(pkt, 0).vlan_id == 10
    assert VlanUtils.get_vlan_by_index(pkt, 1).vlan_id == 20
    assert VlanUtils.get_vlan_by_index(pkt, 5) is None
    assert VlanUtils.get_vlan_by_index(pkt, -1) is None


def test_get_vlan_info_structure():
    pkt = VLAN(tpid=0x88A8, priority=1, dei=0, vlan_id=10) / VLAN(vlan_id=20) / Raw(b"x")
    info = VlanUtils.get_vlan_info(pkt)
    assert len(info) == 2
    assert info[0]["vlan_id"] == 10
    assert info[0]["is_qinq"] is True
    assert info[1]["vlan_id"] == 20
    assert info[1]["is_qinq"] is False


def test_get_outer_and_inner_vlan():
    pkt = VLAN(vlan_id=10) / VLAN(vlan_id=20) / VLAN(vlan_id=30) / Raw(b"x")
    assert VlanUtils.get_outer_vlan(pkt).vlan_id == 10
    assert VlanUtils.get_inner_vlan(pkt).vlan_id == 30


def test_get_outer_inner_vlan_none_when_empty():
    pkt = Raw(b"no vlans")
    assert VlanUtils.get_outer_vlan(pkt) is None
    assert VlanUtils.get_inner_vlan(pkt) is None


def test_count_vlans():
    pkt = VLAN(vlan_id=1) / VLAN(vlan_id=2) / Raw(b"x")
    assert VlanUtils.count_vlans(pkt) == 2
    assert VlanUtils.count_vlans(Raw(b"none")) == 0


def test_is_qinq_true_for_two_or_more():
    single = VLAN(vlan_id=1) / Raw(b"x")
    double = VLAN(vlan_id=1) / VLAN(vlan_id=2) / Raw(b"x")
    assert VlanUtils.is_qinq(single) is False
    assert VlanUtils.is_qinq(double) is True


def test_get_vlan_ids_order_preserved():
    pkt = VLAN(vlan_id=100) / VLAN(vlan_id=200) / Raw(b"x")
    assert VlanUtils.get_vlan_ids(pkt) == [100, 200]