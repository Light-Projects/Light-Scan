# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from typing import List, Dict, Optional, Tuple
from ..Vlan import VLAN
from ..BaseLayer import BaseLayer


class VlanUtils:

    @staticmethod
    def get_all_vlans(packet: BaseLayer) -> List[VLAN]:
        vlans = []
        current = packet
        while current:
            if isinstance(current, VLAN):
                vlans.append(current)
            current = current.payload
        return vlans

    @staticmethod
    def get_vlan_by_index(packet: BaseLayer, index: int) -> Optional[VLAN]:
        vlans = VlanUtils.get_all_vlans(packet)
        if 0 <= index < len(vlans):
            return vlans[index]
        return None

    @staticmethod
    def get_vlan_info(packet: BaseLayer) -> List[Dict]:
        vlans = VlanUtils.get_all_vlans(packet)
        return [
            {
                'index': i,
                'vlan_id': vlan.vlan_id,
                'tpid': vlan.tpid,
                'priority': vlan.priority,
                'dei': vlan.dei,
                'is_qinq': vlan.tpid == 0x88A8
            }
            for i, vlan in enumerate(vlans)
        ]

    @staticmethod
    def get_outer_vlan(packet: BaseLayer) -> Optional[VLAN]:
        vlans = VlanUtils.get_all_vlans(packet)
        return vlans[0] if vlans else None

    @staticmethod
    def get_inner_vlan(packet: BaseLayer) -> Optional[VLAN]:
        vlans = VlanUtils.get_all_vlans(packet)
        return vlans[-1] if vlans else None

    @staticmethod
    def count_vlans(packet: BaseLayer) -> int:
        return len(VlanUtils.get_all_vlans(packet))

    @staticmethod
    def is_qinq(packet: BaseLayer) -> bool:
        vlans = VlanUtils.get_all_vlans(packet)
        return len(vlans) >= 2

    @staticmethod
    def get_vlan_ids(packet: BaseLayer) -> List[int]:
        return [vlan.vlan_id for vlan in VlanUtils.get_all_vlans(packet)]