from typing import List, Dict, Optional, Tuple
from ..Vlan import VLANLayer
from ..BaseLayer import BaseLayer


class VlanUtils:

    @staticmethod
    def get_all_vlans(packet: BaseLayer) -> List[VLANLayer]:
        vlans = []
        current = packet
        while current:
            if isinstance(current, VLANLayer):
                vlans.append(current)
            current = current.payload
        return vlans

    @staticmethod
    def get_vlan_by_index(packet: BaseLayer, index: int) -> Optional[VLANLayer]:
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
    def get_outer_vlan(packet: BaseLayer) -> Optional[VLANLayer]:
        vlans = VlanUtils.get_all_vlans(packet)
        return vlans[0] if vlans else None

    @staticmethod
    def get_inner_vlan(packet: BaseLayer) -> Optional[VLANLayer]:
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