# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from typing import Optional
from .BaseLayer import BaseLayer
from .Layers.Mac import MacAddress
from .Logger.LightLogger import Logger, ErrorCode
from .Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE

LLogger = Logger()

ISL_DST_MAC_1 = '01:00:0c:00:00:00'
ISL_DST_MAC_2 = '03:00:0c:00:00:00'
ISL_SNAP = 0xAAAA03
ISL_HSA = 0x00000C

ISL_TYPE_ETHERNET = 0x00
ISL_TYPE_TOKEN_RING = 0x01
ISL_TYPE_FDDI = 0x02
ISL_TYPE_ATM = 0x03

ISL_TYPE_NAMES = {
    ISL_TYPE_ETHERNET: "Ethernet",
    ISL_TYPE_TOKEN_RING: "Token Ring",
    ISL_TYPE_FDDI: "FDDI",
    ISL_TYPE_ATM: "ATM"
}

ISL_USER_NORMAL = 0x00
ISL_USER_PRIORITY_1 = 0x01
ISL_USER_PRIORITY_2 = 0x02
ISL_USER_HIGHEST = 0x03

ISL_USER_NAMES = {
    ISL_USER_NORMAL: "Normal Priority",
    ISL_USER_PRIORITY_1: "Priority 1",
    ISL_USER_PRIORITY_2: "Priority 2",
    ISL_USER_HIGHEST: "Highest Priority"
}

"""
ISL Layer Creation (class ISLLayer)
"""

class ISLLayer(BaseLayer):
    def __init__(
            self,
            vlan_id: int = 100,
            type_code: int = ISL_TYPE_ETHERNET,
            user_priority: int = ISL_USER_NORMAL,
            source_mac: Optional[str] = None,
            dst_mac: str = ISL_DST_MAC_1,
            bpdu: int = 1,
            index: int = 0,
            reserved: int = 0
    ):
        super().__init__()

        if not (0 <= vlan_id <= 1000):
            LLogger.error(
                error_code=ErrorCode.INVALID_DATA_LENGTH,
                message=f"ISL VLAN ID must be 0-1000, got {vlan_id}"
            )
            return

        self.vlan_id = vlan_id
        self.type_code = type_code
        self.user_priority = user_priority & 0x07
        self.dst_mac = dst_mac
        self.source_mac = MacAddress(source_mac, d_or_s=0) if source_mac else None
        self.bpdu = bpdu
        self.index = index & 0xFFFF
        self.res = reserved

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        len_value = (len(payload_bytes) + 26) - 18

        dst_bytes = self._parse_mac(self.dst_mac)
        type_user = (self.type_code << 4) | (self.user_priority & 0x0F)
        src_bytes = bytes(self.source_mac) if self.source_mac else b'\x00' * 6

        vlan_bpdu = (self.vlan_id & 0x7FFF) | (self.bpdu << 15)

        header = struct.pack(
            '!5s B 6s H 3s 3s H H H',
            dst_bytes,
            type_user,
            src_bytes,
            len_value,
            self._snap_to_bytes(),
            self._hsa_to_bytes(),
            vlan_bpdu,
            self.index,
            self.res
        )
        if payload_bytes:
            return header + payload_bytes
        return header

    def _parse_mac(self, mac_str: str) -> bytes:
        mac = mac_str.replace(':', '').replace('-', '').replace('.', '')
        if len(mac) != 10:
            if len(mac) >= 12:
                mac = mac[:10]
        return bytes.fromhex(mac)

    def _snap_to_bytes(self) -> bytes:
        return struct.pack('!I', ISL_SNAP)[1:4]  # 0xAAAA03 as 3 bytes

    def _hsa_to_bytes(self) -> bytes:
        return struct.pack('!I', ISL_HSA)[1:4]  # 0x00000C as 3 bytes

    def __len__(self) -> int:
        return 26

    def __repr__(self) -> str:
        type_name = ISL_TYPE_NAMES.get(self.type_code, f"Unknown(0x{self.type_code:x})")
        user_name = ISL_USER_NAMES.get(self.user_priority, f"Unknown(0x{self.user_priority:x})")
        return (
            f"<ISL vlan={self.vlan_id} type={type_name} "
            f"priority={user_name} bpdu={self.bpdu} index={self.index} "
            f"len={len(self)}>"
        )

    def copy(self) -> 'ISLLayer':
        new_layer = ISLLayer(
            vlan_id=self.vlan_id,
            type_code=self.type_code,
            user_priority=self.user_priority,
            source_mac=str(self.source_mac) if self.source_mac else None,
            dst_mac=self.dst_mac,
            bpdu=self.bpdu,
            index=self.index
        )
        if self.payload:
            new_layer.payload = self.payload.copy()
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        type_name = ISL_TYPE_NAMES.get(self.type_code, f"Unknown(0x{self.type_code:x})")
        user_name = ISL_USER_NAMES.get(self.user_priority, f"Unknown(0x{self.user_priority:x})")
        return [
            f"vlan_id={self.vlan_id}",
            f"type={type_name}",
            f"priority={user_name}",
            f"dst_mac={self.dst_mac}",
            f"src_mac={self.source_mac or 'None'}",
            f"bpdu={self.bpdu}",
            f"index={self.index}",
        ]

"""
ISL Parser (separate from the builder)
"""

class ISLParser:

    @staticmethod
    def load_as_isl_layer(raw_packet, verbose: bool = False):
        if isinstance(raw_packet, list):
            raw_packet = raw_packet[0]

        if len(raw_packet) < 26:
            LLogger.error(
                error_code=ErrorCode.INVALID_DATA_LENGTH,
                message="ISL header must be at least 26 bytes"
            )
            return None

        offset = 0

        dst_mac = raw_packet[offset:offset + 5]
        offset += 5
        dst_mac_str = ':'.join(f'{b:02x}' for b in dst_mac)

        type_user_byte = raw_packet[offset]
        offset += 1
        type_code = (type_user_byte >> 4) & 0x0F
        user_priority = type_user_byte & 0x0F

        src_mac = raw_packet[offset:offset + 6]
        offset += 6
        src_mac_str = ':'.join(f'{b:02x}' for b in src_mac)

        len_value = struct.unpack('!H', raw_packet[offset:offset + 2])[0]
        offset += 2

        snap = raw_packet[offset:offset + 3]
        offset += 3
        snap_value = int.from_bytes(snap, 'big')

        hsa = raw_packet[offset:offset + 3]
        offset += 3
        hsa_value = int.from_bytes(hsa, 'big')

        vlan_id = struct.unpack('!H', raw_packet[offset:offset + 2])[0] & 0x7FFF
        offset += 2

        bpdu_index = struct.unpack('!H', raw_packet[offset:offset + 2])[0]
        offset += 2
        bpdu = (bpdu_index >> 15) & 0x01
        index = bpdu_index & 0x7FFF

        res = struct.unpack('!H', raw_packet[offset:offset + 2])[0]
        offset += 2

        payload = raw_packet[offset:]

        if verbose:
            type_name = ISL_TYPE_NAMES.get(type_code, f"Unknown(0x{type_code:x})")
            user_name = ISL_USER_NAMES.get(user_priority, f"Unknown(0x{user_priority:x})")
            print(f"\n{BOLD}ISL LAYER : {RESET}Len({PURPLE}{26 + len(payload)}{RESET}) >")
            print(f'   {BLUE}VLAN ID:{CYAN} {vlan_id}')
            print(f'   {BLUE}Frame Type:{CYAN} {type_name}')
            print(f'   {BLUE}Priority:{CYAN} {user_name}')
            print(f'   {BLUE}DST MAC:{CYAN} {dst_mac_str}')
            print(f'   {BLUE}SRC MAC:{CYAN} {src_mac_str}')
            print(f'   {BLUE}BPDU:{CYAN} {bpdu}')
            print(f'   {BLUE}Index:{CYAN} {index}')
            print(f'   {BLUE}SNAP:{CYAN} 0x{snap_value:06x}')
            print(f'   {BLUE}HSA:{CYAN} 0x{hsa_value:06x}')
            print(f'   {BLUE}LEN:{CYAN} {len_value}{RESET}')
            print(f'   {BLUE}RES:{CYAN} {res}{RESET}')

        isl = ISLLayer(
            vlan_id=vlan_id,
            type_code=type_code,
            user_priority=user_priority,
            source_mac=src_mac_str if src_mac_str != '00:00:00:00:00:00' else None,
            dst_mac=dst_mac_str,
            bpdu=bpdu,
            index=index
        )

        if len(payload) > 0:
            if type_code == 0:
                HHH = payload[12:14]
                try:
                    eth_type = struct.unpack('>H', HHH)[0]
                except:
                    from .Raw import RawParser
                    s = RawParser.load_as_Raw_layer(payload, verbose=verbose)
                    return isl / s

                if eth_type >= 0x0600:
                    if eth_type == 0x8100 or eth_type == 0x88A8:
                        from .Vlan import vlannum
                        numofvlan = vlannum(payload[12:])
                        ethertype = payload[12 + (4 * numofvlan):14 + (4 * numofvlan)]
                        ethertype = struct.unpack('>H', ethertype)[0]
                        if ethertype >= 0x0600:
                            from .EthernetII import EthernetParser
                            s = EthernetParser.load_as_ethernet_layer(payload,verbose=verbose)
                        else:
                            from .Dot3 import Dot3Parser
                            s = Dot3Parser.load_as_dot3_layer(payload, verbose=verbose)
                    else:
                        from .EthernetII import EthernetParser
                        s = EthernetParser.load_as_ethernet_layer(payload,verbose=verbose)
                elif eth_type <= 0x05DC:
                    from .Dot3 import Dot3Parser
                    s = Dot3Parser.load_as_dot3_layer(payload,verbose=verbose)
                else:
                    from .Raw import RawParser
                    s = RawParser.load_as_Raw_layer(payload, verbose=verbose)
            else:
                from .Raw import RawParser
                s = RawParser.load_as_Raw_layer(payload,verbose=verbose)
            return isl / s

        return isl


def is_isl_frame(data: bytes) -> bool:
    if len(data) < 26:
        return False

    if data[0:5] != b'\x01\x00\x0c\x00\x00' and data[0:5] != b'\x03\x00\x0c\x00\x00':
        return False

    if data[14:17] != b'\xaa\xaa\x03':
        return False

    if data[17:20] != b'\x00\x00\x0c':
        return False

    return True

