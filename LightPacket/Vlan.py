# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from .BaseLayer import BaseLayer
from .Logger.LightLogger import Logger, ErrorCode
from .Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE

LLogger = Logger()

"""
VLAN Layer Creation (class VLANLayer)
"""


class VLANLayer(BaseLayer):

    def __init__(self, tpid=0x8100, priority=0, dei=0, vlan_id=1):

        super().__init__()
        self.tpid = tpid
        self.priority = priority & 0x07
        self.dei = dei & 0x01
        self.vlan_id = vlan_id & 0x0FFF

    def build(self) -> bytes:
        self.check_layers()
        tci = (self.priority << 13) | (self.dei << 12) | self.vlan_id
        result = struct.pack('!HH', self.tpid, tci)

        if self.payload:
            return result + self.payload.build()
        return result

    def check_layers(self) -> int:
        layer = self.payload.__class__.__name__

        if layer == 'VLANLayer':
            self.tpid = 0x88A8
            numofvlan,self.nxl = self.payload.num()
        else:
            numofvlan = 0
            self.nxl = layer

        return numofvlan

    def num(self):
        return 1 + self.check_layers(),self.nxl

    def __len__(self):
        return 4 + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (
            f"<VLAN tpid={hex(self.tpid)}, "
            f"priority={self.priority}, "
            f"dei={self.dei}, "
            f"vlan_id={self.vlan_id}>"
        )

    def copy(self) -> 'VLANLayer':
        new_layer = VLANLayer(
            tpid=self.tpid,
            priority=self.priority,
            dei=self.dei,
            vlan_id=self.vlan_id
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"tpid={hex(self.tpid)}",
            f"priority={self.priority}",
            f"dei={self.dei}",
            f"vlan_id={self.vlan_id}"
        ]

"""
VLAN Parser (separate from the builder)
"""

class VLANParser:

    @staticmethod
    def load_as_vlan_layer(raw_packet, Alr=0, verbose=False):

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]

        if len(raw_packet[0]) < 4:
            LLogger.error(
                error_code=ErrorCode.INVALID_DATA_LENGTH,
                message="VLAN required header is 4 bytes"
            )
            return None

        vlan_header = raw_packet[0][:4]
        payload = raw_packet[0][4:]

        tpid, tci = struct.unpack('!HH', vlan_header)

        priority = (tci >> 13) & 0x07
        dei = (tci >> 12) & 0x01
        vlan_id = tci & 0x0FFF

        length = len(vlan_header)
        vlan = VLANLayer(
            tpid=tpid,
            priority=priority,
            dei=dei,
            vlan_id=vlan_id
        )

        if verbose:
            print(f"\n{BOLD}VLAN LAYER : {RESET}Len({PURPLE}{length}{RESET}) >")
            print(f'   {BLUE}TPID:{CYAN} {hex(tpid)}')
            print(f'   {BLUE}Priority:{CYAN} {priority}')
            print(f'   {BLUE}DEI:{CYAN} {dei}')
            print(f'   {BLUE}VLAN ID:{CYAN} {vlan_id}{RESET}')

        if len(payload) > 0 and tpid == 0x88A8:
            prelayer = VLANParser.load_as_vlan_layer(payload,verbose=verbose)
            return vlan / prelayer

        return vlan


def vlannum(raw_packet):
    count = 0
    offset = 0

    while offset + 4 <= len(raw_packet):
        try:
            tpid = struct.unpack('!H', raw_packet[offset:offset + 2])[0]
            if tpid in [0x8100, 0x88A8, 0x9100, 0x9200]:
                count += 1
                offset += 4
            else:
                break
        except:
            break

    return count