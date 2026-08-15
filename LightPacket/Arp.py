# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from .Decoration.Colors import RESET, CYAN, BLUE, PURPLE, BOLD
from .Logger.LightLogger import Logger, ErrorCode
from .BaseLayer import BaseLayer
from typing import Union
from .Layers.Mac import MacAddress
from .Layers.IPtoa import inet_aton, inet_ntoa
from .Consts import HWTYPES,ETHERTYPE

LLogger = Logger()

"""
Arp Layer Creation (class ArpLayer)
"""

class ArpLayer(BaseLayer):

    def __init__(self, hwtype: int, ptype: int, maclen: int, plen: int, opcode: int, macsrc: Union[str, bytes],
                 ipsrc: str, macdst: Union[str, bytes], ipdst: str):
        super().__init__()
        self.hwtype = hwtype
        self.ptype = ptype
        self.maclen = maclen
        self.plen = plen
        self.opcode = opcode
        self.macsrc = MacAddress(macsrc, d_or_s=0)
        self.ipsrc = ipsrc
        self.macdst = MacAddress(macdst, d_or_s=1)
        self.ipdst = ipdst

    def build(self) -> bytes:

        arp = struct.pack(
            '!HHBBH6s4s6s4s',
            self.hwtype,
            self.ptype,
            self.maclen,
            self.plen,
            self.opcode,
            bytes(self.macsrc),
            inet_aton(self.ipsrc),
            bytes(self.macdst),
            inet_aton(self.ipdst),
        )
        if self.payload:
            return arp + self.payload.build()
        return arp

    def __len__(self):
        return 28

    def __repr__(self):
        return (
            f"<Arp opcode={self.opcode} plen={self.plen} ptype={hex(self.ptype)} maclen={self.maclen} hwtype={self.hwtype} macsrc={self.macsrc} ipsrc={self.ipsrc} macdst={self.macdst} ipdst={self.ipdst}>")

    def copy(self) -> 'ArpLayer':
        new_layer = ArpLayer(
            hwtype=self.hwtype,
            ptype=self.ptype,
            maclen=self.maclen,
            plen=self.plen,
            opcode=self.opcode,
            macsrc=str(self.macsrc),
            ipsrc=self.ipsrc,
            macdst=str(self.macdst),
            ipdst=self.ipdst
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"hwtype={self.hwtype}",
            f"ptype=0x{self.ptype:04x}",
            f"maclen={self.maclen}",
            f"plen={self.plen}",
            f"opcode={self.opcode}",
            f"macsrc={self.macsrc}",
            f"ipsrc={self.ipsrc}",
            f"macdst={self.macdst}",
            f"ipdst={self.ipdst}"
        ]

"""
Arp Parser (separate from the builder)
"""

class ArpParser:

    @staticmethod
    def load_as_arp_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 28:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="Arp required header is 28 bytes")


        ArpHeader = raw_packet[0]

        hwtype, ptype, maclen, plen, opcode = struct.unpack('!HHBBH', ArpHeader[:8])
        offset = 8
        sender_mac = ArpHeader[offset:offset + 6]
        offset += 6
        sender_mac_str = ':'.join(f'{b:02x}' for b in sender_mac)
        sender_ip = ArpHeader[offset:offset + 4]
        offset += 4
        sender_ip_str = inet_ntoa(sender_ip)
        target_mac = ArpHeader[offset:offset + 6]
        offset += 6
        target_mac_str = ':'.join(f'{b:02x}' for b in target_mac)
        target_ip = ArpHeader[offset:offset + 4]
        target_ip_str = inet_ntoa(target_ip)
        payload = ArpHeader[28:]
        Lenght = len(ArpHeader[:28])
        Total = len(payload) + Lenght
        if opcode == 1:
            opcode_e = "(who-has)"
        elif opcode == 2:
            opcode_e = "(is-at)"
        elif opcode == 3:
            opcode_e = "(RARP-req)"
        elif opcode == 4:
            opcode_e = "(RARP-rep)"
        elif opcode == 5:
            opcode_e = "(Dyn-RARP-req)"
        elif opcode == 6:
            opcode_e = "(Dyn-RARP-rep)"
        elif opcode == 7:
            opcode_e = "(Dyn-RARP-err)"
        elif opcode == 8:
            opcode_e = "(In-ARP-req)"
        elif opcode == 9:
            opcode_e = "(In-ARP-rep)"
        else:
            opcode_e = "(Unknown)"

        if verbose:
            print(f"\n{BOLD}ARP LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}HWTYPE:{CYAN} {hwtype} {HWTYPES.get(hwtype,'Unknown')}')
            print(f'   {BLUE}PTYPE:{CYAN} {hex(ptype)} {ETHERTYPE.get(ptype,'Unknown')}')
            print(f'   {BLUE}MACLEN:{CYAN} {maclen}')
            print(f'   {BLUE}PLEN:{CYAN} {plen}')
            print(f'   {BLUE}OPCODE:{CYAN} {opcode} {opcode_e}')
            print(f'   {BLUE}MAC SRC:{CYAN} {sender_mac_str}')
            print(f'   {BLUE}IP SRC:{CYAN} {sender_ip_str}')
            print(f'   {BLUE}MAC DST:{CYAN} {target_mac_str}')
            print(f'   {BLUE}IP DST:{CYAN} {target_ip_str}{RESET}')

        if len(payload) > 0:
            from .Raw import RawParser
            RawParser.load_as_Raw_layer(payload,verbose=verbose)

        arp = ArpLayer(
            hwtype=hwtype,
            ptype=ptype,
            maclen=maclen,
            plen=plen,
            opcode=opcode,
            macsrc=sender_mac_str,
            macdst=target_mac_str,
            ipsrc=sender_ip_str,
            ipdst=target_ip_str
        )

        return arp


