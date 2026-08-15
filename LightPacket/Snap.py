# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from .BaseLayer import BaseLayer
from .Consts import ARP_var, ETHERTYPE
from .Logger.LightLogger import Logger, ErrorCode
from .Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE

LLogger = Logger()

"""
SNAP Layer Creation (class SNAPLayer)
"""

class SNAPLayer(BaseLayer):

    def __init__(self, oui=0x000000, pid=None):
        super().__init__()
        self.oui = oui
        self.pid = pid

    def build(self) -> bytes:
        layer = self.payload.__class__.__name__
        if self.pid is None:
            if layer == 'PPPoELayer':
                self.pid = 0x8863
            elif layer == 'ArpLayer':
                self.pid = ARP_var
            elif layer == 'PPP2bLayer':
                self.pid = 0x880B
            else:
                self.pid = ARP_var

        oui_bytes = self.oui.to_bytes(3, byteorder='big')
        result = struct.pack('!3sH', oui_bytes, self.pid)

        if self.payload:
            return result + self.payload.build()
        return result

    def __len__(self):
        return 5 + (len(self.payload) if self.payload else 0)


    def __repr__(self):
        return (
            f"<SNAP oui={self.oui}, pid={hex(self.pid)}>")

    def copy(self) -> 'SNAPLayer':
        new_layer = SNAPLayer(
            oui=self.oui,
            pid=self.pid
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"oui={self.oui}",
            f"pid={hex(self.pid)}",
        ]


"""
SNAP Parser (separate from the builder)
"""

class SNAPParser:

    @staticmethod
    def load_as_snap_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 5:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="SNAP required header is 5 bytes")

        if len(raw_packet[0]) >= 22 and Alr == 0:
            from .LLC import LLCParser
            LLCParser.load_as_llc_layer(raw_packet[0],Alr=2)
            SNAPHeader = raw_packet[0][17:22]

        elif len(raw_packet[0]) == 22:
            SNAPHeader = raw_packet[0][17:22]

        try:
            if SNAPHeader:
                pass
        except UnboundLocalError:
            SNAPHeader = raw_packet[0][:5]

        oui, pid = struct.unpack('!3sH', SNAPHeader)

        payload = raw_packet[0][5:]
        Lenght = len(SNAPHeader)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}SNAP LAYER: {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}OUI:{CYAN} {oui}')
            print(f'   {BLUE}PID:{CYAN} {hex(pid)} {ETHERTYPE.get(pid,'Unknown')}{RESET}')

        snap = SNAPLayer(
            oui=oui,
            pid=pid
        )

        if len(payload) > 0:
            if pid == ARP_var:
                from .Arp import ArpParser
                prelayer = ArpParser.load_as_arp_layer(payload,Alr=1,verbose=verbose)
            elif pid == 0x8863 or pid == 0x8864:
                from .ppp import PPPoEParser
                prelayer = PPPoEParser.load_as_pppoe_layer(payload, Alr=0, verbose=verbose)
            elif pid == 0x880B:
                from .ppp import PPP2bParser
                prelayer = PPP2bParser.load_as_ppp2b_layer(payload, Alr=0, verbose=verbose)
            else:
                from .Detect_layer import DetectLayer
                d = DetectLayer()
                prelayer = d.start(payload, previous_layer="SNAP",verbose=verbose)

            return snap / prelayer
        return snap
