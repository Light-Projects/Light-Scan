# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Consts import ARP_var, ETHERTYPE, OUI_MAP, IPv6_var, IPv4_var
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE

LLogger = Logger()

"""
SNAP Layer Creation (class SNAP)
"""

class SNAP(BaseLayer):

    def __init__(self, oui=0x000000, pid=None):
        super().__init__()
        self.oui = oui
        self.pid = pid

    def build(self) -> bytes:
        layer = self.payload.__class__.__name__
        if self.pid is None:
            if layer == 'PPPoE':
                self.pid = 0x8864
            elif layer == 'ARP':
                self.pid = ARP_var
            elif layer == 'PPP2b':
                self.pid = 0x880B
            elif layer == 'EAPOL':
                self.pid = 0x888E
            elif layer == 'IPv4':
                self.pid = IPv4_var
            elif layer == 'IPv6':
                self.pid = IPv6_var
            elif layer == 'Raw':
                self.pid = 0
            else:
                self.pid = ARP_var

        if isinstance(self.oui, int):
            oui_bytes = self.oui.to_bytes(3, byteorder='big')
        elif isinstance(self.oui, bytes):
            oui_bytes = self.oui[:3].rjust(3, b'\x00')
        elif isinstance(self.oui, str):
            clean = self.oui.replace(':', '').replace('-', '')
            try:
                oui_bytes = bytes.fromhex(clean)[:3].rjust(3, b'\x00')
            except ValueError:
                oui_bytes = b'\x00\x00\x00'
        else:
            try:
                oui_bytes = int(self.oui).to_bytes(3, byteorder='big')
            except Exception:
                oui_bytes = b'\x00\x00\x00'

        result = struct.pack('!3sH', oui_bytes, self.pid if self.pid is not None else 0)
        return result + self.get_payload_bytes()

    def __len__(self):
        return 5 + (len(self.payload) if self.payload else 0)


    def __repr__(self):
        if isinstance(self.oui, int):
            oui_str = f"0x{self.oui:06x}"
        elif isinstance(self.oui, bytes):
            oui_str = self.oui.hex()
        else:
            oui_str = str(self.oui)
        pid_str = f"0x{self.pid:04x}" if self.pid is not None else "None"
        return f"<SNAP oui={oui_str} pid={pid_str}>"

    def copy(self) -> 'SNAP':
        new_layer = SNAP(
            oui=self.oui,
            pid=self.pid
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        if isinstance(self.oui, int):
            oui_str = f"0x{self.oui:06x}"
        elif isinstance(self.oui, bytes):
            oui_str = self.oui.hex()
        else:
            oui_str = str(self.oui)
        pid_str = f"0x{self.pid:04x}" if self.pid is not None else "None"
        return [
            f"oui={oui_str}",
            f"pid={pid_str}",
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

        data = raw_packet[0]
        if Alr == 0 and len(data) >= 22:
            from .LLC import LLCParser
            LLCParser.load_as_llc_layer(data, Alr=2)
            SNAPHeader = data[17:22]
            payload = data[22:]
        else:
            if len(data) < 5:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH, message="SNAP required header is 5 bytes")
            SNAPHeader = data[:5]
            payload = data[5:]

        oui, pid = struct.unpack('!3sH', SNAPHeader)
        Lenght = len(SNAPHeader)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}SNAP LAYER: {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f"   {BLUE}OUI:{CYAN} {oui.hex()} ({OUI_MAP.get(oui.hex(),'?')})")
            print(f"   {BLUE}PID:{CYAN} {hex(pid)} {ETHERTYPE.get(pid,'Unknown')}{RESET}")

        snap = SNAP(
            oui=oui,
            pid=pid
        )

        if len(payload) > 0:
            if pid == ARP_var and len(payload) >= 28:
                try:
                    from LightPacket.Arp import ArpParser
                    return snap / ArpParser.load_as_arp_layer(payload, Alr=1, verbose=verbose)
                except Exception:
                    pass

            if pid == 0x888E:
                try:
                    from LightPacket.eapol import EAPOLParser
                    return snap / EAPOLParser.load_as_eapol_layer(payload, verbose=verbose)
                except Exception:
                    pass

            if pid in (0x8863, 0x8864):
                try:
                    from LightPacket.ppp import PPPoEParser
                    return snap / PPPoEParser.load_as_pppoe_layer(payload, Alr=0, verbose=verbose)
                except Exception:
                    pass

            if pid == 0x880B:
                try:
                    from LightPacket.ppp import PPP2bParser
                    return snap / PPP2bParser.load_as_ppp2b_layer(payload, Alr=0, verbose=verbose)
                except Exception:
                    pass

            if pid == IPv4_var and len(payload) >= 20:
                try:
                    from LightPacket.ipv4 import IPv4Parser
                    return snap / IPv4Parser.load_as_ip_layer(payload, verbose=verbose)
                except Exception:
                    pass

            if pid == IPv6_var and len(payload) >= 40:
                try:
                    from LightPacket.ipv6 import IPv6Parser
                    return snap / IPv6Parser.load_as_ip_layer(payload, verbose=verbose)
                except Exception:
                    pass

            from LightPacket.Raw import RawParser
            return snap / RawParser.load_as_Raw_layer(payload, verbose=verbose)

        return snap
