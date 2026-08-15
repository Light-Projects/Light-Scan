# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from .Arp import ArpParser
from .Layers.Mac import MacAddress
from .Logger.LightLogger import Logger, ErrorCode, WarningCode
from .BaseLayer import BaseLayer
from typing import Union
from .Detect_layer import DetectLayer
import struct
from .Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from .Consts import *

LLogger = Logger()

"""
Ethernet Layer Creation (class EthernetLayer)
"""

class EthernetLayer(BaseLayer):

    def __init__(self, dst: Union[str, bytes], src: Union[str, bytes],
                 ethertype: Union[str, bytes] = None):
        super().__init__()
        self.dst = MacAddress(dst, d_or_s=1)
        self.src = MacAddress(src, d_or_s=0)
        self.ethertype = ethertype

    def build(self) -> bytes:
        self.numofvlan = 0
        layer = self.payload.__class__.__name__
        if self.ethertype is None:
            if layer == 'ArpLayer':
                self.ethertype =  ARP_var
            elif layer == 'PPPoELayer':
                self.ethertype = 0x8863
            elif layer == 'PPP2bLayer':
                self.ethertype = 0x880B
            elif layer == 'VLANLayer':
                self.numofvlan, layer = self.vlanhandler()
                self.ethertype = self.check_layers_fromvar(layer)
            else:
                self.ethertype =  IPv4
        else:
            pass

        if self.ethertype < 0x0600:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="Ether Type Field should not be less then 0x0600")
        payload_bytes = self.get_payload_bytes()
        chunked = b''
        try:
            if self.numofvlan > 0:
                vlan_bytes = b''
                for i in range(self.numofvlan):
                    chunk = payload_bytes[i * 4:(i + 1) * 4]
                    vlan_bytes += chunk

                payload_bytes = payload_bytes[self.numofvlan * 4:]
                chunked = vlan_bytes
        except AttributeError:
            pass

        return (
                    bytes(self.dst) +
                    bytes(self.src) +
                    bytes(chunked) +
                    struct.pack('>H', self.ethertype) +
                    payload_bytes
            )

    def check_layers_fromvar(self,var):
        if var == 'ArpLayer':
            return ARP_var
        elif var == 'PPPoELayer':
            return 0x8863
        elif var == 'PPP2bLayer':
            return 0x880B
        else:
            return IPv4

    def vlanhandler(self):
        return self.payload.num()

    def __len__(self):
        return 14

    def __repr__(self):
        return (f"<Ethernet dst={self.dst} src={self.src} "
                f"type={self.ethertype} {ETHERTYPE.get(self.ethertype, 'Unknown')} "
                f"len={14} (bytes) >")

    def copy(self) -> 'EthernetLayer':
        new_layer = EthernetLayer(
            dst=str(self.dst),
            src=str(self.src),
            ethertype=self.ethertype
        )

        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [f"dst={self.dst}", f"src={self.src} ",f"type={self.ethertype} {ETHERTYPE.get(self.ethertype, 'Unknown')}"]


"""
Ethernet Parser (separate from the builder)
"""

class EthernetParser:

    @staticmethod
    def load_as_ethernet_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 14:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="Ethernet required header is 14 bytes")

        EtherHeader = raw_packet[0][:14]
        Length = len(EtherHeader)
        mac_dst = EtherHeader[:6]
        mac_src = EtherHeader[6:12]
        mac_dst_str = ':'.join(f'{b:02x}' for b in mac_dst)
        mac_src_str = ':'.join(f'{b:02x}' for b in mac_src)
        ether_type_raw = EtherHeader[12:14]
        ether_type = struct.unpack('>H', ether_type_raw)[0]
        payload = raw_packet[0][14:]
        Total = len(payload) + Length

        if ether_type <= 1500:
            from .Dot3 import Dot3Parser
            Dot3Parser.load_as_dot3_layer(raw_packet,verbose=verbose)

        elif ether_type == 33024 or ether_type == 34984:
            from .Vlan import vlannum, VLANParser
            vl = None
            prelayer = None
            number = vlannum(raw_packet[0][12:])
            ethertype = raw_packet[0][12 + (4 * number):14 + (4 * number)]
            ethertype = struct.unpack('>H', ethertype)[0]
            payload = raw_packet[0][14+(number * 4):]

            if ethertype <= 0x05DC:
                from .Dot3 import Dot3Parser
                Dot3Parser.load_as_dot3_layer(raw_packet, verbose=verbose)
            else:
                if verbose:
                    print(
                        f"\n{BOLD}ETHERNET LAYER : {RESET}Len({PURPLE}{Length}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
                    print(f'   {BLUE}MAC DST:{CYAN} {mac_dst_str}')
                    print(f'   {BLUE}MAC SRC:{CYAN} {mac_src_str}')
                    print(f'   {BLUE}ETHER TYPE:{CYAN} {hex(ethertype)} '
                          f'{ETHERTYPE.get(ethertype, "Unknown")}{RESET}')


                vl = VLANParser.load_as_vlan_layer(raw_packet[0][12:14 + (number * 4)],verbose=verbose)

                if len(payload) > 0 and Alr != 1 and payload != b'':
                    if ethertype == ARP_var:
                        prelayer = ArpParser.load_as_arp_layer(payload, Alr=1, verbose=verbose)
                    elif ethertype == 0x8863 or ethertype == 0x8864:
                        from .ppp import PPPoEParser
                        prelayer = PPPoEParser.load_as_pppoe_layer(payload, Alr=0, verbose=verbose)
                    elif ethertype == 0x880B:
                        from .ppp import PPP2bParser
                        prelayer = PPP2bParser.load_as_ppp2b_layer(payload, Alr=0, verbose=verbose)
                    else:
                        d = DetectLayer()
                        prelayer = d.start(payload, Alr=0, previous_layer="Ethernet", verbose=verbose)


                ether = EthernetLayer(
                    dst=mac_dst_str,
                    src=mac_src_str,
                    ethertype=ethertype,
                )

                if vl != None:
                    if prelayer != None:
                        return ether / vl / prelayer
                    return ether / vl
                elif prelayer != None:
                    return ether / prelayer
                else:
                    return ether

        else:
            if ether_type >= 0x0600:
                if verbose:
                    print(f"\n{BOLD}ETHERNET LAYER : {RESET}Len({PURPLE}{Length}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
                    print(f'   {BLUE}MAC DST:{CYAN} {mac_dst_str}')
                    print(f'   {BLUE}MAC SRC:{CYAN} {mac_src_str}')
                    print(f'   {BLUE}ETHER TYPE:{CYAN} {hex(ether_type)} '
                          f'{ETHERTYPE.get(ether_type, "Unknown")}{RESET}')

                ether = EthernetLayer(
                    dst=mac_dst_str,
                    src=mac_src_str,
                    ethertype=ether_type,
                )

                if len(payload) > 0 and Alr == 0:
                    if ether_type == ARP_var:
                        prelayer = ArpParser.load_as_arp_layer(payload, Alr=1,verbose=verbose)
                    elif ether_type == 0x8863 or ether_type == 0x8864:
                        from .ppp import PPPoEParser
                        prelayer = PPPoEParser.load_as_pppoe_layer(payload, Alr=0, verbose=verbose)
                    elif ether_type == 0x880B:
                        from .ppp import PPP2bParser
                        prelayer = PPP2bParser.load_as_ppp2b_layer(payload, Alr=0, verbose=verbose)
                    else:
                        d = DetectLayer()
                        prelayer = d.start(payload, Alr=0, previous_layer="Ethernet",verbose=verbose)

                    return ether / prelayer
                return ether
            else:
                from .Raw import RawParser
                l = RawParser.load_as_Raw_layer(raw_packet,verbose=verbose)
                return l


def EthertypeHex(ether_type):
    return hex(ether_type)

