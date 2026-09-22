# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from LightPacket.Arp import ArpParser
from LightPacket.Layers.Mac import MacAddress
from LightPacket.Logger.LightLogger import Logger, ErrorCode, WarningCode
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Layers.register import registry
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from LightPacket.Consts import OUI_MAP,ARP_var,BROADCAST_MAC,IPv4_var,ETHERTYPE,MC,IPv6_var
from LightPacket.GetMac import GetMac

from typing import Union
import struct

LLogger = Logger()

"""
Ethernet Layer Creation (class Ethernet)
"""

class Ethernet(BaseLayer):

    def __init__(self, dst: Union[str, bytes] = BROADCAST_MAC, src: Union[str, bytes]= GetMac(),
                 ethertype: Union[str, bytes] = None):
        super().__init__()
        self.dst = MacAddress(dst, d_or_s=1)
        self.src = MacAddress(src, d_or_s=0)
        self.ethertype = ethertype

    def build(self) -> bytes:
        self.numofvlan = 0
        layer = self.payload.__class__.__name__
        if self.ethertype is None:
            if layer == 'VLAN':
                self.numofvlan, layer = self.vlanhandler()
                self.ethertype = self.check_layers_fromvar(layer)
            else:
                self.ethertype =  self.check_layers_fromvar(layer)
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
        if var == 'ARP':
            return ARP_var
        elif var == 'PPPoE':
            return 0x8864
        elif var == 'PPP2b':
            return 0x880B
        elif var == 'EAPOL':
            return 0x888E
        elif var == 'Loopback':
            return 0x9000
        elif var == 'IPv4':
            return IPv4_var
        elif var == 'IPv6':
            return IPv6_var
        else:
            return IPv4_var

    def vlanhandler(self):
        return self.payload.num()

    def __len__(self):
        return 14

    def __repr__(self):
        return (f"<Ethernet dst={self.dst} src={self.src} "
                f"type={self.ethertype} {ETHERTYPE.get(self.ethertype, 'Unknown')} "
                f"len={14} (bytes) >")

    def copy(self) -> 'Ethernet':
        new_layer = Ethernet(
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

MIN_ETH_HEADER_LEN = 14

ETHERTYPE_LEN_MAX = 1500
ETHERTYPE_MIN = 0x0600

ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_ARP = 0x0806
ETHERTYPE_ARP_ALT = 0x8035
ETHERTYPE_EAPOL = 0x888E
ETHERTYPE_PPPOE_DISCOVERY = 0x8863
ETHERTYPE_PPPOE_SESSION = 0x8864
ETHERTYPE_PPP_2B = 0x880B
ETHERTYPE_LOOPBACK = 0x9000

class EthernetParser:

    @staticmethod
    def load_as_ethernet_layer(raw_packet, Alr=0, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        packet = raw_packet[0]

        if len(packet) < MIN_ETH_HEADER_LEN:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="Ethernet required header is 14 bytes")
            return None

        header = packet[:MIN_ETH_HEADER_LEN]
        mac_dst = header[:6]
        mac_src = header[6:12]
        raw_type = EthernetParser._read_ethertype(header, offset=12)

        if raw_type <= ETHERTYPE_LEN_MAX:
            from LightPacket.Dot3 import Dot3Parser
            return Dot3Parser.load_as_dot3_layer(raw_packet, verbose=verbose)

        vlan_layer = None
        if raw_type in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
            from LightPacket.Vlan import vlannum, VLANParser

            num_tags = vlannum(packet[12:])
            inner_offset = 12 + (4 * num_tags)
            ethertype = EthernetParser._read_ethertype(packet, offset=inner_offset)
            payload = packet[14 + (num_tags * 4):]

            if ethertype <= ETHERTYPE_LEN_MAX:
                from LightPacket.Dot3 import Dot3Parser
                return Dot3Parser.load_as_dot3_layer(raw_packet, verbose=verbose)

            vlan_layer = VLANParser.load_as_vlan_layer(
                packet[12:14 + (num_tags * 4)], verbose=verbose
            )
        else:
            ethertype = raw_type
            payload = packet[14:]

        if verbose:
            EthernetParser._print_verbose(mac_dst, mac_src, ethertype, len(header), len(payload) + len(header))

        ether = Ethernet(
            dst=EthernetParser._mac_to_str(mac_dst),
            src=EthernetParser._mac_to_str(mac_src),
            ethertype=ethertype,
        )

        should_parse_payload = len(payload) > 0 and payload != b'' and Alr != 1
        prelayer = None
        if should_parse_payload:
            prelayer = EthernetParser._parse_payload(ethertype, payload, verbose)

        return EthernetParser._assemble(ether, vlan_layer, prelayer)

    @staticmethod
    def _assemble(ether, vlan_layer, prelayer):
        result = ether
        if vlan_layer is not None:
            result = result / vlan_layer
        if prelayer is not None:
            result = result / prelayer
        return result

    @staticmethod
    def _read_ethertype(data, offset):
        return struct.unpack('>H', data[offset:offset + 2])[0]

    @staticmethod
    def _mac_to_str(mac_bytes):
        return ':'.join(f'{b:02x}' for b in mac_bytes)

    @staticmethod
    def _print_verbose(mac_dst, mac_src, ethertype, header_len, total_len):
        mac_dst_str = EthernetParser._mac_to_str(mac_dst)
        mac_src_str = EthernetParser._mac_to_str(mac_src)

        def vendor(mac_str):
            if mac_str[:2] in MC:
                return 'Multicast'
            return OUI_MAP.get(mac_str.replace(":", "")[:6], '?')

        print(f"\n{BOLD}ETHERNET LAYER : {RESET}Len({PURPLE}{header_len}{RESET}) "
              f"Total Len({PURPLE}{total_len}{RESET}) >")
        print(f'   {BLUE}MAC DST:{CYAN} {mac_dst_str} ({vendor(mac_dst_str)})')
        print(f'   {BLUE}MAC SRC:{CYAN} {mac_src_str} ({vendor(mac_src_str)})')
        print(f'   {BLUE}ETHER TYPE:{CYAN} {hex(ethertype)} '
              f'{ETHERTYPE.get(ethertype, "Unknown")}{RESET}')

    @staticmethod
    def _parse_payload(ethertype, payload, verbose):

        from LightPacket.Layers.register import registry
        custom = registry.get_parser('ethertype', ethertype)
        if custom:
            return custom['parser'](payload, verbose=verbose)

        if ethertype in (ETHERTYPE_ARP, ETHERTYPE_ARP_ALT):
            from LightPacket.Arp import ArpParser
            return ArpParser.load_as_arp_layer(payload, Alr=1, verbose=verbose)

        if ethertype == ETHERTYPE_EAPOL:
            from LightPacket.eapol import EAPOLParser
            return EAPOLParser.load_as_eapol_layer(payload, verbose=verbose)

        if ethertype in (ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION):
            from LightPacket.ppp import PPPoEParser
            return PPPoEParser.load_as_pppoe_layer(payload, Alr=0, verbose=verbose)

        if ethertype == ETHERTYPE_PPP_2B:
            from LightPacket.ppp import PPP2bParser
            return PPP2bParser.load_as_ppp2b_layer(payload, Alr=0, verbose=verbose)

        if ethertype == ETHERTYPE_LOOPBACK:
            return LoopbackParser.load_as_loopback_layer(payload, verbose=verbose)

        if ethertype == IPv4_var:
            from LightPacket.ipv4 import IPv4Parser
            return IPv4Parser.load_as_ip_layer(payload, verbose=verbose)

        if ethertype == IPv6_var:
            from LightPacket.ipv6 import IPv6Parser
            return IPv6Parser.load_as_ip_layer(payload, verbose=verbose)

        from LightPacket.Raw import RawParser
        return RawParser.load_as_Raw_layer(payload, verbose=verbose)


"""
Loopback Layer Creation (Loopback class)
"""

class Loopback(BaseLayer):
    def __init__(self, skipcount:int = 1,func:int = 1,fmac:bytes = b'\x00' * 6,data:bytes = b'\x00\x00Ping'):
        super().__init__()
        self.skipcount = skipcount
        self.func = func
        self.fmac = fmac
        self.data = data

    def build(self):
        payload_bytes = self.get_payload_bytes()
        result = struct.pack('HH',self.skipcount,self.func)
        if self.func == 2:
            result += self.fmac
        result += self.data
        if payload_bytes:
            result += payload_bytes
        return result

    def __repr__(self):
        return (f"<Loopback skipcount={self.skipcount} func={self.func} fmac={self.fmac}"
                f"data={self.data} >")

    def copy(self) -> 'Loopback':
        new_layer = Loopback(
            skipcount=self.skipcount,
            func=self.func,
            fmac=self.fmac,
            data=self.data,
        )

        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [f"skipcount={self.skipcount}", f"func={self.func} ",f"fmac={self.fmac} ",
                f"data={self.data}"]

"""
Loopback Parser (separate from the builder)
"""

class LoopbackParser:

    @staticmethod
    def load_as_loopback_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 4:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="Loopback required header is 4 bytes")


        LH = raw_packet[0][:4]

        skipcount, func = struct.unpack('<HH', LH)

        payload = raw_packet[0][4:]
        Lenght = len(LH)
        Total = len(payload) + Lenght
        fmac = b'\x00' * 6

        if verbose:
            print(f"\n{BOLD}LOOPBACK LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}SKIPCOUNT:{CYAN} {skipcount} ')
            print(f'   {BLUE}FUNC:{CYAN} {func} {RESET}')
            if func == 2:
                print(f'   {BLUE}FMAC:{CYAN} {payload[:6]} {RESET}')
                fmac = payload[:6]
                payload = payload[6:]

            if payload != b'':
                print(f'   {BLUE}DATA:{CYAN} {payload}{RESET}')

        lpb = Loopback(
            skipcount=skipcount,
            func=func,
            data=payload,
            fmac=fmac
        )

        return lpb


def EthertypeHex(ether_type):
    return hex(ether_type)

