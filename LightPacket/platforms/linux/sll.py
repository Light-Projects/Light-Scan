# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from LightPacket.Layers.Mac import MacAddress
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Layers.register import registry
from typing import Union
import struct
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from LightPacket.Consts import ARP_var, IPv4_var, ETHERTYPE, OUI_MAP, MC, IPv6_var

LLogger = Logger()

PACKET_TYPE_NAMES = {
    0: "unicast-to-us",
    1: "broadcast",
    2: "multicast",
    3: "unicast-to-other",
    4: "sent-by-us",
}

ARPHRD_NAMES = {
    1:     "Ethernet",
    512:   "PPP",
    772:   "Loopback",
    778:   "GRE",
    801:   "IEEE 802.11",
    65534: "None",
}


ETHERTYPE_ARP = 0x0806
ETHERTYPE_ARP_ALT = 0x8035
ETHERTYPE_EAPOL = 0x888E
ETHERTYPE_PPPOE_DISCOVERY = 0x8863
ETHERTYPE_PPPOE_SESSION = 0x8864
ETHERTYPE_PPP_2B = 0x880B
ETHERTYPE_LOOPBACK = 0x9000

class SLLv1(BaseLayer):
    def __init__(self, packet_type: int = 0,
                 arphrd_type: int = 1,
                 addr_len: int = 6,
                 addr: Union[str, bytes] = None,
                 proto: Union[str, int] = None):
        super().__init__()
        self.packet_type = packet_type
        self.arphrd_type = arphrd_type
        self.addr_len = addr_len
        self.addr = MacAddress(addr if addr is not None else b'\x00' * 6)
        self.proto = proto

    def build(self) -> bytes:
        layer = self.payload.__class__.__name__
        if self.proto is None:
            if layer == 'ARP':
                self.proto = ARP_var
            elif layer == 'PPPoE':
                self.proto = 0x8864
            elif layer == 'PPP2b':
                self.proto = 0x880B
            elif layer == 'EAPOL':
                self.proto = 0x888E
            elif layer == 'Loopback':
                self.proto = 0x9000
            elif layer == 'IPv6':
                self.proto = IPv6_var
            else:
                self.proto = IPv4_var
        else:
            pass

        if self.proto < 0x0600:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="SLLv1 Protocol Type should not be less then 0x0600")

        payload_bytes = self.get_payload_bytes()

        return (
            struct.pack('>HHH', self.packet_type, self.arphrd_type, self.addr_len) +
            bytes(self.addr)[:8].ljust(8, b'\x00') +
            struct.pack('>H', self.proto) +
            payload_bytes
        )

    def __len__(self):
        return 16

    def __repr__(self):
        return (
            f"<SLLv1 pkttype={self.packet_type} "
            f"({PACKET_TYPE_NAMES.get(self.packet_type, 'Unknown')}) "
            f"arphrd={self.arphrd_type} "
            f"src={self.addr} "
            f"proto={self.proto} {ETHERTYPE.get(self.proto, 'Unknown')} "
            f"len=16 (bytes) >"
        )

    def copy(self) -> 'SLLv1':
        new_layer = SLLv1(
            packet_type=self.packet_type,
            arphrd_type=self.arphrd_type,
            addr_len=self.addr_len,
            addr=str(self.addr),
            proto=self.proto,
        )

        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"pkttype={self.packet_type} ({PACKET_TYPE_NAMES.get(self.packet_type, 'Unknown')})",
            f"arphrd={self.arphrd_type} ({ARPHRD_NAMES.get(self.arphrd_type, 'Unknown')})",
            f"src={self.addr}",
            f"proto={self.proto} {ETHERTYPE.get(self.proto, 'Unknown')}",
        ]


class SLLv1Parser:
    @staticmethod
    def load_as_sll1_layer(raw_packet, Alr=0, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 16:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="SLLv1 required header is 16 bytes")

        header = raw_packet[0][:16]
        Length = len(header)

        packet_type, arphrd_type, addr_len, addr_raw, proto = struct.unpack(
            '>HHH8sH', header
        )

        if addr_len > 8:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message=f"SLLv1 addr_len ({addr_len}) exceeds 8 bytes")

        addr_bytes = addr_raw[:addr_len]
        payload = raw_packet[0][16:]
        Total = len(payload) + Length

        addr_str = ':'.join(f'{b:02x}' for b in addr_bytes) if addr_bytes else "00:00:00:00:00:00"

        if verbose:
            print(f"\n{BOLD}SLLv1 LAYER : {RESET}Len({PURPLE}{Length}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}PKTTYPE:{CYAN} {packet_type} ({PACKET_TYPE_NAMES.get(packet_type, "Unknown")}){RESET}')
            print(f'   {BLUE}ARPHRD:{CYAN} {arphrd_type} ({ARPHRD_NAMES.get(arphrd_type, "Unknown")}){RESET}')
            print(f'   {BLUE}SRC ADDR:{CYAN} {addr_str} ({'Multicast' if addr_str[:2] in MC else OUI_MAP.get(addr_str.replace(":", "")[:6],'?')}) (len={addr_len}){RESET}')
            print(f'   {BLUE}PROTO:{CYAN} {hex(proto)} {ETHERTYPE.get(proto, "Unknown")}{RESET}')

        sll = SLLv1(
            packet_type=packet_type,
            arphrd_type=arphrd_type,
            addr_len=addr_len,
            addr=addr_str,
            proto=proto,
        )

        if len(payload) > 0 and payload != b'':
            from LightPacket.Layers.register import registry
            custom = registry.get_parser('ethertype', proto)
            if custom:
                return custom['parser'](payload, verbose=verbose)

            if proto in (ETHERTYPE_ARP, ETHERTYPE_ARP_ALT):
                from LightPacket.Arp import ArpParser
                return sll / ArpParser.load_as_arp_layer(payload, Alr=1, verbose=verbose)

            if proto == ETHERTYPE_EAPOL:
                from LightPacket.eapol import EAPOLParser
                return sll / EAPOLParser.load_as_eapol_layer(payload, verbose=verbose)

            if proto in (ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION):
                from LightPacket.ppp import PPPoEParser
                return sll / PPPoEParser.load_as_pppoe_layer(payload, Alr=0, verbose=verbose)

            if proto == ETHERTYPE_PPP_2B:
                from LightPacket.ppp import PPP2bParser
                return sll / PPP2bParser.load_as_ppp2b_layer(payload, Alr=0, verbose=verbose)

            if proto == ETHERTYPE_LOOPBACK:
                from LightPacket.EthernetII import LoopbackParser
                return sll / LoopbackParser.load_as_loopback_layer(payload, verbose=verbose)

            if proto == IPv4_var:
                from LightPacket.ipv4 import IPv4Parser
                return sll / IPv4Parser.load_as_ip_layer(payload, verbose=verbose)

            if proto == IPv6_var:
                from LightPacket.ipv6 import IPv6Parser
                return sll / IPv6Parser.load_as_ip_layer(payload, verbose=verbose)

            from LightPacket.Raw import RawParser
            return sll / RawParser.load_as_Raw_layer(payload, verbose=verbose)

        return sll

class SLLv2(BaseLayer):
    def __init__(self, proto: Union[str, int] = None,
                 reserved: int = 0,
                 if_index: int = 0,
                 arphrd_type: int = 1,
                 packet_type: int = 0,
                 addr_len: int = 6,
                 addr: Union[str, bytes] = None):
        super().__init__()
        self.proto = proto
        self.reserved = reserved
        self.if_index = if_index
        self.arphrd_type = arphrd_type
        self.packet_type = packet_type
        self.addr_len = addr_len
        self.addr = MacAddress(addr if addr is not None else b'\x00' * 6)

    def build(self) -> bytes:
        layer = self.payload.__class__.__name__
        if self.proto is None:
            if layer == 'ARP':
                self.proto = ARP_var
            elif layer == 'PPPoE':
                self.proto = 0x8864
            elif layer == 'PPP2b':
                self.proto = 0x880B
            elif layer == 'EAPOL':
                self.proto = 0x888E
            elif layer == 'Loopback':
                self.proto = 0x9000
            elif layer == 'IPv6':
                self.proto = IPv6_var
            else:
                self.proto = IPv4_var
        else:
            pass

        if self.proto < 0x0600:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="SLLv2 Protocol Type should not be less then 0x0600")

        payload_bytes = self.get_payload_bytes()

        return (
            struct.pack('>HHI', self.proto, self.reserved, self.if_index) +
            struct.pack('>HBB', self.arphrd_type, self.packet_type, self.addr_len) +
            bytes(self.addr)[:8].ljust(8, b'\x00') +
            payload_bytes
        )

    def __len__(self):
        return 20

    def __repr__(self):
        return (
            f"<SLLv2 proto={self.proto} {ETHERTYPE.get(self.proto, 'Unknown')} "
            f"ifindex={self.if_index} "
            f"pkttype={self.packet_type} ({PACKET_TYPE_NAMES.get(self.packet_type, 'Unknown')}) "
            f"src={self.addr} "
            f"len=20 (bytes) >"
        )

    def copy(self) -> 'SLLv2':
        new_layer = SLLv2(
            proto=self.proto,
            reserved=self.reserved,
            if_index=self.if_index,
            arphrd_type=self.arphrd_type,
            packet_type=self.packet_type,
            addr_len=self.addr_len,
            addr=str(self.addr),
        )

        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"proto={self.proto} {ETHERTYPE.get(self.proto, 'Unknown')}",
            f"ifindex={self.if_index}",
            f"arphrd={self.arphrd_type} ({ARPHRD_NAMES.get(self.arphrd_type, 'Unknown')})",
            f"pkttype={self.packet_type} ({PACKET_TYPE_NAMES.get(self.packet_type, 'Unknown')})",
            f"src={self.addr}",
        ]


class SLLv2Parser:

    @staticmethod
    def load_as_sll2_layer(raw_packet, Alr=0, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 20:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="SLLv2 required header is 20 bytes")

        header = raw_packet[0][:20]
        Length = len(header)

        proto, reserved, if_index, arphrd_type, packet_type, addr_len, addr_raw = \
            struct.unpack('>HHIHBB8s', header)

        if addr_len > 8:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message=f"SLLv2 addr_len ({addr_len}) exceeds 8 bytes")

        addr_bytes = addr_raw[:addr_len]
        payload = raw_packet[0][20:]
        Total = len(payload) + Length

        addr_str = ':'.join(f'{b:02x}' for b in addr_bytes) if addr_bytes else "00:00:00:00:00:00"

        if verbose:
            print(f"\n{BOLD}SLLv2 LAYER : {RESET}Len({PURPLE}{Length}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}PROTO:{CYAN} {hex(proto)} {ETHERTYPE.get(proto, "Unknown")}{RESET}')
            print(f'   {BLUE}IFINDEX:{CYAN} {if_index}{RESET}')
            print(f'   {BLUE}ARPHRD:{CYAN} {arphrd_type} ({ARPHRD_NAMES.get(arphrd_type, "Unknown")}){RESET}')
            print(f'   {BLUE}PKTTYPE:{CYAN} {packet_type} ({PACKET_TYPE_NAMES.get(packet_type, "Unknown")}){RESET}')
            print(f'   {BLUE}SRC ADDR:{CYAN} {addr_str} ({'Multicast' if addr_str[:2] in MC else OUI_MAP.get(addr_str.replace(":", "")[:6],'?')}) (len={addr_len}){RESET}')

        sll = SLLv2(
            proto=proto,
            reserved=reserved,
            if_index=if_index,
            arphrd_type=arphrd_type,
            packet_type=packet_type,
            addr_len=addr_len,
            addr=addr_str,
        )

        if len(payload) > 0 and payload != b'':
            from LightPacket.Layers.register import registry
            custom = registry.get_parser('ethertype', proto)
            if custom:
                return custom['parser'](payload, verbose=verbose)

            if proto in (ETHERTYPE_ARP, ETHERTYPE_ARP_ALT):
                from LightPacket.Arp import ArpParser
                return sll / ArpParser.load_as_arp_layer(payload, Alr=1, verbose=verbose)

            if proto == ETHERTYPE_EAPOL:
                from LightPacket.eapol import EAPOLParser
                return sll / EAPOLParser.load_as_eapol_layer(payload, verbose=verbose)

            if proto in (ETHERTYPE_PPPOE_DISCOVERY, ETHERTYPE_PPPOE_SESSION):
                from LightPacket.ppp import PPPoEParser
                return sll / PPPoEParser.load_as_pppoe_layer(payload, Alr=0, verbose=verbose)

            if proto == ETHERTYPE_PPP_2B:
                from LightPacket.ppp import PPP2bParser
                return sll / PPP2bParser.load_as_ppp2b_layer(payload, Alr=0, verbose=verbose)

            if proto == ETHERTYPE_LOOPBACK:
                from LightPacket.EthernetII import LoopbackParser
                return sll / LoopbackParser.load_as_loopback_layer(payload, verbose=verbose)

            if proto == IPv4_var:
                from LightPacket.ipv4 import IPv4Parser
                return sll / IPv4Parser.load_as_ip_layer(payload, verbose=verbose)

            if proto == IPv6_var:
                from LightPacket.ipv6 import IPv6Parser
                return sll / IPv6Parser.load_as_ip_layer(payload, verbose=verbose)

            from LightPacket.Raw import RawParser
            return sll / RawParser.load_as_Raw_layer(payload, verbose=verbose)

        return sll