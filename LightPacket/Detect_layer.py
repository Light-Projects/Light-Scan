# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.ppp import is_ppp_frame
from LightPacket.Consts import Layers_names
from LightPacket.Config import config

# pcap/pcapng LINKTYPE_* values this module knows how to dispatch on.
# https://www.tcpdump.org/linktypes.html
LINKTYPE_ETHERNET = 1
LINKTYPE_PPP = 9
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
LINKTYPE_RAW_IP = 101
LINKTYPE_IEEE802_11 = 105

ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

ETHERTYPE_MIN = 0x0600
ETHERTYPE_LEN_MAX = 0x05DC

MIN_ETH_HEADER_LEN = 14

class DetectLayer:
    """
    Identifies the correct parser for a raw frame/packet based on its
    pcap linktype and, for Ethernet-family links, its EtherType (with
    VLAN/QinQ tag unwrapping).
    """

    def start(
            self, packet, linktype=config.network.DEFAULT_LINKTYPE,
              previous_layer=None, verbose=config.logging.VERBOSE
    ):

        if hasattr(packet, 'build') and callable(packet.build):
            packet = packet.build()

        if previous_layer in Layers_names:
            return self._parse_raw(packet, verbose)

        try:
            if len(packet) >= MIN_ETH_HEADER_LEN:
                return self._dispatch_by_linktype(packet, linktype, verbose)
            elif is_ppp_frame(packet) or linktype == LINKTYPE_PPP:
                return self._parse_ppp(packet, verbose)
            else:
                return self._parse_raw(packet, verbose)
        except Exception as e:
            from LightPacket.Raw import RawParser
            return RawParser.load_as_Raw_layer(b"We got some errors here " + str(e).encode(),verbose=verbose)

    def _dispatch_by_linktype(self, packet, linktype, verbose):
        linktype_handlers = {
            LINKTYPE_PPP: self._parse_ppp,
            LINKTYPE_IEEE802_11: self._parse_wifi,
            LINKTYPE_LINUX_SLL: self._parse_sll1,
            LINKTYPE_LINUX_SLL2: self._parse_sll2,
            LINKTYPE_RAW_IP: self._parse_ip,
        }

        handler = linktype_handlers.get(linktype)
        if handler is not None:
            return handler(packet, verbose)

        return self._dispatch_by_ethertype(packet, verbose)

    def _dispatch_by_ethertype(self, packet, verbose):
        eth_type = self._read_ethertype(packet, offset=12)

        if eth_type in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
            return self._dispatch_vlan(packet, verbose)

        if eth_type >= ETHERTYPE_MIN:
            return self._parse_ethernet(packet, verbose)

        if eth_type <= ETHERTYPE_LEN_MAX:
            return self._parse_dot3(packet, verbose)

        return self._parse_raw(packet, verbose)

    def _dispatch_vlan(self, packet, verbose):
        from LightPacket.Vlan import vlannum

        num_vlans = vlannum(packet[12:])
        inner_offset = 12 + (4 * num_vlans)
        inner_ethertype = self._read_ethertype(packet, offset=inner_offset)

        if inner_ethertype >= ETHERTYPE_MIN:
            return self._parse_ethernet(packet, verbose)
        return self._parse_dot3(packet, verbose)

    @staticmethod
    def _read_ethertype(packet, offset):
        raw = packet[offset:offset + 2]
        return struct.unpack('>H', raw)[0]

    @staticmethod
    def _parse_ppp(packet, verbose):
        from LightPacket.ppp import PPPParser
        return PPPParser.load_as_ppp_layer(packet, verbose=verbose)

    @staticmethod
    def _parse_wifi(packet, verbose):
        from LightPacket.Wireless.wlan import WiFiParser
        return WiFiParser.load_as_wifi_layer(packet, verbose=verbose)

    @staticmethod
    def _parse_sll1(packet, verbose):
        from LightPacket.platforms.linux.sll import SLLv1Parser
        return SLLv1Parser.load_as_sll1_layer(packet, verbose=verbose)

    @staticmethod
    def _parse_sll2(packet, verbose):
        from LightPacket.platforms.linux.sll import SLLv2Parser
        return SLLv2Parser.load_as_sll2_layer(packet, verbose=verbose)

    @staticmethod
    def _parse_ip(packet, verbose):
        from LightPacket.ipv4 import IPv4Parser
        return IPv4Parser.load_as_ip_layer(packet, verbose=verbose)

    @staticmethod
    def _parse_ethernet(packet, verbose):
        from LightPacket.EthernetII import EthernetParser
        return EthernetParser.load_as_ethernet_layer(packet, verbose=verbose)

    @staticmethod
    def _parse_dot3(packet, verbose):
        from LightPacket.Dot3 import Dot3Parser
        return Dot3Parser.load_as_dot3_layer(packet, verbose=verbose)

    @staticmethod
    def _parse_raw(packet, verbose):
        from LightPacket.Raw import RawParser
        return RawParser.load_as_Raw_layer(packet, verbose=verbose)