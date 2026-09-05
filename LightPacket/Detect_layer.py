# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from .Layers.IS_LLC import is_llc
from .Wireless.wlan import is_wifi_packet
from .ppp import is_ppp_frame
from .Consts import Layers_names

class DetectLayer:
    def start(self, packet, Alr=0, previous_layer=None, verbose=False):
        if hasattr(packet, 'build') and callable(packet.build) and Alr == 0:
            packet = packet.build()

        Lenght = len(packet)

        if previous_layer in Layers_names:
            from .Raw import RawParser
            s = RawParser.load_as_Raw_layer(packet,verbose=verbose)
            return s

        try:
            if Lenght >= 14:
                HHH = packet[12:14]
                eth_type = struct.unpack('>H', HHH)[0]
                if is_ppp_frame(packet):
                    from .ppp import PPPParser
                    s = PPPParser.load_as_ppp_layer(packet,verbose=verbose)
                elif is_wifi_packet(packet):
                    from .Wireless.wlan import WiFiParser
                    s = WiFiParser.load_as_wifi_layer(packet,verbose=verbose)
                elif eth_type >= 0x0600:
                    if eth_type == 0x8100 or eth_type == 0x88A8:
                        from .Vlan import vlannum
                        numofvlan = vlannum(packet[12:])
                        ethertype = packet[12 + (4 * numofvlan):14 + (4 * numofvlan)]
                        ethertype = struct.unpack('>H', ethertype)[0]
                        if ethertype >= 0x0600:
                            from .EthernetII import EthernetParser
                            s = EthernetParser.load_as_ethernet_layer(packet,verbose=verbose)
                        else:
                            from .Dot3 import Dot3Parser
                            s = Dot3Parser.load_as_dot3_layer(packet, verbose=verbose)
                    else:
                        from .EthernetII import EthernetParser
                        s = EthernetParser.load_as_ethernet_layer(packet,verbose=verbose)
                elif eth_type <= 0x05DC:
                    from .Dot3 import Dot3Parser
                    s = Dot3Parser.load_as_dot3_layer(packet,verbose=verbose)
                else:
                    from .Raw import RawParser
                    s = RawParser.load_as_Raw_layer(packet,verbose=verbose)

            elif is_llc(packet):
                from .LLC import LLCParser
                s = LLCParser.load_as_llc_layer(packet,verbose=verbose)
            elif is_ppp_frame(packet):
                from .ppp import PPPParser
                s = PPPParser.load_as_ppp_layer(packet, verbose=verbose)
            else:
                from .Raw import RawParser
                s = RawParser.load_as_Raw_layer(packet,verbose=verbose)

        except Exception as e:
            print(e)
            from .Raw import RawParser
            s = RawParser.load_as_Raw_layer(packet,verbose=verbose)

        return s