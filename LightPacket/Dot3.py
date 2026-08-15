# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from .Decoration.Colors import BOLD, RESET, PURPLE, BLUE, CYAN
from .Layers.Mac import MacAddress
from .Layers.IS_LLC import is_llc
from .Logger.LightLogger import Logger, ErrorCode
from .BaseLayer import BaseLayer
from typing import Union

LLogger = Logger()

"""
Dot3 (802.3) Layer Creation (class Dot3Layer)
"""

class Dot3Layer(BaseLayer):

    def __init__(self, dst: Union[str, bytes], src: Union[str, bytes],
                 length: int = 0):
        super().__init__()
        self.dst = MacAddress(dst, d_or_s=1)
        self.src = MacAddress(src, d_or_s=0)
        self.length = length


    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        if self.length == 0:
            self.length = len(payload_bytes)

        elif self.length > 0x05DC:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="Lenght Field in 802.3 should not be more then 0x05DC")
        self.check_layers()
        chunked = b''
        try:
            if self.numofvlan > 0:
                vlan_bytes = b''
                for i in range(self.numofvlan):
                    chunk = payload_bytes[i * 4:(i + 1) * 4]
                    vlan_bytes += chunk

                payload_bytes = payload_bytes[self.numofvlan * 4:]
                chunked = vlan_bytes
                self.length -= self.numofvlan * 4
        except AttributeError:
            pass

        return (
                bytes(self.dst) +
                bytes(self.src) +
                bytes(chunked) +
                struct.pack('>H', self.length) +
                payload_bytes
        )

    def check_layers(self):
        layer = self.payload.__class__.__name__

        if layer == 'VLANLayer':
            self.numofvlan,layer = self.vlanhandler()

    def vlanhandler(self):
        return self.payload.num()

    def __len__(self):
        return 14 + len(self.get_payload_bytes())

    def __repr__(self):
        return (f"<Dot3 dst={self.dst} src={self.src} "
                f"length=0x{self.length:04x}>")

    def copy(self) -> 'Dot3Layer':
        new_layer = Dot3Layer(
            dst=str(self.dst),
            src=str(self.src),
            length=self.length
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [f"dst={self.dst} ",f"src={self.src} ",f"length=0x{self.length:04x}"]

"""
Dot3 (802.3) Parser (separate from the builder)
"""

class Dot3Parser:

    @staticmethod
    def load_as_dot3_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 14:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="Dot3 (802.3) required header is 14 bytes")

        Dot3Header = raw_packet[0][:14]
        Length = len(Dot3Header)
        mac_dst = Dot3Header[:6]
        mac_src = Dot3Header[6:12]
        mac_dst_str = ':'.join(f'{b:02x}' for b in mac_dst)
        mac_src_str = ':'.join(f'{b:02x}' for b in mac_src)
        length_raw = Dot3Header[12:14]
        length = struct.unpack('>H', length_raw)[0]
        payload = raw_packet[0][14:]
        Total = len(payload) + Length

        if length == 0x8100 or length == 0x88a8:
            from .Vlan import vlannum, VLANParser
            prelayer = None
            number = vlannum(raw_packet[0][12:])
            ethertype = raw_packet[0][12 + (4 * number):14 + (4 * number)]
            ethertype = struct.unpack('>H', ethertype)[0]
            payload = raw_packet[0][14 + (number * 4):]
            if ethertype > 0x05DC:
                from .EthernetII import EthernetParser
                EthernetParser.load_as_ethernet_layer(raw_packet, verbose=verbose)
            else:
                if verbose:
                    print(
                        f"\n{BOLD}DOT3 (802.3) LAYER : {RESET}Len({PURPLE}{Length}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
                    print(f'   {BLUE}MAC DST:{CYAN} {mac_dst_str}')
                    print(f'   {BLUE}MAC SRC:{CYAN} {mac_src_str}')
                    print(f'   {BLUE}LENGHT:{CYAN} {hex(ethertype)}{RESET}')


                vl = VLANParser.load_as_vlan_layer(raw_packet[0][12:14 + (number * 4)],verbose=verbose)
                dot3 = Dot3Layer(
                    dst=mac_dst_str,
                    src=mac_src_str,
                    length=ethertype,
                )

                if len(payload) > 0 and payload != b'':
                    if is_llc(payload):
                        from .LLC import LLCParser
                        prelayer = LLCParser.load_as_llc_layer(payload, Alr=1, verbose=verbose)
                    else:

                        from .Detect_layer import DetectLayer
                        d = DetectLayer()
                        prelayer = d.start(packet=payload, previous_layer="Dot3", verbose=verbose)

                    return dot3 / vl / prelayer
                return dot3 / vl

        elif length > 0x05DC:
            from .EthernetII import EthernetParser
            EthernetParser.load_as_ethernet_layer(raw_packet,verbose=verbose)
        else:
            if verbose:
                print(f"\n{BOLD}DOT3 (802.3) LAYER : {RESET}Len({PURPLE}{Length}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
                print(f'   {BLUE}MAC DST:{CYAN} {mac_dst_str}')
                print(f'   {BLUE}MAC SRC:{CYAN} {mac_src_str}')
                print(f'   {BLUE}LENGHT:{CYAN} {hex(length)}{RESET}')

            dot3 = Dot3Layer(
                dst=mac_dst_str,
                src=mac_src_str,
                length=length,
            )

            if len(payload) > 0:
                if is_llc(payload):
                    from .LLC import LLCParser
                    prelayer = LLCParser.load_as_llc_layer(payload,Alr=1,verbose=verbose)
                else:
                    from .Detect_layer import DetectLayer
                    d = DetectLayer()
                    prelayer = d.start(packet=payload, previous_layer="Dot3",verbose=verbose)

                return dot3 / prelayer
            return dot3

