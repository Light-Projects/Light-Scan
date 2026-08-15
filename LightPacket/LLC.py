# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from .BaseLayer import BaseLayer
from .Consts import SAP_VALUES, SAP_LLC_SNAP
from .Logger.LightLogger import Logger, ErrorCode
from .Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE

LLogger = Logger()

"""
LLC Layer Creation (class LLCLayer)
"""

class LLCLayer(BaseLayer):

    def __init__(self, dsap=None, ssap=None, control=0x03):
        super().__init__()
        self.dsap = dsap
        self.ssap = ssap
        self.control = control

    def build(self) -> bytes:
        layer = self.payload.__class__.__name__
        if self.dsap is None and self.ssap is None:
            if layer == 'SNAPLayer':
                self.dsap = 0xAA
                self.ssap = 0xAA
            elif layer == 'STPLayer':
                self.ssap = 0x42
                self.dsap = 0x42
            else:
                self.dsap = 0xAA
                self.ssap = 0xAA
        else:
            if self.dsap is None and self.ssap is not None:
                self.dsap = 0xAA
            elif self.ssap is None and self.dsap is not None:
                self.ssap = 0xAA
            else:
                pass

        result = struct.pack('!BBB', self.dsap, self.ssap, self.control)

        if self.payload:
            return result + self.payload.build()
        return result

    def __len__(self):
        return 3 + (len(self.payload) if self.payload else 0)


    def __repr__(self):
        return (
            f"<LLC dsap={hex(self.dsap)}, ssap={hex(self.ssap)}, control={hex(self.control)}>")

    def copy(self) -> 'LLCLayer':
        new_layer = LLCLayer(
            dsap=self.dsap,
            ssap=self.ssap,
            control=self.control
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"dsap={self.dsap}",
            f"ssap={self.ssap}",
            f"control={self.control}"
        ]


"""
LLC Parser (separate from the builder)
"""

class LLCParser:

    @staticmethod
    def load_as_llc_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 3:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="LLC required header is 3 bytes")


        LLCHeader = raw_packet[0][:3]

        dsap, ssap, control = struct.unpack('!BBB', LLCHeader)

        payload = raw_packet[0][3:]
        Lenght = len(LLCHeader)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}LLC LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}DSAP:{CYAN} {hex(dsap)} {SAP_VALUES.get(dsap,'Unknown')}')
            print(f'   {BLUE}SSAP:{CYAN} {hex(ssap)} {SAP_VALUES.get(ssap,'Unknown')}')
            print(f'   {BLUE}CONTROL:{CYAN} {hex(control)}{RESET}')

        llc = LLCLayer(
            dsap=dsap,
            ssap=ssap,
            control=control
        )

        if len(payload) > 0:
            if ssap == SAP_LLC_SNAP and dsap == SAP_LLC_SNAP:
                from .Snap import SNAPParser
                prelayer = SNAPParser.load_as_snap_layer(payload,Alr=1,verbose=verbose)
            elif ssap == 0x42 and dsap == 0x42:
                from .Stp import STPParser
                prelayer = STPParser.load_as_stp_layer(payload,Alr=1,verbose=verbose)
            else:
                from .Detect_layer import DetectLayer
                d = DetectLayer()
                prelayer = d.start(payload, previous_layer="LLC",verbose=verbose)


            return llc / prelayer
        return llc
