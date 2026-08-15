# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from .BaseLayer import BaseLayer
from .Logger.LightLogger import Logger, ErrorCode
from .Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE

LLogger = Logger()

"""
PPP Layer Creation (class PPPLayer)
"""

class PPPLayer(BaseLayer):

    def __init__(self, address=0xFF, control=0x03, proto=0x0021):
        super().__init__()
        self.address = address
        self.control = control
        self.proto = proto

    def build(self) -> bytes:
        result = struct.pack('!BBH', self.address, self.control, self.proto)

        if self.payload:
            return result + self.payload.build()
        return result

    def __len__(self):
        return 4 + (len(self.payload) if self.payload else 0)


    def __repr__(self):
        return (
            f"<PPP address={hex(self.address)}, control={hex(self.control)}, proto={hex(self.proto)}>")

    def copy(self) -> 'PPPLayer':
        new_layer = PPPLayer(
            address=self.address,
            control=self.control,
            proto=self.proto
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"address={self.address}",
            f"control={self.control}",
            f"proto={self.proto}"
        ]


"""
PPP Parser (separate from the builder)
"""

class PPPParser:

    @staticmethod
    def load_as_ppp_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 4:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="PPP required header is 4 bytes")


        PPPH = raw_packet[0][:4]

        address, control, proto = struct.unpack('!BBH', PPPH)

        payload = raw_packet[0][4:]
        Lenght = len(PPPH)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}PPP LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}ADDR:{CYAN} {hex(address)}')
            print(f'   {BLUE}CONTROL:{CYAN} {hex(control)}')
            print(f'   {BLUE}PROTO:{CYAN} {hex(proto)}{RESET}')

        llc = PPPLayer(
            address=address,
            control=control,
            proto=proto
        )

        if len(payload) > 0:
            from .Detect_layer import DetectLayer
            d = DetectLayer()
            prelayer = d.start(payload, previous_layer="PPP",verbose=verbose)

            return llc / prelayer

        return llc

"""
PPP2b Layer Creation (class PPP2bLayer)
"""

class PPP2bLayer(BaseLayer):
    def __init__(self,proto=0x0021):
        super().__init__()
        self.proto = proto

    def build(self) -> bytes:
        result = struct.pack('!H', self.proto)

        if self.payload:
            return result + self.payload.build()
        return result

    def __len__(self):
        return 2 + (len(self.payload) if self.payload else 0)


    def __repr__(self):
        return (
            f"<PPP2b proto={hex(self.proto)}>")

    def copy(self) -> 'PPP2bLayer':
        new_layer = PPP2bLayer(
            proto=self.proto
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"proto={self.proto}"
        ]

"""
PPP2b Parser (separate from the builder)
"""

class PPP2bParser:

    @staticmethod
    def load_as_ppp2b_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 2:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="PPP2b required header is 2 bytes")


        PPPH = raw_packet[0][:2]

        proto = struct.unpack('!H', PPPH)

        payload = raw_packet[0][2:]
        Lenght = len(PPPH)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}PPP2b LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}PROTO:{CYAN} {hex(proto[0])}{RESET}')

        llc = PPP2bLayer(
            proto=proto[0],
        )

        if len(payload) > 0:
            from .Detect_layer import DetectLayer
            d = DetectLayer()
            prelayer = d.start(payload, previous_layer="PPP",verbose=verbose)

            return llc / prelayer

        return llc

"""
PPPoE Layer Creation (class PPPoELayer)
"""

class PPPoELayer(BaseLayer):

    def __init__(self, version=0x1, type=0x1, code=0x00,ssid=0x0000,lenght=0):
        super().__init__()
        self.version = version
        self.type = type
        self.code = code
        self.ssid = ssid
        self.lenght = lenght

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        if self.lenght == 0:
            self.lenght = len(payload_bytes)

        vt = (self.version << 4) | self.type

        result = struct.pack('!BBHH', vt, self.code,self.ssid,self.lenght)

        if self.payload:
            return result + self.payload.build()
        return result

    def __len__(self):
        return 6 + (len(self.payload) if self.payload else 0)


    def __repr__(self):
        return (
            f"<PPPoE version={hex(self.version)}, type={hex(self.type)}, code={hex(self.code)}, ssid={hex(self.ssid)}, lenght={hex(self.lenght)} >")

    def copy(self) -> 'PPPoELayer':
        new_layer = PPPoELayer(
            version=self.version,
            type=self.type,
            code=self.code,
            ssid=self.ssid,
            lenght=self.lenght
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"version={self.version}",
            f"type={self.type}",
            f"code={self.code}",
            f"ssid={self.ssid}",
            f"lenght={self.lenght}"
        ]


"""
PPPoE Parser (separate from the builder)
"""

class PPPoEParser:

    @staticmethod
    def load_as_pppoe_layer(raw_packet,Alr=0,verbose=False):
        from builtins import type
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="PPPoE required header is 6 bytes")


        PPPH = raw_packet[0][:6]

        vt, code, ssid, lenght = struct.unpack('!BBHH', PPPH)
        version = (vt >> 4) & 0x0F
        type = vt & 0x0F

        payload = raw_packet[0][6:]
        Lenght = len(PPPH)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}PPPoE LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}VERSION:{CYAN} {hex(version)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(type)}')
            print(f'   {BLUE}CODE:{CYAN} {hex(code)}')
            print(f'   {BLUE}SSID:{CYAN} {hex(ssid)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(lenght)}{RESET}')

        llc = PPPoELayer(
            version=version,
            type=type,
            code=code,
            ssid=ssid,
            lenght=lenght
        )

        if len(payload) > 0:
            if code == 0 and ssid != 0:
                prelayer = PPP2bParser.load_as_ppp2b_layer(payload, verbose=verbose)
            else:
                from .Detect_layer import DetectLayer
                d = DetectLayer()
                prelayer = d.start(payload, previous_layer="PPP",verbose=verbose)

            return llc / prelayer

        return llc

def is_ppp_frame(packet) -> bool:
    if packet[0] == 0xFF and packet[1] == 0x03:
        return True
    return False
