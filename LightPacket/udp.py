# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from LightPacket.utils.Checksum import transport_checksum
import socket

LLogger = Logger()

UDP_HEADER_LEN = 8

def _ones_complement_checksum(data: bytes) -> int:
    """16-bit one's complement checksum of a byte string."""
    if len(data) % 2:
        data += b'\x00'
    total = 0

    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class UDP(BaseLayer):

    def __init__(self, sport=10000, dport=53, length=None, checksum=None):
        super().__init__()
        self.sport = sport & 0xFFFF
        self.dport = dport & 0xFFFF
        self.length = length
        self.checksum = checksum

    def compute_checksum(self, src: str, dst: str, is_ipv6: bool = False) -> int:
        payload_bytes = self.get_payload_bytes()
        length = self.length if self.length is not None else UDP_HEADER_LEN + len(payload_bytes)

        af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        src_bytes = socket.inet_pton(af, src)
        dst_bytes = socket.inet_pton(af, dst)

        udp_header_zero_csum = struct.pack('>HHHH', self.sport, self.dport, length, 0)
        transport_bytes = udp_header_zero_csum + payload_bytes

        checksum = transport_checksum(src_bytes, dst_bytes, 17, transport_bytes)
        self.checksum = checksum
        return checksum

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        length = self.length
        if length is None:
            length = UDP_HEADER_LEN + len(payload_bytes)

        checksum = self.checksum
        if checksum is None:
            checksum = 0

        self.length = length
        self.checksum = checksum

        header = struct.pack('>HHHH', self.sport, self.dport, length, checksum)
        return header + payload_bytes

    def __len__(self):
        return UDP_HEADER_LEN

    def __repr__(self):
        return (f"<UDP sport={self.sport} dport={self.dport} "
                f"length={self.length} checksum=0x{self.checksum:04x} >"
                if self.checksum is not None else
                f"<UDP sport={self.sport} dport={self.dport} "
                f"length={self.length} checksum=None >")

    def copy(self) -> 'UDP':
        new_layer = UDP(
            sport=self.sport,
            dport=self.dport,
            length=self.length,
            checksum=self.checksum,
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"sport={self.sport}",
            f"dport={self.dport}",
            f"length={self.length}",
            f"checksum=0x{self.checksum:04x}" if self.checksum else "checksum=None",
        ]


class UDPParser:

    @staticmethod
    def load_as_udp_layer(raw_packet, Alr=0, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        raw = raw_packet[0]

        if len(raw) < UDP_HEADER_LEN:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="UDP required header is 8 bytes")
            return None

        sport, dport, length, checksum = struct.unpack('>HHHH', raw[:UDP_HEADER_LEN])

        payload = raw[UDP_HEADER_LEN:length] if length >= UDP_HEADER_LEN else raw[UDP_HEADER_LEN:]

        udp = UDP(
            sport=sport,
            dport=dport,
            length=length,
            checksum=checksum,
        )

        if verbose:
            print(f"\n{BOLD}UDP LAYER : {RESET}Len({PURPLE}{length}{RESET}) Total Len({PURPLE}{len(raw)}{RESET}) >")
            print(f'   {BLUE}SPORT:{CYAN} {sport}')
            print(f'   {BLUE}DPORT:{CYAN} {dport}')
            print(f'   {BLUE}LENGTH:{CYAN} {length}')
            print(f'   {BLUE}CHECKSUM:{CYAN} 0x{checksum:04x} {RESET}')

        if len(payload) > 0 and Alr != 1 and payload != b'':
            from LightPacket.Raw import RawParser
            return udp / RawParser.load_as_Raw_layer(payload, verbose=verbose)

        return udp