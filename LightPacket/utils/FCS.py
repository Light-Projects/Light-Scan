# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from typing import Union

class FCS:

    @staticmethod
    def crc32_ethernet(data: bytes) -> bytes:
        crc = 0xFFFFFFFF
        poly = 0x04C11DB7

        for byte in data:
            crc ^= byte << 24
            for _ in range(8):
                if crc & 0x80000000:
                    crc = (crc << 1) ^ poly
                else:
                    crc <<= 1
                crc &= 0xFFFFFFFF

        crc ^= 0xFFFFFFFF
        return crc.to_bytes(4, 'big')

    @staticmethod
    def crc32_ieee(data: bytes) -> bytes:
        import binascii
        crc = binascii.crc32(data) & 0xFFFFFFFF
        return crc.to_bytes(4, 'big')

    @staticmethod
    def crc16_ccitt(data: bytes) -> bytes:
        crc = 0xFFFF
        poly = 0x1021

        for byte in data:
            crc ^= byte << 8
            for _ in range(8):
                if crc & 0x8000:
                    crc = (crc << 1) ^ poly
                else:
                    crc <<= 1
                crc &= 0xFFFF

        crc ^= 0xFFFF
        return crc.to_bytes(2, 'big')

    @staticmethod
    def verify(packet: bytes, fcs_type: str = 'ethernet') -> bool:
        if len(packet) < 4:
            return False

        data = packet[:-4]
        received_fcs = packet[-4:]

        if fcs_type == 'ethernet':
            calculated_fcs = FCS.crc32_ethernet(data)
        elif fcs_type == 'ieee':
            calculated_fcs = FCS.crc32_ieee(data)
        elif fcs_type == 'frame_relay':
            calculated_fcs = FCS.crc16_ccitt(data)
            received_fcs = packet[-2:]
        else:
            return False

        return received_fcs == calculated_fcs