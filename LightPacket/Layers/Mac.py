# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from typing import Union
from ..Logger.LightLogger import *


BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
NULL_MAC = '00:00:00:00:00:00'
BROADCAST_MAC_RAW = 'ffffffffffff'
NULL_MAC_RAW = '000000000000'

LLogger = Logger()

class MacAddress:

    def __init__(self, mac: Union[str, bytes], d_or_s: int = 0):
        if isinstance(mac, str):
            mac = mac.replace(':', '').replace('-', '').replace('.', '')
            if len(mac) != 12:
                LLogger.error(error_code=ErrorCode.INVALID_MAC,message=f"Invalid Mac Address : {':'.join(mac[i:i+2] for i in range(0, len(mac), 2))}")
            try:
                self.bytes = bytes.fromhex(mac)
            except ValueError:
                if d_or_s == 0:
                    self.bytes = bytes.fromhex(NULL_MAC_RAW)
                else:
                    self.bytes = bytes.fromhex(BROADCAST_MAC_RAW)
                LLogger.warning(warning_code=WarningCode.NONHEXVALUE,message=f'Non Hex-Decimal MAC Value : {':'.join(mac[i:i+2] for i in range(0, len(mac), 2))}')
        elif isinstance(mac, bytes):
            if len(mac) != 6:
                LLogger.error(error_code=ErrorCode.INVALID_MAC,message=f"MAC must be 6 bytes, got {len(mac)}")
            self.bytes = mac
        else:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_TYPE,message=f"MAC must be str or bytes, got {type(mac)}")

    def __str__(self):
        return ':'.join(f'{b:02x}' for b in self.bytes)

    def __bytes__(self):
        return self.bytes

def MacFromBytes(MacBytes):
    return MacBytes.hex(':')


