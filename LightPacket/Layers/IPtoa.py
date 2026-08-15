# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from ..Logger.LightLogger import *

LLogger = Logger()


def inet_aton(ip_string: str) -> bytes:
    parts = ip_string.split('.')

    if len(parts) != 4:
        LLogger.error(error_code=ErrorCode.INVALID_IP,message="Invalid IP address format")

    ints = [int(p) for p in parts]
    if any(i < 0 or i > 255 for i in ints):
        LLogger.error(error_code=ErrorCode.INVALID_IP,message="IP octets must be between 0 and 255")

    packed = (ints[0] << 24) | (ints[1] << 16) | (ints[2] << 8) | ints[3]

    return packed.to_bytes(4,byteorder='big')


def inet_ntoa(ip_bytes: bytes) -> str:
    if len(ip_bytes) != 4:
        LLogger.error(error_code=ErrorCode.INVALID_IP,message="Packed IP must be exactly 4 bytes long")

    return ".".join(str(b) for b in ip_bytes)

def ipv6_bytes_to_str(addr_bytes):

    if len(addr_bytes) != 16:
        return ""

    chunks = []
    for i in range(0, 16, 2):
        chunk = (addr_bytes[i] << 8) | addr_bytes[i + 1]
        chunks.append(f'{chunk:04x}')

    return ':'.join(chunks)


def ipv6_str_to_bytes(ipv6_str: str) -> bytes:
    parts = ipv6_str.split(':')

    if '' in parts:
        non_empty = [p for p in parts if p != '']
        zeros_needed = 8 - len(non_empty)
        empty_index = parts.index('')
        result_parts = non_empty[:empty_index] + ['0'] * zeros_needed + non_empty[empty_index:]
    else:
        result_parts = parts

    if len(result_parts) != 8:
        LLogger.error(error_code=ErrorCode.INVALID_IP,message="Invalid IPv6 address format")

    result = bytearray()
    for part in result_parts:
        if part == '':
            part = '0'
        val = int(part, 16)
        if not (0 <= val <= 0xFFFF):
            LLogger.error(error_code=ErrorCode.INVALID_IP,message="IPv6 part must be between 0 and 0xFFFF")
        result.append((val >> 8) & 0xFF)
        result.append(val & 0xFF)

    return bytes(result)