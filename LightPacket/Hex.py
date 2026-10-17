# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

def hexdump(data: bytes, offset: int = 0) -> str:
    result = []
    length = len(data)
    for i in range(0, length, 16):
        chunk = data[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f"0x{i + offset:04x}: {hex_part}  {ascii_part}")
    return '\n'.join(result)