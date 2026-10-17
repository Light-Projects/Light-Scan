# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Shared checksum utilities (RFC 1071).

Used by IPv4 header, UDP, and TCP. One implementation, three callers.
"""


def ones_complement(data: bytes) -> int:

    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_header_checksum(header_with_zero_csum: bytes) -> int:
    return ones_complement(header_with_zero_csum)


def verify_ipv4_header(header_with_csum: bytes) -> bool:
    return ones_complement(header_with_csum) == 0


def _build_pseudo_header(src_bytes: bytes, dst_bytes: bytes,
                         protocol: int, length: int) -> bytes:

    if len(src_bytes) == 4 and len(dst_bytes) == 4:
        return src_bytes + dst_bytes + b'\x00' + bytes([protocol]) + length.to_bytes(2, 'big')

    if len(src_bytes) == 16 and len(dst_bytes) == 16:
        return (src_bytes + dst_bytes + length.to_bytes(4, 'big')
                + b'\x00\x00\x00' + bytes([protocol]))

    raise ValueError(
        f"Pseudo-header requires 4-byte or 16-byte addresses, "
        f"got src={len(src_bytes)}, dst={len(dst_bytes)}"
    )


def transport_checksum(src_bytes: bytes, dst_bytes: bytes,
                       protocol: int, transport_bytes: bytes) -> int:
    pseudo = _build_pseudo_header(src_bytes, dst_bytes, protocol, len(transport_bytes))
    csum = ones_complement(pseudo + transport_bytes)
    return 0xFFFF if csum == 0 else csum


def verify_transport_checksum(src_bytes: bytes, dst_bytes: bytes,
                              protocol: int, transport_bytes: bytes) -> bool:

    pseudo = _build_pseudo_header(src_bytes, dst_bytes, protocol, len(transport_bytes))
    return ones_complement(pseudo + transport_bytes) == 0