# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import random
from LightPacket.ipv4 import IPv4
from LightPacket.ipv6 import IPv6
from LightPacket.helper.ipv6.IPv6ExtHeader import IPv6ExtHeader
from LightPacket.Raw import Fragment
from LightPacket.Logger.LightLogger import Logger, ErrorCode
import struct

# ---------------------------------------------------------------- IPv4

def fragment4(pkt, mtu=1480, ident=None):
    """
    Split an IPv4 packet so every fragment is <= mtu bytes on the wire.

    pkt   : a fully-built packet whose outer layer is IPv4 (may have payload).
    mtu   : link MTU in bytes (including the IP header).
    ident : optional 16-bit identification; auto-generated when omitted.

    Returns a list of IPv4/Raw fragments, or [pkt] unchanged if no split is
    required.  Raises FragmentError when DF is set or MTU is unusable.

    """
    ip = pkt[IPv4]              # adapt: your layer accessor
    if ip is None:
        Logger().error(message="No IPv4 Layer was found in this packet.",error_code=ErrorCode.NOT_FOUND)

    # DF bit is the 0x2 bit in the flags nibble
    if getattr(ip, "flags", 0) & 0x2:
        Logger().error(message="DF bit is set",error_code=ErrorCode.FRAGMENT_ERROR)

    wire = pkt.build()
    ihl_bytes = (getattr(ip, "ihl", 5) or 5) * 4
    if len(wire) <= mtu:
        return [pkt]

    payload = wire[ihl_bytes:]

    max_data = (mtu - ihl_bytes) & ~7
    if max_data <= 0:
        Logger().error(message=f"MTU {mtu} too small for {ihl_bytes}-byte IP header",error_code=ErrorCode.FRAGMENT_ERROR)

    if ident is None:
        ident = getattr(ip, "id", 0) or random.randint(1, 0xFFFF)

    fragments, offset = [], 0
    while offset < len(payload):
        chunk = payload[offset:offset + max_data]
        more  = offset + len(chunk) < len(payload)

        frag = IPv4(
            version=4,
            ihl=ihl_bytes // 4,
            tos=getattr(ip, "tos", 0),
            total_len=ihl_bytes + len(chunk),
            id=ident,
            flags=0x1 if more else 0x0,
            frag_offset=offset // 8,                  # 13-bit field, 8-byte units
            ttl=getattr(ip, "ttl", 64),
            proto=getattr(ip, "proto", 0),
            src=ip.src,
            dst=ip.dst,
            options=getattr(ip, "options", None),
        ) / Fragment(payload=chunk)
        fragments.append(frag)
        offset += len(chunk)

    return fragments

# ---------------------------------------------------------------- IPv6

def fragment6(pkt, mtu=1280, ident=None):
    ip6 = pkt[IPv6]
    if ip6 is None:
        Logger().error(message="No IPv6 Layer was found in this packet.",error_code=ErrorCode.NOT_FOUND)
    if mtu < 1280:
        Logger().error(message=f"MTU {mtu} smaller then 1280 min",error_code=ErrorCode.FRAGMENT_ERROR)

    wire = pkt.build()
    if len(wire) <= mtu:
        return [pkt]

    BASE_HDR = 40
    FRAG_HDR = 8
    payload = wire[BASE_HDR:]

    max_data = (mtu - BASE_HDR - FRAG_HDR) & ~0x07
    if max_data <= 0:
        Logger().error(message=f"MTU to small for IPv6 base",error_code=ErrorCode.FRAGMENT_ERROR)

    if ident is None:
        ident = random.randint(0, 0xFFFFFFFF)

    # next_header on the fragment header = the original upper-layer protocol
    original_nh = getattr(ip6, "next_header", None) or 59

    fragments, offset = [], 0
    while offset < len(payload):
        chunk = payload[offset:offset + max_data]
        more  = 1 if offset + len(chunk) < len(payload) else 0

        # 7-byte Fragment Header body: Reserved | Offset|Res|M | Identification
        frag_body = struct.pack(
            '>BHI',
            0,                                          # Reserved
            ((offset // 8) << 3) | (more & 0x1),        # Offset(13)|Res(2)|M(1)
            ident & 0xFFFFFFFF,                         # Identification
        )

        frag = IPv6(
            version=6,
            traffic_class=getattr(ip6, "traffic_class", 0),
            flow_label=getattr(ip6, "flow_label", 0),
            payload_len=FRAG_HDR + len(chunk),
            next_header=44,                             # Fragment Header
            hop_limit=getattr(ip6, "hop_limit", 64),
            src=ip6.src,
            dst=ip6.dst,
        ) / IPv6ExtHeader(
            type=44,                                    # <-- `type=`, not ext_type=
            next_header=original_nh,
            data=frag_body,                             # <-- 7 raw bytes
        ) / Fragment(chunk)

        fragments.append(frag)
        offset += len(chunk)

    return fragments