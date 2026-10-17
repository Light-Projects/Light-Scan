# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Adam Boulaaz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""
UDP closed-port probe (nmap calls this the "U1" test): send a UDP packet
to a port that's almost certainly closed and inspect the resulting ICMP
"port unreachable" message. Different stacks differ in the TTL used for
that ICMP reply, whether/how much of the original payload gets quoted
back, and the IP ID behaviour -- enough to tag a handful of coarse
"quirk" buckets that the OS signatures can match against.
"""

try:
    from LightPacket import L2Socket, DetectLayer, GetMac, is_in_same_network
    from LightPacket.l2 import Ethernet, Raw
    from LightPacket.l3 import IPv4, UDP, ICMP
    LIGHTPACKET_AVAILABLE = True
except ImportError:
    LIGHTPACKET_AVAILABLE = False

# A high, unlikely-to-be-listening UDP port.
DEFAULT_CLOSED_PORT = 40125


def probe_udp(target, port=DEFAULT_CLOSED_PORT, timeout=2):
    """
    Returns {"quirk": str|None, "reply_ttl": int|None} or None if there
    was no ICMP unreachable reply at all (common when a firewall silently
    drops it -- that absence is itself sometimes informative, but we
    leave that call to the engine rather than guessing here).
    """
    if not LIGHTPACKET_AVAILABLE:
        return None

    dstmac = GetMac.GetMacByIP(target) if is_in_same_network(target) else GetMac.GetMacGateway()
    pkt = Ethernet(dst=str(dstmac)) / IPv4(dst=target) / UDP(sport=53000, dport=port) / Raw(payload=b"lightscan-probe")

    resp = L2Socket().srp1(pkt, timeout=timeout, filter_str=f'src host {target} and icmp')
    resp = DetectLayer().start(resp)

    if resp is None:
        return None

    icmp_layer = resp[ICMP]
    ip_layer = resp[IPv4]

    if icmp_layer.type != 3 or icmp_layer.code != 3:
        return None

    reply_ttl = ip_layer.ttl if ip_layer else None
    quoted = bytes(icmp_layer.payload) if icmp_layer.payload else b""

    if reply_ttl is None:
        quirk = None
    elif reply_ttl >= 250:
        quirk = "icmp_ttl_255_sysv_style"
    elif reply_ttl >= 120:
        quirk = "icmp_ttl_128_no_extra_data"
    elif len(quoted) > 40:
        quirk = "icmp_ttl_64_bsd_style" if reply_ttl > 60 else "icmp_ttl_64_darwin_style"
    else:
        quirk = "icmp_ttl_64_quoted_payload"

    return {"quirk": quirk, "reply_ttl": reply_ttl}