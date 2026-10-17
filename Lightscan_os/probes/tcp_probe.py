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
TCP SYN probe: sends a SYN with a fixed, recognizable option set to an open
port and inspects the SYN/ACK reply for TCP option order, window size and
TTL/hop-limit -- the same core idea nmap's TCP-based OS tests use.
"""

import random

try:
    from LightPacket.helper.tcp.TCPOptions import TCPOptions
    from LightPacket.l3 import TCP,IPv4,IPv6
    from LightPacket.l2 import Ethernet
    from LightPacket import L2Socket, DetectLayer, GetMac, is_in_same_network
    LIGHTPACKET_AVAILABLE = True
except ImportError:
    LIGHTPACKET_AVAILABLE = False


def craft_tcp_syn(target, port, version=4):
    if not LIGHTPACKET_AVAILABLE:
        raise RuntimeError("scapy is required for TCP probing (pip install scapy)")

    options = [
        TCPOptions.mss(1460),
        TCPOptions.sack_permitted(),
        TCPOptions.timestamps(random.randint(1, 1_000_000_000), 0),
        TCPOptions.window_scale(8)
    ]

    dstmac = GetMac.GetMacByIP(target) if is_in_same_network(target) else GetMac.GetMacGateway()
    sport = random.randint(60000, 65535)

    if version == 6:
        return Ethernet(
            dst=str(dstmac)) / IPv6(
            dst=target,
            hop_limit=128,
            next_header=6) / TCP(
            dport=port,
            sport=sport,
            seq=random.randint(0, 0xFFFFFFFF),
            window=65535,
            options=options,
            flags=0x02,
        ), sport

    return Ethernet(
        dst=str(dstmac)) / IPv4(dst=target, id=random.randint(1, 65535), ttl=128) / TCP(
        dport=port,
        sport=sport,
        seq=random.randint(0, 0xFFFFFFFF),
        window=65535,
        flags=0x02,
        options=options,
    ) , sport


def probe_tcp(target, port, version=4, timeout=2):
    """
    Returns a dict with the fields the analyzer/scorer need, or None if
    there was no usable reply.
    """

    probe,sport = craft_tcp_syn(target, port, version)
    resp = L2Socket().srp1(probe, timeout=timeout, filter_str=f'tcp and src host {target} and src port {port} and dst port {sport}')
    resp = DetectLayer().start(resp)

    ip_layer_cls = IPv6 if version == 6 else IPv4
    if resp is None:
        return None

    tcp_layer = resp[TCP]
    ip_layer = resp[ip_layer_cls]

    if not (tcp_layer.flags & 0x12):
        return None

    ttl_or_hlim = ip_layer.hlim if version == 6 else ip_layer.ttl

    return {
        "raw_response": resp,
        "window": tcp_layer.window,
        "options": tcp_layer.options,
        "ttl_or_hlim": ttl_or_hlim,
        "ip_id": getattr(ip_layer, 'id', 0),
        "seq": tcp_layer.seq,
        "port": port,
    }