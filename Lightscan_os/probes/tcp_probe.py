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
    from scapy.layers.inet import IP, TCP, sr1
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def craft_tcp_syn(target, port, version=4):
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for TCP probing (pip install scapy)")

    common_opts = [
        ('MSS', 1460),
        ('SAckOK', b''),
        ('Timestamp', (random.randint(1, 1_000_000_000), 0)),
        ('NOP', None),
        ('WScale', 8),
    ]

    if version == 6:
        return IPv6(dst=target, hlim=128, nh=6) / TCP(
            dport=port,
            sport=random.randint(60000, 65535),
            seq=random.randint(1_000_000_000, 4_294_967_295),
            window=65535,
            options=common_opts,
            flags="S",
        )

    return IP(dst=target, id=random.randint(1, 65535), ttl=128) / TCP(
        dport=port,
        sport=random.randint(60000, 65535),
        seq=random.randint(1_000_000_000, 4_294_967_295),
        window=65535,
        options=common_opts,
        flags="S",
    )


def send_tcp_syn(probe, timeout=2):
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for TCP probing (pip install scapy)")
    return sr1(probe, timeout=timeout, verbose=False)


def probe_tcp(target, port, version=4, timeout=2):
    """
    Returns a dict with the fields the analyzer/scorer need, or None if
    there was no usable reply.
    """
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6

    probe = craft_tcp_syn(target, port, version)
    resp = send_tcp_syn(probe, timeout=timeout)

    ip_layer_cls = IPv6 if version == 6 else IP
    if not resp or not resp.haslayer(TCP) or not resp.haslayer(ip_layer_cls):
        return None

    tcp_layer = resp.getlayer(TCP)
    ip_layer = resp.getlayer(ip_layer_cls)

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