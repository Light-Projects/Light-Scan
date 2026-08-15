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
ICMP echo probe: a plain ping. On its own this is a weak signal (default
TTLs cluster around 64 / 128 / 255 and get decremented per hop, so it's
easy to be off by a few), but combined with TCP/banner evidence it helps
confirm or downgrade a candidate -- e.g. a TTL that decrements to ~255
strongly rules out Windows/Linux/BSD/macOS/Android and points at a
network device or a Unix/Solaris-class host.
"""

try:
    from scapy.layers.inet import IP, ICMP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def probe_icmp(target, timeout=2):
    """
    Returns {"ttl": int, "code_quirk": str|None} or None if no reply.
    """
    if not SCAPY_AVAILABLE:
        return None

    pkt = IP(dst=target) / ICMP(type=8, code=0)
    resp = sr1(pkt, timeout=timeout, verbose=False)

    if resp is None or not resp.haslayer(ICMP):
        return None

    icmp_layer = resp.getlayer(ICMP)
    ip_layer = resp.getlayer(IP)
    ttl = ip_layer.ttl if ip_layer else None

    code_quirk = None

    if icmp_layer.code != 0:
        code_quirk = f"nonzero_code_{icmp_layer.code}"

    return {"ttl": ttl, "code_quirk": code_quirk}