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

import scapy.all as scapy
import random
from scapy.layers.inet6 import IPv6

def dns_payload_udp(target, version):
    query_type = "A"
    domain = random.choice([
        "google.com", "youtube.com", "github.com",
        "microsoft.com", "amazon.com"
    ])
    qtype_map = {
        "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12,
        "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255
    }
    qtype = qtype_map.get(query_type.upper(), 1)

    if version == 4:
        dns_query = (
                     scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32, 255), flags="DF") /
                     scapy.UDP(dport=53, sport=random.randint(60000, 65535)) /
                     scapy.DNS(id=random.randint(1, 65535), rd=1, qd=scapy.DNSQR(qname=domain, qtype=qtype)))
    else:
        dns_query = (
                     IPv6(dst=target, nh=17, hlim=random.randint(32, 255)) /
                     scapy.UDP(dport=53, sport=random.randint(60000, 65535)) /
                     scapy.DNS(id=random.randint(1, 65535), rd=1, qd=scapy.DNSQR(qname=domain, qtype=qtype)))

    return dns_query