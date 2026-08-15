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
Light-Scan Scripting Engine (LSSE)
Script Name : dns-lookup
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --domain
--> Optional Arguments
----> --dns-server
Categorie : safe/discovery/dns
"""

from scapy.all import IP, UDP, DNS, DNSQR, sr1, conf

def dns_lookup(domain, dns_server=None):
    if dns_server is None:
        dns_server = conf.route.route("0.0.0.0")[2]

    print(f"\n[*] Looking up {domain} using {dns_server}")

    for qtype, qname in [("A", "IPv4"), ("AAAA", "IPv6")]:
        packet = IP(dst=dns_server) / UDP(dport=53) / DNS(
            rd=1, qd=DNSQR(qname=domain, qtype=qtype)
        )

        resp = sr1(packet, timeout=3, verbose=False)

        if resp and resp.haslayer(DNS):
            for i in range(resp[DNS].ancount):
                rr = resp[DNS].an[i]
                if rr.type == (1 if qtype == "A" else 28):
                    print(f"  {qname:4} → {rr.rdata}")
