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
from banner_grabber.probes import get_probe
from ..Transport import Stealth_tcp_options

def ssh_payload_tcp(target, version):
    ssh_banner = get_probe(
        target=target,
        protocol="tcp",
        port=22
    )

    if version == 4:
        packet = (
                  scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32, 255), flags="DF") /
                  scapy.TCP(dport=22, sport=random.randint(60000, 65535),
                            seq=random.randint(1000000000, 4294967295),
                            window=random.choice([5840, 64240, 65535, 29200, 8760]),
                            options=Stealth_tcp_options(), flags="S") /
                  scapy.Raw(load=ssh_banner))
    else:
        packet = (
                  IPv6(dst=target, nh=6, hlim=random.randint(32, 255)) /
                  scapy.TCP(dport=22, sport=random.randint(60000, 65535),
                            seq=random.randint(1000000000, 4294967295),
                            window=random.choice([5840, 64240, 65535, 29200, 8760]),
                            options=Stealth_tcp_options(), flags="S") /
                  scapy.Raw(load=ssh_banner))

    return packet


def ssh_payload_udp(target, version):
    ssh_banner = get_probe(
        target=target,
        protocol="udp",
        port=22
    )

    if version == 4:
        packet = (
                  scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32, 255), flags="DF") /
                  scapy.UDP(dport=22, sport=random.randint(60000, 65535)) /
                  scapy.Raw(load=ssh_banner))
    else:
        packet = (
                  IPv6(dst=target, nh=17, hlim=random.randint(32, 255)) /
                  scapy.UDP(dport=22, sport=random.randint(60000, 65535)) /
                  scapy.Raw(load=ssh_banner))

    return packet