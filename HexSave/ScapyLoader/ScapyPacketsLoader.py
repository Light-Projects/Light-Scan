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

from scapy.all import IP, Ether, IPv6, ARP

def LoadFromLightHexToScapyPackets(raw_packets):
    scapy_packets = []
    for raw_packet in raw_packets:
        if len(raw_packet) > 0:
            first_byte = raw_packet[0]
            if first_byte in [0x45, 0x46]:
                try:
                    from scapy.layers.inet import IP as IPLayer
                    packet = IPLayer(raw_packet)
                except:
                    packet = Ether(raw_packet)
            elif first_byte == 0x60:
                try:
                    from scapy.layers.inet6 import IPv6 as IPv6Layer
                    packet = IPv6Layer(raw_packet)
                except:
                    packet = Ether(raw_packet)
            else:
                try:
                    packet = Ether(raw_packet)
                    if packet.haslayer(IP) and packet.haslayer(IPv6):
                        try:
                            from scapy.layers.inet import IP as IPLayer
                            packet = IPLayer(raw_packet)
                        except:
                            packet = Ether(raw_packet)
                    elif packet.haslayer(ARP):
                        packet = Ether(raw_packet)
                except:
                    packet = Ether(raw_packet)
        else:
            packet = Ether(raw_packet)

        scapy_packets.append(packet)
    return scapy_packets

def LoadFromLightBinToScapyPackets(raw_packet):
    if len(raw_packet) > 0:
        first_byte = raw_packet[0]
        if first_byte in [0x45, 0x46]:
            try:
                from scapy.layers.inet import IP as IPLayer
                packet = IPLayer(raw_packet)
            except:
                packet = Ether(raw_packet)
        elif first_byte == 0x60:
            try:
                from scapy.layers.inet6 import IPv6 as IPv6Layer
                packet = IPv6Layer(raw_packet)
            except:
                packet = Ether(raw_packet)
        else:
            try:
                packet = Ether(raw_packet)
                if packet.haslayer(IP) and packet.haslayer(IPv6):
                    try:
                        from scapy.layers.inet import IP as IPLayer
                        packet = IPLayer(raw_packet)
                    except:
                        packet = Ether(raw_packet)
                elif packet.haslayer(ARP):
                    packet = Ether(raw_packet)
            except:
                packet = Ether(raw_packet)
    else:
        packet = Ether(raw_packet)

    return packet

def DetectScapyLayer(pkt):
    if pkt.haslayer(Ether):
        if pkt[Ether].type == 0x8100:
            return 'ether-vlan'
        return 'ether'
    elif pkt.haslayer(IP):
        return 'ip'
    elif pkt.haslayer(IPv6):
        return 'ipv6'
    else:
        return 'raw'