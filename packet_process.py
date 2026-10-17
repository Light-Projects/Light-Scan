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

from Decoration.Colors import RESET, GREEN, RED
from LightPacket.l3 import TCP, UDP
from LightPacket.l2 import ARP
import time

def apply_filter(packets, filt):

    def matches(packet):
        f = filt.lower()
        if 'arp' in f and ARP in packet:
            return True
        if 'tcp' in f and TCP in packet:
            return True
        if 'udp' in f and UDP in packet:
            return True
        if 'port 80' in f and TCP in packet and 80 in (packet[TCP].sport, packet[TCP].dport):
            return True
        if 'port 443' in f and TCP in packet and 443 in (packet[TCP].sport, packet[TCP].dport):
            return True
        if 'port 53' in f:
            if TCP in packet and 53 in (packet[TCP].sport, packet[TCP].dport):
                return True
            if UDP in packet and 53 in (packet[UDP].sport, packet[UDP].dport):
                return True
        return False

    filtered = [p for p in packets if matches(p)]
    print(f"{GREEN}[+] Filtered to {len(filtered)} packets with filter: {filt}{RESET}")
    return filtered


def export_stats_to_file(stats, filename):
    if not stats:
        return

    try:
        with open(filename, 'w') as f:
            f.write("LightSniff Statistics\n")
            f.write("=" * 50 + "\n")

            elapsed = time.time() - stats.stats['start_time']
            pps = stats.stats['total_packets'] / elapsed if elapsed > 0 else 0

            f.write(f"Total Packets: {stats.stats['total_packets']}\n")
            f.write(f"Total Bytes: {stats.stats['total_bytes'] / 1024:.1f} KB\n")
            f.write(f"Duration: {elapsed:.1f}s\n")
            f.write(f"PPS: {pps:.1f}\n")
            if stats.stats['total_packets'] > 0:
                f.write(f"Avg Packet Size: {stats.stats['total_bytes'] / stats.stats['total_packets']:.0f} bytes\n")

            f.write("\nProtocol Distribution:\n")
            for proto, count in sorted(stats.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                percentage = count / stats.stats['total_packets'] * 100 if stats.stats['total_packets'] > 0 else 0
                f.write(f"  {proto}: {count} ({percentage:.1f}%)\n")

            f.write("\nTop Source Addresses:\n")
            for src, count in sorted(stats.stats['top_src'].items(), key=lambda x: x[1], reverse=True)[:5]:
                f.write(f"  {src}: {count}\n")

            f.write("\nTop Destination Addresses:\n")
            for dst, count in sorted(stats.stats['top_dst'].items(), key=lambda x: x[1], reverse=True)[:5]:
                f.write(f"  {dst}: {count}\n")

            f.write("\nTop Flows:\n")
            for flow, count in sorted(stats.stats['flows'].items(), key=lambda x: x[1], reverse=True)[:5]:
                f.write(f"  {flow}: {count}\n")

        print(f"{GREEN}[+] Statistics exported to {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error exporting stats: {e}{RESET}")