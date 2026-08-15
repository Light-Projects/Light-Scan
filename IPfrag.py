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
import time

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"
green = "\033[32m"
cyan = "\033[36m"

def fragementation(packet, Proto, scan_type, verbose, v6=False):
    if v6:
        from scapy.layers.inet6 import IPv6

        fragments = scapy.fragment6(packet, fragSize=1280)

        sent_count = 0
        for fragment in fragments:
            scapy.send(fragment, verbose=False)
            time.sleep(0.2)
            sent_count += 1

        time.sleep(0.5)

        if Proto == "udp":
            if IPv6 in packet:
                dst_ip = packet[IPv6].dst
            else:
                dst_ip = packet[scapy.IP].dst

            filter_str = f"icmp6 and ip6 dst {dst_ip}"
            response = scapy.sniff(filter=filter_str, timeout=3)
            if verbose:
                print(
                    f"\n[+] IPv6 Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")
            return response[0] if response else None

        elif Proto == "tcp":
            if IPv6 in packet:
                dst_ip = packet[IPv6].dst
            else:
                dst_ip = packet[scapy.IP].dst

            if scan_type == "syn":
                filter_str = f"tcp and ip6 src {dst_ip} and tcp dst port {packet[scapy.TCP].sport}"
                response = scapy.sniff(filter=filter_str, timeout=3)
                if verbose:
                    print(
                        f"[+] IPv6 Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")
                return response[0] if response else None
            else:
                filter_str = f"tcp and ip6 src {dst_ip} and tcp dst port {packet[scapy.TCP].sport}"
                response = scapy.sniff(filter=filter_str, timeout=3)
                if verbose:
                    print(
                        f"[+] IPv6 Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")
                return response[0] if response else None

        else:
            print(f"\n{red}[!] IPv6 Fragmentation Error: (Protocol is not valid){reset}\n")
            return None

    else:
        packet[scapy.IP].flags = "MF"

        fragments = scapy.fragment(packet, fragsize=16)
        sent_count = 0
        for fragment in fragments:
            scapy.send(fragment, verbose=False)
            time.sleep(0.2)
            sent_count += 1

        time.sleep(0.5)

        if Proto == "udp":
            filter_str = f"udp and src host {packet[scapy.IP].dst} and dst port {packet[scapy.UDP].sport}"
            response = scapy.sniff(filter=filter_str, timeout=3)
            if verbose:
                print(f"\n[+] Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")
            return response[0] if response else None

        elif Proto == "tcp":
            if scan_type == "tcp":
                if verbose:
                    print(
                        f"\n[+] Fragmentation: {len(fragments)} packets sent to {packet[scapy.IP].dst}, {sent_count} responses received\n")
                return sent_count
            elif scan_type == "syn":
                filter_str = f"tcp and src host {packet[scapy.IP].dst} and dst port {packet[scapy.TCP].sport} and (tcp[13] & 0x12 = 0x12 or tcp[13] & 0x04 = 0x04 or tcp[13] & 0x14 = 0x14)"
                response = scapy.sniff(filter=filter_str, timeout=3)
                if verbose:
                    print(f"[+] Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")
                return response[0] if response else None
            else:
                filter_str = f"tcp and src host {packet[scapy.IP].dst} and dst port {packet[scapy.TCP].sport}"
                response = scapy.sniff(filter=filter_str, timeout=3)
                if verbose:
                    print(f"[+] Fragmentation: {len(fragments)} packets sent, {len(response)} responses received\n")
                return response[0] if response else None
        else:
            print(f"\n{red}[!] Fragmentation Error: (Protocol is not valid){reset}\n")
            return None