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
LightSniff Quick Help Module
Cross-platform, modular, and descriptive help system for LightSniff
"""

from Gui2.Help import QuickHelp


class SniffHelpContent:
    BASIC = {
        "title": "Basic Options",
        "icon": "🧩",
        "content": """
Interface (-i)
  The network interface to capture packets on.

  Examples:
    -i eth0        (Linux wired)
    -i wlan0       (Linux wireless)
    -i Wi-Fi       (Windows wireless)
    -i lo          (loopback)
    -i en0         (macOS)

List Interfaces (-I)
  Show every network interface available on the
  system, then exit. Useful to find the exact name
  to pass to -i.

Count (-c)
  Number of packets to capture before stopping.

  -c 100     Stop after 100 packets
  -c 0       Infinite (runs until stopped manually)

  Default is 0 (infinite) for live capture.
  When reading from a file, -c limits how many
  packets are processed.

BPF Filter (-f)
  Berkeley Packet Filter expression. Only packets
  matching the filter are captured.

  Common filters:
    'tcp port 80'             HTTP traffic
    'tcp port 443'            HTTPS traffic
    'udp port 53'             DNS traffic
    'icmp'                    Ping / ICMP only
    'arp'                     ARP only
    'host 192.168.1.1'        Traffic to/from a host
    'net 192.168.1.0/24'      Traffic to/from a subnet
    'not port 22'             Everything except SSH

Verbose (-v)
  Show detailed packet information for each frame:
  addresses, ports, flags, sequence numbers, and
  payload previews. Without -v, only a one-line
  summary per packet is printed.

Quiet (-q)
  Suppress the startup banner. Useful when piping
  output to a file or another program.
"""
    }

    PROTOCOLS = {
        "title": "Protocol Filters",
        "icon": "🔬",
        "content": """
These flags restrict the capture to a specific
protocol. They are simpler than writing BPF
filters by hand, and can be combined.

ARP (--arp)
  Only Address Resolution Protocol packets.
  Use this to map IP addresses to MAC addresses
  on the local network.

TCP (--tcp)
  Only Transmission Control Protocol packets.
  Covers HTTP, HTTPS, SSH, FTP, and most
  connection-oriented services.

UDP (--udp)
  Only User Datagram Protocol packets.
  Covers DNS, DHCP, SNMP, and most
  connectionless services.

ICMP (--icmp)
  Only Internet Control Message Protocol packets
  (IPv4). This is what ping uses.

ICMPv6 (--icmpv6)
  Only ICMPv6 packets. This is what ping6 uses,
  plus Neighbor Discovery and Router Advertisements.

IGMP (--igmp)
  Only Internet Group Management Protocol packets.
  Used for multicast group management.

IPv4 (--ipv4)
  Only IPv4 packets. Skips ARP and IPv6.

IPv6 (--ipv6)
  Only IPv6 packets. Skips ARP and IPv4.

SCTP (--sctp)
  Only Stream Control Transmission Protocol packets.
  Used in telecom (SS7 over IP) and WebRTC.

Ethernet Info (--eth)
  Show Ethernet frame header details:
  source MAC, destination MAC, EtherType.

VLAN (--vlan)
  Show 802.1Q VLAN tags, including stacked
  QinQ (802.1ad) tags.
"""
    }

    OUTPUT = {
        "title": "Save & Load",
        "icon": "💾",
        "content": """
Writing Captures
  LightSniff can save captures in three formats:

  -w FILE, --write FILE
    Save to standard PCAP or PCAPNG format.
    Compatible with Wireshark, tcpdump, and any
    other PCAP-aware tool.

    Example: -w capture.pcap

  --bin-save FILE
    Save to LightBin (.lbn) — Light-Scan's native
    binary format. Smaller files, faster loading,
    and supports compression.

    Example: --bin-save capture.lbn

  --hex-save FILE
    Save to hexadecimal text format (.lhex).
    Human-readable, useful for debugging and
    for sharing on forums or chat.

    Example: --hex-save capture.lhex

Compression (-C)
  Compress LightBin output using zlib.
  Only valid together with --bin-save.

    Example: --bin-save capture.lbn -C

Reading Captures
  Instead of capturing live traffic, LightSniff
  can process a saved file:

  -r FILE, --read FILE
    Read from PCAP or PCAPNG.

  --bin-load FILE
    Read from LightBin (.lbn).

  --hex-load FILE
    Read from hex format (.lhex).

  When a read flag is set, live capture is disabled.
  The interface (-i) and filter (-f) flags are
  ignored in offline mode.
"""
    }

    ADVANCED = {
        "title": "Advanced Options",
        "icon": "🧠",
        "content": """
Promiscuous Mode (--no-promisc)
  By default, LightSniff puts the interface into
  promiscuous mode, which captures every frame on
  the wire — even ones not addressed to your machine.

  Use --no-promisc to disable this. You will only
  see frames addressed to you or broadcast/multicast.

MAC Filter (--mac)
  Filter by source or destination MAC address.
  This runs at Layer 2, before the BPF filter.

    Example: --mac aa:bb:cc:dd:ee:ff

  Only packets whose source OR destination MAC
  matches the given value are kept.

Statistics (--stats)
  After the capture ends, print flow statistics:
    - Total packets captured
    - Packets per protocol
    - Top source/destination pairs
    - Bytes transferred

Export Statistics (--export-stats FILE)
  Write the same statistics to a file instead of
  (or in addition to) printing them on screen.

    Example: --export-stats report.txt

Combining Filters
  Protocol flags, BPF filters, and MAC filters can
  all be used together. The most restrictive wins.

    Example:
      LightSniff -i eth0 --tcp -f 'port 443' \
                 --mac aa:bb:cc:dd:ee:ff -v
"""
    }

    EXAMPLES = {
        "title": "Quick Examples",
        "icon": "✨",
        "content": """
Capture everything on eth0
  LightSniff -i eth0

List available interfaces
  LightSniff -I

Capture HTTP traffic to PCAP
  LightSniff -i eth0 -f 'tcp port 80' -w http.pcap

Capture 100 packets with verbose output
  LightSniff -i wlan0 -c 100 -v

Capture DNS queries only
  LightSniff -i eth0 -f 'udp port 53' -v

Capture ARP traffic
  LightSniff -i eth0 --arp

Save to LightBin with compression
  LightSniff -i eth0 --bin-save capture.lbn -C

Read an existing PCAP
  LightSniff -r capture.pcap -v

Read a LightBin file
  LightSniff --bin-load capture.lbn

Filter by MAC address
  LightSniff -i eth0 --mac aa:bb:cc:dd:ee:ff -v

Capture with statistics report
  LightSniff -i eth0 -c 1000 --stats

Export statistics to a file
  LightSniff -i eth0 -c 1000 --stats --export-stats stats.txt

Stealth capture (no promisc, quiet)
  LightSniff -i eth0 --no-promisc -q
"""
    }


def show_sniff_help(parent):
    dialog = QuickHelp(
        parent=parent,
        sections=[
            ("Basic", SniffHelpContent.BASIC.get("icon"), SniffHelpContent.BASIC),
            ("Protocols", SniffHelpContent.PROTOCOLS.get("icon"), SniffHelpContent.PROTOCOLS),
            ("Save & Load", SniffHelpContent.OUTPUT.get("icon"), SniffHelpContent.OUTPUT),
            ("Advanced", SniffHelpContent.ADVANCED.get("icon"), SniffHelpContent.ADVANCED),
            ("Examples", SniffHelpContent.EXAMPLES.get("icon"), SniffHelpContent.EXAMPLES),
        ],
        title="Quick Help - LightSniff Guide",
        stitle="📡 Quick Help",
        subtitle="LightSniff Capture Guide",
        version="LightSniff v1.0.3"
    )
    dialog.exec()

