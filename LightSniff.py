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

import argparse
import time
from HexSave.LightBin import load_binary
from ch_admin import check_admin
from Sfaces import get_interfaces, get_eth_type_name, detect_file_type
from scapy.all import sniff, wrpcap, rdpcap, Ether, Raw, IP, TCP, UDP, ICMP, ARP, DNS, conf
from scapy.layers.sctp import SCTP, SCTPChunkInit, SCTPChunkInitAck, SCTPChunkCookieEcho, SCTPChunkCookieAck, \
    SCTPChunkAbort, SCTPChunkData, SCTPChunkShutdown, SCTPChunkShutdownAck, SCTPChunkShutdownComplete, SCTPChunkSACK, \
    SCTPChunkHeartbeatReq, SCTPChunkHeartbeatAck, SCTPChunkError
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq, IGMPv3mr, IGMPv3gr
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Dot1Q
from HexSave.LightHex import load_hexdump
from packet_process import print_table_header, export_hex_and_bin, apply_filter, export_stats_to_file
from HexSave.ScapyLoader.ScapyPacketsLoader import LoadFromLightHexToScapyPackets
from Decoration.Colors import *

conf.use_pcap = True
conf.use_npcap = True

try:
    from scapy.all import get_if_list

    HAVE_IF_LIST = True
except:
    HAVE_IF_LIST = False

Version = "1.0.3"


class FlowStatistics:
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': {},
            'top_src': {},
            'top_dst': {},
            'flows': {},
            'start_time': time.time()
        }

    def update(self, packet):
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += len(packet)

        proto = "OTHER"
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        elif ICMP in packet:
            proto = "ICMP"
        elif ARP in packet:
            proto = "ARP"
        elif DNS in packet:
            proto = "DNS"
        elif SCTP in packet:
            proto = "SCTP"
        elif IPv6 in packet:
            proto = "IPv6"
        elif IP in packet:
            if packet[IP].proto == 2:
                proto = "IGMP"
            else:
                proto = "IPv4"

        self.stats['protocols'][proto] = self.stats['protocols'].get(proto, 0) + 1

        src = "N/A"
        dst = "N/A"

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst
        elif ARP in packet:
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
        else:
            if Ether in packet:
                src = packet[Ether].src
                dst = packet[Ether].dst

        if src != "N/A":
            self.stats['top_src'][src] = self.stats['top_src'].get(src, 0) + 1
        if dst != "N/A":
            self.stats['top_dst'][dst] = self.stats['top_dst'].get(dst, 0) + 1

        if src != "N/A" and dst != "N/A":
            src_port = ""
            dst_port = ""
            if TCP in packet:
                src_port = f":{packet[TCP].sport}"
                dst_port = f":{packet[TCP].dport}"
            elif UDP in packet:
                src_port = f":{packet[UDP].sport}"
                dst_port = f":{packet[UDP].dport}"
            elif SCTP in packet:
                src_port = f":{packet[SCTP].sport}"
                dst_port = f":{packet[SCTP].dport}"

            flow_key = f"{src}{src_port} -> {dst}{dst_port}"
            self.stats['flows'][flow_key] = self.stats['flows'].get(flow_key, 0) + 1

    def display_summary(self):
        elapsed = time.time() - self.stats['start_time']
        pps = self.stats['total_packets'] / elapsed if elapsed > 0 else 0


        print(f"\n\n[+] {CYAN}Capture Statistics{RESET}\n{'-'*50}")
        print(f"Total Packets: {self.stats['total_packets']}")
        print(f"Total Bytes: {self.stats['total_bytes'] / 1024:.1f} KB")
        print(f"Duration: {elapsed:.1f}s")
        print(f"PPS: {pps:.1f}")
        if self.stats['total_packets'] > 0:
            print(f"Avg Packet Size: {self.stats['total_bytes'] / self.stats['total_packets']:.0f} bytes")

        print("\nProtocol Distribution:")
        for proto, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            if self.stats['total_packets'] > 0:
                percentage = count / self.stats['total_packets'] * 100
                bar = '█' * int(percentage / 2)
                print(f"  {proto:6}: {count:4} ({percentage:5.1f}%) {bar}")

        print("\nTop Source Addresses:")
        for src, count in sorted(self.stats['top_src'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {src}: {count}")

        print("\nTop Destination Addresses:")
        for dst, count in sorted(self.stats['top_dst'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {dst}: {count}")

        print("\nTop Flows:")
        for flow, count in sorted(self.stats['flows'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {flow}: {count}")

def parse_args():
    parser = argparse.ArgumentParser(
        description="LightSniff - Light-Scan Packet Capture Tool",
        epilog="""
Examples:
    LightSniff -i eth0
    LightSniff -i eth0 -f 'tcp port 80' -w http.pcap
    LightSniff -i Wi-Fi -c 100 -v
    LightSniff -r capture.pcap
    LightSniff --bin-load capture.lbn""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    basic = parser.add_argument_group('Basic Sniffing Options')
    saving = parser.add_argument_group('Writing & Reading Options')
    adv = parser.add_argument_group('Advanced Sniffing Options')
    filters = parser.add_argument_group('Filters Options')
    stats_group = parser.add_argument_group('Statistics Options')

    stats_group.add_argument("--stats", action="store_true",
                             help="Display flow statistics after capture")
    stats_group.add_argument("--export-stats", metavar="FILE",
                             help="Export statistics to file")

    basic.add_argument("-i", "--interface", help="Network interface (e.g., eth0, Wi-Fi, wlan0)")
    basic.add_argument("-I", "--interfaces", action="store_true", help="Show all available Network Interfaces")
    basic.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80', 'icmp', 'arp')")
    basic.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture/process (0 = infinite/all). "
                             "Was previously defaulted to 100, which silently truncated "
                             "--read/--bin-load/--hex-load files to their first 100 packets.")
    saving.add_argument("-w", "--write", help="Save to PCAP/PCAPNG file")
    saving.add_argument("-r", "--read", help="Read packets from PCAP/PCAPNG file (offline mode)")
    saving.add_argument("--bin-save", help="Save to LightBin binary format (.lbn)")
    saving.add_argument("--bin-load", help="Load from LightBin binary format (.lbn)")
    saving.add_argument("--hex-save", help="Save to hexadecimal format (.lhex)")
    saving.add_argument("--hex-load", help="Load from hexadecimal format (.lhex)")
    saving.add_argument("-C", "--compress", action="store_true", help="To compress saved output (only for .lbn)")
    basic.add_argument("-v", "--verbose", action="store_true", help="Show detailed packet info")
    adv.add_argument("--no-promisc", action="store_true", help="Disable promiscuous mode")
    basic.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (no banner)")
    adv.add_argument("--eth", action="store_true", help="Show Ethernet frame info (MAC addresses, frame type)")
    adv.add_argument("--vlan", action="store_true", help="Show VLAN tags (802.1Q)")
    filters.add_argument("--arp", action="store_true", help="Show only ARP packets")
    filters.add_argument("--tcp", action="store_true", help="Show only TCP packets")
    filters.add_argument("--udp", action="store_true", help="Show only UDP packets")
    filters.add_argument("--icmp", action="store_true", help="Show only ICMP packets")
    filters.add_argument("--igmp",action="store_true", help="Show only IGMP packets")
    filters.add_argument("--ipv4",action="store_true", help="Show only IPv4 packets")
    filters.add_argument("--ipv6",action="store_true", help="Show only IPv6 packets")
    filters.add_argument("--sctp",action="store_true", help="Show only SCTP packets")
    filters.add_argument("--icmpv6",action="store_true", help="Show only ICMPv6 packets")
    adv.add_argument("--mac", help="Filter by source or destination MAC address (e.g., aa:bb:cc:dd:ee:ff)")

    return parser.parse_args()


def extract_port(packet, direction):
    if TCP in packet:
        if direction == "src":
            return packet[TCP].sport
        return packet[TCP].dport
    elif UDP in packet:
        if direction == "src":
            return packet[UDP].sport
        return packet[UDP].dport
    elif SCTP in packet:
        if direction == "src":
            return packet[SCTP].sport
        return packet[SCTP].dport
    return ""


def analyze_igmp(packet):
    details = ""
    if packet.haslayer(Raw):
        packet = packet[Raw].load
        packet = IGMPv3(packet)

    if IGMPv3 in packet:
        igmpv3 = packet[IGMPv3]
        igmp_type = igmpv3.type
        max_resp = igmpv3.mrcode

        igmpv3_types = {
            0x11: "Membership Query (v3)",
            0x22: "Membership Report (v3)",
            0x23: "v3 Report (RFC 4604)",
        }

        type_name = igmpv3_types.get(igmp_type, f"Unknown (0x{igmp_type:02x})")

        if IGMPv3mq in packet:
            mq = packet[IGMPv3mq]
            group_addr = str(mq.gaddr)
            details = f"Type: {type_name}, Group: {group_addr}, MaxResp: {max_resp}"

            if hasattr(mq, 's') and mq.s:
                details += ", S Flag: ON"
            if hasattr(mq, 'qrv'):
                details += f", QRV: {mq.qrv}"
            if hasattr(mq, 'qqic'):
                details += f", QQIC: {mq.qqic}s"
            if hasattr(mq, 'srcaddrs') and mq.srcaddrs:
                src_count = len(mq.srcaddrs)
                if src_count > 0:
                    details += f", {src_count} source(s)"
                    if src_count <= 3:
                        src_str = ', '.join(str(s) for s in mq.srcaddrs[:3])
                        details += f" [{src_str}]"

        elif IGMPv3mr in packet:
            mr = packet[IGMPv3mr]
            details = f"Type: {type_name}, MaxResp: {max_resp}"

            if hasattr(mr, 'records') and mr.records:
                record_count = len(mr.records)
                details += f", {record_count} record(s)"

                for idx, record in enumerate(mr.records[:2]):
                    if hasattr(record, 'rtype'):
                        record_types = {
                            1: "Current State",
                            2: "Source List Change",
                            3: "Source List Change (v3)",
                            4: "Mode is Include",
                            5: "Mode is Exclude",
                            6: "Change to Include",
                            7: "Change to Exclude",
                            8: "Allow Sources",
                            9: "Block Sources",
                        }
                        rtype_name = record_types.get(record.rtype, f"Unknown ({record.rtype})")

                        if hasattr(record, 'maddr'):
                            details += f" [{idx + 1}: {rtype_name} → {record.maddr}"
                            if hasattr(record, 'srcaddrs') and record.srcaddrs:
                                src_list = ', '.join(str(s) for s in record.srcaddrs[:3])
                                if len(record.srcaddrs) > 3:
                                    src_list += f" +{len(record.srcaddrs) - 3} more"
                                details += f" Sources: {src_list}"
                            details += "]"
        else:
            details += f"IGMPv3 |Type: {type_name}, MaxResp: {max_resp}"

    elif IGMP in packet:
        igmp = packet[IGMP]
        igmp_type = igmp.type
        max_resp = igmp.mrcode
        group_addr = str(igmp.gaddr) if hasattr(igmp, 'gaddr') else "0.0.0.0"

        igmp_types = {
            0x11: "Membership Query",
            0x12: "v1 Membership Report",
            0x16: "v2 Membership Report",
            0x17: "Leave Group",
            0x13: "Distance Vector Multicast",
            0x14: "PIM version 1",
            0x15: "Cisco Trace",
            0x1E: "RFC 2914",
        }

        type_name = igmp_types.get(igmp_type, f"Unknown (0x{igmp_type:02x})")

        version = "v2"
        if igmp_type == 0x12:
            version = "v1"
        elif igmp_type == 0x11:
            version = "v1" if max_resp == 0 else "v2"
        elif igmp_type == 0x16:
            version = "v2"
        elif igmp_type == 0x17:
            version = "v2"

        details = f"IGMP{version} | Type: {type_name}"

        if max_resp is not None:
            if max_resp <= 0x7F:
                resp_time = max_resp / 10.0
                details += f", MaxResp: {resp_time:.1f}s"
            else:
                exponent = (max_resp >> 4) & 0x07
                mantissa = max_resp & 0x0F
                if exponent > 0:
                    resp_time = (mantissa | 0x10) << (exponent + 3)
                    details += f", MaxResp: {resp_time / 1000.0:.1f}s"
                else:
                    details += f", MaxResp: {max_resp / 10.0:.1f}s"

        if group_addr and group_addr != "0.0.0.0":
            details += f", Group: {group_addr}"

    return details


def detect_quicc(payload, dport, sport):
    if not payload or len(payload) < 1:
        return False, None, "Empty payload"

    is_long_marker = payload[0] in [0xC0, 0xCD, 0xEA, 0xE2, 0xC6, 0x46]
    if not (is_long_marker or sport == 443 or dport == 443):
        return False, None, "Invalid payload"

    first_byte = payload[0]
    header_form = (first_byte & 0x80) >> 7
    fixed_bit = (first_byte & 0x40) >> 6

    if fixed_bit != 1:
        return False, None, "Invalid Fixed Bit"

    if header_form == 1 and len(payload) < 10:
        return False, None, "Not QUIC: Long header too short"
    elif header_form == 0 and len(payload) < 5:
        return False, None, "Not QUIC: Short header too short"

    if header_form == 1:
        version = int.from_bytes(payload[1:5], 'big')

        version_names = {
            0x00000001: "QUIC v1 (RFC 9000)",
            0x51303439: "QUIC Q043",
            0x51303538: "QUIC Q058",
            0x51303132: "QUIC Q012",
            0x51303333: "QUIC Q033",
            0x51303636: "QUIC Q066",
            0xff00001d: "Draft 29",
            0x709a50c4: "Draft 27",
            0x00000000: "Version Negotiation"
        }

        version_str = version_names.get(version, f"Unknown (0x{version:08x})")
        details = f"Long | Version: {version_str}"

        if len(payload) >= 6:
            dcid_len = payload[5]
            if len(payload) >= 6 + dcid_len:
                dcid = payload[6:6 + dcid_len]
                details += f" | DCID: {dcid.hex()}"

        return True, "Long", details

    pkt_num_len = (first_byte & 0x03) + 1
    spin_bit = (first_byte & 0x20) >> 5
    key_phase = (first_byte & 0x04) >> 2
    details = f"Short | PN Len: {pkt_num_len}"
    details += f" | Spin:{spin_bit} | K:{key_phase}"
    return True, "Short", details


def packet_callback(packet, verbose, packet_count, args):
    timestamp = time.strftime('%H:%M:%S')

    eth = packet[Ether] if Ether in packet else None
    src_mac = eth.src if eth else "N/A"
    dst_mac = eth.dst if eth else "N/A"
    eth_type = eth.type if eth else 0
    eth_type_name = get_eth_type_name(eth_type)

    vlan_id = None
    if Dot1Q in packet and args.vlan:
        vlan = packet[Dot1Q]
        vlan_id = vlan.vlan

    src_ip = "N/A"
    dst_ip = "N/A"
    proto = "OTHER"
    proto_color = RED
    details = ""
    size = len(packet)

    if Ether in packet:
        proto = "Ether"
        proto_color = GREY

    if IP in packet:
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = "IPv4"
        proto_color = GREEN
        size = len(ip)

    elif IPv6 in packet:
        ipv6 = packet[IPv6]
        src_ip = ipv6.src
        dst_ip = ipv6.dst
        proto = "IPv6"
        proto_color = CYAN
        size = len(ipv6)

        if ICMPv6EchoRequest in packet:
            proto = "ICMPv6"
            details = "Echo Request (ping)"
        elif ICMPv6EchoReply in packet:
            proto = "ICMPv6"
            details = "Echo Reply (pong)"

    if SCTP in packet:
        sctp = packet[SCTP]
        proto = "SCTP"
        proto_color = ORANGE

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            src_ip = "N/A"
            dst_ip = "N/A"

        details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag}"
        size = len(sctp.payload)

        chunk_types = []
        if SCTPChunkInit in packet:
            proto = "SCTP-INIT"
            init = packet[SCTPChunkInit]
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{init.init_tag} | Out:{init.n_out_streams} | In:{init.n_in_streams}"

        elif SCTPChunkInitAck in packet:
            proto = "SCTP-INIT-ACK"
            init_ack = packet[SCTPChunkInitAck]
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{init_ack.init_tag} | Cookie: present"

        elif SCTPChunkCookieEcho in packet:
            proto = "SCTP-COOKIE-ECHO"
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag}"

        elif SCTPChunkCookieAck in packet:
            proto = "SCTP-COOKIE-ACK"
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag}"

        elif SCTPChunkAbort in packet:
            proto = "SCTP-ABORT"
            abort = packet[SCTPChunkAbort]
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag} | Flags:{abort.flags}"

        elif SCTPChunkData in packet:
            data = packet[SCTPChunkData]
            proto = "SCTP-DATA"
            details = f"S:{sctp.sport} → D:{sctp.dport} | TSN:{data.tsn} | Stream:{data.stream_id}"
            if args.verbose and data.payload:
                try:
                    payload_preview = bytes(data.payload)[:30]
                    details += f" | Data: {payload_preview.hex()}"
                except:
                    pass

        elif SCTPChunkShutdown in packet:
            proto = "SCTP-SHUTDOWN"
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag}"

        elif SCTPChunkShutdownAck in packet:
            proto = "SCTP-SHUTDOWN-ACK"
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag}"

        elif SCTPChunkShutdownComplete in packet:
            proto = "SCTP-SHUTDOWN-COMPLETE"
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag}"

        elif SCTPChunkSACK in packet:
            sack = packet[SCTPChunkSACK]
            proto = "SCTP-SACK"
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag} | TSN:{sack.cum_tsn_ack}"

        elif SCTPChunkHeartbeatReq in packet:
            proto = "SCTP-HEARTBEAT"
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag}"

        elif SCTPChunkHeartbeatAck in packet:
            proto = "SCTP-HEARTBEAT-ACK"
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag}"

        elif SCTPChunkError in packet:
            proto = "SCTP-ERROR"
            details = f"S:{sctp.sport} → D:{sctp.dport} | Tag:{sctp.tag}"

    if TCP in packet:
        tcp = packet[TCP]
        proto = "TCP"
        proto_color = GREEN
        flags = tcp.sprintf("%flags%")
        details = f"S:{tcp.sport} → D:{tcp.dport} Flags:[{flags}]"
        size = len(tcp.payload)

        tls_ports = [443, 465, 587, 993, 995, 8443, 8080]
        is_tls_port = tcp.sport in tls_ports or tcp.dport in tls_ports
        if tcp.payload and len(tcp.payload) > 5:
            payload = bytes(tcp.payload)

            if is_tls_port or (len(payload) >= 6 and payload[0] == 0x16 and payload[1] in [0x03, 0x02, 0x01]):

                tls_version = None
                version_bytes = payload[1:3] if len(payload) >= 3 else b''

                if version_bytes == b'\x03\x00':
                    tls_version = "SSLv3 (WEAK - Deprecated)"
                elif version_bytes == b'\x03\x01':
                    tls_version = "TLS 1.0 (WEAK - Deprecated)"
                elif version_bytes == b'\x03\x02':
                    tls_version = "TLS 1.1 (WEAK - Deprecated)"
                elif version_bytes == b'\x03\x03':
                    tls_version = "TLS 1.2"
                elif version_bytes == b'\x03\x04':
                    tls_version = "TLS 1.3"

                if len(payload) >= 6 and payload[5] == 0x01:
                    proto = "TLS"
                    proto_color = BLUE
                    details = f"Client Hello [{tls_version if tls_version else 'Unknown'}]"

                    try:
                        offset = 6

                        if len(payload) > offset + 4:
                            offset += 4

                            offset += 2

                            offset += 32

                            if len(payload) > offset:
                                session_id_len = payload[offset]
                                offset += 1 + session_id_len

                            if len(payload) > offset + 2:
                                cipher_suites_len = int.from_bytes(payload[offset:offset + 2], 'big')
                                offset += 2 + cipher_suites_len

                            if len(payload) > offset:
                                compression_len = payload[offset]
                                offset += 1 + compression_len

                            if len(payload) > offset + 2:
                                extensions_len = int.from_bytes(payload[offset:offset + 2], 'big')
                                offset += 2
                                end_offset = offset + extensions_len

                                while offset + 4 <= len(payload) and offset < end_offset:
                                    ext_type = int.from_bytes(payload[offset:offset + 2], 'big')
                                    ext_len = int.from_bytes(payload[offset + 2:offset + 4], 'big')
                                    offset += 4

                                    if ext_type == 0x0000 and ext_len > 2:
                                        if len(payload) > offset + 2:
                                            sni_len = int.from_bytes(payload[offset:offset + 2], 'big')
                                            if sni_len > 0 and len(payload) > offset + 2 + sni_len:
                                                sni = payload[offset + 2:offset + 2 + sni_len].decode('utf-8',
                                                                                                      errors='ignore')
                                                details += f" SNI: {sni}"

                                    offset += ext_len
                    except Exception as e:
                        pass

                elif len(payload) >= 6 and payload[5] == 0x02:
                    proto = "TLS"
                    proto_color = CYAN
                    details = f"Server Hello [{tls_version if tls_version else 'Unknown'}]"

                elif len(payload) >= 6 and payload[5] == 0x0B:
                    proto = "TLS"
                    proto_color = GREEN
                    details = f"Certificate [{tls_version if tls_version else 'Unknown'}]"

                    if args.verbose:
                        try:
                            cert_start = payload.find(b'\x30\x82')
                            if cert_start > 0:
                                cert_info = f" (Certificate chain length: {len(payload) - cert_start} bytes)"
                                details += cert_info
                        except:
                            pass

                elif len(payload) >= 1 and payload[0] == 0x17:
                    proto = "TLS"
                    proto_color = BLUE
                    details = f"Application Data [{tls_version if tls_version else 'Unknown'}]"
                    size = len(payload)

                elif len(payload) >= 1 and payload[0] == 0x15:
                    proto = "TLS"
                    proto_color = YELLOW
                    alert_level = "Unknown"
                    alert_desc = "Unknown"
                    if len(payload) >= 2:
                        alert_level = "Warning" if payload[1] == 0x01 else "Fatal"
                    if len(payload) >= 3:
                        desc_map = {
                            0x00: "close_notify", 0x0A: "unexpected_message",
                            0x14: "bad_record_mac", 0x15: "decryption_failed",
                            0x16: "record_overflow", 0x1E: "decompression_failure",
                            0x28: "handshake_failure", 0x29: "no_certificate",
                            0x2A: "bad_certificate", 0x2B: "unsupported_certificate",
                            0x2C: "certificate_revoked", 0x2D: "certificate_expired",
                            0x2E: "certificate_unknown", 0x2F: "illegal_parameter",
                            0x30: "unknown_ca", 0x31: "access_denied",
                            0x32: "decode_error", 0x33: "decrypt_error",
                            0x3C: "export_restriction", 0x46: "protocol_version",
                            0x47: "insufficient_security", 0x50: "internal_error",
                            0x5A: "user_canceled", 0x64: "no_renegotiation"
                        }
                        alert_desc = desc_map.get(payload[2], f"0x{payload[2]:02x}")
                    details = f"Alert [{alert_level}: {alert_desc}]"

        if tcp.dport == 853 or tcp.sport == 853:
            proto = "DoT"
            proto_color = PURPLE
            details = f"DNS over TLS {details}"

        if tcp.dport == 53 or tcp.sport == 53:
            proto = "DNS"
            proto_color = PURPLE
            try:
                from scapy.layers.dns import DNS, DNSQR
                if len(tcp.payload) > 2:
                    dns_payload = bytes(tcp.payload)[2:]
                    dns = DNS(dns_payload)
                    if dns and dns.qr == 0:
                        if dns.qd:
                            query_name = dns.qd.qname.decode('utf-8', errors='ignore')
                            query_type = dns.qd.qtype
                            type_names = {1: 'A', 28: 'AAAA', 15: 'MX', 2: 'NS', 5: 'CNAME', 12: 'PTR', 16: 'TXT',
                                          6: 'SOA', 33: 'SRV'}
                            type_str = type_names.get(query_type, str(query_type))
                            details = f"Query: {query_name} ({type_str})"
                    elif dns and dns.qr == 1:
                        if dns.an:
                            answer = dns.an
                            if hasattr(answer, 'rdata'):
                                details = f"Response: {answer.rdata}"
                        else:
                            details = "Response: No answer"
            except Exception as e:
                pass

        ssh_ports = [22]
        if tcp.dport in ssh_ports or tcp.sport in ssh_ports:
            if tcp.payload and len(tcp.payload) > 0:
                try:
                    payload = bytes(tcp.payload)

                    if payload.startswith(b'SSH-'):
                        proto = "SSH"
                        proto_color = RED
                        try:
                            banner = payload.split(b'\r\n')[0].decode('utf-8', errors='ignore')
                        except:
                            banner = payload[:40].decode('utf-8', errors='ignore')

                        parts = banner.split('-', 2)
                        if len(parts) >= 3:
                            ssh_version = parts[1]
                            software = parts[2]
                            details = f"Banner: SSH {ssh_version} ({software[:25]})"
                        else:
                            details = f"Banner: {banner[:35]}"
                    else:
                        proto = "SSH"
                        proto_color = RED
                        details = f"Encrypted SSH data ({len(payload)} bytes)"

                        if len(payload) >= 5:
                            pkt_len = int.from_bytes(payload[0:4], 'big')
                            if 0 < pkt_len < 262144:
                                details += f" [len:{pkt_len}]"

                except Exception as e:
                    pass

        ftp_ports = [21, 990]
        if (tcp.dport in ftp_ports or tcp.sport in ftp_ports) and tcp.payload:
            try:
                payload = bytes(tcp.payload)
                payload_str = payload.decode('utf-8', errors='ignore').strip()

                if payload_str.startswith('220 '):
                    proto = "FTP"
                    proto_color = ORANGE
                    details = f"Banner: {payload_str[:50]}"
                elif payload_str.upper().startswith(('USER ', 'PASS ', 'LIST', 'RETR ', 'STOR ', 'PORT ',
                                                     'PASV', 'QUIT', 'SYST', 'TYPE ', 'MKD', 'CWD ',
                                                     'CDUP', 'DELE', 'RMD', 'PWD', 'NLST', 'APPE')):
                    proto = "FTP"
                    proto_color = ORANGE
                    parts = payload_str.split(' ', 1)
                    cmd = parts[0].upper()
                    arg = parts[1][:30] if len(parts) > 1 else ''
                    details = f"Command: {cmd} {arg}".strip()
                elif len(payload_str) >= 4 and payload_str[:3].isdigit() and payload_str[3] in (' ', '-'):
                    proto = "FTP"
                    proto_color = ORANGE
                    code = payload_str[:3]
                    message = payload_str[4:50].strip()
                    details = f"Response: {code} {message}".strip()
                elif any(
                        kw in payload for kw in (b'USER', b'PASS', b'LIST', b'RETR', b'STOR', b'PORT', b'PASV', b'QUIT',
                                                 b'SYST', b'TYPE', b'MKD', b'CWD', b'CDUP', b'DELE', b'RMD', b'PWD',
                                                 b'NLST', b'APPE')):
                    proto = "FTP"
                    proto_color = ORANGE
                    details = f"FTP data (contains command): {payload_str[:40]}"
                elif all(32 <= b <= 126 or b in (9, 10, 13) for b in payload[:30]):
                    proto = "FTP"
                    proto_color = ORANGE
                    details = f"FTP control data: {payload_str[:40]}"
            except Exception:
                pass

        http_ports = [80, 8080, 8000, 8888]
        if tcp.dport in http_ports or tcp.sport in http_ports:
            if tcp.payload and len(tcp.payload) > 0:
                try:
                    payload = bytes(tcp.payload)
                    payload_str = payload.decode('utf-8', errors='ignore')[:200]

                    http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']
                    is_http = False

                    for method in http_methods:
                        if payload_str.startswith(method + ' '):
                            is_http = True
                            proto = "HTTP"
                            proto_color = YELLOW

                            lines = payload_str.split('\r\n')
                            if lines:
                                parts = lines[0].split(' ')
                                if len(parts) >= 3:
                                    path = parts[1][:30]
                                    if len(parts[1]) > 30:
                                        path += '...'
                                    details = f"{method} {path}"
                                else:
                                    details = payload_str[:40].replace('\r', '').replace('\n', ' ')
                            break

                    if not is_http and payload_str.startswith('HTTP/'):
                        is_http = True
                        proto = "HTTP"
                        proto_color = CYAN
                        lines = payload_str.split('\r\n')
                        if lines:
                            parts = lines[0].split(' ')
                            if len(parts) >= 3:
                                details = f"{parts[0]} {parts[1]} {parts[2][:20]}"
                            else:
                                details = payload_str[:40].replace('\r', '').replace('\n', ' ')

                    if not is_http:
                        http_keywords = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'HTTP/', b'<html',
                                         b'<!DOCTYPE']
                        for keyword in http_keywords:
                            if keyword in payload[:100]:
                                is_http = True
                                proto = "HTTP"
                                proto_color = YELLOW
                                details = payload_str[:40].replace('\r', '').replace('\n', ' ') + '...'
                                break

                except Exception as e:
                    try:
                        payload = bytes(tcp.payload)
                        http_keywords = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'HTTP/', b'<html',
                                         b'<!DOCTYPE']
                        for keyword in http_keywords:
                            if keyword in payload[:100]:
                                proto = "HTTP"
                                proto_color = YELLOW
                                details = "HTTP traffic detected"
                                break
                    except:
                        pass


    elif UDP in packet:
        udp = packet[UDP]
        proto = "UDP"
        proto_color = CYAN
        details = f"S:{udp.sport} → D:{udp.dport}"
        size = len(udp.payload)

        if udp.dport == 53 or udp.sport == 53:
            proto = "DNS"
            proto_color = PURPLE

            try:
                from scapy.layers.dns import DNS, DNSQR

                if DNS in packet:
                    dns = packet[DNS]
                    if dns.qr == 0:
                        if dns.qd:
                            query_name = dns.qd.qname.decode('utf-8', errors='ignore')
                            query_type = dns.qd.qtype
                            type_names = {1: 'A', 28: 'AAAA', 15: 'MX', 2: 'NS', 5: 'CNAME', 12: 'PTR', 16: 'TXT',
                                          6: 'SOA', 33: 'SRV'}
                            type_str = type_names.get(query_type, str(query_type))
                            details = f"Query: {query_name} ({type_str})"
                    elif dns.qr == 1:
                        if dns.an:
                            answer = dns.an
                            if hasattr(answer, 'rdata'):
                                details = f"Response: {answer.rdata}"
                        else:
                            details = "Response: No answer"
            except Exception as e:
                pass


        else:
            try:

                payload = bytes(udp.payload)
                is_quic, header_type, quic_details = detect_quicc(payload, udp.dport, udp.sport)

                if is_quic or udp.dport == 443 or udp.sport == 443:
                    proto = "QUIC"
                    proto_color = BLUE
                    details = quic_details
                    size = len(payload)

                    details += f" | S:{udp.sport} → D:{udp.dport}"

            except Exception as e:
                if args.verbose:
                    details = f"QUIC parse error: {e}"
                pass

    elif ICMP in packet and proto != "ICMPv6":
        icmp = packet[ICMP]
        proto = "ICMP"
        proto_color = YELLOW
        details = f"Type:{icmp.type} Code:{icmp.code}"
        size = 0

    elif ARP in packet:
        arp = packet[ARP]
        proto = "ARP"
        proto_color = PURPLE
        src_ip = arp.psrc
        dst_ip = arp.pdst
        details = f"{arp.psrc} → {arp.pdst}"
        size = 0

    elif IP in packet and packet[IP].proto == 2:
        proto = "IGMP"
        proto_color = BLUE
        src_ip = packet[IP].src if IP in packet else "N/A"
        dst_ip = packet[IP].dst if IP in packet else "N/A"
        details = analyze_igmp(packet)
        size = len(packet) - (len(packet[IP]) if IP in packet else 0)

    if vlan_id is not None:
        details += f" [VLAN:{vlan_id}]"

    if verbose:
        print(f"{BOLD}[{timestamp}]{RESET} {proto_color}{proto:6}{RESET} "
              f"{str(src_ip):16} → {str(dst_ip):16} | "
              f"{src_mac:17} → {dst_mac:17} | "
              f"{eth_type_name:8} | "
              f"{details} | "
              f"Size: {size:4} bytes")
    else:
        src_port = extract_port(packet, 'src')
        dst_port = extract_port(packet, 'dst')

        if args.eth:
            src_display = f"{src_mac}"
            dst_display = f"{dst_mac}"
            if src_port:
                src_display += f":{src_port}"
            if dst_port:
                dst_display += f":{dst_port}"
        else:
            src_display = f"{src_ip}:{src_port}" if src_port else str(src_ip)
            dst_display = f"{dst_ip}:{dst_port}" if dst_port else str(dst_ip)

        if args.eth:
            print(f"{BOLD}[{timestamp}]{RESET} {proto_color}{proto:4}{RESET} "
                  f"{src_display:27} {GREEN}→{RESET} "
                  f"{dst_display:27} "
                  f"{DIM}{eth_type_name:8} {details[:35]}{RESET}")
        else:
            print(f"{BOLD}[{timestamp}]{RESET} {proto_color}{proto:4}{RESET} "
                  f"{src_display:22} {GREEN}→{RESET} "
                  f"{dst_display:22} "
                  f"{DIM}{details}{RESET}")


def process_packets(packets, args, lightpcap=False):
    if not packets:
        print(f"{YELLOW}[!] No packets to process{RESET}")
        return

    print(f"{GREEN}[+] Analyzing {len(packets)} packets...{RESET}\n")

    if not lightpcap:
        print_table_header(args)

    packet_count = 0
    for idx, packet in enumerate(packets, 1):
        if lightpcap:
            packet = LoadFromLightHexToScapyPackets([packet['data']])[0]

        if args.mac:
            eth = packet[Ether] if Ether in packet else None
            if eth:
                if args.mac.lower() not in (eth.src.lower(), eth.dst.lower()):
                    continue

        packet_count += 1
        packet_callback(packet, args.verbose, packet_count, args)

    print(f"\n{GREEN}[+] Processed {packet_count} packets{RESET}")


def main():
    args = parse_args()

    if args.bin_load:
        packets, metadata = load_binary(args.bin_load,scapy_compatible=True)
        if packets is None:
            return
        process_packets(packets, args)

        if args.write and packets:
            wrpcap(args.write, packets)
            print(f"{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")

        export_hex_and_bin(packets, args)
        return

    if args.hex_load:
        packets = load_hexdump(args.hex_load)
        if packets is None:
            return
        scapy_packets = LoadFromLightHexToScapyPackets(packets)
        process_packets(scapy_packets, args)

        if args.write and packets:
            wrpcap(args.write, packets)
            print(f"{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")

        export_hex_and_bin(scapy_packets, args)
        return

    if args.read:
        try:
            file_type = detect_file_type(args.read)

            if file_type == 'lightbin':
                packets, metadata = load_binary(args.read,scapy_compatible=True)
                if packets is None:
                    return
            else:
                if file_type == 'unknown':
                    print(f"{YELLOW}[!] Unknown file format: {args.read}{RESET}")
                    print(f"{YELLOW}[!] Trying as PCAP...{RESET}")
                packets = rdpcap(args.read)
                print(f"{GREEN}[+] Loaded {len(packets)} packets from {args.read}{RESET}")

            if not packets:
                print(f"{YELLOW}[!] No packets in file{RESET}")
                return

            if args.filter:
                packets = apply_filter(packets, args.filter)

            if args.count > 0 and args.count < len(packets):
                packets = packets[:args.count]
                print(f"{GREEN}[+] Limited to {args.count} packets{RESET}")

            process_packets(packets, args)

            if args.write and packets:
                wrpcap(args.write, packets)
                print(f"{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")

            export_hex_and_bin(packets, args)
            return

        except FileNotFoundError:
            print(f"{RED}[-] File not found: {args.read}{RESET}")
            return
        except Exception as e:
            print(f"{RED}[-] Error loading file: {e}{RESET}")
            return

    filter_parts = []

    if args.arp:
        filter_parts.append("arp")
    if args.tcp:
        filter_parts.append("tcp")
    if args.udp:
        filter_parts.append("udp")
    if args.icmp:
        filter_parts.append("icmp")
    if args.igmp:
        filter_parts.append("igmp")
    if args.ipv4:
        filter_parts.append("ip")
    if args.ipv6:
        filter_parts.append("ip6")
    if args.sctp:
        filter_parts.append("sctp")
    if args.icmpv6:
        filter_parts.append("icmpv6")

    if filter_parts:
        args.filter = " or ".join(filter_parts)
    elif args.filter:
        pass
    else:
        args.filter = None

    stats = None
    if args.stats or args.export_stats:
        stats = FlowStatistics()

    if not args.quiet:
        print(f"""
{GREEN}╔══════════════════════════════════════╗
║           LightSniff v{Version}          ║
║      Light-Scan Packet Sniffer       ║
╚══════════════════════════════════════╝{RESET}
        """)

    if not check_admin():
        print(f"{YELLOW}[!] Warning: Running without admin/root privileges{RESET}")
        print(f"{YELLOW}[!] Some interfaces may not be accessible{RESET}\n")

    if args.interfaces:
        print(f"{GREEN}[+] Available interfaces:{RESET}")
        for iface in get_interfaces():
            print(f"    - {iface}")
        print(f"\n{GREEN}[+] Usage: LightSniff -i eth0 -f 'tcp port 80' -w capture.pcap{RESET}")
        return

    if not args.interface:
        print(f"{YELLOW}[!] No interface specified{RESET}")
        print(f"{GREEN}[+] Available interfaces:{RESET}")
        for iface in get_interfaces():
            print(f"    - {iface}")
        print(f"\n{GREEN}[+] Usage: LightSniff -i eth0 -f 'tcp port 80' -w capture.pcap{RESET}")
        return

    if args.mac:
        mac_filter = args.mac.lower()
        print(f"{CYAN}[+] Filtering by MAC: {mac_filter}{RESET}")

    print(f"{GREEN}[+] Sniffing on {args.interface}{RESET}")
    if args.filter:
        print(f"{CYAN}[+] Filter: {args.filter}{RESET}")
    if args.eth:
        print(f"{CYAN}[+] Ethernet mode enabled (showing MAC addresses){RESET}")
    if args.vlan:
        print(f"{CYAN}[+] VLAN tag detection enabled{RESET}")
    if args.count > 0:
        print(f"{YELLOW}[+] Capturing {args.count} packets...{RESET}")
    else:
        print(f"{YELLOW}[+] Press Ctrl+C to stop{RESET}")
    print()

    print_table_header(args)

    packets = []
    packet_count = 0

    def callback(packet):
        nonlocal packet_count
        packet_count += 1

        if args.mac:
            eth = packet[Ether] if Ether in packet else None
            if eth:
                if args.mac.lower() not in (eth.src.lower(), eth.dst.lower()):
                    return

        if stats:
            stats.update(packet)

        packets.append(packet)
        packet_callback(packet, args.verbose, len(packets), args)

    try:
        if args.count > 0:
            sniff(
                iface=args.interface,
                filter=args.filter,
                count=args.count,
                prn=callback,
                store=True,
                promisc=not args.no_promisc
            )
        else:
            print(f"{YELLOW}[+] Sniffing indefinitely. Press Ctrl+C to stop...{RESET}\n")
            sniff(
                iface=args.interface,
                filter=args.filter,
                prn=callback,
                store=True,
                promisc=not args.no_promisc,
                timeout=None
            )

        if args.write and packets:
            wrpcap(args.write, packets)
            print(f"\n{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")

        export_hex_and_bin(packets, args)

        if stats and args.stats:
            stats.display_summary()

        if stats and args.export_stats:
            export_stats_to_file(stats, args.export_stats)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Stopped by user{RESET}")
        if args.write and packets:
            wrpcap(args.write, packets)
            print(f"{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")

        if stats and args.stats:
            print("\n")
            stats.display_summary()

        if stats and args.export_stats:
            export_stats_to_file(stats, args.export_stats)
    except PermissionError:
        print(f"{RED}[-] Permission denied! Run as administrator/root.{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error: {e}{RESET}")

    if packets and args.verbose:
        print(f"\n{GREEN}[+] Captured {len(packets)} packets{RESET}")


if __name__ == "__main__":
    main()