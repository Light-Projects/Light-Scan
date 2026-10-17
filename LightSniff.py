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
import signal

from HexSave.LightHex import load_hexdump, save_hexdump

from ch_admin import check_admin
from Sfaces import get_eth_type_name
from confparser import sniffer_parser

from LightPacket.file.dtype import detect_file_type
from Interfaces import interfaces

from packet_process import apply_filter, export_stats_to_file
from Decoration.Colors import *

from LightPacket import (
    Sniffer,PcapWrite,PcapRead,LbnWrite,LbnRead,PcapngWriter,PcapngReader,
    DetectLayer, BaseLayer
)

from LightPacket.l3 import (
    IPv6,IPv4,TCP,UDP
)
from LightPacket.l2 import (
    Ethernet, EAPOL, Raw, ARP, SLLv1, SLLv2, Dot3, LLC,
    SNAP, VLAN, Fragment, STP
)

from dquic import detect_quicc


def signal_handler(sig,frame):
    raise SystemExit()

signal.signal(signal.SIGTERM,signal_handler)

Version = "1.0.4"
_iface, count = sniffer_parser()

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
        elif ARP in packet:
            proto = "ARP"
        elif IPv6 in packet:
            proto = "IPv6"
        elif IPv4 in packet:
            proto = "IPv4"
        elif STP in packet:
            proto = "STP"
        elif SNAP in packet:
            proto = "SNAP"
        elif LLC in packet:
            proto = "LLC"
        elif Dot3 in packet:
            proto = "Dot3"
        elif Ethernet in packet:
            proto = "Ether"

        self.stats['protocols'][proto] = self.stats['protocols'].get(proto, 0) + 1

        src = "N/A"
        dst = "N/A"


        if IPv4 in packet:
            src = packet[IPv4].src
            dst = packet[IPv4].dst
        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst
        elif ARP in packet:
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
        else:
            if Ethernet in packet:
                src = packet[Ethernet].src
                dst = packet[Ethernet].dst
            elif Dot3 in packet:
                src = packet[Dot3].src
                dst = packet[Dot3].dst

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
                             "--read/-r files to their first 100 packets.")
    saving.add_argument("-w", "--write", help="Save to PCAP/PCAPNG/LBN/LHEX file")
    saving.add_argument("-r", "--read", help="Read packets from PCAP/PCAPNG/LBN/LHEX file (offline mode)")
    saving.add_argument("-C", "--compress", action="store_true", help="To compress saved output (only for LBN)")
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
    return ""



def packet_callback(packet, verbose, packet_count, args,linktype):
    timestamp = time.strftime('%H:%M:%S')
    if not isinstance(packet, BaseLayer):
        packet = DetectLayer().start(packet,linktype=linktype)
    if Ethernet in packet:
        eth = packet[Ethernet]
        src_mac = eth.src if eth else "N/A"
        dst_mac = eth.dst if eth else "N/A"
        eth_type = eth.ethertype if eth and Ethernet in packet else "N/A"
        eth_type_name = get_eth_type_name(eth_type)
        proto = "Ether"
        proto_color = GREY
        details = ""
    elif Dot3 in packet:
        dot3 = packet[Dot3]
        src_mac = dot3.src if dot3 else "N/A"
        dst_mac = dot3.dst if dot3 else "N/A"
        eth_type = dot3.length
        eth_type_name = f"Len:{dot3.length}"
        proto = "Dot3"
        proto_color = GREY
        details = f"Len:{dot3.length}"

    elif SLLv2 in packet or SLLv1 in packet:
        if SLLv2 in packet:
            sll = packet[SLLv2]
            proto = "SLLv2"
        else:
            sll = packet[SLLv1]
            proto = "SLLv1"
        proto_color = CYAN
        src_mac = sll.addr if hasattr(sll, 'addr') else "N/A"
        dst_mac = "N/A"
        eth_type = sll.proto
        eth_type_name = get_eth_type_name(eth_type)

        pkttype = sll.packet_type
        pkttype_names = {
            0: "unicast-to-us",
            1: "broadcast",
            2: "multicast",
            3: "unicast-to-another",
            4: "sent-by-us"
        }
        details = f"SLL pkttype:{pkttype_names.get(pkttype, pkttype)}"

        if eth_type == 0x0800:
            pass
    else:
        try:
            if hasattr(packet, 'build') and callable(packet.build):
                byt = packet.build()
            else:
                byt = bytes(packet)
        except Exception:
            byt = b''
        print(f"[{timestamp}] {RED}Raw{RESET} {GREY}bytes={byt[:20]} size={len(byt)}{RESET}")
        return

    vlan_id = None
    if VLAN in packet and args.vlan:
        vlan = packet[VLAN]
        vlan_id = vlan.vlan_id

    src_ip = "N/A"
    dst_ip = "N/A"
    size = len(packet)

    if LLC in packet:
        llc = packet[LLC]
        proto = "LLC"
        proto_color = CYAN
        details = f"DSAP:{hex(llc.dsap)} SSAP:{hex(llc.ssap)}"

    if SNAP in packet:
        snap = packet[SNAP]
        proto = "SNAP"
        proto_color = BLUE
        eth_type = snap.pid
        eth_type_name = get_eth_type_name(eth_type)
        oui_val = snap.oui if isinstance(snap.oui, str) else hex(snap.oui) if isinstance(snap.oui,int) else snap.oui.hex()
        details = f"OUI:{oui_val} PID:{hex(snap.pid)}"

    if STP in packet:
        proto = "STP"
        proto_color = PURPLE
        details = "STP"

    if EAPOL in packet:
        proto = "EAPOL"
        proto_color = YELLOW
        details = f"ver: {packet[EAPOL].version} code: {packet[EAPOL].code}"

    if IPv4 in packet:
        ip = packet[IPv4]
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

    if TCP in packet:
        tcp = packet[TCP]
        proto = "TCP"
        proto_color = GREEN
        flags = tcp.flags
        details = f"S:{tcp.sport} → D:{tcp.dport} Flags:[{flags}]"

        tls_ports = [443, 465, 587, 993, 995, 8443, 8080]
        is_tls_port = tcp.sport in tls_ports or tcp.dport in tls_ports
        if Raw in packet or Fragment in packet:
            if Raw in packet:
                pyl = packet[Raw]
            else:
                pyl = packet[Fragment]

            if not len(pyl) > 5:
                return

            payload = bytes(pyl)

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

        ssh_ports = [22]
        if tcp.dport in ssh_ports or tcp.sport in ssh_ports:
            if Raw in packet or Fragment in packet:
                if Raw in packet:
                    pyl = packet[Raw]
                else:
                    pyl = packet[Fragment]

                try:
                    payload = bytes(pyl)

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
        if (tcp.dport in ftp_ports or tcp.sport in ftp_ports) and Raw in packet or Fragment in packet:
            if Raw in packet:
                pyl = packet[Raw]
            else:
                pyl = packet[Fragment]

            try:
                payload = bytes(pyl)
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

            if Raw in packet or Fragment in packet:
                if Raw in packet:
                    pyl = packet[Raw]
                else:
                    pyl = packet[Fragment]

                try:
                    payload = bytes(pyl)
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

        try:
            if Raw in packet or Fragment in packet:
                if Raw in packet:
                    pyl = packet[Raw]
                else:
                    pyl = packet[Fragment]

                try:
                    payload = bytes(pyl)
                    size = len(pyl)

                    is_quic, header_type, quic_details = detect_quicc(payload, udp.dport, udp.sport)

                    if is_quic or udp.dport == 443 or udp.sport == 443:
                        proto = "QUIC"
                        proto_color = BLUE
                        details = quic_details
                        size = len(payload)

                        details += f" | S:{udp.sport} → D:{udp.dport}"
                except:
                    pass

        except Exception as e:
            if args.verbose:
                details = f"QUIC parse error: {e}"
            pass

    elif ARP in packet:
        arp = packet[ARP]
        proto = "ARP"
        proto_color = PURPLE
        src_ip = arp.ipsrc
        dst_ip = arp.ipdst
        details = f"{arp.ipsrc} → {arp.ipdst}"
        size = 0

    if vlan_id is not None:
        details += f" [VLAN:{vlan_id}]"

    if verbose:
        print(f"{BOLD}[{timestamp}]{RESET} {proto_color}{proto:6}{RESET} "
              f"{str(src_ip):16} {GREEN}→{RESET} {str(dst_ip):16} | "
              f"{src_mac} {GREEN}→{RESET} {dst_mac} | "
              f"{eth_type_name:8} | "
              f"{details}  "
              f"Size: {size:4} bytes")
    else:
        src_port = extract_port(packet, 'src')
        dst_port = extract_port(packet, 'dst')

        if args.eth or (src_ip == "N/A" and dst_ip == "N/A"):
            src_display = f"  {src_mac}"
            dst_display = f"{dst_mac}"

        else:
            src_display = f"  {src_ip}:{src_port}  " if src_port else str(src_ip)
            dst_display = f"{dst_ip}:{dst_port}  " if dst_port else str(dst_ip)

        if args.eth or (src_ip == "N/A" and dst_ip == "N/A"):
            print(f"{BOLD}[{timestamp}]{RESET} {proto_color}{proto}{RESET} "
                  f" {src_display:28}  "
                  f" {dst_display:28}  "
                  f"{DIM}{eth_type_name}        {details[:35]}{RESET}")
        else:
            print(f"{BOLD}[{timestamp}]{RESET} {proto_color}{proto:4}{RESET} "
                  f"{src_display:22}   {GREEN}→{RESET} "
                  f"{dst_display:22} "
                  f"{DIM} {details}{RESET}")


def process_packets(packets, args, lightpcap=False,link=1):
    if not packets:
        print(f"{YELLOW}[!] No packets to process{RESET}")
        return

    print(f"{GREEN}[+] Analyzing {len(packets)} packets...{RESET}\n")


    packet_count = 0
    for idx, packet in enumerate(packets, 1):
        parsed = packet if isinstance(packet, BaseLayer) else DetectLayer().start(packet, linktype=link)

        if args.mac:
            mac_filter = args.mac.lower()
            src_m = None
            dst_m = None
            if Ethernet in parsed:
                src_m = str(parsed[Ethernet].src).lower()
                dst_m = str(parsed[Ethernet].dst).lower()
            elif Dot3 in parsed:
                src_m = str(parsed[Dot3].src).lower()
                dst_m = str(parsed[Dot3].dst).lower()

            if not (src_m and dst_m and (mac_filter in (src_m, dst_m))):
                continue

        packet_count += 1
        packet_callback(parsed, args.verbose, packet_count, args, link)

    print(f"\n{GREEN}[+] Processed {packet_count} packets{RESET}")


def main():
    args = parse_args()

    if args.read:
        try:
            file_type = detect_file_type(args.read)

            if file_type == 'lightbin':
                packets = LbnRead(args.read)
                if packets is None:
                    return
                link = 1
            elif file_type == 'pcap':
                data = PcapRead(args.read)
                packets = [i['data'] for i in data[1]]
                link = data[0][0]['network']
            elif file_type == 'pcapng':
                packets = []
                with PcapngReader(args.read) as pcap:
                    p = list(pcap)
                    packets.extend([i.data for i in p])
                    link = pcap.interfaces[0].link_type
            elif args.read.endswith('.lhex') or args.read.endswith('.hex'):
                packets = load_hexdump(args.read)
                link = 1
            else:
                if file_type == 'unknown':
                    print(f"{YELLOW}[!] Unknown file format: {args.read}{RESET}")
                    print(f"{YELLOW}[!] Trying as PCAP...{RESET}")
                data = PcapRead(args.read)
                packets = [i['data'] for i in data[1]]
                link = data[0][0]['network']
                print(f"{GREEN}[+] Loaded {len(packets)} packets from {args.read}{RESET}")

            if not packets:
                print(f"{YELLOW}[!] No packets in file{RESET}")
                return

            if args.filter:
                packets = apply_filter(packets, args.filter)

            if args.count > 0 and args.count < len(packets):
                packets = packets[:args.count]
                print(f"{GREEN}[+] Limited to {args.count} packets{RESET}")

            process_packets(packets, args, link=link)

            if args.write and packets:
                if args.write.endswith('.pcap'):
                    PcapWrite(packets, args.write, linktype=link)
                elif args.write.endswith('.pcapng'):
                    with PcapngWriter(args.write) as pcap:
                        ifa = pcap.add_interface(link, 65535, args.interface)
                        for i in packets:
                            pcap.write_packet(ifa, int(time.time()) * 1_000_000, i)
                        pcap.close()
                elif args.write.endswith('.lhex') or args.write.endswith('.hex'):
                    save_hexdump(packets, args.write)
                else:
                    if args.compress:
                        LbnWrite(args.write, packets, compress=1)
                    else:
                        LbnWrite(args.write, packets)
                print(f"{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")

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
        for iface in interfaces:
            print(f"    - {iface}")
        print(f"\n{GREEN}[+] Usage: LightSniff -i eth0 -f 'tcp port 80' -w capture.pcap{RESET}")
        return

    if not args.interface:
        if args.verbose:
            print(f"{YELLOW}[!] No interface specified, (using conf) .{RESET}")
        args.interface = _iface

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

    if args.count > 0:
        print(f"{YELLOW}[+] Sniffing indefinitely. Press Ctrl+C to stop...{RESET}\n")

    print()

    packets = []
    packet_count = 0
    _linktype = 1
    snaplen = 65535

    def callback(packet):
        nonlocal packet_count
        parsed_packet = packet if isinstance(packet, BaseLayer) else DetectLayer().start(packet, linktype=_linktype)

        if args.mac:
            mac_filter = args.mac.lower()
            src_m = None
            dst_m = None
            if Ethernet in parsed_packet:
                src_m = str(parsed_packet[Ethernet].src).lower()
                dst_m = str(parsed_packet[Ethernet].dst).lower()
            elif Dot3 in parsed_packet:
                src_m = str(parsed_packet[Dot3].src).lower()
                dst_m = str(parsed_packet[Dot3].dst).lower()

            if not (src_m and dst_m and (mac_filter in (src_m, dst_m))):
                return

        packet_count += 1

        if stats:
            stats.update(parsed_packet)

        packets.append(packet)
        packet_callback(parsed_packet, args.verbose, len(packets), args, _linktype)


    try:
        _sniffer = Sniffer(
            iface=args.interface,
            filter=args.filter,
            count=args.count,
            promisc=not args.no_promisc,
        )
        _linktype = _sniffer.__link__()
        snaplen = _sniffer.snaplen
        _sniffer.start(callback=callback)

        if args.write and packets:
            if args.write.endswith('.pcap'):
                PcapWrite(packets,args.write,linktype=_linktype)
            elif args.write.endswith('.pcapng'):
                with PcapngWriter(args.write) as pcap:
                    ifa = pcap.add_interface(_linktype,snaplen,args.interface)
                    for i in packets:
                        pcap.write_packet(ifa,int(time.time()) * 1_000_000,i)
                    pcap.close()
            elif args.write.endswith('.lhex') or args.write.endswith('.hex'):
                save_hexdump(packets,args.write)
            else:
                if args.compress:
                    LbnWrite(args.write, packets, compress=1)
                else:
                    LbnWrite(args.write, packets)
            print(f"\n{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")


        if stats and args.stats:
            stats.display_summary()

        if stats and args.export_stats:
            export_stats_to_file(stats, args.export_stats)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Stopped by user{RESET}")
        if args.write and packets:
            if args.write.endswith('.pcap'):
                PcapWrite(packets, args.write, linktype=_linktype)
            elif args.write.endswith('.pcapng'):
                with PcapngWriter(args.write) as pcap:
                    ifa = pcap.add_interface(_linktype, snaplen, args.interface)
                    for i in packets:
                        pcap.write_packet(ifa, int(time.time()) * 1_000_000, i)
                    pcap.close()
            elif args.write.endswith('.lhex') or args.write.endswith('.hex'):
                save_hexdump(packets,args.write)
            else:
                if args.compress:
                    LbnWrite(args.write, packets, compress=1)
                else:
                    LbnWrite(args.write, packets)
            print(f"{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")

        if stats and args.stats:
            print("\n")
            stats.display_summary()

        if stats and args.export_stats:
            export_stats_to_file(stats, args.export_stats)
    except PermissionError:
        print(f"{RED}[-] Permission denied! Run as administrator/root.{RESET}")
    except SystemExit:
        if args.write and packets:
            if args.write.endswith('.pcap'):
                PcapWrite(packets, args.write, linktype=_linktype)
            elif args.write.endswith('.pcapng'):
                with PcapngWriter(args.write) as pcap:
                    ifa = pcap.add_interface(_linktype, snaplen, args.interface)
                    for i in packets:
                        pcap.write_packet(ifa, int(time.time()) * 1_000_000, i)
                    pcap.close()
            elif args.write.endswith('.lhex') or args.write.endswith('.hex'):
                save_hexdump(packets,args.write)
            else:
                if args.compress:
                    LbnWrite(args.write, packets, compress=1)
                else:
                    LbnWrite(args.write, packets)
            print(f"{GREEN}[+] Saved {len(packets)} packets to {args.write}{RESET}")

        if stats and args.stats:
            print("\n")
            stats.display_summary()

        if stats and args.export_stats:
            export_stats_to_file(stats, args.export_stats)
    except Exception as e:
        print(f"{RED}[-] Error: {e}{RESET}")


    if packets and args.verbose:
        print(f"\n{GREEN}[+] Captured {len(packets)} packets{RESET}")


if __name__ == "__main__":
    main()
