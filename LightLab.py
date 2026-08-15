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

import ast
import cmd
import time
import re
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6Unknown
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.layers.http import HTTPRequest, HTTP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from LightLayers.layer7.ssh import SSH
from LightLayers.layer7.ftp import FTPRequest, FTPResponse
from HexSave.LightHex import save_hexdump, load_hexdump
from HexSave.ScapyLoader.ScapyPacketsLoader import LoadFromLightHexToScapyPackets
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq, IGMPv3mr, IGMPv3gr
from scapy.layers.sctp import SCTP, SCTPChunkInit, SCTPChunkInitAck, SCTPChunkCookieEcho, SCTPChunkCookieAck, \
    SCTPChunkAbort, SCTPChunkData, SCTPChunkShutdown, SCTPChunkShutdownAck, SCTPChunkShutdownComplete, SCTPChunkSACK, \
    SCTPChunkHeartbeatReq, SCTPChunkHeartbeatAck, SCTPChunkError
from Decoration.Colors import *
import struct
import pickle
import zlib
from Sfaces import lbn_chksum

bind_layers(TCP, SSH, dport=22)
bind_layers(TCP, FTPRequest, dport=21)
bind_layers(IP, IGMP, proto=2)
bind_layers(IGMPv3, IGMPv3mq, type=0x11)
bind_layers(IGMPv3, IGMPv3mr, type=0x22)

version = "1.0.1"

LIGHTBIN_MAGIC = b'LBN\x00'
LIGHTBIN_VERSION = 1
FLAG_NULL = 0x00
FLAG_COMPRESSED = 0x01
FLAG_METADATA_ONLY = 0x02

def save_binary(filename, packets, layers=None, args=None, stats=None):
    try:
        packet_data = []
        for pkt in packets:
            timestamp = time.time()
            raw_bytes = zlib.compress(bytes(pkt), 6)
            packet_data.append({
                'timestamp': timestamp,
                'size': len(raw_bytes),
                'data': raw_bytes
            })
        Timeheader = int(time.time())

        metadata = {
            'version': LIGHTBIN_VERSION,
            'created': Timeheader,
            'packet_count': len(packets),
            'args': vars(args) if args else None,
            'stats': stats,
            'tool': 'LightLab'
        }
        CHKSUM = lbn_chksum(LIGHTBIN_VERSION, Timeheader, len(packets), FLAG_COMPRESSED)

        header = struct.pack(
            '<4sIIIII',
            LIGHTBIN_MAGIC,
            LIGHTBIN_VERSION,
            Timeheader,
            len(packet_data),
            FLAG_COMPRESSED,
            CHKSUM
        )

        with open(filename, 'wb') as f:
            f.write(header)
            for pkt in packet_data:
                f.write(struct.pack('<dI', pkt['timestamp'], pkt['size']))
                f.write(pkt['data'])

            metadata_bytes = pickle.dumps(metadata)
            metadata_bytes = zlib.compress(metadata_bytes, 6)
            f.write(struct.pack('<I', len(metadata_bytes)))
            f.write(metadata_bytes)

        print(f"{GREEN}[+] Saved {len(packets)} packets to {filename} (LightBin){RESET}")
        return True
    except Exception as e:
        print(f"{RED}[!] Save failed: {e}{RESET}")
        return False


def parse_igmpv3gr(record_str):
    try:
        if record_str.strip().startswith('{'):
            parsed = ast.literal_eval(record_str)
            return IGMPv3gr(**parsed)
    except:
        pass

    rtype_match = re.search(r"rtype[=:]\s*(\d+)", record_str)
    rtype = int(rtype_match.group(1)) if rtype_match else 1

    maddr_match = re.search(r"maddr[=:]\s*['\"]?([^'\")\s]+)['\"]?", record_str)
    maddr = maddr_match.group(1) if maddr_match else "0.0.0.0"

    srcaddrs = []
    srcaddrs_match = re.search(r"srcaddrs[=:]\s*\[([^\]]*)\]", record_str)
    if srcaddrs_match:
        src_list = srcaddrs_match.group(1)
        ip_matches = re.findall(r"['\"]?([0-9.]+)['\"]?", src_list)
        srcaddrs = [ip for ip in ip_matches if ip]

    if srcaddrs:
        return IGMPv3gr(rtype=rtype, maddr=maddr, srcaddrs=srcaddrs)
    else:
        return IGMPv3gr(rtype=rtype, maddr=maddr)


def load_binary(filename):
    try:
        with open(filename, 'rb') as f:
            header_data = f.read(24)
            if len(header_data) != 24:
                raise ValueError("Invalid LightBin file")

            magic, version, created, count, flags, ck = struct.unpack('<4sIIIII', header_data)

            if magic != LIGHTBIN_MAGIC:
                raise ValueError(f"Invalid LightBin magic: {magic}")

            is_compressed = bool(flags & FLAG_COMPRESSED)
            is_only_met = bool(flags & FLAG_NULL)
            chksum = lbn_chksum(version, created, count, flags)

            print(f"{GREEN}[+] Loading LightBin...{RESET}")
            print(f"{CYAN}     Version: {version}{RESET}")
            print(f"{CYAN}     Created: {time.ctime(created)}{RESET}")
            print(f"{CYAN}     Packets: {count}{RESET}")
            if is_compressed:
                print(f"{CYAN}     Compression: Enabled{RESET}")
            elif is_only_met:
                print(f"{CYAN}     Metadata-Only: Enabled{RESET}")

            if ck != chksum:
                print(f"{RED}     Chksum: Invalid{RESET}")

            packets = []
            for i in range(1):
                pkt_header = f.read(12)
                if len(pkt_header) != 12:
                    break
                timestamp, size = struct.unpack('<dI', pkt_header)
                pkt_data = f.read(size)
                if len(pkt_data) != size:
                    break
                if is_compressed:
                    pkt_data = zlib.decompress(pkt_data)

                if len(pkt_data) > 0:
                    first_byte = pkt_data[0]
                    if first_byte in [0x45, 0x46]:
                        try:
                            from scapy.layers.inet import IP as IPLayer
                            packet = IPLayer(pkt_data)
                        except:
                            packet = Ether(pkt_data)
                    elif first_byte == 0x60:
                        try:
                            from scapy.layers.inet6 import IPv6 as IPv6Layer
                            packet = IPv6Layer(pkt_data)
                        except:
                            packet = Ether(pkt_data)
                    else:
                        try:
                            packet = Ether(pkt_data)
                            if packet.haslayer(IP) and packet.haslayer(IPv6):
                                try:
                                    from scapy.layers.inet import IP as IPLayer
                                    packet = IPLayer(pkt_data)
                                except:
                                    packet = Ether(pkt_data)
                            elif packet.haslayer(ARP):
                                packet = Ether(pkt_data)
                        except:
                            packet = Ether(pkt_data)
                else:
                    packet = Ether(pkt_data)

                packets.append(packet)

            metadata = {}
            if flags & FLAG_METADATA_ONLY or flags & FLAG_COMPRESSED:
                try:
                    metadata_size_bytes = f.read(4)
                    if len(metadata_size_bytes) == 4:
                        metadata_size = struct.unpack('<I', metadata_size_bytes)[0]
                        metadata_bytes = f.read(metadata_size)
                        if is_compressed:
                            try:
                                metadata_bytes = zlib.decompress(metadata_bytes)
                            except zlib.error as e:
                                print(f"{YELLOW}[!] Warning: Could not decompress metadata: {e}{RESET}")
                        metadata = pickle.loads(metadata_bytes)
                except:
                    pass

                print(f"{GREEN}[+] Loaded {len(packets)} packets{RESET}")
                return packets, metadata

            print(f"{GREEN}[+] Loaded {len(packets)} packets{RESET}")
            return packets, None

    except FileNotFoundError:
        print(f"{RED}[-] File not found: {filename}{RESET}")
        return None, None
    except Exception as e:
        print(f"{RED}[!] Load failed: {e}{RESET}")
        return None, None


class LightLab(cmd.Cmd):
    intro = f"""
{BOLD}{CYAN}LightLab v{version} - Lightscan Packet Crafting Laboratory{RESET}
{YELLOW}Type 'help' for commands{RESET}
"""
    prompt = f"{CYAN}LightLab>{RESET} "

    def __init__(self):
        super().__init__()
        self.packet_layers = []
        self.timeout = 10
        self.interval = 0.5
        self._history = []

        self.layer_params = {
            'ether': ['dst', 'src', 'type'],
            'vlan': ['prio', 'vlan', 'dei', 'type'],
            'arp': ['hwtype', 'ptype', 'hwlen', 'plen', 'op', 'hwsrc', 'psrc', 'hwdst', 'pdst'],
            'ip': ['dst', 'src', 'ttl', 'id', 'flags', 'proto', 'version', 'ihl', 'len', 'tos', 'frag', 'chksum'],
            'ipv6': ['dst', 'src', 'hlim', 'nh', 'version', 'tc', 'fl', 'plen'],
            'ndp_ns': ['tgt', 'type', 'code', 'cksum', 'res'],
            'ndp_na': ['tgt', 'R', 'S', 'O', 'type', 'code', 'cksum', 'res'],
            'ndp_rs': ['type', 'code', 'cksum', 'res'],
            'ndp_ra': ['chlim', 'M', 'O', 'H', 'P', 'prf', 'type', 'code', 'cksum', 'res', 'reachabletime',
                       'retranstimer', 'routerlifetime'],
            'tcp': ['dport', 'sport', 'flags', 'seq', 'ack', 'dataofs', 'chksum', 'window', 'urgptr', 'reserved',
                    'options'],
            'udp': ['dport', 'sport', 'len', 'chksum'],
            'ssh': ['data', 'padding', 'packet_length', 'padding_length'],
            'sctp': ['sport', 'dport', 'tag', 'chksum'],
            'sctp_init': ['init_tag', 'a_rwnd', 'n_out_streams', 'n_in_streams', 'init_tsn', 'flags', 'type', 'len'],
            'sctp_init_ack': ['init_tag', 'a_rwnd', 'n_out_streams', 'n_in_streams', 'init_tsn', 'flags', 'type',
                              'len'],
            'sctp_cookie_echo': ['cookie', 'flags', 'len', 'type'],
            'sctp_cookie_ack': ['flags', 'len', 'type'],
            'sctp_abort': ['len', 'TCB', 'error_causes', 'reserved', 'type'],
            'sctp_data': ['tsn', 'stream_id', 'stream_seq', 'proto_id', 'data', 'type', 'reserved', 'delay_sack',
                          'unordered', 'beginning', 'ending'],
            'sctp_shutdown': ['cumul_tsn_ack', 'flags', 'type', 'len'],
            'sctp_shutdown_ack': ['flags', 'len', 'type'],
            'sctp_shutdown_complete': ['type', 'len', 'TCB', 'reserved'],
            'sctp_sack': ['cum_tsn_ack', 'a_rwnd', 'n_gap_ack', 'type', 'len', 'flags', 'n_dup_tsn', 'gap_ack_list',
                          'dup_tsn_list'],
            'sctp_heartbeat': ['type', 'flags', 'len'],
            'sctp_heartbeat_ack': ['type', 'flags', 'len'],
            'sctp_error': ['error_causes', 'type', 'len', 'flags'],
            'igmp': ['type', 'mrcode', 'chksum', 'gaddr'],
            'igmpv3': ['type', 'mrcode', 'chksum'],
            'igmpv3mq': ['gaddr', 'resv', 's', 'qrv', 'qqic', 'numsrc', 'srcaddrs'],
            'igmpv3mr': ['res2', 'numgrp', 'records'],
            'ftp': ['comd', 'arg'],
            'dns': ['id', 'qr', 'opcode', 'aa', 'tc', 'rd', 'ra', 'z', 'rcode', 'qdcount', 'ancount', 'nscount',
                    'arcount', 'qd', 'an', 'ns', 'ar'],
            'icmp': ['type', 'code', 'id', 'seq', 'chksum', 'ts_ori', 'ts_rx', 'ts_tx', 'gw', 'ptr', 'reserved',
                     'addr_mask',
                     'nexthopmtu', 'unused', 'extpad', 'ext'],
            'icmpv6': ['type', 'code', 'cksum', 'msgbody'],
            'icmpv6_echo': ['type', 'code', 'cksum', 'id', 'seq', 'data'],
            'http': ['Method', 'Path', 'Http_Version', 'Host', 'Connection', 'Content_Type', 'Content_Length',
                     'User_Agent', 'Cookie', 'Referer', 'Accept', 'Accept_Language', 'Accept_Encoding',
                     'Upgrade_Insecure_Requests', 'Origin', 'Cache_Control', 'Pragma', 'Authorization',
                     'X_Forwarded_For',
                     'Proxy_Authorization', 'Proxy_Connection', 'Keep_Alive', 'X_Wap_Profile', 'X_Request_ID', 'DNT',
                     'TE',
                     'Date', 'Upgrade', 'X_ATT_DeviceId', 'X_Correlation_ID', 'X_Csrf_Token', 'X_Forwarded_Host',
                     'X_Forwarded_Proto',
                     'X_Http_Method_Override', 'X_Requested_With', 'X_UIDH', 'Unknown_Headers', 'Content_MD5'],
            'raw': ['load']
        }

    def onecmd(self, line):
        if line and line not in ['history', 'exit', 'quit']:
            self._history.append(line)
        return super().onecmd(line)

    def do_new(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: new <layer>{RESET}")
            return

        layer_type = arg.lower()
        valid = ['ether', 'vlan', 'arp', 'ip', 'ipv6', 'tcp', 'udp', 'icmp', 'icmpv6', 'icmpv6_echo',
                 'http', 'raw', 'ndp_ns', 'ndp_na', 'ndp_rs', 'ndp_ra', 'dns', 'ssh', 'ftp', 'sctp', 'sctp_init',
                 'sctp_init_ack', 'sctp_cookie_echo', 'sctp_cookie_ack',
                 'sctp_abort', 'sctp_data', 'sctp_shutdown', 'sctp_shutdown_ack',
                 'sctp_shutdown_complete', 'sctp_sack', 'sctp_heartbeat', 'sctp_heartbeat_ack',
                 'sctp_error', 'igmp', 'igmpv3', 'igmpv3mq', 'igmpv3mr']

        if layer_type not in valid:
            print(f"{RED}[!] Unknown: {layer_type}{RESET}")
            return

        self.packet_layers.append({'type': layer_type, 'params': {}})
        print(f"{GREEN}[+] Added {layer_type}{RESET}")
        self._show()

    def do_savehex(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: savehex <filename.lhex>{RESET}")
            return

        packet = self._build()
        if not packet:
            print(f"{RED}[!] Nothing to save{RESET}")
            return

        save_hexdump([packet], arg)

    def do_loadhex(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: loadbin <filename.lhex>{RESET}")
            return

        packets = load_hexdump(arg)
        packets = LoadFromLightHexToScapyPackets(packets)
        if not packets:
            return

        self._packet_to_layers(packets[0])

        print(f"{GREEN}[+] Loaded from {arg}{RESET}")
        self._show()

    def do_savebin(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: savebin <filename.lbn>{RESET}")
            return

        packet = self._build()
        if not packet:
            print(f"{RED}[!] Nothing to save{RESET}")
            return

        save_binary(arg, [packet], self.packet_layers)

    def do_loadbin(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: loadbin <filename.lbn>{RESET}")
            return

        packets, metadata = load_binary(arg)
        if not packets:
            return

        self.packet_layers = []

        if metadata and 'layers' in metadata:
            self.packet_layers = metadata['layers']
            print(f"{GREEN}[+] Loaded layers from metadata{RESET}")
        else:
            self._packet_to_layers(packets[0])

        print(f"{GREEN}[+] Loaded from {arg}{RESET}")
        self._show()

    def do_timeout(self, arg):
        try:
            self.timeout = int(arg)
            print(f"{GREEN}[+] Timeout set to {self.timeout} seconds{RESET}")
        except:
            print(f"{RED}[!] Invalid timeout{RESET}")

    def do_interval(self, arg):
        try:
            self.interval = int(arg)
            print(f"{GREEN}[+] Interval set to {self.interval} seconds{RESET}")
        except:
            print(f"{RED}[!] Invalid interval{RESET}")

    def do_params(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: params <layer>{RESET}")
            return

        layer = arg.lower()
        if layer in self.layer_params:
            print(f"\n{BOLD}{layer.upper()} parameters:{RESET}")
            for p in self.layer_params[layer]:
                print(f"  {p}")
            print()
        else:
            print(f"{RED}[!] Unknown layer: {layer}{RESET}")

    def do_set(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: set <layer>.<param>=<value>{RESET}")
            return

        try:
            if '=' not in arg or '.' not in arg:
                print(f"{RED}[!] Format: layer.param=value{RESET}")
                return

            left, value = arg.split('=', 1)
            value = value.strip().strip('"')
            layer_name, param = left.split('.', 1)
            layer_name = layer_name.lower()

            for layer in self.packet_layers:
                if layer['type'] == layer_name:
                    if param in ['dport', 'sport', 'ttl', 'id', 'tos', 'version', 'hlim', 'ihl', 'seq', 'ack', 'window',
                                 'type', 'code', 'Status_Code', 'len', 'urgptr', 'reserved', 'frag'
                                                                                             'prio', 'dei', 'vlan',
                                 'qdcount', 'ancount', 'nscount', 'arcount',
                                 'qr', 'opcode', 'proto', 'aa', 'tc', 'rd', 'ra', 'z', 'rcode', 'packet_length'
                        , 'padding_length']:
                        try:
                            if isinstance(value, str) and value.lower().startswith('0x'):
                                value = int(value, 16)
                            else:
                                value = int(value)
                        except:
                            print(f"{RED}[!] {param} needs a number{RESET}")
                            return

                    layer['params'][param] = value
                    print(f"{GREEN}[+] {layer_name}.{param} = {value}{RESET}")
                    return

            print(f"{RED}[!] Layer '{layer_name}' not found{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error: {e}{RESET}")

    def do_show(self, arg):
        self._show()

    def do_clear(self, arg):
        self.packet_layers = []
        print(f"{GREEN}[+] Cleared{RESET}")

    def do_send(self, arg):
        if not self.packet_layers:
            print(f"{RED}[!] No layers. Use 'new'{RESET}")
            return

        count = 1
        verbose = False
        if arg:
            parts = arg.split()
            if '-v' in parts:
                verbose = True
            for p in parts:
                if p.isdigit():
                    count = int(p)

        packet = self._build()
        if not packet:
            print(f"{RED}[!] Build failed{RESET}")
            return

        has_ether = any(l['type'] == 'ether' for l in self.packet_layers)
        has_http = any(l['type'] == 'http' for l in self.packet_layers)
        has_ssh = any(l['type'] == 'ssh' for l in self.packet_layers)
        has_ftp = any(l['type'] == 'ftp' for l in self.packet_layers)

        if verbose:
            print()
            packet.show2()
            print()

        print(f"{YELLOW}[*] Sending {count} packet(s)...{RESET}")

        for i in range(count):
            try:
                start = time.time()

                if has_http:
                    response = self._send_http(packet)
                    elapsed = (time.time() - start) * 1000
                    if response:
                        print(f"{GREEN}[+] Response ({elapsed:.2f}ms){RESET}")
                        print('=' * 50)
                        response.show2()
                        if response.haslayer(Raw):
                            raw = response[Raw].load
                            print(f"\n{CYAN}[RAW]{RESET}")
                            print(f"Hex: {raw.hex()}")
                            try:
                                text = raw.decode('utf-8', errors='ignore')
                                if text.strip():
                                    print(f"Text: {text[:500]}")
                            except:
                                pass
                        print('=' * 50)
                    else:
                        print(f"{YELLOW}[!] No response{RESET}")

                elif has_ftp:
                    response = self._send_ftp(packet)
                    elapsed = (time.time() - start) * 1000
                    if response:
                        print(f"{GREEN}[+] Response ({elapsed:.2f}ms){RESET}")
                        print('=' * 50)
                        response.show2()
                        if response.haslayer(Raw):
                            raw = response[Raw].load
                            print(f"\n{CYAN}[RAW]{RESET}")
                            print(f"Hex: {raw.hex()}")
                            try:
                                text = raw.decode('utf-8', errors='ignore')
                                if text.strip():
                                    print(f"Text: {text[:500]}")
                            except:
                                pass
                        print('=' * 50)
                    else:
                        print(f"{YELLOW}[!] No response{RESET}")

                elif has_ssh:
                    response = self._send_ssh(packet)
                    elapsed = (time.time() - start) * 1000
                    if response:
                        print(f"{GREEN}[+] Response ({elapsed:.2f}ms){RESET}")
                        print('=' * 50)
                        response.show2()
                        if response.haslayer(Raw):
                            raw = response[Raw].load
                            print(f"\n{CYAN}[RAW]{RESET}")
                            print(f"Hex: {raw.hex()}")
                            try:
                                text = raw.decode('utf-8', errors='ignore')
                                if text.strip():
                                    print(f"Text: {text[:500]}")
                            except:
                                pass
                        print('=' * 50)
                    else:
                        print(f"{YELLOW}[!] No response{RESET}")

                elif has_ether:
                    response, unanswered = srp(packet, timeout=self.timeout, verbose=0)
                    elapsed = (time.time() - start) * 1000
                    if response:
                        print(f"{GREEN}[+] Response ({elapsed:.2f}ms){RESET}")
                        print('=' * 50)
                        for sent, received in response:
                            received.show2()
                        print('=' * 50)
                    else:
                        print(f"{YELLOW}[!] No response{RESET}")

                else:
                    response = sr1(packet, timeout=self.timeout, verbose=0)
                    elapsed = (time.time() - start) * 1000
                    if response:
                        print(f"{GREEN}[+] Response ({elapsed:.2f}ms){RESET}")
                        print('=' * 50)
                        response.show2()
                        if response.haslayer(Raw):
                            raw = response[Raw].load
                            print(f"\n{CYAN}[RAW]{RESET}")
                            print(f"Hex: {raw.hex()[:200]}{'...' if len(raw) > 100 else ''}")
                            try:
                                text = raw.decode('utf-8', errors='ignore')
                                if text.strip():
                                    print(f"Text: {text[:500]}")
                            except:
                                pass
                        print('=' * 50)
                    else:
                        print(f"{YELLOW}[!] No response{RESET}")

                if count > 1 and i < count - 1:
                    time.sleep(self.interval)
            except Exception as e:
                print(f"{RED}[!] Error: {e}{RESET}")

    def _send_ftp(self, packet):
        if not packet.haslayer(IP):
            print(f"{RED}[!] FTP requires an IP layer{RESET}")
            return None

        ip_layer = packet[IP]
        tcp_layer = packet[TCP] if packet.haslayer(TCP) else None

        if tcp_layer and tcp_layer.dport == 21:
            dst = ip_layer.dst
            dport = tcp_layer.dport
        elif tcp_layer and tcp_layer.sport == 21:
            dst = ip_layer.src
            dport = tcp_layer.sport
        else:
            dst = ip_layer.dst
            dport = 21

        sport = random.randint(1024, 65535)
        ftp_layer = packet[FTPRequest]

        print(f"{YELLOW}[*] TCP handshake to {dst}:{dport}...{RESET}")
        syn = IP(dst=dst) / TCP(sport=sport, dport=dport, flags='S', seq=1000)
        syn_ack = sr1(syn, timeout=5, verbose=0)

        if not syn_ack or syn_ack[TCP].flags == "R" or syn_ack[TCP].flags == "RA":
            print(f"{RED}[!] No SYN-ACK — host may be down or port closed{RESET}")
            return None

        server_seq = syn_ack[TCP].seq
        server_ack = syn_ack[TCP].ack

        ack = IP(dst=dst) / TCP(
            sport=sport, dport=dport, flags='A',
            seq=server_ack, ack=server_seq + 1
        )
        send(ack, verbose=0)

        ftp_pkt = IP(dst=dst) / TCP(
            sport=sport, dport=dport, flags='PA',
            seq=server_ack, ack=server_seq + 1
        ) / ftp_layer

        print(f"{YELLOW}[*] Sending FTP request...{RESET}")
        print(f"{CYAN}[DEBUG] Command: {ftp_layer.comd}{ftp_layer.arg} {RESET}")

        response = sr1(ftp_pkt, timeout=self.timeout, verbose=0)

        if response and response.haslayer(Raw):
            raw_response = response[Raw].load
            try:
                resp_str = raw_response.decode('utf-8', errors='ignore')
                print(f"{GREEN}[+] FTP Response received:{RESET}")
                lines = resp_str.split('\r\n')
                for line in lines:
                    if line.strip():
                        print(f"    {line}")
            except Exception as e:
                print(f"{RED}[!] Failed to decode response: {e}{RESET}")
        elif response and response.haslayer(FTPResponse):
            ftp_resp = response[FTPResponse]
            print(f"{GREEN}[+] FTP Response: {ftp_resp.code} {ftp_resp.message}{RESET}")
        else:
            print(f"{YELLOW}[!] No FTP response received (or unknown format){RESET}")

        return response

    def _send_ssh(self, packet):
        if not packet.haslayer(IP):
            print(f"{RED}[!] SSH requires an IP layer{RESET}")
            return None

        ip_layer = packet[IP]
        tcp_layer = packet[TCP] if packet.haslayer(TCP) else None

        if tcp_layer and tcp_layer.dport == 22:
            dst = ip_layer.dst
            dport = tcp_layer.dport
        elif tcp_layer and tcp_layer.sport == 22:
            dst = ip_layer.src
            dport = tcp_layer.sport
        else:
            dst = ip_layer.dst
            dport = 22

        sport = random.randint(1024, 65535)
        ssh_layer = packet[SSH]

        print(f"{YELLOW}[*] TCP handshake to {dst}:{dport}...{RESET}")
        syn = IP(dst=dst) / TCP(sport=sport, dport=dport, flags='S', seq=1000)
        syn_ack = sr1(syn, timeout=self.timeout, verbose=0)

        if not syn_ack or syn_ack[TCP].flags == "R" or syn_ack[TCP].flags == "RA":
            print(f"{RED}[!] No SYN-ACK — host may be down or port closed{RESET}")
            return None

        server_seq = syn_ack[TCP].seq
        server_ack = syn_ack[TCP].ack

        ack = IP(dst=dst) / TCP(
            sport=sport, dport=dport, flags='A',
            seq=server_ack, ack=server_seq + 1
        )
        send(ack, verbose=0)

        ssh_pkt = IP(dst=dst) / TCP(
            sport=sport, dport=dport, flags='PA',
            seq=server_ack, ack=server_seq + 1
        ) / ssh_layer

        print(f"{YELLOW}[*] Sending SSH request...{RESET}")
        print(f"{CYAN}[DEBUG] Client: {ssh_layer.data} {RESET}")

        response = sr1(ssh_pkt, timeout=self.timeout, verbose=0)

        if response and response.haslayer(SSH):
            raw_response = response[SSH].data
            try:
                resp_str = raw_response.decode('utf-8', errors='ignore')
                if resp_str.startswith('SSH-'):
                    print(f"{GREEN}[+] SSH Response received:{RESET}")
                    lines = resp_str.split('\r\n')
                    if lines:
                        print(f"    {lines[0]}")
            except:
                pass

        return response

    def do_save(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: save <filename.pcap>{RESET}")
            return

        packet = self._build()
        if not packet:
            print(f"{RED}[!] Nothing to save{RESET}")
            return

        try:
            if Dot1Q in packet:
                if not packet.haslayer(Ether):
                    packet = Ether() / packet
                    print(f"{YELLOW}[!] Wrapped VLAN packet in Ethernet for PCAP compatibility{RESET}")

            wrpcap(arg, packet)
            print(f"{GREEN}[+] Saved to {arg}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Save failed: {e}{RESET}")

    def do_load(self, arg):
        if not arg:
            print(f"{RED}[!] Usage: load <filename.pcap>{RESET}")
            return

        try:
            packets = rdpcap(arg)
            if not packets:
                print(f"{RED}[!] No packets in {arg}{RESET}")
                return

            self.packet_layers = []
            packet = packets[0]

            self._packet_to_layers(packet)

            print(f"{GREEN}[+] Loaded {len(packets)} packet(s) from {arg} (using first){RESET}")
            self._show()
        except Exception as e:
            print(f"{RED}[!] Load failed: {e}{RESET}")

    def _packet_to_layers(self, packet):
        layers = []
        current = packet

        if not packet.haslayer(Ether):
            pass

        while current:
            layer_name = current.name.lower()

            if 'dot1q' in layer_name or 'vlan' in layer_name:
                layer_type = 'vlan'
                params = {}
                for field in current.fields_desc:
                    value = getattr(current, field.name)
                    if value is not None and value != field.default:
                        params[field.name] = value
                layers.append({'type': layer_type, 'params': params})
                current = current.payload if hasattr(current, 'payload') and current.payload else None
                continue

            elif 'dns' in layer_name:
                layer_type = 'dns'
                params = {}
                for field in current.fields_desc:
                    value = getattr(current, field.name)
                    if value is not None and value != field.default:
                        params[field.name] = value
                layers.append({'type': layer_type, 'params': params})
                current = current.payload if hasattr(current, 'payload') and current.payload else None
                continue


            elif layer_name == 'raw' and current.haslayer(Raw):
                raw_data = current[Raw].load
                try:
                    data_str = raw_data.decode('utf-8', errors='ignore')
                    if data_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                        lines = data_str.split('\r\n')
                        if lines:
                            request_line = lines[0].split(' ')
                            if len(request_line) >= 3:
                                http_params = {
                                    'Method': request_line[0],
                                    'Path': request_line[1],
                                    'Http_Version': request_line[2].split('/')[1] if '/' in request_line[2] else
                                    request_line[2]
                                }
                                for line in lines[1:]:
                                    if ': ' in line:
                                        key, val = line.split(': ', 1)
                                        key_clean = key.replace('-', '_')
                                        if key_clean in ['Host', 'User_Agent', 'Connection', 'Content_Type',
                                                         'Content_Length', 'Cookie', 'Referer', 'Accept']:
                                            http_params[key_clean] = val
                                layers.append({'type': 'http', 'params': http_params})
                                current = current.payload if hasattr(current, 'payload') and current.payload else None
                                continue

                    if packet.haslayer(scapy.layers.inet.IP) and packet[scapy.layers.inet.IP].proto == 2:
                        raw_data = current[Raw].load

                        if len(raw_data) > 0:
                            igmp_type = raw_data[0]
                            if igmp_type in [0x11, 0x12, 0x16, 0x17, 0x22, 0x23]:
                                try:
                                    if len(raw_data) < 8:
                                        raw_data = raw_data + b'\x00' * (8 - len(raw_data))

                                    if igmp_type in [0x11, 0x22, 0x23]:
                                        igmp = IGMPv3(raw_data)
                                        header_params = {}

                                        for field_name in ['type', 'mrcode', 'chksum']:
                                            if hasattr(igmp, field_name):
                                                value = getattr(igmp, field_name)
                                                if value is not None:
                                                    header_params[field_name] = value

                                        layers.append({'type': 'igmpv3', 'params': header_params})

                                        if igmp_type == 0x11:
                                            body = raw_data[4:]
                                            if len(body) < 8:
                                                body += b'\x00' * (8 - len(body))
                                            probe = IGMPv3mq(body)
                                            numsrc = getattr(probe, 'numsrc', 0) or 0
                                            needed = 8 + 4 * numsrc
                                            if len(body) < needed:
                                                body += b'\x00' * (needed - len(body))
                                            mq = IGMPv3mq(body)
                                            mq_params = {}
                                            for field_name in ['gaddr', 'resv', 's', 'qrv', 'qqic', 'numsrc',
                                                               'srcaddrs']:
                                                if hasattr(mq, field_name):
                                                    value = getattr(mq, field_name)
                                                    if value is not None:
                                                        mq_params[field_name] = value
                                            layers.append({'type': 'igmpv3mq', 'params': mq_params})

                                        elif igmp_type == 0x22:
                                            body = raw_data[4:]
                                            if len(body) < 4:
                                                body += b'\x00' * (4 - len(body))
                                            probe = IGMPv3mr(body)
                                            numgrp = getattr(probe, 'numgrp', 0) or 0
                                            needed = 4 + 8 * numgrp
                                            if len(body) < needed:
                                                body += b'\x00' * (needed - len(body))
                                            mr = IGMPv3mr(body)
                                            mr_params = {}
                                            for field_name in ['res2', 'numgrp', 'records']:
                                                if hasattr(mr, field_name):
                                                    value = getattr(mr, field_name)
                                                    if value is not None:
                                                        mr_params[field_name] = value
                                            layers.append({'type': 'igmpv3mr', 'params': mr_params})
                                    else:
                                        igmp = IGMP(raw_data)
                                        params = {}
                                        for field in igmp.fields_desc:
                                            value = getattr(igmp, field.name)
                                            if value is not None and value != field.default:
                                                params[field.name] = value
                                        layers.append({'type': 'igmp', 'params': params})

                                    current = current.payload if hasattr(current,
                                                                         'payload') and current.payload else None
                                    continue
                                except Exception as e:
                                    print(e)

                except Exception as e:
                    print(e)
                if isinstance(raw_data, bytes) and len(raw_data) > 0:
                    try:
                        if raw_data[0] in [0x45, 0x46] and len(raw_data) > 20:
                            from scapy.layers.inet import IP
                            ip = IP(raw_data)
                            self._packet_to_layers(ip)
                            return
                    except:
                        pass

            if 'neighbor solicitation' in layer_name:
                layer_type = 'ndp_ns'
            elif 'neighbor advertisement' in layer_name:
                layer_type = 'ndp_na'
            elif 'router solicitation' in layer_name:
                layer_type = 'ndp_rs'
            elif 'router advertisement' in layer_name:
                layer_type = 'ndp_ra'
            elif 'icmpv6 echo request' in layer_name:
                layer_type = 'icmpv6_echo'
            elif 'icmpv6 fallback class' in layer_name:
                layer_type = 'icmpv6'
            elif 'http request' in layer_name:
                layer_type = 'http'
            elif '802.1q' in layer_name:
                layer_type = 'vlan'
            elif 'ipv6' in layer_name:
                layer_type = 'ipv6'
            elif 'sctpchunkinit' in layer_name:
                layer_type = 'sctp_init'
            elif 'sctpchunkinitack' in layer_name:
                layer_type = 'sctp_init_ack'
            elif 'sctpchunkcookieecho' in layer_name:
                layer_type = 'sctp_cookie_echo'
            elif 'sctpchunkcookieack' in layer_name:
                layer_type = 'sctp_cookie_ack'
            elif 'sctpchunkabort' in layer_name:
                layer_type = 'sctp_abort'
            elif 'sctpchunkdata' in layer_name:
                layer_type = 'sctp_data'
            elif 'sctpchunkshutdown' in layer_name:
                layer_type = 'sctp_shutdown'
            elif 'sctpchunkshutdownack' in layer_name:
                layer_type = 'sctp_shutdown_ack'
            elif 'sctpchunkshutdowncomplete' in layer_name:
                layer_type = 'sctp_shutdown_complete'
            elif 'sctpchunksack' in layer_name:
                layer_type = 'sctp_sack'
            elif 'sctpchunkheartbeatreq' in layer_name:
                layer_type = 'sctp_heartbeat'
            elif 'sctpchunkheartbeatack' in layer_name:
                layer_type = 'sctp_heartbeat_ack'
            elif 'sctpchunkerror' in layer_name:
                layer_type = 'sctp_error'
            elif 'ip' in layer_name:
                layer_type = 'ip'
            elif 'tcp' in layer_name:
                layer_type = 'tcp'
            elif 'igmpv3mq' in layer_name:
                layer_type = 'igmpv3mq'
            elif 'igmpv3mr' in layer_name:
                layer_type = 'igmpv3mr'
            elif 'igmpv3' in layer_name:
                layer_type = 'igmpv3'
            elif 'igmp' in layer_name:
                layer_type = 'igmp'
            elif 'udp' in layer_name:
                layer_type = 'udp'
            elif 'icmp' in layer_name and 'v6' not in layer_name:
                layer_type = 'icmp'
            elif 'icmpv6' in layer_name:
                layer_type = 'icmpv6'
            elif 'arp' in layer_name:
                layer_type = 'arp'
            elif 'ssh' in layer_name:
                layer_type = 'ssh'
            elif 'ftp' in layer_name:
                layer_type = 'ftp'
            else:
                name_map = {
                    'ethernet': 'ether',
                    'ip': 'ip',
                    'ipv6': 'ipv6',
                    'tcp': 'tcp',
                    'udp': 'udp',
                    'icmp': 'icmp',
                    'icmpv6': 'icmpv6',
                    'raw': 'raw',
                    'arp': 'arp',
                    'ndp_rs': 'ndp_rs',
                    'ndp_ra': 'ndp_ra',
                    'ndp_ns': 'ndp_ns',
                    'ndp_na': 'ndp_na',
                }
                layer_type = name_map.get(layer_name, layer_name)

            if layer_type == 'raw' and layers and layers[-1].get('type') == 'http':
                current = current.payload if hasattr(current, 'payload') and current.payload else None
                continue

            if layer_type == 'raw' and layers and layers[-1].get('type') == 'igmpv3':
                current = current.payload if hasattr(current, 'payload') and current.payload else None
                continue

            if layer_type == 'raw' and layers and layers[-1].get('type') == 'igmp':
                current = current.payload if hasattr(current, 'payload') and current.payload else None
                continue

            params = {}
            for field in current.fields_desc:
                value = getattr(current, field.name)
                if value is not None and value != field.default:
                    if layer_type == 'tcp' and field.name == 'flags':
                        flag_map = {0x01: 'F', 0x02: 'S', 0x04: 'R', 0x08: 'P', 0x10: 'A', 0x20: 'U', 0x40: 'E',
                                    0x80: 'C'}
                        flag_str = ''
                        for fnum, fchar in flag_map.items():
                            if value & fnum:
                                flag_str += fchar
                        params[field.name] = flag_str if flag_str else 'None'
                    elif layer_type == 'ip' and field.name == 'flags':
                        params[field.name] = str(value)
                    elif field.name == 'load' and isinstance(value, bytes):
                        if not (layers and layers[-1].get('type') == 'http'):
                            try:
                                params[field.name] = value.decode('utf-8', errors='ignore')
                            except:
                                params[field.name] = value.hex()
                    elif field.name == 'dst' and isinstance(value, bytes):
                        continue
                    elif field.name == 'src' and isinstance(value, bytes):
                        continue
                    else:
                        params[field.name] = value

            if params:
                layers.append({'type': layer_type, 'params': params})

            current = current.payload if hasattr(current, 'payload') and current.payload else None

        self.packet_layers = layers

    def do_templates(self, arg):
        from LabTemplates import Templates
        Templates()

    def do_exit(self, arg):
        print(f"{CYAN}[+] Bye from Heretic{RESET}")
        return True

    def do_delete(self, arg):
        for i, layer in enumerate(self.packet_layers):
            if layer['type'] == arg.lower():
                self.packet_layers.pop(i)
                print(f"{GREEN}[+] Removed {arg}{RESET}")
                self._show()
                return
        print(f"{RED}[!] Layer not found{RESET}")

    def do_quit(self, arg):
        return self.do_exit(arg)

    def do_history(self, arg):
        if not self._history:
            print(f"{YELLOW}[!] No history{RESET}")
            return

        for i, cmd in enumerate(self._history, 1):
            print(f"{i:4}  {cmd}")

    def do_help(self, arg):
        from LabTemplates import LabHelp
        LabHelp(version)

    def _show(self):
        if not self.packet_layers:
            print(f"{YELLOW}[!] No layers{RESET}")
            return

        print(f"\n{BOLD}{CYAN}Current Packet (layers from bottom to top):{RESET}")
        for i, layer in enumerate(self.packet_layers):
            print(f"  {i + 1}. {BOLD}{layer['type'].upper()}{RESET}")
            if layer['params']:
                for p, v in layer['params'].items():
                    if p in ['qd', 'an', 'ns', 'ar'] and hasattr(v, 'summary'):
                        print(f"       {p}: {v.summary()}")
                    else:
                        print(f"       {p}: {v}")
        print()

    def _send_http(self, packet):
        if not packet.haslayer(IP):
            print(f"{RED}[!] HTTP requires an IP layer{RESET}")
            return None

        ip_layer = packet[IP]
        tcp_layer = packet[TCP] if packet.haslayer(TCP) else None

        if tcp_layer and tcp_layer.dport == 80:
            dst = ip_layer.dst
            dport = tcp_layer.dport
        elif tcp_layer and tcp_layer.sport == 80:
            dst = ip_layer.src
            dport = tcp_layer.sport
        else:
            dst = ip_layer.dst
            dport = 80

        sport = random.randint(1024, 65535)

        http_layer = None
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            print(f"{YELLOW}[*] Found HTTPRequest layer{RESET}")
        elif packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                http_str = raw_data.decode('utf-8', errors='ignore')
                if http_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                    lines = http_str.split('\r\n')
                    if lines:
                        request_line = lines[0].split(' ')
                        if len(request_line) >= 3:
                            method = request_line[0]
                            path = request_line[1]
                            http_ver = request_line[2].split('/')[1] if '/' in request_line[2] else request_line[2]

                            host = 'localhost'
                            user_agent = f'LightLab/{version}'
                            connection = 'close'
                            content_type = None
                            content_length = 0

                            for line in lines[1:]:
                                if ': ' in line:
                                    key, val = line.split(': ', 1)
                                    key_lower = key.lower()
                                    if key_lower == 'host':
                                        host = val
                                    elif key_lower == 'user-agent':
                                        user_agent = val
                                    elif key_lower == 'connection':
                                        connection = val
                                    elif key_lower == 'content-type':
                                        content_type = val
                                    elif key_lower == 'content-length':
                                        content_length = int(val)

                            http_layer = HTTPRequest(
                                Method=method,
                                Path=path,
                                Http_Version=http_ver,
                                Host=host,
                                User_Agent=user_agent,
                                Connection=connection
                            )
                            if content_type:
                                http_layer.Content_Type = content_type
                            if content_length:
                                http_layer.Content_Length = str(content_length)

                            print(f"{YELLOW}[*] Parsed HTTP request from Raw layer{RESET}")
            except Exception as e:
                print(f"{YELLOW}[!] Could not parse Raw as HTTP: {e}{RESET}")

        if not http_layer:
            print(f"{RED}[!] No HTTPRequest layer found in packet{RESET}")
            return None

        print(f"{YELLOW}[*] TCP handshake to {dst}:{dport}...{RESET}")
        syn = IP(dst=dst) / TCP(sport=sport, dport=dport, flags='S', seq=1000)
        syn_ack = sr1(syn, timeout=self.timeout, verbose=0)

        if not syn_ack or syn_ack[TCP].flags == "R" or syn_ack[TCP].flags == "RA":
            print(f"{RED}[!] No SYN-ACK — host may be down or port closed{RESET}")
            return None

        server_seq = syn_ack[TCP].seq
        server_ack = syn_ack[TCP].ack

        ack = IP(dst=dst) / TCP(
            sport=sport, dport=dport, flags='A',
            seq=server_ack, ack=server_seq + 1
        )
        send(ack, verbose=0)

        http_pkt = IP(dst=dst) / TCP(
            sport=sport, dport=dport, flags='PA',
            seq=server_ack, ack=server_seq + 1
        ) / http_layer

        print(f"{YELLOW}[*] Sending HTTP request...{RESET}")
        print(f"{CYAN}[DEBUG] Request: {http_layer.Method} {http_layer.Path} HTTP/{http_layer.Http_Version}{RESET}")

        response = sr1(http_pkt, timeout=self.timeout, verbose=0)

        if response and response.haslayer(Raw):
            raw_response = response[Raw].load
            try:
                resp_str = raw_response.decode('utf-8', errors='ignore')
                if resp_str.startswith('HTTP/'):
                    print(f"{GREEN}[+] HTTP Response received:{RESET}")
                    lines = resp_str.split('\r\n')
                    if lines:
                        print(f"    {lines[0]}")
            except:
                pass

        return response

    def _build(self):
        packet = None
        for info in self.packet_layers:
            t = info['type'].lower()
            p = info['params'].copy()
            port = 0

            if t in ['http', 'http request', 'http_request']:
                http_params = {}
                for k, v in p.items():
                    if isinstance(v, bytes):
                        v = v.decode('utf-8', errors='ignore')
                    if k == 'Http_Version':
                        k = 'Http_Version'
                    elif k == 'User_Agent':
                        k = 'User_Agent'
                    elif k == 'Content_Type':
                        k = 'Content_Type'
                    elif k == 'Content_Length':
                        k = 'Content_Length'
                    http_params[k] = v
                layer = HTTP() / HTTPRequest(**http_params)
            elif t == 'ether':
                layer = Ether(**p)
            elif t == 'vlan':
                vlan_params = {}
                if 'prio' in p:
                    vlan_params['prio'] = p['prio']
                if 'vlan' in p:
                    vlan_params['vlan'] = p['vlan']
                if 'dei' in p:
                    vlan_params['dei'] = p['dei']
                if 'type' in p:
                    vlan_params['type'] = p['type']
                layer = Dot1Q(**vlan_params)
            elif t == 'arp':
                layer = ARP(**p)
            elif t == 'ip':
                if 'dst' in p and isinstance(p['dst'], bytes):
                    p['dst'] = p['dst'].decode('utf-8', errors='ignore')
                if 'src' in p and isinstance(p['src'], bytes):
                    p['src'] = p['src'].decode('utf-8', errors='ignore')
                p.pop('len', None)
                p.pop('chksum', None)
                layer = IP(**p)

            elif t == 'ipv6':
                layer = IPv6(**p)
            elif t == 'ndp_ns':
                from scapy.layers.inet6 import ICMPv6ND_NS
                layer = ICMPv6ND_NS(**p)
            elif t == 'ndp_na':
                from scapy.layers.inet6 import ICMPv6ND_NA
                layer = ICMPv6ND_NA(**p)
            elif t == 'ndp_rs':
                from scapy.layers.inet6 import ICMPv6ND_RS
                layer = ICMPv6ND_RS(**p)
            elif t == 'ndp_ra':
                from scapy.layers.inet6 import ICMPv6ND_RA
                layer = ICMPv6ND_RA(**p)
            elif t == 'tcp':
                if 'options' in p and isinstance(p['options'], str):
                    try:
                        p['options'] = ast.literal_eval(p['options'])
                    except:
                        pass
                if 'sport' in p and isinstance(p['sport'], bytes):
                    p['sport'] = int(p['sport'].decode('utf-8', errors='ignore'))
                if 'dport' in p and isinstance(p['dport'], bytes):
                    p['dport'] = int(p['dport'].decode('utf-8', errors='ignore'))
                    port = int(p['dport'].decode('utf-8', errors='ignore'))
                layer = TCP(**p)
            elif t == 'udp':
                layer = UDP(**p)
            elif t == 'ssh':
                layer = SSH(**p)
            elif t == 'ftp':
                layer = FTPRequest(**p)
            elif t == 'sctp':
                if 'tag' in p and isinstance(p['tag'], str):
                    p['tag'] = int(p['tag'])
                layer = SCTP(**p)

            elif t == 'sctp_init':
                if 'init_tag' in p and isinstance(p['init_tag'], str):
                    if p['init_tag'].lower().startswith('0x'):
                        p['init_tag'] = int(p['init_tag'], 16)
                    else:
                        p['init_tag'] = int(p['init_tag'])
                if 'a_rwnd' in p and isinstance(p['a_rwnd'], str):
                    p['a_rwnd'] = int(p['a_rwnd'])
                if 'n_out_streams' in p and isinstance(p['n_out_streams'], str):
                    p['n_out_streams'] = int(p['n_out_streams'])
                if 'n_in_streams' in p and isinstance(p['n_in_streams'], str):
                    p['n_in_streams'] = int(p['n_in_streams'])
                if 'init_tsn' in p and isinstance(p['init_tsn'], str):
                    if p['init_tsn'].lower().startswith('0x'):
                        p['init_tsn'] = int(p['init_tsn'], 16)
                    else:
                        p['init_tsn'] = int(p['init_tsn'])
                layer = SCTPChunkInit(**p)

            elif t == 'sctp_init_ack':
                if 'init_tag' in p and isinstance(p['init_tag'], str):
                    if p['init_tag'].lower().startswith('0x'):
                        p['init_tag'] = int(p['init_tag'], 16)
                    else:
                        p['init_tag'] = int(p['init_tag'])
                if 'a_rwnd' in p and isinstance(p['a_rwnd'], str):
                    p['a_rwnd'] = int(p['a_rwnd'])
                if 'n_out_streams' in p and isinstance(p['n_out_streams'], str):
                    p['n_out_streams'] = int(p['n_out_streams'])
                if 'n_in_streams' in p and isinstance(p['n_in_streams'], str):
                    p['n_in_streams'] = int(p['n_in_streams'])
                if 'init_tsn' in p and isinstance(p['init_tsn'], str):
                    if p['init_tsn'].lower().startswith('0x'):
                        p['init_tsn'] = int(p['init_tsn'], 16)
                    else:
                        p['init_tsn'] = int(p['init_tsn'])
                layer = SCTPChunkInitAck(**p)

            elif t == 'sctp_cookie_echo':
                if 'cookie' in p:
                    cookie = p['cookie']
                    if isinstance(cookie, str):
                        if cookie.lower().startswith('0x'):
                            cookie = bytes.fromhex(cookie[2:])
                        elif cookie.startswith('\\x'):
                            cookie = cookie.encode('utf-8').decode('unicode_escape').encode('latin-1')
                        else:
                            try:
                                cookie = bytes.fromhex(cookie.replace(' ', ''))
                            except:
                                cookie = cookie.encode('utf-8')
                        p['cookie'] = cookie
                layer = SCTPChunkCookieEcho(**p)

            elif t == 'sctp_cookie_ack':
                layer = SCTPChunkCookieAck()

            elif t == 'sctp_abort':
                if 'error_causes' in p and isinstance(p['error_causes'], str):
                    try:
                        p['error_causes'] = ast.literal_eval(p['error_causes'])
                    except:
                        pass
                layer = SCTPChunkAbort(**p)

            elif t == 'sctp_data':
                if 'tsn' in p and isinstance(p['tsn'], str):
                    if p['tsn'].lower().startswith('0x'):
                        p['tsn'] = int(p['tsn'], 16)
                    else:
                        p['tsn'] = int(p['tsn'])
                if 'stream_id' in p and isinstance(p['stream_id'], str):
                    p['stream_id'] = int(p['stream_id'])
                if 'stream_seq' in p and isinstance(p['stream_seq'], str):
                    p['stream_seq'] = int(p['stream_seq'])
                if 'proto_id' in p and isinstance(p['proto_id'], str):
                    if p['proto_id'].lower().startswith('0x'):
                        p['proto_id'] = int(p['proto_id'], 16)
                    else:
                        p['proto_id'] = int(p['proto_id'])
                if 'data' in p:
                    data = p['data']
                    if isinstance(data, str):
                        if data.lower().startswith('0x'):
                            data = bytes.fromhex(data[2:])
                        elif data.startswith('\\x'):
                            data = data.encode('utf-8').decode('unicode_escape').encode('latin-1')
                        else:
                            try:
                                data = bytes.fromhex(data.replace(' ', ''))
                            except:
                                data = data.encode('utf-8')
                        p['data'] = data
                layer = SCTPChunkData(**p)

            elif t == 'sctp_shutdown':
                if 'cumul_tsn_ack' in p and isinstance(p['cumul_tsn_ack'], str):
                    if p['cumul_tsn_ack'].lower().startswith('0x'):
                        p['cumul_tsn_ack'] = int(p['cumul_tsn_ack'], 16)
                    else:
                        p['cumul_tsn_ack'] = int(p['cumul_tsn_ack'])
                layer = SCTPChunkShutdown(**p)

            elif t == 'sctp_shutdown_ack':
                layer = SCTPChunkShutdownAck()

            elif t == 'sctp_shutdown_complete':
                if 'TCB' in p and isinstance(p['TCB'], str):
                    p['TCB'] = int(p['TCB'])
                layer = SCTPChunkShutdownComplete(**p)

            elif t == 'sctp_sack':
                if 'cum_tsn_ack' in p and isinstance(p['cum_tsn_ack'], str):
                    if p['cum_tsn_ack'].lower().startswith('0x'):
                        p['cum_tsn_ack'] = int(p['cum_tsn_ack'], 16)
                    else:
                        p['cum_tsn_ack'] = int(p['cum_tsn_ack'])
                if 'a_rwnd' in p and isinstance(p['a_rwnd'], str):
                    p['a_rwnd'] = int(p['a_rwnd'])
                if 'n_gap_ack' in p and isinstance(p['n_gap_ack'], str):
                    p['n_gap_ack'] = int(p['n_gap_ack'])
                if 'n_dup_tsn' in p and isinstance(p['n_dup_tsn'], str):
                    p['n_dup_tsn'] = int(p['n_dup_tsn'])
                if 'gap_ack_list' in p and isinstance(p['gap_ack_list'], str):
                    try:
                        p['gap_ack_list'] = ast.literal_eval(p['gap_ack_list'])
                    except:
                        pass
                if 'dup_tsn_list' in p and isinstance(p['dup_tsn_list'], str):
                    try:
                        p['dup_tsn_list'] = ast.literal_eval(p['dup_tsn_list'])
                    except:
                        pass
                layer = SCTPChunkSACK(**p)

            elif t == 'sctp_heartbeat':
                layer = SCTPChunkHeartbeatReq(**p)

            elif t == 'sctp_heartbeat_ack':
                layer = SCTPChunkHeartbeatAck(**p)

            elif t == 'sctp_error':
                if 'error_causes' in p and isinstance(p['error_causes'], str):
                    try:
                        p['error_causes'] = ast.literal_eval(p['error_causes'])
                    except:
                        pass
                layer = SCTPChunkError(**p)

            elif t == 'igmp':
                if 'type' in p:
                    if isinstance(p['type'], str):
                        if p['type'].lower().startswith('0x'):
                            p['type'] = int(p['type'], 16)
                        else:
                            p['type'] = int(p['type'])

                if 'mrcode' in p and isinstance(p['mrcode'], str):
                    p['mrcode'] = int(p['mrcode'])
                if 'chksum' in p and isinstance(p['chksum'], str):
                    if p['chksum'].lower().startswith('0x'):
                        p['chksum'] = int(p['chksum'], 16)
                    else:
                        p['chksum'] = int(p['chksum'])

                if 'gaddr' in p and isinstance(p['gaddr'], str):
                    if p['gaddr'] == '0.0.0.0':
                        p['gaddr'] = '0.0.0.0'
                layer = IGMP(**p)

                raw_igmp = bytes(layer)
                if len(raw_igmp) < 8:
                    pad_len = 8 - len(raw_igmp)
                    pad_bytes = b'\x00' * pad_len
                    print(f"{YELLOW}[*] Adding {pad_len} bytes of padding to IGMP layer{RESET}")

                    if packet is None:
                        packet = layer / Raw(load=pad_bytes)
                    else:
                        packet = packet / layer / Raw(load=pad_bytes)
                else:
                    layer = layer

            elif t == 'igmpv3':
                if 'type' in p:
                    if isinstance(p['type'], str):
                        if p['type'].lower().startswith('0x'):
                            p['type'] = int(p['type'], 16)
                        else:
                            p['type'] = int(p['type'])

                if 'mrcode' in p and isinstance(p['mrcode'], str):
                    p['mrcode'] = int(p['mrcode'])

                if 'chksum' in p and isinstance(p['chksum'], str):
                    if p['chksum'].lower().startswith('0x'):
                        p['chksum'] = int(p['chksum'], 16)
                    else:
                        p['chksum'] = int(p['chksum'])

                layer = IGMPv3(**p)

                raw_igmp = bytes(layer)
                if len(raw_igmp) < 8:
                    pad_len = 8 - len(raw_igmp)
                    pad_bytes = b'\x00' * pad_len
                    print(f"{YELLOW}[*] Adding {pad_len} bytes of padding to IGMP layer{RESET}")

                else:
                    layer = layer

            elif t == 'igmpv3mq':
                if 'gaddr' in p and isinstance(p['gaddr'], str):
                    p['gaddr'] = p['gaddr']
                if 'qrv' in p and isinstance(p['qrv'], str):
                    p['qrv'] = int(p['qrv'])
                if 'qqic' in p and isinstance(p['qqic'], str):
                    p['qqic'] = int(p['qqic'])
                if 'numsrc' in p and isinstance(p['numsrc'], str):
                    p['numsrc'] = int(p['numsrc'])
                if 'srcaddrs' in p:

                    if isinstance(p['srcaddrs'], str):

                        try:
                            if p['srcaddrs'].startswith('['):
                                p['srcaddrs'] = ast.literal_eval(p['srcaddrs'])
                            else:
                                p['srcaddrs'] = [p['srcaddrs']]
                        except:
                            p['srcaddrs'] = []

                layer = IGMPv3mq(**p)

            elif t == 'igmpv3mr':
                if 'numgrp' in p and isinstance(p['numgrp'], str):
                    p['numgrp'] = int(p['numgrp'])

                if 'records' in p:
                    records = p['records']

                    if isinstance(records, str):
                        try:
                            records_list = ast.literal_eval(records)
                            if not isinstance(records_list, list):
                                records_list = [records_list]
                        except:
                            records_list = [records]
                    elif isinstance(records, list):
                        records_list = records
                    else:
                        records_list = [records]

                    parsed_records = []
                    for rec in records_list:
                        if isinstance(rec, IGMPv3gr):
                            parsed_records.append(rec)
                        elif isinstance(rec, dict):
                            rec_params = dict(rec)
                            if 'srcaddrs' in rec_params and isinstance(rec_params['srcaddrs'], str):
                                try:
                                    rec_params['srcaddrs'] = ast.literal_eval(rec_params['srcaddrs'])
                                except:
                                    rec_params['srcaddrs'] = [rec_params['srcaddrs']]
                            parsed_records.append(IGMPv3gr(**rec_params))
                        elif isinstance(rec, str):
                            parsed_records.append(parse_igmpv3gr(rec))

                    p['records'] = parsed_records

                layer = IGMPv3mr(**p)

            elif t == 'dns':
                dns_params = {}
                for k, v in p.items():
                    if k in ['qd', 'an', 'ns', 'ar']:
                        if isinstance(v, str):
                            if 'DNSQR' in v:
                                import re
                                match = re.search(r"qname=['\"]([^'\"]+)['\"]", v)
                                qname = match.group(1) if match else "."
                                match = re.search(r"qtype[=:]\s*(\d+)", v)
                                qtype = int(match.group(1)) if match else 1
                                match = re.search(r"qclass[=:]\s*(\d+)", v)
                                qclass = int(match.group(1)) if match else 1

                                dns_params[k] = DNSQR(qname=qname, qtype=qtype, qclass=qclass)
                            elif 'DNSRR' in v:
                                import re
                                match = re.search(r"rrname=['\"]([^'\"]+)['\"]", v)
                                rrname = match.group(1) if match else "."
                                match = re.search(r"type[=:]\s*(\d+)", v)
                                rtype = int(match.group(1)) if match else 1
                                match = re.search(r"rdata=['\"]([^'\"]+)['\"]", v)
                                rdata = match.group(1) if match else ""
                                dns_params[k] = DNSRR(rrname=rrname, type=rtype, rdata=rdata)
                            else:
                                dns_params[k] = v
                        else:
                            dns_params[k] = v
                    else:
                        dns_params[k] = v
                layer = DNS(**dns_params)
            elif t == 'icmp':
                layer = ICMP(**p)
            elif t == 'icmpv6':
                layer = ICMPv6Unknown(**p)
            elif t == 'icmpv6_echo':
                layer = ICMPv6EchoRequest(**p)
            elif t == 'raw':
                if 'load' in p:
                    load = p['load']
                    if isinstance(load, str):
                        test = load.replace(' ', '').replace('\\x', '')
                        if all(c in '0123456789abcdefABCDEF' for c in test) and '\\x' in load:
                            try:
                                load = bytes.fromhex(test)
                            except:
                                pass
                        elif '\\x' in load:
                            try:
                                load = load.encode('utf-8').decode('unicode_escape').encode('latin-1')
                            except:
                                pass
                    p['load'] = load
                layer = Raw(**p)
            else:
                print(f"{RED}[!] Unknown layer type: {t}{RESET}")
                return None

            packet = layer if packet is None else packet / layer

        return packet

if __name__ == "__main__":
    try:
        LightLab().cmdloop()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Exiting{RESET}")
        sys.exit(0)