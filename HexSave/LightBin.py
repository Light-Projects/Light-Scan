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

import struct
import zlib
import time
from datetime import datetime

LIGHTBIN_MAGIC = b'LBN\x00'
LIGHTBIN_VERSION = 1
FLAG_COMPRESSED = 0x01
FLAG_NULL = 0x00

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def detect_file_type(filename):
    try:
        with open(filename, 'rb') as f:
            magic = f.read(4)
            if magic == LIGHTBIN_MAGIC:
                return 'lightbin'
            elif magic[:4] == b'\xd4\xc3\xb2\xa1' or magic[:4] == b'\xa1\xb2\xc3\xd4':
                return 'pcap'
            elif magic[:4] == b'\x0a\x0d\x0d\x0a':
                return 'pcapng'
            else:
                return 'unknown'
    except:
        return 'unknown'

def lbn_chksum(version, created, count, flags):
    header_data = struct.pack('<IIII', version, created, count, flags)
    return zlib.crc32(header_data) & 0xFFFFFFFF

def save_binary(filename, packets, null=False, compress=False, scapy_compatible=False, args=None, stats=None):
    try:
        if not isinstance(packets, list):
            packets = [packets]

        creation_time = int(time.time())
        packet_count = 0
        if compress:
            FLAG = FLAG_COMPRESSED
        else:
            FLAG = FLAG_NULL

        with open(filename, 'wb') as f:
            header = struct.pack(
                '<4sIIIII',
                LIGHTBIN_MAGIC,
                LIGHTBIN_VERSION,
                creation_time,
                0,
                FLAG,
                0
            )
            f.write(header)
            header_pos = f.tell() - 24

            for pkt in packets:
                timestamp = time.time()
                if compress:
                    raw_bytes = zlib.compress(bytes(pkt), 6)
                else:
                    raw_bytes = bytes(pkt)

                f.write(struct.pack('<dI', timestamp, len(raw_bytes)))
                f.write(raw_bytes)

                packet_count += 1

            f.seek(header_pos + 12)
            f.write(struct.pack('<I', packet_count))
            CHKSUM = lbn_chksum(LIGHTBIN_VERSION, creation_time, packet_count, FLAG)
            f.seek(header_pos + 20)
            f.write(struct.pack('<I', CHKSUM))


        print(f"{GREEN}[+] Saved {packet_count} packets to {filename} (LightBin format){RESET}")
        return True

    except Exception as e:
        print(f"{RED}[-] Error saving LightBin: {e}{RESET}")
        return False

def load_binary(filename,scapy_compatible=False,checksum_bypass=False):
    try:
        with open(filename, 'rb') as f:
            header_data = f.read(24)
            if len(header_data) != 24:
                raise ValueError("Invalid LightBin file (header too short)")

            magic, version, created, count, flags, ck = struct.unpack('<4sIIIII', header_data)

            if magic != LIGHTBIN_MAGIC:
                raise ValueError(f"Invalid LightBin file (magic: {magic})")

            is_compressed = bool(flags & FLAG_COMPRESSED)
            CHKSUM = lbn_chksum(version, created, count, flags)

            print(f"{GREEN}[+] Loading LightBin file...{RESET}")
            print(f"{CYAN}    Version: {version}{RESET}")
            print(f"{CYAN}    Created: {datetime.fromtimestamp(created).strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
            print(f"{CYAN}    Packets: {count}{RESET}")
            if is_compressed:
                print(f"{CYAN}    Compression: Enabled{RESET}")
            else:
                pass

            if CHKSUM != ck:
                print(f"{RED}    Chksum: Invalid{RESET}")

            packets = []
            packet_timestamps = []

            for i in range(count):
                pkt_header = f.read(12)
                if len(pkt_header) != 12:
                    break

                timestamp, size = struct.unpack('<dI', pkt_header)

                pkt_data = f.read(size)
                if len(pkt_data) != size:
                    break
                if is_compressed:
                    pkt_data = zlib.decompress(pkt_data)

                if scapy_compatible:
                    from HexSave.ScapyLoader.ScapyPacketsLoader import LoadFromLightBinToScapyPackets
                    pkt_data = LoadFromLightBinToScapyPackets(pkt_data)

                packets.append(pkt_data)
                packet_timestamps.append(timestamp)

            print(f"{GREEN}[+] Loaded {len(packets)} packets from {filename}{RESET}")

            return packets,None

    except FileNotFoundError:
        print(f"{RED}[-] File not found: {filename}{RESET}")
        return None, None
    except Exception as e:
        print(f"{RED}[-] Error loading LightBin: {e}{RESET}")
        return None, None
