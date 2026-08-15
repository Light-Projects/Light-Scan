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

import re

GREEN = '\033[92m'
RESET = '\033[0m'

def save_hexdump(packets, filename,lightpcap=False):
    if not isinstance(packets, list):
        packets = [packets]

    packet_count = 0
    with open(filename, "w") as f:
        f.write(f"{'=' * 80}\n")
        f.write(f"Hexdump of {len(packets)} packets\n")
        f.write(f"{'=' * 80}\n\n")

        for i,packet in enumerate(packets):
            packet_count += 1
            f.write(f"\n--- Packet {packet_count} ---\n")
            if lightpcap:
                data = packet[i]['data']
            else:
                data = bytes(packet)
            f.write(f"Length: {len(data)} bytes\n")

            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                hex_part = hex_part.ljust(48)
                f.write(f"  {i:04x}: {hex_part} {ascii_part}\n")

        f.write(f"\n{'=' * 80}\n")
        f.write(f"End of hexdump\n")

    print(f"{GREEN}[+] Hexdump saved to {filename}{RESET}")

def load_hexdump(filename):
    packets = []
    current_packet = bytearray()
    inside_packet = False

    with open(filename, "r") as f:
        for line in f:
            line = line.rstrip('\n')

            if line.startswith("--- Packet"):
                if inside_packet and current_packet:
                    packets.append(bytes(current_packet))
                    current_packet = bytearray()
                inside_packet = True
                continue

            if (line.startswith("Length:") or
                    line.startswith("===") or
                    line.startswith("Hexdump of") or
                    line.startswith("End of hexdump") or
                    not line.strip()):
                continue

            match = re.match(r'^\s+[0-9a-fA-F]+:\s+((?:[0-9a-fA-F]{2}\s*)+)', line)
            if match:
                hex_part = match.group(1).strip()
                hex_bytes = hex_part.split()
                for h in hex_bytes:
                    if len(h) == 2:
                        current_packet.append(int(h, 16))

    if inside_packet and current_packet:
        packets.append(bytes(current_packet))

    print(f"{GREEN}[+] Loaded {len(packets)} packets from {filename}{RESET}")
    return packets


def hexdump(data: bytes, offset: int = 0) -> str:

    result = []
    length = len(data)
    for i in range(0, length, 16):
        chunk = data[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        hex_part = hex_part.ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f"0x{i + offset:04x}: {hex_part}  {ascii_part}")
    return '\n'.join(result)

def hexstr(filename,data):
    content = data.encode('utf-8').hex()
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"[+] Hex-Str saved to {filename}")

def printhstr(hexstr):
    print(bytes.fromhex(hexstr).decode('utf-8'))

def loadhexstr(filename):
    with open(filename, "r", encoding="utf-8") as file:
        content = file.read()

    return bytes.fromhex(content).decode('utf-8')




