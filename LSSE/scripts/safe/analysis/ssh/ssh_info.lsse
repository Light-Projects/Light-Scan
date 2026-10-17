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
Light-Scan Scripting Engine (LSSE)
Script Name : ssh-info
Author : Adam Boulaaz, ognamgeek
Arguments
--> Required Arguments
----> --starget
----> -sp
Categorie :safe/analysis/ssh
"""

import socket
from banner_grabber.sprobes.ssh import SSH_PROBES
import struct

def parse_kexinit(data: bytes) -> dict:
    """
    Parse an SSH KEXINIT packet (including the outer packet length and padding).
    Returns a dictionary with all fields.
    """

    print("[+] Packet Info :")
    packet_len = struct.unpack('>I', data[:4])[0]
    print(f"  <> Packet length: {packet_len}")

    padding_len = data[4]
    print(f"  <> Padding length: {padding_len}")

    payload = data[5:5 + packet_len - 1]

    if payload[0] != 20:
        raise ValueError(f"  <> Expected SSH_MSG_KEXINIT (20), got {payload[0]}")
    print("  <> Message: SSH_MSG_KEXINIT")

    pos = 1
    cookie = payload[pos:pos + 16]
    pos += 16
    print(f"  <> Cookie: {cookie.hex()}")

    def read_string() -> str:
        nonlocal pos
        if pos + 4 > len(payload):
            raise ValueError("Truncated data")
        length = struct.unpack('>I', payload[pos:pos + 4])[0]
        pos += 4
        if pos + length > len(payload):
            raise ValueError("String length exceeds payload")
        s = payload[pos:pos + length]
        pos += length
        return s.decode('utf-8', errors='replace')

    kex_algorithms = read_string()
    server_host_key_algorithms = read_string()
    encryption_algorithms_client_to_server = read_string()
    encryption_algorithms_server_to_client = read_string()
    mac_algorithms_client_to_server = read_string()
    mac_algorithms_server_to_client = read_string()
    compression_algorithms_client_to_server = read_string()
    compression_algorithms_server_to_client = read_string()
    languages_client_to_server = read_string()
    languages_server_to_client = read_string()

    if pos >= len(payload):
        raise ValueError("Missing first_kex_packet_follows")
    first_kex_packet_follows = payload[pos] != 0
    pos += 1

    if pos + 4 > len(payload):
        raise ValueError("Missing reserved field")
    reserved = struct.unpack('>I', payload[pos:pos + 4])[0]
    pos += 4

    return {
        'kex_algorithms': kex_algorithms,
        'server_host_key_algorithms': server_host_key_algorithms,
        'encryption_algorithms_client_to_server': encryption_algorithms_client_to_server,
        'encryption_algorithms_server_to_client': encryption_algorithms_server_to_client,
        'mac_algorithms_client_to_server': mac_algorithms_client_to_server,
        'mac_algorithms_server_to_client': mac_algorithms_server_to_client,
        'compression_algorithms_client_to_server': compression_algorithms_client_to_server,
        'compression_algorithms_server_to_client': compression_algorithms_server_to_client,
        'languages_client_to_server': languages_client_to_server,
        'languages_server_to_client': languages_server_to_client,
        'first_kex_packet_follows': first_kex_packet_follows,
        'reserved': reserved,
    }

class SSHRequest:
    def __init__(self, target=None, port=80):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.target = target
        self.port = port

    def start(self):
        self.sock.connect((self.target, self.port))

        banner = b""
        try:
            self.sock.settimeout(2)
            banner = self.sock.recv(4096)
        except socket.timeout:
            pass

        if banner != b'':
            try:
                self.sock.send(SSH_PROBES[1]())
                raw = self.sock.recv(4096)
                try:
                    parsed = parse_kexinit(raw)
                    print(f"\n[+] Server Clint:\n  <> server-client: {banner}")
                    print("\n[+] Key Exchange Init Data:")
                    for key, value in parsed.items():
                        print(f"  <> {key}: {value}")
                except Exception as e:
                    print("\n[!] Error parsing: ", e)
            except socket.timeout:
                pass

        self.sock.close()

