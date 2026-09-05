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

import socket
import binascii

def DNS_PROBES(Proto):
    if Proto == "tcp":
        query = b"\x00\x1a"
        query += b"\x12\x34"
        query += b"\x01\x00"
        query += b"\x00\x01"
        query += b"\x00\x00\x00\x00\x00\x00"
        query += b"\x07version\x04bind\x00"
        query += b"\x00\x10"
        query += b"\x00\x01"
        return query
    elif Proto == "udp":
        query = b"\x12\x34"
        query += b"\x01\x00"
        query += b"\x00\x01"
        query += b"\x00\x00\x00\x00\x00\x00"
        query += b"\x07version\x04bind\x00"
        query += b"\x00\x10"
        query += b"\x00\x03"
        return query

def DNS_BANNER(target_ip, port,version):
    query = DNS_PROBES("udp")

    af = socket.AF_INET6 if version == 6 else socket.AF_INET
    sock = socket.socket(af, socket.SOCK_DGRAM)
    sock.settimeout(10)
    sock.connect((target_ip, port))

    sock.sendto(query, (target_ip, port))

    response, _ = sock.recvfrom(4096)
    sock.close()

    hex_banner = binascii.hexlify(response).decode('utf-8')
    formatted_hex = ' '.join(hex_banner[i:i + 2] for i in range(0, len(hex_banner), 2))

    parts = response.rstrip(b'\x00').split(b'\x00')

    if len(parts) >= 1:
        dns_server = parts[-1].decode('ascii', errors='ignore')

        return formatted_hex + "\n\n[Extracted]\n" + dns_server + "\n"
    return formatted_hex