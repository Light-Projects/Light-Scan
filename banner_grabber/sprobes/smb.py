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

def SMB_PROBES():
    negotiate_packet = b'\x00\x00\x00\x31\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x45\x68\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x97\x34\x00\x00\x01\x00\x00\x0e\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00\x02\x00'
    return negotiate_packet

def SMB_BANNER(target_ip, port, version):
    af = socket.AF_INET6 if version == 6 else socket.AF_INET
    sock = socket.socket(af, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((target_ip, port))

    negotiate_packet = (
            b'\x00\x00\x00\x31' +
            b'\xff\x53\x4d\x42' +
            b'\x72\x00\x00\x00' +
            b'\x00\x18\x45\x68\x00\x00\x00\x00' +
            b'\x00\x00\x00\x00' +
            b'\x00\x00\x00\x00\x00\x00\x97\x34' +
            b'\x00\x00' +
            b'\x01\x00' +
            b'\x00\x0e\x00\x02' +
            b'\x4e\x54' +
            b'\x20\x4c' +
            b'\x4d' +
            b'\x20' +
            b'\x30\x2e' +
            b'\x31\x32\x00\x02\x00'
    )

    sock.send(negotiate_packet)
    neg_response = sock.recv(4096)

    if len(neg_response) < 36:
        return None

    session_packet = (b'\x00\x00\x00\x91\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x45\x68\x00'
                      b'\x00\x97\x38\x7d\xdb\x71\x1d\xb2\xfc\x00\x00\x00\x00\x4f\x71\x00\x00'
                      b'\x01\x00\x0c\xff\x00\x91\x00\xff\xff\x01\x00\x01\x00\x00\x00\x00\x00'
                      b'\x42\x00\x00\x00\x00\x00\x50\x00\x00\x80\x56\x00\x60\x40\x06\x06\x2b'
                      b'\x06\x01\x05\x05\x02\xa0\x36\x30\x34\xa0\x0e\x30\x0c\x06\x0a\x2b\x06'
                      b'\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x22\x04\x20\x4e\x54\x4c\x4d\x53'
                      b'\x53\x50\x00\x01\x00\x00\x00\x15\x82\x08\x00\x00\x00\x00\x00\x00\x00'
                      b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4c\x69\x67\x68\x74\x00\x4e\x61'
                      b'\x74\x69\x76\x65\x20\x4c\x61\x6e\x6d\x61\x6e\x00\x00')

    sock.send(session_packet)
    session_response = sock.recv(4096)

    hex_banner = binascii.hexlify(session_response).decode('utf-8')
    formatted_hex = ' '.join(hex_banner[i:i + 2] for i in range(0, len(hex_banner), 2))

    parts = session_response.rstrip(b'\x00').split(b'\x00')

    if len(parts) >= 2:
        native_lanman = parts[-1].decode('ascii', errors='ignore')
        native_os = parts[-2].decode('ascii', errors='ignore')

        return formatted_hex + "\n\n[Extracted]\n" + native_lanman + "\n" + native_os
    return formatted_hex