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

def get_interfaces():
    interfaces = []
    from LightPacket import NetworkInterfaces
    for i in NetworkInterfaces().values():
        interfaces.append(i['name'])

    return interfaces

def get_eth_type_name(eth_type):
    from LightPacket.Consts import ETHERTYPE

    return ETHERTYPE.get(eth_type, f"0x{eth_type:04x}")

def detect_file_type(filename):
    try:
        with open(filename, 'rb') as f:
            magic = f.read(4)
            if magic == b'LBN\x00':
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
    import struct
    import zlib
    header_data = struct.pack('<IIII', version, created, count, flags)
    return zlib.crc32(header_data) & 0xFFFFFFFF