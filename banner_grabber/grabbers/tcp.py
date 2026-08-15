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
import ssl
from ..utils import color_text, RED
import binascii
from ..binaryprotos import bprotos

SSL_PORTS = {443, 465, 993, 995, 8443, 4643, 636, 3269}

def tcp_grab(target, port, probe, timeout=5, verbose=False, version=4):
    try:
        af = socket.AF_INET6 if version == 6 else socket.AF_INET
        sock = socket.socket(af, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        if port in SSL_PORTS:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=target)

        banner = b""
        try:
            sock.settimeout(2)
            banner = sock.recv(4096)
        except socket.timeout:
            pass

        if not banner.strip() and probe:
            if verbose:
                print(f"[+] Sending TCP payload: {probe[:50]}...")
            sock.settimeout(timeout)
            sock.send(probe)
            try:
                banner = sock.recv(4096)
            except socket.timeout:
                pass

        sock.close()
        if banner.strip():
            if port in bprotos:
                hex_banner = binascii.hexlify(banner).decode('utf-8')
                formatted_hex = ' '.join(hex_banner[i:i + 2] for i in range(0, len(hex_banner), 2))
                return formatted_hex
            return banner.decode('utf-8', errors='ignore')
        return None
    except socket.timeout:
        if verbose:
            print(color_text(f"[!] TCP timeout on {target}:{port}", RED))
    except ConnectionRefusedError:
        if verbose:
            print(color_text(f"[!] TCP connection refused on {target}:{port}", RED))
    except Exception as e:
        if verbose:
            print(color_text(f"[!] TCP error: {e}", RED))
    return None