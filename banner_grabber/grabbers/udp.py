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
from ..utils import color_text, RED, YELLOW, RESET

def udp_grab(target, port, probe, timeout=5, verbose=False, version=4):
    try:
        af = socket.AF_INET6 if version == 6 else socket.AF_INET
        sock = socket.socket(af, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        if probe:
            if verbose:
                print(f"[+] Sending UDP payload: {probe[:50]}...")
            sock.sendto(probe, (target, port))
        try:
            response, _ = sock.recvfrom(4096)
            sock.close()
            if response.strip():
                return response.decode('utf-8', errors='ignore')
        except socket.timeout:
            if verbose:
                print(color_text(f"[!] UDP timeout on {target}:{port}", RED))
        sock.close()
    except Exception as e:
        if verbose:
            print(color_text(f"[!] UDP error: {e}", RED))
    return None