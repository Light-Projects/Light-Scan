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
from .probes import get_probe
from .grabbers import tcp_grab, udp_grab, sctp_grab
from .analyzer import analyse_banner
from .utils import color_text, RED, GREEN, YELLOW, RESET

class Banner:
    @staticmethod
    def grab(target, port, protocol="tcp", timeout=5, verbose=False, version=4):
        if verbose:
            print(f"\n[+] Banner grab on {target}:{port} ({protocol.upper()})")

        probe = get_probe(port, target, protocol)
        if protocol.lower() == "tcp":
            banner = tcp_grab(target, port, probe, timeout, verbose, version)
        elif protocol.lower() == "udp":
            banner = udp_grab(target, port, probe, timeout, verbose, version)
        elif protocol.lower() == "sctp":
            probes = [probe] if isinstance(probe, bytes) else [probe]
            banner = sctp_grab(target, port, probes, timeout, verbose, version)
        else:
            if verbose:
                print(color_text(f"[!] Unknown protocol: {protocol}", YELLOW))
            return None

        if banner:
            service = analyse_banner(banner, port)
            if verbose:
                print(color_text(f"[+] Banner received ({len(banner)} chars)", GREEN))
                if service:
                    print(color_text(f"[+] Identified service: {service}", GREEN))
            return {"banner": banner, "service": service}
        else:
            if verbose:
                print(color_text(f"[!] No banner received", YELLOW))
            return None



