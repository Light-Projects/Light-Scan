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

import random
from scapy.all import sr1, IP, IPv6, SCTP, SCTPChunkInit, SCTPChunkInitAck, SCTPChunkCookieEcho, SCTPChunkCookieAck, SCTPChunkAbort, SCTPChunkData
from ..utils import color_text, RED, GREEN, YELLOW, RESET

def sctp_grab(target, port, probes, timeout=5, verbose=False, version=4):
    try:
        init_tag = random.randint(0, 0xFFFFFFFF)
        initial_tsn = random.randint(0, 0xFFFFFFFF)
        if version == 6:
            packet = IPv6(dst=target, nh=132) / SCTP(sport=random.randint(1024,65535), dport=port, tag=0) / SCTPChunkInit(init_tag=init_tag, a_rwnd=65535, n_out_streams=10, n_in_streams=10, init_tsn=initial_tsn)
        else:
            packet = IP(dst=target, proto=132) / SCTP(sport=random.randint(1024,65535), dport=port, tag=0) / SCTPChunkInit(init_tag=init_tag, a_rwnd=65535, n_out_streams=10, n_in_streams=10, init_tsn=initial_tsn)

        if verbose:
            print(f"[+] Sending SCTP INIT to {target}:{port}")
        response = sr1(packet, timeout=timeout, verbose=0)
        if response is None:
            if verbose:
                print(color_text(f"[!] No SCTP response from {target}:{port}", YELLOW))
            return None

        if SCTPChunkInitAck in response:
            init_ack = response[SCTPChunkInitAck]
            server_tag = init_ack.init_tag
            if verbose:
                print(f"[+] Received INIT ACK, server tag: {server_tag}")

            cookie = extract_cookie(response)
            if cookie is None:
                if verbose:
                    print(color_text(f"[!] Could not extract cookie from {target}:{port}", YELLOW))
                return f"SCTP Service on port {port}\nINIT ACK received"

            if version == 6:
                cookie_packet = IPv6(dst=target, nh=132) / SCTP(sport=random.randint(1024,65535), dport=port, tag=server_tag) / SCTPChunkCookieEcho(cookie=cookie)
            else:
                cookie_packet = IP(dst=target, proto=132) / SCTP(sport=random.randint(1024,65535), dport=port, tag=server_tag) / SCTPChunkCookieEcho(cookie=cookie)

            cookie_response = sr1(cookie_packet, timeout=timeout, verbose=0)
            if cookie_response and SCTPChunkCookieAck in cookie_response:
                if verbose:
                    print(f"[+] SCTP handshake complete")
                for i, probe in enumerate(probes):
                    if verbose:
                        print(f"[+] Sending probe {i+1}/{len(probes)}")
                    if version == 6:
                        data_packet = IPv6(dst=target, nh=132) / SCTP(sport=random.randint(1024,65535), dport=port, tag=server_tag) / SCTPChunkData(tsn=random.randint(0,0xFFFFFFFF), stream_id=0, stream_seq=0, ppid=0, payload=probe)
                    else:
                        data_packet = IP(dst=target, proto=132) / SCTP(sport=random.randint(1024,65535), dport=port, tag=server_tag) / SCTPChunkData(tsn=random.randint(0,0xFFFFFFFF), stream_id=0, stream_seq=0, ppid=0, payload=probe)
                    data_response = sr1(data_packet, timeout=timeout, verbose=0)
                    if data_response and SCTPChunkData in data_response:
                        payload = data_response[SCTPChunkData].payload
                        if payload:
                            try:
                                return payload.decode('utf-8', errors='ignore').strip()
                            except:
                                return str(payload)
                return f"SCTP Service on port {port}\nHandshake complete, no data"
            elif cookie_response and SCTPChunkAbort in cookie_response:
                if verbose:
                    print(color_text(f"[!] SCTP ABORT received after COOKIE ECHO", RED))
                return None
            else:
                if verbose:
                    print(color_text(f"[!] No COOKIE ACK", YELLOW))
                return f"SCTP Service on port {port}\nINIT ACK received, COOKIE ACK timeout"
        elif SCTPChunkAbort in response:
            if verbose:
                print(color_text(f"[!] SCTP port closed - ABORT received", RED))
            return None
        elif SCTPChunkData in response:
            payload = response[SCTPChunkData].payload
            if payload:
                try:
                    return payload.decode('utf-8', errors='ignore').strip()
                except:
                    return str(payload)
        else:
            if verbose:
                print(color_text(f"[!] Unknown SCTP response", YELLOW))
            return None
    except Exception as e:
        if verbose:
            print(color_text(f"[!] SCTP error: {e}", RED))
        return None

def extract_cookie(response):
    try:
        init_ack = response[SCTPChunkInitAck]
        if hasattr(init_ack, 'cookie'):
            return init_ack.cookie
        raw = bytes(init_ack)
        pos = 0
        while pos + 4 <= len(raw):
            ptype = int.from_bytes(raw[pos:pos+2], 'big')
            plen = int.from_bytes(raw[pos+2:pos+4], 'big')
            if ptype == 7:
                return raw[pos+4:pos+plen]
            pos += plen
    except:
        pass
    return None