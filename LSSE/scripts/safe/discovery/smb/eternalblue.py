# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Adam Boulaaz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

"""
Light-Scan Scripting Engine (LSSE)
Script Name : eternalblue
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --starget
----> -sp
Categorie : safe/discovery/smb
"""

import socket
import sys

class EternalBlue:
    def __init__(self):
        self.vulnerable_indicators = [
            b'Windows 7',
            b'Windows 8.1',
            b'Windows 8',
            b'Windows 10',
            b'Windows Server 2008',
            b'Windows Server 2008 R2',
            b'Windows Server 2012',
            b'Windows Server 2012 R2',
            b'Windows Server 2016',
            b'Windows Server 2019',
            b'Windows Server 2003',
            b'Windows XP',
            b'Windows Vista',
            b'Windows 2000',
            b'NT 5.1',
            b'NT 5.0',
            b'NT 6.0',
            b'NT 6.1',
            b'NT 6.2',
            b'NT 6.3',
            b'NT 10.0'
        ]

        self.patch_info = {
            'Windows 7': {
                'kb': 'KB4012212',
                'description': 'Security Update for Windows 7 SP1 (March 2017)',
                'patched_builds': ['6.1.7601.23677', '6.1.7601.23678', '6.1.7601.23714']
            },
            'Windows 8.1': {
                'kb': 'KB4012213',
                'description': 'Security Update for Windows 8.1 (March 2017)',
                'patched_builds': ['6.3.9600.18340', '6.3.9600.18516']
            },
            'Windows 10 1511': {
                'kb': 'KB4013198',
                'description': 'Security Update for Windows 10 Version 1511 (March 2017)',
                'patched_builds': ['10.0.10586.839', '10.0.10586.842']
            },
            'Windows 10 1607': {
                'kb': 'KB4013429',
                'description': 'Security Update for Windows 10 Version 1607 (March 2017)',
                'patched_builds': ['10.0.14393.953', '10.0.14393.954']
            },
            'Windows 10 1703': {
                'kb': 'KB4016635',
                'description': 'Security Update for Windows 10 Version 1703 (April 2017)',
                'patched_builds': ['10.0.15063.138', '10.0.15063.250']
            },
            'Windows Server 2008': {
                'kb': 'KB4012212',
                'description': 'Security Update for Windows Server 2008 SP2 (March 2017)',
                'patched_builds': ['6.0.6002.19708', '6.0.6002.24021']
            },
            'Windows Server 2008 R2': {
                'kb': 'KB4012212',
                'description': 'Security Update for Windows Server 2008 R2 SP1 (March 2017)',
                'patched_builds': ['6.1.7601.23677', '6.1.7601.23678']
            },
            'Windows Server 2012': {
                'kb': 'KB4012214',
                'description': 'Security Update for Windows Server 2012 (March 2017)',
                'patched_builds': ['6.2.9200.22031', '6.2.9200.22049']
            },
            'Windows Server 2012 R2': {
                'kb': 'KB4012213',
                'description': 'Security Update for Windows Server 2012 R2 (March 2017)',
                'patched_builds': ['6.3.9600.18340', '6.3.9600.18516']
            },
            'Windows Server 2016': {
                'kb': 'KB4013429',
                'description': 'Security Update for Windows Server 2016 (March 2017)',
                'patched_builds': ['10.0.14393.953', '10.0.14393.954']
            },
            'Windows XP': {
                'kb': None,
                'description': 'No patch available - upgrade required',
                'patched_builds': []
            },
            'Windows Vista': {
                'kb': None,
                'description': 'No patch available - upgrade required',
                'patched_builds': []
            },
            'Windows 2000': {
                'kb': None,
                'description': 'No patch available - upgrade required',
                'patched_builds': []
            },
            'Windows Server 2003': {
                'kb': None,
                'description': 'No patch available - upgrade required',
                'patched_builds': []
            }
        }

def detect_ms17_010(target_ip, port=445):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target_ip, port))

        print(f"[*] Connected to {target_ip}:{port}")

        # ============================================================
        # 1. SMB Negotiate Protocol Request (SMB_COM_NEGOTIATE - 0x72)
        # ============================================================
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
            return False, "Invalid negotiate response"

        # ============================================================
        # 2. SMB Session Setup AndX Request (SMB_COM_SESSION_SETUP_ANDX - 0x73)
        # ============================================================

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

        if len(session_response) < 36:
            return False, "Invalid session response"

        sock.close()

        if session_response:
            print(f"[*] Session response: PRESENT")
            parts = session_response.rstrip(b'\x00').split(b'\x00')

            if len(parts) >= 2:
                native_lanman = parts[-1].decode('ascii', errors='ignore')
                native_os = parts[-2].decode('ascii', errors='ignore')

                print(f"[*] Native OS: {native_os}")
                print(f"[*] Native LAN Manager: {native_lanman}")

            for i in EternalBlue().vulnerable_indicators:
                if i.decode() in native_os:
                    print(f"[*] OS Version: {i}")
                    return True, f" -> OS Version: {i}"

            return True, "-> Session response"
        else:
            return False, f"Unexpected SMB Behavior"

    except socket.timeout:
        return False, "Connection timeout"
    except socket.error as e:
        return False, f"Socket error: {e}"
    except Exception as e:
        return False, f"Error: {e}"


def run(target,port):
    print(f"\nChecking {target} for MS17-010 -- CVE-2017-0144 (EternalBlue)...\n")

    is_vulnerable, message = detect_ms17_010(target,port)

    if is_vulnerable:
        print(f"\n[!] {target} is VULNERABLE to MS17-010 (EternalBlue)!")
        print(f"    {message}")
    else:
        print(f"\n[+] {target} is NOT vulnerable to MS17-010")
        print(f"    {message}")

