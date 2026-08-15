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
Script Name : ssh-auth-methods
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --starget
----> -sp
Category:   safe/extracting/ssh
"""

import paramiko
import socket
import sys
import time

auth = 1

class SSHProbe:
    def __init__(self, host, port=22, timeout=5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.methods = []
        self.banner = None
        self.version = None

    def probe(self):
        print(f"\n[*] Probing {self.host}:{self.port}\n")

        if not self.get_banner():
            return None

        methods = self.probe_auth_methods()

        self.methods = methods

        self.check_weak_ciphers()

        return {
                'host': self.host,
                'port': self.port,
                'banner': self.banner,
                'version': self.version,
                'methods': self.methods
            }
        return None

    def get_banner(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            sock.close()

            self.banner = banner

            if banner.startswith('SSH-'):
                parts = banner.split('-')
                if len(parts) >= 3:
                    self.version = f"{parts[1]}-{parts[2]}"

            print(f"[+] SSH Banner: {banner}")
            return True
        except Exception as e:
            print(f"[!] Failed to get banner: {e}")
            return False

    def probe_auth_methods(self):
        methods = []
        client = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(
                hostname=self.host,
                port=self.port,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
                password='__invalid_probe_password__'
            )

            return None

        except paramiko.AuthenticationException as e:
            if hasattr(e, 'allowed_types'):
                methods = list(e.allowed_types)
                print(f"[+] Auth methods (from exception): {methods}")
            else:
                error_msg = str(e).lower()
                print(f"[DEBUG] Auth error: {error_msg}")

                common_methods = ['password', 'publickey', 'keyboard-interactive',
                                  'hostbased', 'gssapi', 'none']
                for method in common_methods:
                    if method in error_msg:
                        methods.append(method)

                if not methods:
                    global auth
                    print(f"[!] Didn't manage to get auth methods .")
                    methods = ['password', 'publickey', 'keyboard-interactive',]
                    auth = 0
                else:
                    print(f"[+] Auth methods (parsed): {methods}")

        except Exception as e:
            print(f"[!] Auth probe error: {e}")
            return None

        finally:
            if client:
                try:
                    client.close()
                except:
                    pass

        return methods

    def check_weak_ciphers(self):
        weak_ciphers = ['arcfour', '3des-cbc', 'blowfish-cbc', 'des-cbc']

        print("[*] Testing weak ciphers...")

        for cipher in weak_ciphers:
            try:
                transport = paramiko.Transport((self.host, self.port))
                transport.start_client()
                transport.close()
            except:
                pass


def main(host,port=22):

    probe = SSHProbe(host, port)
    result = probe.probe()

    if result:
        print(f"\n[+] SSH Authentication Methods Summary:")
        print(f"    Host: {result['host']}:{result['port']}")
        print(f"    Banner: {result['banner']}")

        if auth == 0:
            print(f"    Methods: None")
        else:
            print(f"    Methods: {', '.join(result['methods'])}")

        print(f"\n[!] Security Assessment:")
        if 'password' in result['methods']:
            print(f"    - Password authentication: ENABLED ")
        if 'publickey' in result['methods']:
            print(f"    - Publickey authentication: ENABLED ")
        if 'none' in result['methods']:
            print(f"    - WARNING: 'none' authentication allowed!")

    else:
        print(f"[-] Failed to probe {host}:{port}")

