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
Script Name : dns-ns
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --domain
--> Optional Arguments
----> --dns-server
Categorie : safe/discovery/dns
"""

import dns.resolver
import dns.exception
import argparse
import sys

def get_nameservers(domain, dns_server=None):
    try:
        resolver = dns.resolver.Resolver()

        if dns_server:
            resolver.nameservers = [dns_server]

        answers = resolver.resolve(domain, 'NS')

        nameservers = []
        for rdata in answers:
            ns = str(rdata.target)
            if ns.endswith('.'):
                ns = ns[:-1]
            nameservers.append(ns)

        return nameservers

    except dns.resolver.NoAnswer:
        print(f"  [!] No NS records found for {domain}")
        return []
    except dns.resolver.NXDOMAIN:
        print(f"  [!] Domain does not exist: {domain}")
        return []
    except dns.resolver.Timeout:
        print(f"  [!] DNS query timed out")
        return []
    except dns.exception.DNSException as e:
        print(f"  [!] DNS error: {e}")
        return []
    except Exception as e:
        print(f"  [!] Error: {e}")
        return []


def run(domain, dns_server=None):

    print(f"\n[+] NS Record Lookup for {domain}")
    print("-" * 50)

    if dns_server:
        print(f"[*] Using DNS server: {dns_server}")
    else:
        print("[*] Using system default DNS")

    nameservers = get_nameservers(domain, dns_server)

    if not nameservers:
        print("\n[-] No nameservers found")
        return False

    print(f"\n[+] Found {len(nameservers)} nameserver(s):")
    for i, ns in enumerate(nameservers, 1):
        print(f"    {i}. {ns}")


    print("\n[+] NS lookup completed successfully")
    return True
