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
Script Name : dns-zone-transfer
Author : Adam Boulaaz, ognamgeek
Arguments
--> Required Arguments
----> --domain
--> Optional Arguments
----> --dns-server
Categorie : medium/extracting/dns
"""

import socket

import dns.exception
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone


def get_nameservers(domain):
    try:
        resolver = dns.resolver.Resolver()
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
    except Exception as e:
        print(f"  [!] Error resolving NS: {e}")
        return []

def is_valid_nameserver(ns: str) -> bool:
    try:
        socket.gethostbyname(ns)
        return True
    except socket.gaierror:
        return False

def attempt_zone_transfer(domain, ns_server):
    try:
        print(f"\n  [*] Attempting AXFR from {ns_server}")

        if not is_valid_nameserver(ns_server):
            print(f"  [!] Invalid nameserver: {ns_server}")
            return None

        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_server, domain, timeout=10))
        except dns.query.TransferError as e:

            print(f"  [!] Transfer refused by {ns_server}: {e}")
            return None
        except dns.exception.Timeout:
            print(f"  [!] Timeout from {ns_server}")
            return None
        except ConnectionRefusedError:
            print(f"  [!] Connection refused by {ns_server}")
            return None
        except socket.error as e:
            print(f"  [!] Network error with {ns_server}: {e}")
            return None
        except Exception as e:
            print(f"  [!] Error with {ns_server}: {e}")
            return None

        if not zone or len(zone.nodes) == 0:
            print(f"  [!] No records received from {ns_server}")
            return None

        records = []
        for name, node in zone.nodes.items():
            for rdtype, rdset in node.rdtypes.items():
                for rdata in rdset:
                    records.append({
                        'name': str(name),
                        'type': dns.rdatatype.to_text(rdtype),
                        'value': str(rdata)
                    })

        return {
            'nameserver': ns_server,
            'record_count': len(records),
            'records': records
        }

    except Exception as e:
        print(f"  [!] Unexpected error with {ns_server}: {e}")
        return None

def format_output(result):
    if not result:
        return

    print(f"\n[+] Zone transfer SUCCESSFUL from {result['nameserver']}")
    print(f"[+] Found {result['record_count']} records\n")

    by_type = {}
    for rec in result['records']:
        rtype = rec['type']
        if rtype not in by_type:
            by_type[rtype] = []
        by_type[rtype].append(rec)


    print("\n[*] All records:")
    for rec in result['records']:
        name = rec['name'] if rec['name'] != '@' else '(root)'
        print(f"    {name:30} [{rec['type']:8}] → {rec['value']}")

def runzon(domain, dns_server=None):
    print(f"\n[+] Zone Transfer Scan for {domain}")
    print("-" * 50)

    if dns_server:
        nameservers = [dns_server]
        print(f"[*] Using custom DNS server: {dns_server}")
    else:
        print("[*] Discovering authoritative nameservers...")
        nameservers = get_nameservers(domain)
        if not nameservers:
            print("[!] No nameservers found. Try specifying with --dns-server")
            return False
        print(f"[*] Found nameservers: {', '.join(nameservers)}")

    print()

    success = False
    for ns in nameservers:
        result = attempt_zone_transfer(domain, ns)
        if result:
            format_output(result)
            success = True
            break

    print("-" * 50)

    if success:
        print("[+] Zone transfer completed successfully")
        return True
    else:
        print("[-] Zone transfer failed on all nameservers (secure configuration)")
        return False

# success =
