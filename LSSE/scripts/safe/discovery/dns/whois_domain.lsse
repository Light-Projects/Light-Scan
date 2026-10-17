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
Script Name : whois-domain
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --domain
Categorie : safe/discovery/dns
"""

import socket
import re
from datetime import datetime


class WhoisDomain:
    def __init__(self, domain, timeout=10):
        self.domain = self.clean_domain(domain)
        self.timeout = timeout
        self.whois_servers = {
            '.com': 'whois.verisign-grs.com',
            '.net': 'whois.verisign-grs.com',
            '.org': 'whois.pir.org',
            '.info': 'whois.afilias.net',
            '.biz': 'whois.neulevel.biz',
            '.us': 'whois.nic.us',
            '.uk': 'whois.nic.uk',
            '.eu': 'whois.eu',
            '.ca': 'whois.cira.ca',
            '.au': 'whois.auda.org.au',
            '.de': 'whois.denic.de',
            '.fr': 'whois.nic.fr',
            '.jp': 'whois.jprs.jp',
            '.cn': 'whois.cnnic.cn',
            '.ru': 'whois.ripn.net',
            '.br': 'whois.registro.br',
            '.it': 'whois.nic.it',
            '.nl': 'whois.domain-registry.nl',
            '.se': 'whois.iis.se',
            '.pl': 'whois.dns.pl',
            '.in': 'whois.registry.in',
            '.io': 'whois.nic.io',
            '.co': 'whois.nic.co',
            '.me': 'whois.nic.me',
            '.tv': 'whois.nic.tv',
            '.ws': 'whois.website.ws',
            '.cc': 'whois.nic.cc',
            '.tk': 'whois.dot.tk',
            '.ml': 'whois.dot.ml',
            '.ga': 'whois.dot.ga',
            '.cf': 'whois.dot.cf',
        }
        self.default_server = 'whois.iana.org'

    def clean_domain(self, domain):
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.replace('www.', '')
        domain = domain.split('/')[0].split(':')[0]
        return domain.lower().strip()

    def get_tld(self):
        parts = self.domain.split('.')
        if len(parts) > 1:
            return '.' + parts[-1].lower()
        return None

    def get_whois_server(self):
        tld = self.get_tld()
        if tld and tld in self.whois_servers:
            return self.whois_servers[tld]
        return self.default_server

    def query_whois(self, server):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((server, 43))

            query = f"{self.domain}\r\n"
            sock.send(query.encode('utf-8'))

            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

            sock.close()
            return response.decode('utf-8', errors='ignore')

        except socket.timeout:
            print(f"[-] Timeout connecting to {server}")
            return None
        except socket.error as e:
            print(f"[-] Socket error: {e}")
            return None
        except Exception as e:
            print(f"[-] Error: {e}")
            return None

    def parse_whois(self, raw_data):
        info = {
            'domain': self.domain,
            'registrar': None,
            'creation_date': None,
            'expiry_date': None,
            'updated_date': None,
            'name_servers': [],
            'registrant': None,
            'admin_email': None,
            'tech_email': None,
            'status': [],
            'raw': raw_data
        }

        if not raw_data:
            return info

        patterns = {
            'registrar': [
                r'Registrar:\s*(.+?)(?:\n|$)',
                r'Registrar Name:\s*(.+?)(?:\n|$)',
                r'Sponsoring Registrar:\s*(.+?)(?:\n|$)'
            ],
            'creation_date': [
                r'Creation Date:\s*(.+?)(?:\n|$)',
                r'Domain Creation Date:\s*(.+?)(?:\n|$)',
                r'Created:\s*(.+?)(?:\n|$)',
                r'Registration Date:\s*(.+?)(?:\n|$)'
            ],
            'expiry_date': [
                r'Expiry Date:\s*(.+?)(?:\n|$)',
                r'Registry Expiry Date:\s*(.+?)(?:\n|$)',
                r'Expiration Date:\s*(.+?)(?:\n|$)',
                r'Valid Until:\s*(.+?)(?:\n|$)'
            ],
            'updated_date': [
                r'Updated Date:\s*(.+?)(?:\n|$)',
                r'Last Updated:\s*(.+?)(?:\n|$)',
                r'Changed:\s*(.+?)(?:\n|$)'
            ],
            'name_servers': [
                r'Name Server:\s*(.+?)(?:\n|$)',
                r'Nameserver:\s*(.+?)(?:\n|$)',
                r'nserver:\s*(.+?)(?:\n|$)'
            ],
            'registrant': [
                r'Registrant:\s*(.+?)(?:\n|$)',
                r'Registrant Name:\s*(.+?)(?:\n|$)',
                r'Registrant Organization:\s*(.+?)(?:\n|$)'
            ],
            'admin_email': [
                r'Admin Email:\s*(.+?)(?:\n|$)',
                r'Administrative Email:\s*(.+?)(?:\n|$)'
            ],
            'tech_email': [
                r'Tech Email:\s*(.+?)(?:\n|$)',
                r'Technical Email:\s*(.+?)(?:\n|$)'
            ],
            'status': [
                r'Domain Status:\s*(.+?)(?:\n|$)',
                r'Status:\s*(.+?)(?:\n|$)'
            ]
        }

        for key, pattern_list in patterns.items():
            for pattern in pattern_list:
                matches = re.findall(pattern, raw_data, re.IGNORECASE)
                if matches:
                    if key == 'name_servers':
                        for match in matches:
                            ns = match.strip()
                            if ns and ns not in info['name_servers']:
                                info['name_servers'].append(ns)
                    elif key == 'status':
                        for match in matches:
                            status = match.strip()
                            if status and status not in info['status']:
                                info['status'].append(status)
                    else:
                        value = matches[0].strip()
                        if value and not info[key]:
                            info[key] = value
                    break

        for date_key in ['creation_date', 'expiry_date', 'updated_date']:
            if info[date_key]:
                info[date_key] = self.clean_date(info[date_key])

        info['name_servers'] = [ns for ns in info['name_servers']
                                if ns and ns.lower() != self.domain.lower()]

        return info

    def clean_date(self, date_str):
        try:
            date_str = re.sub(r'\s*\([^)]*\)', '', date_str)
            date_str = date_str.strip()

            formats = [
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d',
                '%d-%b-%Y',
                '%d/%m/%Y',
                '%b %d %Y',
                '%Y.%m.%d'
            ]

            for fmt in formats:
                try:
                    dt = datetime.strptime(date_str, fmt)
                    return dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    continue

            return date_str
        except:
            return date_str

    def get_domain_info(self):
        print(f"\n[*] Querying WHOIS for: {self.domain}\n")

        server = self.get_whois_server()
        print(f"[*] Using WHOIS server: {server}")

        raw_data = self.query_whois(server)

        if not raw_data:
            return None

        if 'whois.' in raw_data.lower() and 'referral' in raw_data.lower():
            match = re.search(r'Referral Server:\s*(.+?)(?:\n|$)', raw_data, re.IGNORECASE)
            if match:
                referral_server = match.group(1).strip()
                print(f"[*] Following referral to: {referral_server}")
                raw_data = self.query_whois(referral_server)

        info = self.parse_whois(raw_data)

        return info

    def print_info(self, info):
        if not info:
            print(f"[-] No WHOIS information found for {self.domain}")
            return

        print(f"\n{'=' * 60}")
        print(f"WHOIS Domain Information: {info['domain']}")
        print(f"{'=' * 60}\n")

        if info['registrar']:
            print(f"  Registrar:       {info['registrar']}")
        if info['creation_date']:
            print(f"  Creation Date:   {info['creation_date']}")
        if info['expiry_date']:
            print(f"  Expiry Date:     {info['expiry_date']}")
        if info['updated_date']:
            print(f"  Updated Date:    {info['updated_date']}")
        if info['name_servers']:
            print(f"\n  Name Servers:")
            for ns in info['name_servers']:
                print(f"    - {ns}")
        if info['registrant']:
            print(f"\n  Registrant:      {info['registrant']}")
        if info['admin_email']:
            print(f"  Admin Email:     {info['admin_email']}")
        if info['tech_email']:
            print(f"  Tech Email:      {info['tech_email']}")

        if info['status']:
            print(f"\n  Domain Status:")
            for status in info['status']:
                print(f"    - {status}")
        print(f"\n[+] Raw Data:\n\n        {info['raw']}")
        print(f"\n{'=' * 60}")

def main(domain):
    timeout = 15

    whois = WhoisDomain(domain, timeout)
    result = whois.get_domain_info()

    if result:
        whois.print_info(result)
    else:
        print(f"[-] Failed to get WHOIS info for {domain}")
