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
Script Name : dns-subdomain-fuzzing
Author : Adam Boulaaz, ognamgeek
Arguments
--> Required Arguments
----> --domain
--> Optional Arguments
----> --dns-server
----> --wordlist
Categorie : medium/discovery/dns
"""



import random
import signal
import string
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import scapy.all as scapy

red = "\033[31m"
green = "\033[32m"
yellow = "\033[33m"
blue = "\033[34m"
magenta = "\033[35m"
cyan = "\033[36m"
reset = "\033[0m"
bold = "\033[1m"


class DNSBruteForce:
    def __init__(self, domain, dns_server=None, max_threads=15, timeout=3, retries=2):
        self.domain = domain
        self.dns_server = dns_server or self.get_default_dns()
        self.max_threads = max_threads
        self.timeout = timeout
        self.retries = retries
        self.results = defaultdict(lambda: {
            'A': [],
            'AAAA': [],
            'CNAME': [],
            'errors': []
        })
        self.wildcards = {
            'A': None,
            'AAAA': None
        }
        self.stats = {
            'total_queries': 0,
            'successful': 0,
            'failed': 0,
            'wildcards': 0,
            'start_time': 0,
            'end_time': 0
        }
        self.running = False
        self.found_subdomains = []

    def get_default_dns(self):
        try:
            default_dns = scapy.conf.route.route("0.0.0.0")[2]
            if default_dns == "0.0.0.0":
                default_dns = "8.8.8.8"

            return default_dns
        except:
            return "8.8.8.8"

    def generate_random_subdomain(self, length=20):
        return ''.join(random.choices(string.ascii_lowercase, k=length))

    def create_dns_query(self, hostname, qtype="A", query_id=None):
        if query_id is None:
            query_id = random.randint(1, 65535)

        dns_query = scapy.DNS(
            id=query_id,
            rd=1,
            qd=scapy.DNSQR(
                qname=hostname,
                qtype=qtype
            )
        )
        ip_layer = scapy.IP(dst=self.dns_server, ttl=64)
        udp_layer = scapy.UDP(
            dport=53,
            sport=random.randint(1024, 65535)
        )

        return ip_layer / udp_layer / dns_query

    def send_dns_query(self, query, retry=None):
        if retry is None:
            retry = self.retries

        for attempt in range(retry):
            try:
                response = scapy.sr1(
                    query,
                    timeout=self.timeout,
                    verbose=0,
                    retry=0
                )

                if response and response.haslayer(scapy.DNS):
                    return response

            except Exception as e:
                if attempt == retry - 1:
                    return None
                time.sleep(0.1 * (attempt + 1))

        return None

    def parse_dns_response(self, response, qtype: str = "A") -> list[str]:
        if not response or not response.haslayer(scapy.DNS):
            return []

        dns_layer = response[scapy.DNS]

        if dns_layer.rcode != 0:
            return []

        records = []

        if dns_layer.ancount > 0:
            for i in range(dns_layer.ancount):
                answer = dns_layer.an[i]

                if qtype == "A" and answer.type == 1:
                    records.append(str(answer.rdata))

                elif qtype == "AAAA" and answer.type == 28:
                    records.append(str(answer.rdata))

                elif qtype == "CNAME" and answer.type == 5:
                    cname = str(answer.rdata).rstrip('.')
                    records.append(cname)
        return records

    def detect_wildcards(self):

        for qtype in ["A", "AAAA"]:
            rand1 = self.generate_random_subdomain()
            rand2 = self.generate_random_subdomain()

            hostname1 = f"{rand1}.{self.domain}"
            hostname2 = f"{rand2}.{self.domain}"

            query1 = self.create_dns_query(hostname1, qtype)
            query2 = self.create_dns_query(hostname2, qtype)

            response1 = self.send_dns_query(query1)
            response2 = self.send_dns_query(query2)

            records1 = self.parse_dns_response(response1, qtype)
            records2 = self.parse_dns_response(response2, qtype)

            if records1 and records2 and records1 == records2:
                self.wildcards[qtype] = records1[0]
                self.stats['wildcards'] += 1

        if not any(self.wildcards.values()):
            pass

    def query_subdomain(self, subdomain: str) -> dict:
        full_domain = f"{subdomain}.{self.domain}"
        result = {
            'subdomain': subdomain,
            'full_domain': full_domain,
            'A': [],
            'AAAA': [],
            'CNAME': [],
            'valid': False
        }
        a_query = self.create_dns_query(full_domain, "A")
        a_response = self.send_dns_query(a_query)
        a_records = self.parse_dns_response(a_response, "A")

        if a_records and (not self.wildcards['A'] or a_records[0] != self.wildcards['A']):
            result['A'] = a_records
            result['valid'] = True

        aaaa_query = self.create_dns_query(full_domain, "AAAA")
        aaaa_response = self.send_dns_query(aaaa_query)
        aaaa_records = self.parse_dns_response(aaaa_response, "AAAA")

        if aaaa_records and (not self.wildcards['AAAA'] or aaaa_records[0] != self.wildcards['AAAA']):
            result['AAAA'] = aaaa_records
            result['valid'] = True

        cname_query = self.create_dns_query(full_domain, "CNAME")
        cname_response = self.send_dns_query(cname_query)
        cname_records = self.parse_dns_response(cname_response, "CNAME")

        if cname_records:
            result['CNAME'] = cname_records
            result['valid'] = True

        return result

    def worker(self, subdomain):
        try:
            result = self.query_subdomain(subdomain)
            return result
        except Exception as e:
            self.results[subdomain]['errors'].append(str(e))
            return None

    def load_wordlist(self, wordlist_source):
        subdomains = []

        if isinstance(wordlist_source, list):
            subdomains = [s.strip().lower() for s in wordlist_source if s.strip()]

        elif isinstance(wordlist_source, str):
            try:
                with open(wordlist_source, 'r', encoding='utf-8', errors='ignore') as f:
                    subdomains = [line.strip().lower() for line in f if line.strip()]
            except (FileNotFoundError, OSError):
                subdomains = [s.strip().lower() for s in wordlist_source.split(',') if s.strip()]
        subdomains = list(set(subdomains))
        subdomains.sort()

        return subdomains

    def get_default_wordlist(self):
        return [
            "activesync", "admin", "administration", "ads", "adserver",
            "alerts", "alpha", "ap", "apache", "api", "app", "apps",
            "appserver", "aptest", "assets", "audit", "auth", "autodiscover",
            "backup", "beta", "blog", "bucket", "cdn", "chat", "ci", "citrix",
            "cloud", "cms", "console", "control", "corp", "cpanel", "crs",
            "cvs", "dashboard", "database", "db", "dbserver", "demo", "dev",
            "devel", "development", "devsql", "devtest", "dhcp", "direct",
            "directadmin", "dmz", "dns", "dns0", "dns1", "dns2", "docs",
            "download", "docker", "elastic", "emea", "en", "erp", "eshop",
            "eu", "exchange", "f5", "fileserver", "firewall", "forum",
            "ftp", "ftp0", "gateway", "git", "global", "gw", "help",
            "helpdesk", "home", "host", "horde", "http", "id", "images",
            "imap", "img", "info", "internal", "internet", "intra", "intranet",
            "ios", "ipv6", "jenkins", "kb", "lab", "ldap", "linux", "local",
            "log", "mail", "mail2", "mail3", "mailgate", "mailserver", "main",
            "manage", "media", "mgmt", "mirror", "mobile", "m", "monitor",
            "mongodb", "mssql", "mta", "mx", "mx0", "mx1", "mx2", "mysql",
            "news", "noc", "ns", "ns0", "ns1", "ns2", "ns3", "ntp", "oauth",
            "office", "ops", "oracle", "owa", "pbx", "plesk", "pop", "portal",
            "postgres", "prod", "proxy", "redis", "registry", "roundcube",
            "router", "s3", "scan", "secure", "security", "server", "shop",
            "sip", "smtp", "squirrelmail", "sql", "squid", "ssh", "ssl",
            "stage", "staging", "static", "stats", "status", "storage",
            "support", "svn", "switch", "syslog", "tls", "test", "test1",
            "test2", "testing", "upload", "us", "uk", "videos", "vm", "vnc",
            "voip", "vpn", "wap", "web", "web2test", "webdisk", "webftp",
            "webmail", "webmin", "webserver", "whm", "whois", "wiki",
            "xml", "www", "www2"
        ]

    def run_scan(self, wordlist_source=None):
        self.stats['start_time'] = time.time()
        self.running = True

        if wordlist_source:
            subdomains = self.load_wordlist(wordlist_source)
        else:
            subdomains = self.get_default_wordlist()

        self.detect_wildcards()

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_subdomain = {
                executor.submit(self.worker, subdomain): subdomain
                for subdomain in subdomains
            }

            completed = 0
            total = len(subdomains)

            for future in as_completed(future_to_subdomain):
                if not self.running:
                    print(f"{yellow}[!] Scan interrupted by user{reset}")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                completed += 1
                subdomain = future_to_subdomain[future]
                self.stats['total_queries'] += 3

                try:
                    result = future.result(timeout=self.timeout + 2)

                    if result and result['valid']:
                        self.stats['successful'] += 1
                        self.found_subdomains.append(result)

                        self.results[subdomain]['A'] = result['A']
                        self.results[subdomain]['AAAA'] = result['AAAA']
                        self.results[subdomain]['CNAME'] = result['CNAME']
                    else:
                        self.stats['failed'] += 1

                except Exception:
                    self.stats['failed'] += 1

                if completed % 50 == 0 or completed == total:
                    self.display_progress(completed, total)

        self.stats['end_time'] = time.time()
        self.running = False

        return self.generate_report()

    def display_progress(self, completed, total):
        elapsed = time.time() - self.stats['start_time']
        percent = (completed / total) * 100
        found = len(self.found_subdomains)

        print(f"{cyan}\n   [*] Progress: {completed}/{total} ({percent:.1f}%) | "
              f"Found: {found} | Elapsed: {elapsed:.1f}s{reset}")

    def signal_handler(self, sig, frame):
        if self.running:
            print(f"\n{yellow}\n   [!] Interrupt received, stopping scan...{reset}")
            self.running = False
            sys.exit(0)
        else:
            sys.exit(0)

    def generate_report(self):
        elapsed = self.stats['end_time'] - self.stats['start_time']

        report = f"\n   {bold}Dns Subdomain Fuzzing:{reset}\n   ---------------------------------------------------\n\n"

        report += f"      [+] Target Domain: {self.domain}\n"
        report += f"      [+] DNS Server: {self.dns_server}\n"
        report += f"      [+] Time Elapsed: {elapsed:.2f} seconds\n"
        report += f"      [+] Subdomains Tested: {self.stats['total_queries'] // 3}\n"
        report += f"      [+] Valid Subdomains Found: {len(self.found_subdomains)}\n"
        report += f"      [+] Successful Queries: {self.stats['successful']}\n"
        report += f"      [+] Failed Queries: {self.stats['failed']}\n"

        if self.wildcards['A'] or self.wildcards['AAAA']:
            report += "\n      [+] Wildcard Records:\n"
            if self.wildcards['A']:
                report += f"        *A (IPv4)   : {self.wildcards['A']}\n"
            if self.wildcards['AAAA']:
                report += f"        *AAAA (IPv6): {self.wildcards['AAAA']}\n"

        if self.found_subdomains:
            report += f"\n   {bold}Discovered Subdomains:{reset}\n   "
            report += "-" * 40 + "\n"

            for result in sorted(self.found_subdomains, key=lambda x: x['subdomain']):
                report += f"\n      [+] {green}{result['full_domain']}{reset} :\n\n"

                if result['A']:
                    for ip in result['A']:
                        report += f"           IPv4 *A   : {ip}\n"

                if result['AAAA']:
                    for ip in result['AAAA']:
                        report += f"           IPv6 *AAAA: {ip}\n"

                if result['CNAME']:
                    for cname in result['CNAME']:
                        report += f"           CNAME: {cname}\n"

        else:
            report += f"\n   {red}No valid subdomains found.{reset}\n"
        return report

def main(domain: str, dns: str | None = None, wordlist: str | None = None) -> None:
    scanner = DNSBruteForce(
        domain=domain,
        dns_server=dns,
        max_threads=15
    )

    signal.signal(signal.SIGINT, scanner.signal_handler)

    try:
        report = scanner.run_scan(wordlist)
        print(report)

    except KeyboardInterrupt:
        print(f"\n{yellow}[!] Scan interrupted by user{reset}")
    except Exception as e:
        print(f"{red}[!] Error during scan: {e}{reset}")
