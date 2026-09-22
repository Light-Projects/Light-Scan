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

import scapy.all as scapy
import json
import os
import sys
import threading
import warnings
import logging
import platform
import ipaddress
import time
import socket
import argparse

from scapy.config import conf
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6TimeExceeded
from scapy.contrib.igmp import IGMP

from concurrent.futures import ThreadPoolExecutor, as_completed

from VersionParser import VersionParser
from banner_grabber import Banner
from Services import Lightscan_Service_List, top_1000_ports, top_100_ports, top_20_tcp_ports, top_20_udp_ports
from decoy import decoy_order, decoy
from verify import ver_ttl, ver_ip_id, ver_hlim, ver_ip_flags
from confparser import speed_parser,Global
from Decoration.Colors import *
from Versions import *

from LightEngine import Payloads
from LightMirage import mirage
from Lightscan_os.core.engine import OSFingerprintEngine
from LightPacket.utils.CIDR import parse_targets, TargetParser
from LightPacket.GetIPv4 import GetIPv4


class VersionManager:
    FRAMEWORK = __framework__
    LIGHTSCAN = __lightscan__
    LSSE = __lsse__
    LIGHTSAVE = __lightsave__
    LIGHTPANEL = __lightpanel6__
    LIGHTSNIFF = __lightsniff__
    MINT = __mint__
    LIGHTPACKET = __lightpacket__
    LIGHTBIN = __lightbin__
    LIGHTHEX = __lighthex__
    LIGHTDIFF = __lightdiff__

    @classmethod
    def show_banner(cls):
        print(f"""
╔══════════════════════════════════════════╗
║         Light-Scan Framework             ║
║            v{cls.FRAMEWORK}                        ║
╠══════════════════════════════════════════╣
║ Lightscan       : v{cls.LIGHTSCAN}                 ║
║ LSSE Engine     : v{cls.LSSE}                 ║
║ LightSave       : v{cls.LIGHTSAVE}                 ║
║ LightSniff      : v{cls.LIGHTSNIFF}                 ║
║ LightPanel6     : v{cls.LIGHTPANEL}                 ║
║ Mint            : v{cls.MINT}                 ║
║ LightPacket     : v{cls.LIGHTPACKET}                 ║
║ LightBin        : v{cls.LIGHTBIN}                   ║
║ LightHex        : v{cls.LIGHTHEX}                   ║
║ LightDiff       : v{cls.LIGHTDIFF}                 ║
╚══════════════════════════════════════════╝
        """)

red = RED
green = GREEN
reset = RESET
yellow = YELLOW

PORT_SECTIONS = {
    "tcp": [("open_ports", "opened_ports_services", "Open Ports"),
            ("closed_ports", "closed_ports_services", "Closed Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports")],
    "custom":[("open_ports", "opened_ports_services", "Open Ports"),
            ("closed_ports", "closed_ports_services", "Closed Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports"),
            ("open_filtered_ports", "open_filtered_ports_services", "Open|Filtered Ports", False)],
    "syn": [("open_ports", "opened_ports_services", "Open Ports"),
            ("closed_ports", "closed_ports_services", "Closed Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports"),
            ("open_filtered_ports", "open_filtered_ports_services", "Open|Filtered Ports", False)],
    "udp": [("open_ports", "opened_ports_services", "Open Ports"),
            ("closed_ports", "closed_ports_services", "Closed Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports"),
            ("open_filtered_ports", "open_filtered_ports_services", "Open|Filtered Ports", False)],
    "init": [("open_ports", "opened_ports_services", "Open Ports"),
            ("closed_ports", "closed_ports_services", "Closed Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports")],
    "idle": [("open_ports", "opened_ports_services", "Open Ports"),
            ("closed_filtered_ports", "closed_filtered_ports_services", "Closed|Filtered Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports")],
    "null": [("closed_ports", "closed_ports_services", "Closed Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports"),
            ("null_ports", "null_ports_services", "(NULL Scan) Open|Filtered Ports")],
    "fin": [("closed_ports", "closed_ports_services", "Closed Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports"),
            ("fin_ports", "fin_ports_services", "(FIN Scan) Open|Filtered Ports")],
    "xmas": [("closed_ports", "closed_ports_services", "Closed Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports"),
            ("open_filtered_ports", "open_filtered_ports_services", "(XMAS Scan) Open|Filtered Ports")],
    "ack": [("filtered_ports", "filtered_ports_services", "Filtered Ports", False),
            ("unfiltered_ports", "unfiltered_ports_services", "Unfiltered Ports")],
    "maimon": [("closed_ports", "closed_ports_services", "Closed Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports"),
            ("open_filtered_ports", "open_filtered_ports_services", "(MAIMON Scan) Open|Filtered Ports", False)],
    "window": [("open_ports", "opened_ports_services", "Open Ports"),
            ("closed_ports", "closed_ports_services", "Closed Ports"),
            ("filtered_ports", "filtered_ports_services", "Filtered Ports"),
            ("open_filtered_ports", "open_filtered_ports_services", "(WINDOW Scan) Open|Filtered Ports", False)],
    "fdd": [("defended_ports", "defended_ports_services", "Defended Ports"),
            ("undefended_ports", "undefended_ports_services", "Undefended Ports")],
}

PROFILE_FIELDS = {
    "target":         ("target",          "str"),
    "exclude":        ("exclude",         "str"),
    "scan_type":      ("scan_type",       "str"),
    "speed":          ("speed",           "str"),
    "ports":          ("port",            "str"),
    "save":           ("save",            "str"),
    "payload":        ("payload",         "str"),

    "threads":        ("threads",         "int"),
    "max_retries":    ("max_retries",     "int"),
    "ttl":            ("ttl",             "int"),
    "hlim":           ("hlim",            "int"),
    "sport":          ("sport",           "int"),
    "id":             ("id",              "int"),
    "ip_flags":       ("ip_flags",        "int"),

    "timeout":        ("timeout",         "float"),
    "interval":       ("interval",        "float"),

    "banner":         ("banner",          "bool"),
    "os":             ("os",              "bool"),
    "F":              ("F",               "bool"),
    "fragmente":      ("fragmente",       "bool"),
    "no_ping":        ("no_ping",         "bool"),
    "recursively":    ("recursively",     "bool"),
    "verbose":        ("verbose",         "bool"),
    "quiet":          ("quiet",           "bool"),
}

PORT_BUCKETS = {
    'open_ports':            'opened_ports_services',
    'closed_ports':          'closed_ports_services',
    'filtered_ports':        'filtered_ports_services',
    'open_filtered_ports':   'open_filtered_ports_services',
    'null_ports':            'null_ports_services',
    'fin_ports':             'fin_ports_services',
    'defended_ports':        'defended_ports_services',
    'undefended_ports':      'undefended_ports_services',
    'unfiltered_ports':      'unfiltered_ports_services',
    'closed_filtered_ports': 'closed_filtered_ports_services',
}

conf.sniff_promisc = 0
conf.bufsize = 65536
conf.use_bpf = False
conf.L3socket.timeout = 1
conf.debug_dissector = 0
conf.use_pcap = True

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*MAC address to reach destination not found.*")

def handle_thread_exception(args):
    if isinstance(args.exc_value, OSError):
        return
    print(f"Thread exception: {args.exc_type.__name__}: {args.exc_value}")
threading.excepthook = handle_thread_exception

def is_loopback(target):
    return (target == '127.0.0.1' or target == '::1' or
            target.startswith('127.') or target == 'localhost' or
            target == GetIPv4())

class Lightscan:
    __slots__ = [
        'speed_presets', 'host_ext', 'Proto', 'scan_type', 'version','lsse_ports_to_scan',
        'max_threads', 'socket_timeout', 'args', 'parser','pp','valid',
        'targetss', 'ports_to_scan', 'target_results', 'targets','dns','rff_targets',
        'profile_dir', 'interval','start_time', 'end_time','lock','capture_buffer','old_stdout',
        '__weakref__','E','EE','timeout_count','user_os','LSSE',"protocols","saving",
        '_output_filename'
    ]

    def __init__(self):
        self.speed_presets = {
            'paranoid':    speed_parser('paranoid'),
            'slow':        speed_parser('slow'),
            'normal':      speed_parser('normal'),
            'fast':        speed_parser('fast'),
            'insane':      speed_parser('insane'),
            'light-mode':  speed_parser('light-mode')
        }
        self.host_ext = {
            '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
            '.info', '.biz', '.name', '.pro', '.xyz', '.online', '.site',
            '.tech', '.store', '.app', '.dev', '.io', '.ai', '.cloud',
            '.us', '.uk', '.ca', '.au', '.de', '.fr', '.jp', '.cn', '.in',
            '.br', '.ru', '.mx', '.it', '.es', '.nl', '.se', '.no', '.ch',
            '.at', '.dk', '.fi', '.ie', '.nz', '.za', '.sg', '.kr', '.tw',
            '.hk', '.tr', '.ae', '.sa',
            '.eu', '.asia', '.africa',
            '.academy', '.school', '.college', '.university',
            '.business', '.company', '.co', '.shop', '.market',
            '.media', '.news', '.tv', '.film', '.music', '.games',
            '.law', '.legal', '.medical', '.health', '.finance',
            '.realestate', '.travel', '.restaurant', '.club',
            '.art', '.design', '.blog', '.social', '.space', '.world',
            '.expert', '.guru', '.agency', '.services',
            '.fitness', '.health', '.food', '.travel', '.cars', '.fashion'
        }
        self.lsse_ports_to_scan = []
        self.profile_dir = os.path.join(os.path.dirname(__file__), "Profiles")
        self.protocols = []
        self.valid = []
        self.pp = []
        self.capture_buffer = None
        self.old_stdout = None
        self.E = None
        self.EE = None
        self.saving = None
        self.Proto = "tcp"
        self.scan_type = "tcp"
        self.version = "1.1.9"
        self.dns = None
        self.interval = 0.02
        self.max_threads = 60
        self.socket_timeout = 0.0
        self.targetss = []
        self.ports_to_scan = []
        self.target_results = {}
        self.targets = []
        self.rff_targets = []
        self.lock = threading.Lock()
        self.timeout_count = 0
        self.user_os = platform.system()
        os.makedirs(self.profile_dir, exist_ok=True)

    def Banner(self):
        print(BLUE)
        print("""
    __    _       __    __                                                                                                                                              
   / /   (_)___ _/ /_  / /_______________ _____                                                                                                                         
  / /   / / __ `/ __ \\/ __/ ___/ ___/ __ `/ __ \\                                                                                                                        
 / /___/ / /_/ / / / / /_(__  ) /__/ /_/ / / / /                                                                                                                        
/_____/_/\\__, /_/ /_/\\__/____/\\___/\\__,_/_/ /_/                                                                                                                         
        /____/  
        
        """)
        print(f"{RESET}{BOLD}Version  :{RESET}{GREEN} {self.version}")
        print(f"{RESET}{BOLD}Platform :{RESET}{GREEN} {self.user_os} \n{RESET}")

    def initialize_target_results(self, target):
        self.target_results[target] = {
            'open_ports': [],
            'open_protocols': [],
            'open_protocols_names':[],
            'closed_protocols':[],
            'closed_protocols_names':[],
            'open_filtered_protocols':[],
            'open_filtered_protocols_names':[],
            'filtered_protocols':[],
            'filtered_protocols_names':[],
            'closed_ports': [],
            'closed_filtered_ports':[],
            'filtered_ports': [],
            'defended_ports': [],
            'undefended_ports': [],
            'unfiltered_ports': [],
            'open_filtered_ports': [],
            'null_ports': [],
            'fin_ports':[],
            'opened_ports_services': [],
            'closed_ports_services': [],
            'closed_filtered_ports_services':[],
            'filtered_ports_services': [],
            'defended_ports_services': [],
            'undefended_ports_services': [],
            'unfiltered_ports_services': [],
            'open_filtered_ports_services': [],
            'os_confi': 0,
            'os_main_tree':'',
            'os_version':'',
            'null_ports_services': [],
            'fin_ports_services': [],
            'banners': [],
            'banners_ports': [],
            'window_scan_os': [],
            'up': 0,
            'down': 0
        }

    def _sync_and_deduplicate_ports(self, target):
        if target not in self.target_results:
            return

        def deduplicate_sync(ports, services):
            seen = set()
            unique_ports = []
            unique_services = []

            for port, service in zip(ports, services):
                if port not in seen:
                    seen.add(port)
                    unique_ports.append(port)
                    unique_services.append(service)

            return unique_ports, unique_services

        results = self.target_results[target]

        results['open_ports'], results['opened_ports_services'] = deduplicate_sync(
            results['open_ports'], results['opened_ports_services'])
        results['closed_ports'], results['closed_ports_services'] = deduplicate_sync(
            results['closed_ports'], results['closed_ports_services'])
        results['filtered_ports'], results['filtered_ports_services'] = deduplicate_sync(
            results['filtered_ports'], results['filtered_ports_services'])
        results['open_filtered_ports'], results['open_filtered_ports_services'] = deduplicate_sync(
            results['open_filtered_ports'], results['open_filtered_ports_services'])
        results['banners'], results['banners_ports'] = deduplicate_sync(
            results['banners'], results['banners_ports'])


    def Firewall_detection(self, target, results):
        from firewall_ase import FirewallDetector
        detector = FirewallDetector()

        assessment = detector.detect(
            target=target,
            results=results,
            scan_type=self.args.scan_type,
            ports_to_scan=self.ports_to_scan,
        )

        detector._print_assessment(assessment, target)


    def args_parse(self):
        self.parser = argparse.ArgumentParser(
            description="Lightscan Port Scanner - Advanced Network Scanning Tool",
            epilog="""
COMMON EXAMPLES:\n
  Basic SYN scan:  Lightscan.py -T 192.168.1.1 -p 1-1000 -st SYN -s normal
  Aggressive scan: Lightscan.py -T example.com -A
  OS detection:    Lightscan.py -T 10.0.0.1 -O -b -s slow
  Run script:      Lightscan.py --lsse --script http-cert --domain example.com -sp 443\n""",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        basic = self.parser.add_argument_group('Basic Scanning Options')

        basic.add_argument("-T", "--target", required=False, help="Target IP or Hostname")
        basic.add_argument("-V6", required=False, help="used when the target is an IPv6", action="store_true")
        basic.add_argument("-p", "--port", required=False, type=str, help="Port/s to scan")
        basic.add_argument("-s", "--speed", required=False, default="normal",help="Scan speed preset (paranoid,slow,normal,fast,insane,light-mode,etc ...)")
        basic.add_argument("-q","--quiet",action="store_true",help="Quiet mode {does't print the Tool Banner}")
        basic.add_argument("-F",action="store_true",help="Scan The Top 100 ports for fast scanning")

        advanced = self.parser.add_argument_group('Advanced Scanning Options')

        advanced.add_argument("--rff", required=False, type=str, help="Read Target/s from a file")
        advanced.add_argument("--rffp", required=False, type=str, help="Read Port/s from a file")
        advanced.add_argument("--exclude", type=str, help="exclude host/s for the scan")
        advanced.add_argument("--daemon", required=False, action="store_true",help="Run Lightscan as a background task")
        advanced.add_argument("-I", action="store_true", help="display open ports right after the response")
        advanced.add_argument("-pp", "--ping-port", help="Port/s to Ping on it")
        advanced.add_argument("-st","--scan-type",default="TCP", help="Scan types {TCP,SYN,UDP,NULL,FIN,ACK,XMAS,WINDOW,MAIMON,FDD,FTP-BOUNCE,IPPROTO,PING,IDLE,SCTP-INIT,CUSTOM}")
        advanced.add_argument("-D",default=None,help="Decoy machines to use : example {... -D 1.1.1.1,2.2.2.2 }")
        advanced.add_argument("-b","--banner",action="store_true",help="Banner Grabing")
        advanced.add_argument("-O","--os",action="store_true",help="OS Fingerprint ")
        advanced.add_argument("--min-score",type=float,default=15.0,help="Minimum OS Fingerprint Score")
        advanced.add_argument("--min-confi",type=float,default=9.0,help="Minimum OS Confidence Score")
        advanced.add_argument("-Pan","--local-ping",action="store_true",help="Performe an ARP Ping on Local Networks by default or NDP Ping on Local Networks for IPv6 mode")
        advanced.add_argument("-A","--agressive",action="store_true",help="Agressive scan activate all of OS Fingerprints, Banner Grabing, Insane Speed , SYN Scan and Scan Top 100 Ports")

        stealth = self.parser.add_argument_group('Stealth & Evasion')

        stealth.add_argument("--shuffle", action="store_true", help="randomize ports order")
        stealth.add_argument("--no-firewall-ase", action="store_true", help="disabeling firewall assessment")
        stealth.add_argument("--zombie", type=str, help="Zombie IP for idle scan (required for --st IDLE)")
        stealth.add_argument('--ftp-bounce', dest='ftp_server',help='FTP server for bounce scan (required for --st FTP-BOUNCE)')
        stealth.add_argument("-f","--fragmente",action="store_true",help="fragment the sending packet for more stealth ")
        stealth.add_argument("-fg","--fragsize",default=None,help="fragment the sending packet size in bytes")
        stealth.add_argument("-ttl",type=int,help="Time To Live for IPv4 packets")
        stealth.add_argument("-hlim",type=int,help="Hop Limit for IPv6 packets")
        stealth.add_argument("-sport",type=int,help="Source Port")
        stealth.add_argument("-payload",type=str,help="Add a raw custom payload")
        stealth.add_argument("-payload-lenght",type=int,help="Add a raw random payload based on lenght")
        stealth.add_argument("-id",type=int,help="ID Field for IPv4 packets")
        stealth.add_argument("-ip-flags",type=int,help="IP Flags Field for IPv4 packets (DF=2,MF=1,None=0)")
        stealth.add_argument("-tcp-flag",type=str,help="TCP Flags For Custom Packet Manipulation",default="S")

        hostdis = self.parser.add_argument_group('Host Discovery Options')

        hostdis.add_argument("-sn",action="store_true", help="do only a host discovery without port scaning")
        hostdis.add_argument("-Pn","--no-ping",action="store_true",help="Do not ping the target/s")
        hostdis.add_argument("-Pi", "--ip-ping", action="store_true", help="IP Protocol Ping")
        hostdis.add_argument("-Pip", type=str,help="For Specefiy The IP Protocols that -Pi is going to use rather then default")
        hostdis.add_argument("-Pt","--tcp-ping",action="store_true",help="Do a TCP Ping")
        hostdis.add_argument("-Ps","--syn-ping",action="store_true",help="Do a Syn Ping")
        hostdis.add_argument("-Pk","--ack-ping",action="store_true",help="DO a ACK Ping")
        hostdis.add_argument("-Pu","--udp-ping",action="store_true",help="Do a UDP Ping")
        hostdis.add_argument("-PIt","--icmp-timestamp-ping",action="store_true",help="Do scan a ICMP Timestamp Ping")
        hostdis.add_argument("-PA","--icmp-address-ping",action="store_true",help="Do scan a ICMP Address Ping")
        hostdis.add_argument("-Pin","--icmp-information-ping",action="store_true",help="Do scan a ICMP Information Ping")
        hostdis.add_argument("-Pas","--icmp-solicitation-ping",action="store_true",help="Do scan a ICMP Solicitation Ping on the network")
        hostdis.add_argument("-Pg","--igmp-ping",action="store_true",help="Do scan a IGMP Ping on the network")

        performance = self.parser.add_argument_group('Performance Options')

        performance.add_argument("--interval",help="add a little delay between packets for rate limitting ",type=float,default=0.02)
        performance.add_argument("-mx","--max-retries",type=int,help="Max number of retries if port show a no response",default=1)
        performance.add_argument("-t","--threads",type=int,help="Number of threads to use")
        performance.add_argument("-tm","--timeout",type=float,help="Timeout with second")
        performance.add_argument("-Rc","--recursively",action="store_true",help="recursively scan host that shown to be down or not responding and disable flags like -v,-Pn,etc ...")

        output = self.parser.add_argument_group('Output & Logging')

        output.add_argument("--save",required=False,default=None,help="Saving Format (txt,light,html,xml,csv,json,yaml,toml,hex-str)")
        output.add_argument("-v", "--verbose",action="store_true", help="Show verbose output ")
        output.add_argument("-n",action="store_true",help="Disable reverse dns")
        output.add_argument("-V", "--version", action="store_true", help="show Light-Scan version with all additionnal tools")
        output.add_argument("-mac",action="store_true",help="Light-Scan will skip getting the target mac on Local Networks")

        scripting = self.parser.add_argument_group('Scripting Engine (LSSE)')

        scripting.add_argument("--script", type=str, help="LSSE Script ,Ex: --script http-cert")
        scripting.add_argument("--domain", type=str, help="Domain for http/https and Dns based scripts ")
        scripting.add_argument("--dns-server", type=str,help="dns server that Light-Scan is going to use (Is Set by Default ")
        scripting.add_argument("-W", "--wordlist", type=str, help="Wordlist for scripts ")
        scripting.add_argument("--extensions", type=str, help="Extensions for web based scripts ")
        scripting.add_argument("--status-codes", type=str, help="Status Codes for web based scripts ")
        scripting.add_argument("--redirect", action="store_true", help="Redirect http/https requests for http scripts")
        scripting.add_argument("--url", type=str, help="Victime URL")
        scripting.add_argument("--mxp", help="max pages to get")
        scripting.add_argument("--mxd", help="max depth to crawl")
        scripting.add_argument("-sp", help="Port/s that are going to use by scripts")
        scripting.add_argument("--starget", type=str, help="Targets for scripts")
        scripting.add_argument("--username", type=str, help="Single username for LSSE scripts")
        scripting.add_argument("--password", type=str, help="Single password for LSSE scripts")
        scripting.add_argument("--userlist", type=str, help="Userlist for LSSE scripts")
        scripting.add_argument("--passwordlist", type=str, help="Passwordlist for LSSE scripts")
        scripting.add_argument("--file", type=str, help="File for LSSE scripts")
        scripting.add_argument("--request", type=str, help="Request for LSSE scripts")
        scripting.add_argument("--ssl", action="store_true", help="SSL/TLS Encryption for LSSE scripts")
        scripting.add_argument("--lsse", action="store_true",help="Use that flag when you want just to performe a script")

        utility = self.parser.add_argument_group('Utility Options')

        utility.add_argument("-lst",action="store_true",help="List all targets")
        utility.add_argument("--port-lst",action="store_true",help="List all ports that are gonna be scanned")
        utility.add_argument("--lsse-lst", action="store_true", help="List all LSSE Scripts")
        utility.add_argument("--script-help",type=str,help="Show help about a specifique script/s")
        utility.add_argument("--update-lsse",action="store_true",help="Update LSSE Script Data Base")
        utility.add_argument("--profiles-lst", action="store_true", help="List all scan profiles from Profiles directory")
        utility.add_argument("--load-profile", type=str, help="Load the scan profile from Profiles/ directory")
        utility.add_argument("--save-profile", type=str, help="Save the scan profile to Profiles/ directory")
        utility.add_argument("--diff", nargs=2, metavar=("A", "B"),help="Compare two reports (JSON/YAML/TOML/XML)")
        utility.add_argument("--interfaces",action="store_true",help="Show All System interfaces")

        self.args = self.parser.parse_args()

    def verification(self):
        if self.args.ttl:
            self.args.ttl = ver_ttl(self.args.ttl)
        if self.args.hlim:
            self.args.hlim = ver_hlim(self.args.hlim)
        if self.args.ip_flags:
            self.args.ip_flags = ver_ip_flags(self.args.ip_flags)
        if self.args.id:
            self.args.id = ver_ip_id(self.args.id)

    def list_targets(self):
        for target in self.targets:
            print("\nTarget: " + target + "\n")
        exit(0)

    def port_targets(self):
        print("\n[+] Ports : ",self.ports_to_scan,"\n")
        exit(0)

    def loopback_scan_handler(self, target, port, version):
        family = socket.AF_INET6 if self.args.V6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.socket_timeout)
        try:
            result = sock.connect_ex((target, port))
        finally:
            sock.close()

        service = self.service_detection(port)

        if result == 0:
            self._record(target, 'open_ports', port, service)

            if self.args.banner:
                self._grab_and_record_banner(target, port, service, version)
        else:
            self._record(target, 'closed_ports', port, service)

    def agressive_scan_config(self):
        if self.args.agressive:
            self.args.os = True
            self.args.banner = True
            self.args.speed = "insane"
            self.args.scan_type = "SYN"
            self.args.F = True
        else:
            pass

    def target_parse(self):
        if self.args.rff:
            for T in self.rff_targets:
                targets = parse_targets(target_input=T,max_hosts=4000000000)
                self.targets.extend(targets)
        else:
            targets = parse_targets(target_input=self.args.target, max_hosts=4000000000)
            self.targets.extend(targets)

        if self.args.exclude:
            excluded_targets = parse_targets(target_input=self.args.exclude, max_hosts=4000000000)
            self.targets = [target for target in self.targets if target not in excluded_targets]

        self.target_validation()

        for target in self.targets:
            self.initialize_target_results(target)

        self.version = 4

        if self.args.V6:
            self.version = 6
        else:
            self.version = 4

    def rff(self, filename):
        with open(filename, 'r') as file:
            for line in file:
                self.rff_targets.append(line.strip())

    def rffp(self, filename):
        with open(filename, 'r') as file:
            for line in file:
                if self.args.port is None:
                    self.args.port = line.strip()
                else:
                    self.args.port += ',' + line.strip()

    def save_profile(self, profile_name):
        os.makedirs(self.profile_dir, exist_ok=True)
        profile_path = os.path.join(self.profile_dir, f"{profile_name}.json")

        settings = {}
        for json_key, (attr, _type) in PROFILE_FIELDS.items():
            value = getattr(self.args, attr, None)
            if value is None or value is False or value == "":
                continue
            settings[json_key] = value

        profile_data = {
            "name": profile_name,
            "description": f"Light-Scan profile: {profile_name}",
            "settings": settings,
        }

        try:
            with open(profile_path, "w", encoding="utf-8") as f:
                json.dump(profile_data, f, indent=2, sort_keys=False)

            print(f"{green}[+] Profile saved: {profile_name}.json")
            print(f"{yellow}    Location: {profile_path}{reset}")
            return True

        except Exception as e:
            print(f"[!] Error saving profile: {e}")
            return False

    def load_profile(self, profile_name):
        profile_path = os.path.join(self.profile_dir, f"{profile_name}.json")

        if not os.path.exists(profile_path):
            print(f"{red}[!] Profile '{profile_name}' not found in Profiles/{reset}")
            print(f"{yellow}[!] Available profiles:{reset}")
            self.list_profiles()
            sys.exit(1)

        try:
            with open(profile_path, "r") as f:
                profile = json.load(f)

            settings = profile.get("settings", {})

            for json_key, (attr, _type) in PROFILE_FIELDS.items():
                if json_key not in settings:
                    continue

                current = getattr(self.args, attr, None)
                if self._profile_attr_is_default(json_key, attr, current):
                    setattr(self.args, attr, settings[json_key])

            print(f"{green}[+] Loaded profile: {profile.get('name', profile_name)}{reset}")
            if profile.get("description"):
                print(f"    {yellow}{profile['description']}{reset}")

        except json.JSONDecodeError as e:
            print(f"{red}[!] Invalid profile JSON: {e}{reset}")
            sys.exit(1)
        except Exception as e:
            print(f"{red}[!] Error loading profile: {e}{reset}")
            sys.exit(1)

    def _profile_attr_is_default(self, json_key, attr, current):
        if json_key == "ports":
            return not current
        if json_key == "scan_type":
            return current == "TCP"
        if json_key == "speed":
            return current == "normal"
        return current is None or current is False or current == ""

    def target_validation(self):
        resolved_targets = []

        for target in self.targets:
            result = self._resolve_target(target)
            if result is not None:
                resolved_targets.append(result)

        seen = set()
        self.targets = []
        for t in resolved_targets:
            if t not in seen:
                seen.add(t)
                self.targets.append(t)

    def _resolve_target(self, target):
        if TargetParser.validate_ip(ip=target, version=4):
            return target

        if ":" in target:
            if TargetParser.validate_ip(ip=target, version=6):
                return target
            print(f"{yellow}\n[!] Invalid IPv6 target: {target}{reset}")
            return None

        try:
            resolved = TargetParser.resolve_hostname(target)
            if resolved is not None:
                return resolved
            print(f"{yellow}\n[!] Failed to resolve ({target}) {reset}")
            return None
        except Exception:
            print(f"{red}\n[!] Invalid Target IP or Hostname {target}{reset}\n")
            return None

    def list_profiles(self):
        if not os.path.exists(self.profile_dir):
            print(f"{yellow}[!] No profiles directory found{reset}")
            return

        profiles = [f for f in os.listdir(self.profile_dir) if f.endswith('.json')]

        if not profiles:
            print(f"{yellow}[!] No profiles found. Create one in {self.profile_dir}{reset}")
            return

        print(f"\n{green}[*] Available Profiles:{reset}")
        print("-" * 50)

        for profile_file in sorted(profiles):
            try:
                with open(os.path.join(self.profile_dir, profile_file), 'r') as f:
                    profile = json.load(f)

                name = profile.get('name', profile_file.replace('.json', ''))
                desc = profile.get('description', 'No description')
                settings = profile.get('settings', {})

                print(f"  {green}[+] {name}{reset}")
                print(f"     {yellow}--> {desc}{reset}")
                print()
            except Exception as e:
                print(f"  {red}{profile_file}: Error - {e}{reset}")

    def configure_speed(self):
        if self.args.speed is not None and self.args.speed not in Global.buitin:
            preset = speed_parser(self.args.speed)
            self.max_threads = preset['threads']
            self.socket_timeout = preset['timeout']
            return

        preset = self.speed_presets.get(self.args.speed)
        if preset is not None:
            self.max_threads = preset['threads']
            self.socket_timeout = preset['timeout']

        else:
            self.socket_timeout = 1.5

        if self.args.threads:
            self.max_threads = self.args.threads

        if self.args.timeout:
            self.socket_timeout = self.args.timeout

        self.interval = self.args.interval

    def service_detection(self, port):
        try:
            service = Lightscan_Service_List(port,self.Proto)
            if service is None:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = "Unknown"
        except:
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = "Unknown"

        if service is None:
            service = "Unknown"

        return service.lower()

    def reverse_dns_lookup(self, ip):
        if self.args.V6:
            if ip == "::1":
                return ip
            reversed_ip = ipaddress.ip_address(ip).reverse_pointer + '.'
        else:
            reversed_ip = '.'.join(ip.split('.')[::-1]) + '.in-addr.arpa.'

        if self.args.dns_server:
            dns_server = self.args.dns_server
        else:
            dns_server = scapy.conf.route.route("0.0.0.0")[2]
        dns_request = scapy.IP(dst=dns_server) / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=reversed_ip, qtype='PTR'))

        ans = scapy.sr1(dns_request, verbose=False, timeout=2)

        if ans and ans.haslayer(scapy.DNS) and ans[scapy.DNS].an:
            domain_name = ans[scapy.DNS].an.rdata.decode()[:-1]
            return domain_name
        else:
            return None


    def _parse_int_list(self, spec, min_val, max_val, label="Port",
                        on_error="skip"):
        if spec is None:
            return [], False

        values = []
        had_error = False

        for item in spec.split(","):
            item = item.strip()
            if not item:
                continue

            if "-" in item:
                try:
                    start, end = item.split("-", 1)
                    start, end = int(start), int(end)
                    if start < min_val or end > max_val or end < start:
                        raise ValueError
                    values.extend(range(start, end + 1))
                except Exception:
                    print(f"\n{red}[!] Invalid {label} range: <{item}>{reset}\n")
                    had_error = True
                    if on_error == "exit":
                        sys.exit(1)

            else:
                try:
                    v = int(item)
                    if v < min_val or v > max_val:
                        raise ValueError
                    values.append(v)
                except Exception:
                    print(f"\n{red}[!] Invalid {label}: <{item}>{reset}\n")
                    had_error = True
                    if on_error == "exit":
                        sys.exit(1)

        return values, had_error

    def _resolve_scan_list(self, spec, min_val, max_val, label="Port",
                           empty_default=None, fatal_on_empty=False,
                           shuffle=False):
        values, had_error = self._parse_int_list(
            spec, min_val, max_val, label,
            on_error="exit" if fatal_on_empty else "skip")

        if not values:
            if fatal_on_empty:
                print(f"\n{yellow}[!] No {label}/s was assigned{reset}\n")
                sys.exit(1)
            if empty_default is not None:
                if spec is not None and had_error:
                    print(f"\n{red}[!] Invalid {label}/s, using default{reset}\n")
                values = list(empty_default)

        if shuffle and values:
            from Mint.portparser import fisher_yates_shuffle
            values = fisher_yates_shuffle(values)

        return values

    def port_parse(self):
        if self.args.F:
            self.ports_to_scan = list(top_100_ports)
            if self.args.shuffle:
                from Mint.portparser import fisher_yates_shuffle
                self.ports_to_scan = fisher_yates_shuffle(self.ports_to_scan)
            return

        self.ports_to_scan = self._resolve_scan_list(
            self.args.port,
            min_val=1, max_val=65535, label="Port",
            empty_default=top_1000_ports,
            shuffle=self.args.shuffle)

    def ip_ping_protocols(self):
        self.protocols = self._resolve_scan_list(
            self.args.Pip,
            min_val=1, max_val=255, label="Protocol",
            empty_default=[1, 2, 4],
            shuffle=self.args.shuffle)

    def ping_port_parse(self):
        self.pp = self._resolve_scan_list(
            self.args.ping_port,
            min_val=1, max_val=65535, label="Port",
            fatal_on_empty=True,
            shuffle=self.args.shuffle)

    def script_port_parse(self):
        self.lsse_ports_to_scan = self._resolve_scan_list(
            self.args.sp,
            min_val=1, max_val=65535, label="Port",
            fatal_on_empty=True,
            shuffle=self.args.shuffle)
        return self.lsse_ports_to_scan

    def udp_scan(self, port, target):
        version = 6 if self.args.V6 else 4

        self.Proto = "udp"
        self.scan_type = "udp"

        mach, first, last, index = self._decoy_meta(version)

        timeout = self.socket_timeout if self.args.timeout else 5

        for attempt in range(self.args.max_retries):
            try:
                packet = self._build_udp_packet(target, port, version)

                if first:
                    self._send_decoys(packet, mach, mach[:index], version)

                if self.args.fragmente and self.args.recursively:
                    if version == 6:
                        response = Payloads.fragementation(
                            packet, self.Proto, self.scan_type,
                            self.args.verbose,
                            fragsize=self.args.fragsize, v6=True)
                    else:
                        response = Payloads.fragementation(
                            packet, self.Proto, self.scan_type,
                            self.args.verbose,
                            fragsize=self.args.fragsize)
                    if self.args.verbose:
                        print("[+] Demo Fragementation (if you find an error while "
                              "using it leave it in our github for future updates)\n")
                elif self.args.fragmente:
                    if self.args.verbose:
                        print(f"{yellow}[+] Fragmentation is Forbiden with UDP packets "
                              f"(if you want use flag -Rc){reset}\n")
                    response = scapy.sr1(packet, timeout=timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=timeout, verbose=0)

                if last:
                    self._send_decoys(packet, mach, mach[index:], version)

                service = self.service_detection(port)

                if response is None:
                    if attempt == self.args.max_retries - 1:
                        self._record(target, 'open_filtered_ports', port, service)
                        return
                    if self.args.verbose:
                        print(f"{yellow}[!] No response from UDP port {port}, "
                              f"retrying... (attempt {attempt + 1}/{self.args.max_retries}){reset}")
                    time.sleep(0.1)
                    continue

                if response.haslayer(scapy.ICMP) and not self.args.V6:
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code == 3:
                        self._record(target, 'closed_ports', port, service)
                        return

                    self._record(target, 'filtered_ports', port, service)
                    return

                if response.haslayer(scapy.UDP):
                    if self.args.I:
                        print(f"\n[+] Port {port} is open .")
                    self._record(target, 'open_ports', port, service)

                    if self.args.banner:
                        self._grab_and_record_banner(target, port, service,
                                                     version, protocol="udp")
                    return

                self._record(target, 'filtered_ports', port, service)
                return

            except Exception as e:
                if self.args.verbose:
                    print(f"{red}[!] UDP scan failed? That's weird. Heretic fixed this bug?{e}{reset}")
                if attempt == self.args.max_retries - 1:
                    service = self.service_detection(port)
                    if port not in self.target_results.get(target, {}).get('open_ports', []):
                        self._record(target, 'filtered_ports', port, service)
                    return
                time.sleep(0.1)
                continue

    def threaded_udp_scan(self):
        self.start_time = time.perf_counter()

        if self.max_threads == 1:
            for Target in self.targets:
                for Port in self.ports_to_scan:
                    self.udp_scan(Port, Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targetss:
                    for port in self.ports_to_scan:
                        future = executor.submit(
                            self.udp_scan,port,target
                        )
                        time.sleep(self.interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] UDP scan error: {e}{reset}")

        self.end_time = time.perf_counter()

    def _ensure_target(self, target):
        if target not in self.target_results:
            self.initialize_target_results(target)

    def _record(self, target, bucket, port, service):
        with self.lock:
            self._ensure_target(target)
            self.target_results[target][bucket].append(port)
            services_key = PORT_BUCKETS.get(bucket)
            if services_key:
                self.target_results[target][services_key].append(service)

    def _decoy_meta(self, version):
        if not self.args.D:
            return None, None, None, None
        mach = decoy(self.args.D, version)
        first, last, index = decoy_order(mach)
        return mach, first, last, index

    def _send_decoys(self, packet, mach, indices, version):
        if not mach or indices is None:
            return
        for ma in indices:
            if version == 6:
                packet[IPv6].src = ma
            else:
                packet[scapy.IP].src = ma
            scapy.send(packet, verbose=0)

    def _resolve_payload(self):
        if self.args.payload is None:
            return mirage.random_payload()
        return self.args.payload

    def _resolve_ttl(self):
        return self.args.ttl if self.args.ttl else mirage.ipv4_ttl()

    def _resolve_hlim(self):
        return self.args.hlim if self.args.hlim else mirage.ipv6_hlim()

    def _resolve_sport(self, proto="tcp"):
        if self.args.sport:
            return self.args.sport
        return mirage.tcp_sport() if proto == "tcp" else mirage.udp_sport()

    def _resolve_ip_id(self):
        return self.args.id if self.args.id else mirage.ipv4_id()

    def _resolve_ip_flags(self):
        return self.args.ip_flags if self.args.ip_flags is not None else mirage.ipv4_flags()

    def _build_tcp_syn(self, target, port, version):
        if port == 22:
            return mirage.ssh_payload_tcp(target, version)
        if port == 21:
            return mirage.ftp_payload_tcp(target, version)
        if port in (80, 443, 8080, 8000, 8443, 8888):
            return mirage.http_payload_tcp(target, version, port)

        payloads = self._resolve_payload()
        sport = self._resolve_sport("tcp")

        if version == 6:
            hlim = self._resolve_hlim()
            return (IPv6(dst=target, nh=6, hlim=hlim)
                    / scapy.TCP(dport=port, sport=sport,
                                seq=mirage.tcp_seq(), window=mirage.tcp_window(),
                                options=mirage.Stealth_tcp_options(), flags="S")
                    / scapy.Raw(load=payloads))

        return (scapy.IP(dst=target, id=self._resolve_ip_id(),
                         ttl=self._resolve_ttl(), flags=self._resolve_ip_flags())
                / scapy.TCP(dport=port, sport=sport,
                            seq=mirage.tcp_seq(), window=mirage.tcp_window(),
                            options=mirage.Stealth_tcp_options(), flags="S")
                / scapy.Raw(load=payloads))

    def _build_udp_packet(self, target, port, version):
        if port == 53:
            return mirage.dns_payload_udp(target, version)
        if port == 22:
            return mirage.ssh_payload_udp(target, version)
        if port == 21:
            return mirage.ftp_payload_udp(target, version)

        payloads = self._resolve_payload()
        sport = self._resolve_sport("udp")

        if version == 6:
            return (IPv6(dst=target, nh=17, hlim=self._resolve_hlim())
                    / scapy.UDP(dport=port, sport=sport)
                    / scapy.Raw(load=payloads))

        return (scapy.IP(dst=target, id=self._resolve_ip_id(),
                         ttl=self._resolve_ttl(), flags=self._resolve_ip_flags())
                / scapy.UDP(dport=port, sport=sport)
                / scapy.Raw(load=payloads))

    def _build_tcp_ack(self, target, port, response, version):
        sport = self._resolve_sport("tcp")
        ack = response[scapy.TCP].ack
        seq = response[scapy.TCP].seq + 1

        if version == 6:
            return (IPv6(dst=target, hlim=self._resolve_hlim())
                    / scapy.TCP(dport=port, sport=sport, flags="A", seq=ack, ack=seq))
        return (scapy.IP(dst=target, ttl=self._resolve_ttl())
                / scapy.TCP(dport=port, sport=sport, flags="A", seq=ack, ack=seq))

    def _send_rst(self, target, port, version):
        if version == 6:
            scapy.send(IPv6(dst=target) / scapy.TCP(dport=port, flags="R"), verbose=0)
        else:
            scapy.send(scapy.IP(dst=target) / scapy.TCP(dport=port, flags="R"), verbose=0)

    def _send_ack_handshake(self, target, port, response, version,
                            packet, mach, first, last, index):
        ack_packet = self._build_tcp_ack(target, port, response, version)

        if self.args.fragmente:
            if version == 6:
                ack_responses = Payloads.fragementation(
                    ack_packet, self.Proto, self.scan_type,
                    self.args.verbose, v6=True, fragsize=self.args.fragsize)
            else:
                ack_responses = Payloads.fragementation(
                    ack_packet, self.Proto, self.scan_type,
                    self.args.verbose, fragsize=self.args.fragsize)

            if self.args.verbose:
                if ack_responses:
                    print(f"[+] Successfully sent fragemented ACK to {target}, "
                          f"{ack_responses} responses received from {target}")
                else:
                    print(f"[+] Successfully sent fragmented ACK to {target} (no responses)")
            return

        if first:
            self._send_decoys(ack_packet, mach, mach[:index], version)

        scapy.send(ack_packet, verbose=False)

        if last:
            self._send_decoys(ack_packet, mach, mach[index:], version)

    def _grab_and_record_banner(self, target, port, service, version, protocol="tcp"):
        try:
            banner = Banner.grab(target, port, protocol=protocol, timeout=3,
                                 verbose=self.args.verbose, version=version)
        except Exception:
            with self.lock:
                self._ensure_target(target)
                self.target_results[target]['opened_ports_services'].append(service)
            return

        try:
            if banner and banner.get('banner') is not None and banner.get('service') is not None:
                with self.lock:
                    self._ensure_target(target)
                    self.target_results[target]['banners'].append(banner['banner'])
                    self.target_results[target]['banners_ports'].append(port)
                    self.target_results[target]['opened_ports_services'].append(banner['service'])
            else:
                with self.lock:
                    self._ensure_target(target)
                    self.target_results[target]['opened_ports_services'].append(service)
        except Exception:
            with self.lock:
                self._ensure_target(target)
                self.target_results[target]['opened_ports_services'].append(service)

    def _tcp_scan(self, port, target, scan_mode):
        version = 6 if self.args.V6 else 4

        if is_loopback(target):
            self.loopback_scan_handler(target, port, version)
            return

        self.Proto = "tcp"
        self.scan_type = scan_mode

        mach, first, last, index = self._decoy_meta(version)

        for attempt in range(self.args.max_retries):
            try:
                packet = self._build_tcp_syn(target, port, version)

                if first:
                    self._send_decoys(packet, mach, mach[:index], version)

                if self.args.fragmente:
                    if self.args.recursively:
                        if version == 6:
                            response = Payloads.fragementation(
                                packet, self.Proto, self.scan_type,
                                self.args.verbose,
                                fragsize=self.args.fragsize, v6=True)
                        else:
                            response = Payloads.fragementation(
                                packet, self.Proto, self.scan_type,
                                self.args.verbose,
                                fragsize=self.args.fragsize)
                        if self.args.verbose:
                            print("[+] Demo Fragementation (if you find an error while "
                                  "using it leave it in our github for future updates)\n")
                    else:
                        if self.args.verbose:
                            print(f"{yellow}[+] Fragmentation is Forbiden with SYN packets "
                                  f"(if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)

                if last:
                    self._send_decoys(packet, mach, mach[index:], version)

                service = self.service_detection(port)

                if response is None:
                    if attempt == self.args.max_retries - 1:
                        self._record(target, 'filtered_ports', port, service)
                        return
                    if self.args.verbose:
                        print(f"{yellow}[!] No response from TCP(SYN) port {port}, "
                              f"retrying... (attempt {attempt + 1}/{self.args.max_retries}){reset}")
                    time.sleep(0.1)
                    continue

                if response.haslayer(scapy.TCP):
                    tcp_flags = response.getlayer(scapy.TCP).flags

                    if tcp_flags == 0x12:
                        if self.args.I:
                            print(f"\n[+] Port {port} is open .")
                        self._record(target, 'open_ports', port, service)

                        if self.args.banner:
                            self._grab_and_record_banner(target, port, service, version)

                        if scan_mode == "tcp":
                            self._send_ack_handshake(target, port, response, version,
                                                     packet, mach, first, last, index)

                        self._send_rst(target, port, version)
                        return

                    if tcp_flags in (0x14, 0x04):
                        self._record(target, 'closed_ports', port, service)
                        return

                    self._record(target, 'filtered_ports', port, service)
                    return

                self._record(target, 'filtered_ports', port, service)
                return

            except Exception as e:
                if self.args.verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == self.args.max_retries - 1:
                    service = self.service_detection(port)
                    if port not in self.target_results.get(target, {}).get('open_ports', []):
                        self._record(target, 'filtered_ports', port, service)
                    return
                time.sleep(0.1)
                continue

    def tcp_syn_scan(self, port, target):
        self._tcp_scan(port, target, scan_mode="syn")

    def tcp_3_ways_handshake(self, port, target):
        self._tcp_scan(port, target, scan_mode="tcp")

    def Udp_host_discovery(self, Target, port):
        if is_loopback(Target):
            self.targetss.append(Target)
            print(f"[SYS] Host {Target} is up! ")
            return

        response = self._send_udp_ping(Target, port)
        if response is None:
            return

        if self._is_udp_response_meaningful(response):
            print(f"[UDP] Host {Target}:{port} is up! ")
        self._record_host_up(Target)

    def _send_udp_ping(self, Target, port):
        version = 6 if self.args.V6 else 4
        mach, first, last, index = self._decoy_meta(version)
        sport = self._resolve_sport("udp")
        payloads = self._resolve_payload()
        if version == 6:
            packet = (IPv6(dst=Target, nh=17, hlim=self._resolve_hlim())
                      / scapy.UDP(dport=port, sport=sport)
                      / scapy.Raw(load=payloads))
        else:
            packet = (scapy.IP(dst=Target, id=self._resolve_ip_id(),
                               ttl=self._resolve_ttl(), flags=self._resolve_ip_flags())
                      / scapy.UDP(dport=port, sport=sport)
                      / scapy.Raw(load=payloads))

        if first:
            self._send_decoys(packet, mach, 0, index, version)
        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
        if last:
            self._send_decoys(packet, mach, index, None, version)
        return response

    def _is_udp_response_meaningful(self, response):
        if response.haslayer(scapy.UDP):
            return True
        if self.args.V6 and response.haslayer(ICMPv6DestUnreach):
            return response.getlayer(ICMPv6DestUnreach).code in (1, 4)
        if response.haslayer(scapy.ICMP):
            return True
        return False

    def threded_Udp_host_discovery(self):
        if self.max_threads == 1:
            for Target in self.targets:
                if self.args.ping_port:
                    for port in self.pp:
                        self.Udp_host_discovery(Target, port)
                else:
                    for port in top_20_udp_ports:
                        self.Udp_host_discovery(Target,port)

            for target in self.targets:
                if self.target_results[target]['up'] >= 1:
                    pass
                else:
                    print(f"[UDP] Host {target} is shown to be down or not responding")

        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                    if self.args.ping_port:
                        for port in self.pp:
                            future = executor.submit(
                                self.Udp_host_discovery, target, port
                            )
                            time.sleep(self.interval)
                            futures.append(future)
                    else:
                        for port in top_20_udp_ports:
                            future = executor.submit(
                                self.Udp_host_discovery,target,port
                            )
                            time.sleep(self.interval)
                            futures.append(future)


                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] UDP ping error: {e}{reset}")

        for target in self.targets:
            time.sleep(0.01)
            if self.target_results[target]['up'] >= 1:
                pass
            else:
                print(f"[UDP] Host {target} is shown to be down or not responding")

    def Syn_host_discovery(self, Target, port):
        if is_loopback(Target):
            self.targetss.append(Target)
            print(f"[SYS] Host {Target} is up! ")
            return

        response = self._send_syn_ping(Target, port)

        if response is not None:
            if self._is_tcp_res(response):
                print(f"[SYN] Host {Target}:{port} is up! ")
            self._record_host_up(Target)
            return

        if len(self.targets) == 1:
            with self.lock:
                if Target not in self.targetss:
                    self.targetss.append(Target)

    def _is_tcp_res(self, response):
        if not response.haslayer(scapy.TCP):
            return False
        return True

    def _record_host_up(self, Target):
        with self.lock:
            if Target not in self.targetss:
                self.targetss.append(Target)
            self.target_results[Target]['up'] += 1

    def _send_syn_ping(self, Target, port):
        version = 6 if self.args.V6 else 4
        mach, first, last, index = self._decoy_meta(version)
        self.Proto = "tcp"
        sport = self._resolve_sport("tcp")

        if version == 6:
            packet = (IPv6(dst=Target, nh=6, hlim=self._resolve_hlim())
                      / scapy.TCP(dport=port, sport=sport,
                                  seq=mirage.tcp_seq(), window=mirage.tcp_window(),
                                  options=mirage.Stealth_tcp_options(), flags="S"))
        else:
            packet = (scapy.IP(dst=Target, id=self._resolve_ip_id(),
                               ttl=self._resolve_ttl(), flags=self._resolve_ip_flags())
                      / scapy.TCP(dport=port, sport=sport,
                                  seq=mirage.tcp_seq(), window=mirage.tcp_window(),
                                  options=mirage.Stealth_tcp_options(), flags="S"))
        if first:
            self._send_decoys(packet, mach, 0, index, version)
        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
        if last:
            self._send_decoys(packet, mach, index, None, version)
        return response

    def threded_Syn_host_discovery(self):
        if self.max_threads == 1:
            for Target in self.targets:
                if self.args.ping_port:
                    for port in self.pp:
                        self.Syn_host_discovery(Target, port)
                else:
                    for port in top_20_tcp_ports:
                        self.Syn_host_discovery(Target,port)

            for target in self.targets:
                if self.target_results[target]['up'] >= 1:
                    pass
                else:
                    print(f"[SYN] Host {target} is shown to be down or not responding")

        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                    if self.args.ping_port:
                        for port in self.pp:
                            future = executor.submit(
                                self.Syn_host_discovery, target, port
                            )
                            time.sleep(self.interval)
                            futures.append(future)
                    else:
                        for port in top_20_tcp_ports:
                            future = executor.submit(
                                self.Syn_host_discovery,target,port
                            )
                            time.sleep(self.interval)
                            futures.append(future)


                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] SYN ping error: {e}{reset}")

        for target in self.targets:
            time.sleep(0.01)
            if self.target_results[target]['up'] >= 1:
                pass
            else:
                print(f"[SYN] Host {target} is shown to be down or not responding")

    def Tcp_host_discovery(self, Target, port):
        if is_loopback(Target):
            self.targetss.append(Target)
            print(f"[SYS] Host {Target} is up! ")
            return
        self.Proto = "tcp"
        family = socket.AF_INET6 if self.args.V6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.socket_timeout)
        try:
            result = sock.connect_ex((Target, port))
        finally:
            sock.close()

        is_up = (result == 0) or self.args.recursively

        if is_up:
            print(f"[TCP] Host {Target}:{port} is up! ")
            with self.lock:
                if Target not in self.targetss:
                    self.targetss.append(Target)
                self.target_results[Target]['up'] += 1
            return

        if not self.ports_to_scan:
            if len(self.targets) == 1:
                print(f"[TCP] Host {Target} is shown to be down or not responding")
                with self.lock:
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1

            elif self.args.verbose:
                print(f"[TCP] Host {Target} is shown to be down or not responding, <Skip it>")

    def threded_Tcp_host_discovery(self):
        if self.max_threads == 1:
            for Target in self.targets:
                if self.args.ping_port:
                    for port in self.pp:
                        self.Tcp_host_discovery(Target, port)
                else:
                    for port in top_20_tcp_ports:
                        self.Tcp_host_discovery(Target,port)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                    if self.args.ping_port:
                        for port in self.pp:
                            future = executor.submit(
                                self.Tcp_host_discovery, target, port
                            )
                            time.sleep(self.interval)
                            futures.append(future)
                    else:
                        for port in top_20_tcp_ports:
                            future = executor.submit(
                                self.Tcp_host_discovery,target,port
                            )
                            time.sleep(self.interval)
                            futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] TCP ping error: {e}{reset}")

        for target in self.targets:
            time.sleep(0.01)
            if self.target_results[target]['up'] >= 1:
                pass
            else:
                print(f"[TCP] Host {target} is shown to be down or not responding")

    def host_discovery_ipv6(self, Target):
        if is_loopback(Target):
            self.targetss.append(Target)
            print(f"[SYS] Host {Target} is up! ")
            return

        response = self._send_icmpv6_echo(Target)
        if self._is_ipv6_response_up(response):
            print(f"[ECHOv6] Host {Target} is up! ")
            self.targetss.append(Target)
            self.target_results[Target]['up'] += 1
            return

        if self.args.recursively:
            print(f"[ECHOv6] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
            self.targetss.append(Target)
            return

        if len(self.targets) == 1:
            print(f"[ECHOv6] Host {Target} is shown to be down or not responding")
            return

        if self.args.verbose:
            print(f"[ECHOv6] Host {Target} is shown to be down or not responding, <Skip it>")

    def _send_icmpv6_echo(self, Target):
        mach, first, last, index = self._decoy_meta(6)
        hlim = self.args.hlim if self.args.hlim else mirage.ipv6_hlim()
        Echo = IPv6(dst=Target, hlim=hlim) / ICMPv6EchoRequest()
        if first:
            self._send_decoys(Echo, mach, 0, index, 6)

        response = scapy.sr1(Echo, timeout=self.socket_timeout, verbose=0)

        if last:
            self._send_decoys(Echo, mach, index, None, 6)
        return response

    def _is_ipv6_response_up(self, response):
        if response is None:
            return False
        if response.haslayer(ICMPv6EchoReply):
            return True
        if response.haslayer(ICMPv6TimeExceeded):
            return True
        if response.haslayer(ICMPv6DestUnreach):
            return response[ICMPv6DestUnreach].code == 4
        return False

    def _send_icmp_query(self, Target, icmp_type):
        mach, first, last, index = self._decoy_meta(4)
        ttl = self.args.ttl if self.args.ttl else mirage.ipv4_ttl()
        ip_id = self.args.id if self.args.id else mirage.ipv4_id()
        ip_flags = self.args.ip_flags if self.args.ip_flags is not None else mirage.ipv4_flags()

        packet = (scapy.IP(dst=Target, id=ip_id, ttl=ttl, flags=ip_flags)
                  / scapy.ICMP(type=icmp_type, id=mirage.icmp_id(),
                               seq=mirage.icmp_seq(), code=0))

        if first:
            self._send_decoys(packet, mach, 0, index, 4)
        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
        if last:
            self._send_decoys(packet, mach, index, None, 4)
        return response

    def _handle_discovery_response(self, Target, response, tag):
        if response:
            print(f"[{tag}] Host {Target} is up! ")
            self.targetss.append(Target)
            self.target_results[Target]['up'] += 1
            return

        if self.args.recursively:
            print(f"[{tag}] Host {Target} is shown to be down or not responding, "
                  f"<Swithch to TCP Host Discovery>")
            self.threded_Tcp_host_discovery()
            return

        if len(self.targets) == 1:
            print(f"[{tag}] Host {Target} is shown to be down or not responding")
            self.targetss.append(Target)
            return

        if self.args.verbose:
            print(f"[{tag}] Host {Target} is shown to be down or not responding, <Skip it>")

    def _handle_icmp_query(self, Target, icmp_type, tag):
        if is_loopback(Target):
            self.targetss.append(Target)
            print(f"[SYS] Host {Target} is up! ")
            return

        response = self._send_icmp_query(Target, icmp_type)
        self._handle_discovery_response(Target, response, tag)

    def host_discovery(self, Target):
        self._handle_icmp_query(Target, icmp_type=8, tag="ECHO")

    def host_discovery_1(self, Target):
        self._handle_icmp_query(Target, icmp_type=13, tag="TIME STAMP")

    def host_discovery_2(self, Target):
        self._handle_icmp_query(Target, icmp_type=17, tag="ADDR")

    def host_discovery_3(self, Target):
        self._handle_icmp_query(Target, icmp_type=15, tag="INFO")

    def igmp_host_discovery(self):
        ttl = self.args.ttl if self.args.ttl else mirage.ipv4_ttl()
        ip_id = self.args.id if self.args.id else mirage.ipv4_id()
        ip_flags = self.args.ip_flags if self.args.ip_flags is not None else mirage.ipv4_flags()

        packet = (scapy.Ether(dst="01:00:5e:00:00:01")
                  / scapy.IP(dst="224.0.0.1", id=ip_id, ttl=ttl, flags=ip_flags)
                  / IGMP(type=0x11, mrcode=10, gaddr="0.0.0.0"))

        if hasattr(packet[IGMP], 'igmpize'):
            packet[IGMP].igmpize()

        response = scapy.srp1(packet, timeout=self.socket_timeout,
                              verbose=0, filter="igmp")

        if response and IGMP in response:
            src_ip = response[scapy.IP].src
            igmp_type = response[IGMP].type
            version = {0x12: "v1", 0x16: "v2", 0x22: "v3"}.get(igmp_type, "Unknown")
            print(f"[+] Found host: {src_ip} (IGMP{version})")
        else:
            print(f"{yellow}[!] No IGMP response received{reset}")

    def host_discovery_4(self):
        ttl = self.args.ttl if self.args.ttl else mirage.ipv4_ttl()
        ip_id = self.args.id if self.args.id else mirage.ipv4_id()
        ip_flags = self.args.ip_flags if self.args.ip_flags is not None else mirage.ipv4_flags()

        packet = (scapy.Ether(dst="01:00:5e:00:00:02")
                  / scapy.IP(dst="224.0.0.2", id=ip_id, ttl=ttl, flags=ip_flags)
                  / scapy.ICMP(type=10, code=0,
                               id=mirage.icmp_id(), seq=mirage.icmp_seq()))

        response = scapy.srp1(packet, timeout=self.socket_timeout, verbose=0)

        is_alive = False
        router_ip = None
        if response and response.haslayer(scapy.ICMP) and response[scapy.ICMP].type == 9:
            is_alive = True
            router_ip = response[scapy.IP].src if response.haslayer(scapy.IP) else "unknown"
            self._print_router_advertisement(response, router_ip)
        elif response:
            print(f"[!] Received non-router advertisement response from {response[scapy.IP].src}")
        else:
            pass
        self._print_irdp_result(is_alive, router_ip)
        return is_alive

    def _print_router_advertisement(self, response, router_ip):
        print(f"[+] Router Advertisement received:")

        if not response.haslayer(scapy.Ether):
            return

        router_mac = response[scapy.Ether].src
        print(f"    IP: {router_ip}")
        print(f"    MAC: {router_mac}")

        if not hasattr(response[scapy.ICMP], 'payload'):
            return

        payload = bytes(response[scapy.ICMP].payload)
        if len(payload) < 4:
            return

        num_addrs = payload[0]
        lifetime = int.from_bytes(payload[1:4], 'big')
        print(f"    Lifetime: {lifetime} seconds")
        print(f"    Address entries: {num_addrs}")

        offset = 4
        for i in range(num_addrs):
            if offset + 8 > len(payload):
                break
            addr = ".".join(str(b) for b in payload[offset:offset + 4])
            pref = int.from_bytes(payload[offset + 4:offset + 8], 'big')
            print(f"      [{i + 1}] Router: {addr} Preference: {pref}")
            offset += 8

    def _print_irdp_result(self, is_alive, router_ip):
        if is_alive:
            print(f"[SOLT] Router {router_ip} is up! (IRDP)")
            return

        if self.args.recursively:
            print(f"[SOLT] No router discovered via ICMP solicitation")
            return

        if len(self.targets) == 1:
            print(f"[SOLT] No router discovered via ICMP solicitation")
            return

        if self.args.verbose:
            print(f"[SOLT] No router discovered via ICMP solicitation, <Skip it>")
        else:
            print(f"{yellow}[SOLT] No router discovered via ICMP solicitation{reset}")

    def threaded_host_discovery(self):
        if self.max_threads == 1:
            for Target in self.targets:
                self.host_discovery(Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                        future = executor.submit(
                            self.host_discovery,target
                        )
                        time.sleep(self.interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] ICMP ECHO ping error: {e}{reset}")

    def threaded_host_discovery_ipv6(self):
        if self.max_threads == 1:
            for Target in self.targets:
                self.host_discovery_ipv6(Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                        future = executor.submit(
                            self.host_discovery_ipv6,target
                        )
                        time.sleep(self.interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] ICMPv6 ECHO ping error: {e}{reset}")

    def threaded_host_discovery_1(self):
        if self.max_threads == 1:
            for Target in self.targets:
                self.host_discovery_1(Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                        future = executor.submit(
                            self.host_discovery_1,target
                        )
                        time.sleep(self.interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] ICMP TIMESTAMP ping error: {e}{reset}")

    def threaded_host_discovery_2(self):
        if self.max_threads == 1:
            for Target in self.targets:
                self.host_discovery_2(Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                        future = executor.submit(
                            self.host_discovery_2,target
                        )
                        time.sleep(self.interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] ICMP Address ping error: {e}{reset}")

    def threaded_host_discovery_3(self):
        if self.max_threads == 1:
            for Target in self.targets:
                self.host_discovery_3(Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targets:
                        future = executor.submit(
                            self.host_discovery_3,target
                        )
                        time.sleep(self.interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] ICMP Information ping error: {e}{reset}")


    def threaded_tcp_3_ways_handshake(self):

        self.start_time = time.perf_counter()

        if self.max_threads == 1:
            for Target in self.targets:
                for Port in self.ports_to_scan:
                    self.tcp_3_ways_handshake(Port, Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targetss:
                    for port in self.ports_to_scan:
                        future = executor.submit(
                            self.tcp_3_ways_handshake, port, target
                        )
                        time.sleep(self.interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] TCP scan error: {e}{reset}")
        self.end_time = time.perf_counter()

    def threaded_tcp_syn_scan(self):
        self.start_time = time.perf_counter()

        if self.max_threads == 1:
            for Target in self.targets:
                for Port in self.ports_to_scan:
                    self.tcp_syn_scan(Port, Target)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for target in self.targetss:
                    for port in self.ports_to_scan:
                        future = executor.submit(
                            self.tcp_syn_scan, port, target
                        )
                        time.sleep(self.interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] TCP SYN scan error: {e}{reset}")

        self.end_time = time.perf_counter()


    def Scan_details(self, target_results):
        duration = self.end_time - self.start_time
        D = self.EE - self.E

        print(f"\n[*] Scan completed in {duration:.2f} seconds")
        print(f"\n[*] Total Time in {D:.2f} seconds")

        for target in self.targetss:
            self._print_target_report(target, target_results)

        print(f"\n[+] Lightscan scanned {len(self.targetss)} target(s) successfully\n")

    def _print_target_report(self, target, target_results):
        if target not in self.target_results:
            print(f"\n[-] No results for target: {target}")
            return

        self._sync_and_deduplicate_ports(target)
        results = target_results[target]

        self._print_target_header(target)
        self._print_scan_type_sections(target, results)
        self._print_firewall(target, results)
        self._print_banners(results)
        self._print_os_fingerprint(target, results)
        self._print_lsse_scripts()

    def _print_target_header(self, target):
        ip_status = Payloads.is_private_ip(target)
        rdns = None if self.args.n else self.reverse_dns_lookup(target)

        Mac = None
        if ip_status == "Local" and not self.args.mac:
            Mac = (Payloads.NDP_Get_MAC(target) if self.args.V6
                   else Payloads.ARP_Scan(target))

        print(f"\n{'=' * 60}")
        print(f"[+] Scan result for : {target}")
        print(f"[+] Scan Type: {self.scan_type.upper()} | Protocol: {self.Proto.upper()}")
        self.target_results[target]['scan_type'] = self.scan_type.upper()
        if not self.args.n:
            print(f"[+] Reverse DNS: {rdns}")
        if ip_status == "Local":
            print(f"[+] IP Status: {ip_status}")
            if not self.args.mac and Mac:
                print(f"[+] Mac Address: {Mac}")
        elif ip_status == "Public":
            print(f"[+] IP Status: {ip_status}")
        print(f"{'=' * 60}")

    def _print_scan_type_sections(self, target, results):
        if self.scan_type == "ipproto":
            self._print_ipproto_sections(results)
            return

        if self.scan_type in ("ftp-bounce", "FTP-BOUNCE"):
            print(f"\n[+] FTP Bounce Scan Results:")
            print(f"    FTP Server: {self.args.ftp_server if hasattr(self.args, 'ftp_server') else 'Unknown'}")
            print(f"    Target: {target}")

            self._print_port_section(results, "open_ports", "opened_ports_services",
                                     "Open Ports (via FTP bounce)")


            print(f"\n[+] Closed Ports: {len(results.get('closed_ports', []))}")
            print(f"[+] Filtered Ports: {len(results.get('filtered_ports', []))}")
            return

        sections = PORT_SECTIONS.get(self.scan_type)
        if not sections:
            return

        for entry in sections:
            if len(entry) == 4:
                ports_key, services_key, label, verbose_only = entry
            else:
                ports_key, services_key, label = entry
                verbose_only = False

            self._print_port_section(results, ports_key, services_key, label,
                                     verbose_only=verbose_only)

    def _print_port_section(self, results, ports_key, services_key, label,
                            verbose_only=False):
        ports = results.get(ports_key, [])

        if verbose_only and not self.args.verbose:
            return

        print(f"\n[+] {label}: {len(ports)}")
        if not ports:
            return

        services = results.get(services_key, [])
        for i in range(min(len(ports), 20)):
            service = services[i].lower() if i < len(services) else "unknown"
            print(f"     Port {ports[i]} {service}\\{self.Proto}")

        if len(ports) > 20:
            print(f"     ... and {len(ports) - 20} more")

    def _print_ipproto_sections(self, results):
        from Services import proto_names

        sections = [
            ("open_protocols", "OPEN"),
            ("closed_protocols", "CLOSED"),
            ("filtered_protocols", "FILTERED"),
            ("open_filtered_protocols", "OPEN|FILTERED"),
        ]

        for key, label in sections:
            entries = results.get(key, [])
            print(f"\n[+] {label} Protocols: {len(entries)}")
            if not entries:
                continue

            for proto in entries[:20]:
                name = proto_names.get(proto, f"Proto{proto}")
                print(f"     Protocol {proto:3} ({name:12}) : {label}")

            if len(entries) > 20:
                print(f"     ... and {len(entries) - 20} more")

    def _print_firewall(self, target, results):
        if not self.args.no_firewall_ase:
            self.Firewall_detection(target, results)

    def _print_banners(self, results):
        if not self.args.banner or not results.get('banners'):
            return

        print(f"\n[+] Captured Banner/s: {len(results['banners'])}\n")
        for i in range(len(results['banners'])):
            print(f"     [*] Banner from Port {results['banners_ports'][i]}:\n ")

            if "Microsoft-HTTPAPI/2.0" in results['banners'][i]:
                version_info = {
                    'service': 'http',
                    'product': "Microsoft-HTTPAPI",
                    'version': '2.0',
                }
            else:
                version_info = VersionParser.parse_version(
                    results['banners'][i], results['banners_ports'][i])

            if version_info:
                print(f"          [+] Version: {version_info.get('product')} "
                      f"{version_info.get('version')}\n")

            print("=" * 60)
            print(f"     {results['banners'][i]}")
            print("=" * 60)
            print()

    def _print_os_fingerprint(self, target, results):
        if not self.args.os:
            return

        try:
            engine = OSFingerprintEngine(
                min_score=self.args.min_score,
                min_report_confidence=self.args.min_confi)

            version = 6 if self.args.V6 else 4

            if len(results['open_ports']) == 0:
                return

            if is_loopback(target):
                print(f"\n[+] OS Fingerprint Results (IPv{version}):\n----------------------------------------")
                print(f"    [+] {platform.system()}: 100% (score: 0)")
                print(f"        └─ Version: {platform.platform()}\n")
                self.target_results[target]['os_confi'] = 100
                self.target_results[target]['os_main_tree'] = str(platform.system())
                self.target_results[target]['os_version'] = str(platform.platform())
                return

            result = engine.fingerprint(
                target=target,
                open_ports=results.get('open_ports', []),
                banners=results.get('banners', []),
                services=results.get('opened_ports_services', []),
                version=version,
                use_icmp=True,
                use_udp=True,
                use_rdns=True)

            print(f"\n[+] OS Fingerprint Results (IPv{version}):\n----------------------------------------")
            for match in result.matches:
                print(f"    [+] {match.name}: {match.confidence:.1f}% (score: {match.score:.1f})")
                if match.version:
                    print(f"        └─ Version: {match.version}\n")
                    self.target_results[target]['os_confi'] = int(match.confidence)
                    self.target_results[target]['os_main_tree'] = match.name
                    self.target_results[target]['os_version'] = match.version

        except Exception as e:
            print(f"\n[+] OS Detection Error: {e}")

    def _print_lsse_scripts(self):
        if not self.args.script:
            return

        from LSSE import lsse_og
        from LSSE.slist import sscripts

        try:
            scripts = self.args.script.split(",")
            print(f"\n[+] Starting LSSE ... \n")
            alr = 0

            for script in scripts:
                print(f"\n[-] Script : {script}\n")
                if script in sscripts and alr == 0:
                    self.script_port_parse()
                    alr = 1

                output = lsse_og.Lsse.script_list(
                    script,
                    t=self.args.starget,
                    ports=self.lsse_ports_to_scan,
                    redirect=self.args.redirect,
                    domain=self.args.domain,
                    dns=self.args.dns_server,
                    wordlist=self.args.wordlist,
                    url=self.args.url,
                    max_pages=self.args.mxp,
                    max_depth=self.args.mxd,
                    extensions=self.args.extensions,
                    status_codes=self.args.status_codes,
                    user=self.args.username,
                    userlist=self.args.userlist,
                    password=self.args.password,
                    passwordlist=self.args.passwordlist,
                    file=self.args.file,
                    req=self.args.request,
                    ssl=self.args.ssl)

            print(f"\n[+] LSSE run successfully\n")

        except Exception as e:
            print(f"\n{red}[+] Script Error with {self.args.script} : {e}{reset}")

    def daemon(self):
        import subprocess
        import os

        if not self.args.save:
            sys.argv.append("--save")
            sys.argv.append("light")

        sys.argv.remove("--daemon")

        script_dir = os.path.dirname(os.path.abspath(__file__))

        cmd = [sys.executable] + sys.argv[:]

        print(f"Running daemon: {' '.join(cmd)}")
        print(f"Working directory: {script_dir}")

        process = subprocess.Popen(
            cmd,
            cwd=script_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )

        print(f"Daemon started with PID: {process.pid}")
        print(f"Output will be saved to: {script_dir}")

    def Start(self):
        self.E = time.perf_counter()
        self.args_parse()
        if self._handle_diff():
            return
        self._apply_profile()
        self._handle_daemon()
        self._handle_lsse_update()
        self._setup_output_capture()

        self._handle_version()
        self._handle_interfaces()
        self.verification()
        self._preload_targets_file()
        self._resolve_payload_length()
        self._print_banner()
        self._handle_profiles_list()
        self._handle_lsse_list()
        self._handle_script_help()

        if self.args.lsse:
            self._run_lsse_only_mode()
            return

        self._run_scan_mode()

    def _apply_profile(self):
        if self.args.load_profile:
            self.load_profile(self.args.load_profile)


    def _handle_daemon(self):
        if self.args.daemon:
            self.daemon()
            sys.exit(0)


    def _handle_lsse_update(self):
        if self.args.update_lsse:
            from LSSE.update import download_zip
            download_zip()
            sys.exit(0)

    def _setup_output_capture(self):
        if not self.args.save:
            return

        current = time.localtime()
        self._output_filename = f"Lightscan_Output_{time.strftime('%Y-%m-%d_%H-%M-%S', current)}"

        from io import StringIO
        self.capture_buffer = StringIO()
        self.old_stdout = sys.stdout

        class TeeOutput:
            def __init__(self, *outputs):
                self.outputs = outputs

            def write(self, message):
                for output in self.outputs:
                    output.write(message)
                    output.flush()

            def flush(self):
                for output in self.outputs:
                    output.flush()

        sys.stdout = TeeOutput(self.old_stdout, self.capture_buffer)

    def _handle_version(self):
        if self.args.version:
            VersionManager.show_banner()
            sys.exit(0)

    def _handle_interfaces(self):
        if self.args.interfaces:
            print("\n[+] Network Interfaces : \n")
            pl = sys.platform

            if pl == 'win32':
                from LightPacket.LightPacketWin import get_windows_adapter_list_windows
                for i in get_windows_adapter_list_windows():
                    print(f"{i['name']:20} ->    {i['description']}")
            elif pl == 'linux':
                from LightPacket.LightPacketLin import get_libpcap_devices
                for i in get_libpcap_devices():
                    print(f"{i['name']:20} ->    {i['description']}")
            else:
                from LightPacket.LightPacketUnix import get_libpcap_devices_bsd
                for i in get_libpcap_devices_bsd():
                    print(f"{i['name']:20} ->    {i['description']}")
            print()
            sys.exit(0)

    def _preload_targets_file(self):
        if self.args.rff:
            self.rff(self.args.rff)

    def _resolve_payload_length(self):
        if self.args.payload_lenght:
            from LightMirage import mirage
            self.args.payload = mirage.generate_random_ascii(self.args.payload_lenght)

    def _print_banner(self):
        if not self.args.quiet:
            self.Banner()

    def _handle_profiles_list(self):
        if self.args.profiles_lst:
            self.list_profiles()
            sys.exit(0)

    def _handle_lsse_list(self):
        if self.args.lsse_lst:
            from LSSE.slist import script_list
            script_list()

    def _handle_script_help(self):
        if self.args.script_help:
            from LSSE.slist import script_help
            script_help(self.args.script_help)

    def _run_lsse_only_mode(self):
        from LSSE import lsse_og
        from LSSE.slist import sscripts

        try:
            scripts = self.args.script.split(",")
            print(f"\n[+] Starting LSSE ... \n")
            alr = 0
            for script in scripts:
                print(f"\n[-] Script : {script}\n")
                if script in sscripts and alr == 0:
                    self.script_port_parse()
                    alr = 1
                output = lsse_og.Lsse.script_list(
                    script,
                    t=self.args.starget,
                    ports=self.lsse_ports_to_scan,
                    redirect=self.args.redirect,
                    domain=self.args.domain,
                    dns=self.args.dns_server,
                    wordlist=self.args.wordlist,
                    url=self.args.url,
                    max_pages=self.args.mxp,
                    max_depth=self.args.mxd,
                    extensions=self.args.extensions,
                    status_codes=self.args.status_codes,
                    user=self.args.username,
                    userlist=self.args.userlist,
                    password=self.args.password,
                    passwordlist=self.args.passwordlist,
                    file=self.args.file,
                    req=self.args.request,
                    ssl=self.args.ssl
                )
            print(f"\n[+] LSSE run successfully\n")
        except Exception as e:
            print(f"\n{red}[+] Script Error with {self.args.script} : {e}{reset}")

        if self.args.save:
            self._flush_output_file()

    def _run_scan_mode(self):
        self.agressive_scan_config()

        if self.args.os and not self.args.banner and not self.args.recursively:
            print(f"\n{yellow}[!] OS Fingerprint need banner grabbing (-b,--banner){reset}\n")
            sys.exit(1)

        if self.args.icmp_solicitation_ping:
            self._handle_icmp_solicitation()
            return

        if self.args.igmp_ping:
            self._handle_igmp_ping()
            return

        self.target_parse()
        if self.args.lst:
            self.list_targets()

        self.configure_speed()

        if self.args.rffp:
            self.rffp(self.args.rffp)

        self.port_parse()
        if self.args.port_lst:
            self.port_targets()

        if self.args.ping_port:
            self.ping_port_parse()

        if self.args.save_profile:
            self.save_profile(self.args.save_profile)

        if self.args.scan_type == "PING":
            self._run_ping_scan()
            return

        self._run_host_discovery_phase()

        if self.args.sn:
            print(f"\n[+] Lightscan Host Discovery did finnish successfully\n")
            sys.exit(0)

        for target in self.targetss:
            self.initialize_target_results(target)

        self._run_port_scan()

        self.EE = time.perf_counter()
        self.Scan_details(target_results=self.target_results)

        if self.args.save:
            self._flush_output_file()


    def _handle_icmp_solicitation(self):
        try:
            self.host_discovery_4()
        except Exception:
            print(f"{red}[!] Error while ICMP Solicitation <skip>{reset}\n")


    def _handle_igmp_ping(self):
        try:
            self.igmp_host_discovery()
        except Exception:
            print(f"{red}[!] Error while IGMP Ping <skip>{reset}\n")


    def _run_ping_scan(self):
        if self.version == 4:
            self.threaded_host_discovery()
            self.threded_Tcp_host_discovery()
            Payloads.threaded_ack_ping(
                self.max_threads, self.targets, self.args.ping_port, self.pp,
                self.target_results, self.socket_timeout, self.targetss,
                self.args.verbose, len(self.targets), self.version,
                self.args.ttl, self.args.hlim, self.args.sport,
                self.args.id, self.args.ip_flags, self.interval, self.args.D)
            self.threaded_host_discovery_1()
            self.threded_Syn_host_discovery()
        else:
            self.threaded_host_discovery_ipv6()
            self.threded_Tcp_host_discovery()
            Payloads.threaded_ack_ping(
                self.max_threads, self.targets, self.args.ping_port, self.pp,
                self.target_results, self.socket_timeout, self.targetss,
                self.args.verbose, len(self.targets), self.version,
                self.args.ttl, self.args.hlim, self.args.sport,
                self.args.id, self.args.ip_flags, self.interval, self.args.D)
            self.threded_Syn_host_discovery()
        print(f"\n[+] Lightscan Ping scan finnish successfully\n")


    def _run_host_discovery_phase(self):
        if self.args.no_ping:
            self._handle_no_ping()
            return

        if self.args.tcp_ping:
            self._safe_discovery(self.threded_Tcp_host_discovery, 'TCP')
        elif self.args.ack_ping:
            self._safe_discovery(
                lambda: Payloads.threaded_ack_ping(
                    self.max_threads, self.targets, self.args.ping_port, self.pp,
                    self.target_results, self.socket_timeout, self.targetss,
                    self.args.verbose, len(self.targets), self.version,
                    self.args.ttl, self.args.hlim, self.args.sport,
                    self.args.id, self.args.ip_flags, self.interval, self.args.D),
                'ACK')
        elif self.args.udp_ping:
            self._safe_discovery(self.threded_Udp_host_discovery, 'UDP')
        elif self.args.icmp_timestamp_ping:
            self._safe_discovery(self.threaded_host_discovery_1, 'ICMP Timestamp')
        elif self.args.icmp_information_ping:
            self._safe_discovery(self.threaded_host_discovery_3, 'ICMP Information')
        elif self.args.icmp_address_ping:
            self._safe_discovery(self.threaded_host_discovery_2, 'ICMP Address')
        elif self.args.syn_ping:
            self._safe_discovery(self.threded_Syn_host_discovery, 'SYN')
        elif self.args.local_ping:
            self._handle_local_ping()
        elif self.args.ip_ping:
            self._handle_ip_ping()
        else:
            self._safe_discovery(
                self.threaded_host_discovery_ipv6 if self.args.V6 else self.threaded_host_discovery,
                'ICMP')


    def _handle_no_ping(self):
        if self.args.recursively:
            if self.args.verbose and not self.args.recursively:
                print(f"\n{yellow}[!] Skipping flag -Pn because flag -Rc is active {reset}")
            try:
                self.threaded_host_discovery()
            except Exception:
                self.threded_Tcp_host_discovery()
        else:
            if self.args.verbose:
                print(f"\n{yellow}[!] Disabeling Host discovery{reset}")
            self.targetss = self.targets


    def _handle_local_ping(self):
        try:
            if self.args.V6:
                Payloads.threaded_ndp_scan(self.max_threads, self.targets,
                                           self.args.verbose, self.targetss,
                                           len(self.targets), self.interval)
            else:
                Payloads.threaded_arp_scan(self.max_threads, self.targets,
                                           self.args.verbose, self.targetss,
                                           len(self.targets), self.interval)
        except Exception as e:
            print(f"{red}[!] ARP/NDP Ping error: {e}{reset}")


    def _handle_ip_ping(self):
        try:
            self.ip_ping_protocols()
            Payloads.threaded_ip_ping(
                self.max_threads, self.args.verbose, self.socket_timeout,
                self.targets, self.targetss, self.protocols, self.target_results,
                self.args.ttl, self.args.hlim, self.args.id, self.args.ip_flags,
                self.args.V6, self.interval, self.args.D)
        except Exception as e:
            print(f"\n{red}[!] IP Ping Error <skip>{e}{reset}\n")

    def _handle_diff(self):
        if not self.args.diff:
            return False
        from LightDiff import compare_files
        code = compare_files(self.args.diff[0], self.args.diff[1])
        sys.exit(code)

    def _safe_discovery(self, fn, label):
        try:
            fn()
        except Exception:
            print(f"\n{red}[!] Error while {label} Ping <skip>{reset}\n")


    def _run_port_scan(self):
        st = self.args.scan_type

        if st == "TCP":
            self.threaded_tcp_3_ways_handshake()

        elif st == "CUSTOM":
            self._run_flag_scan("custom",Payloads.threaded_custom_scan,custom=True)

        elif st == "SYN":
            self.threaded_tcp_syn_scan()

        elif st == "UDP":
            self.threaded_udp_scan()

        elif st == "NULL":
            self._run_flag_scan("null", Payloads.threaded_null_scan)

        elif st == "FIN":
            self._run_flag_scan("fin", Payloads.threaded_fin_scan)

        elif st == "ACK":
            self._run_flag_scan("ack", Payloads.threaded_ack_scan)

        elif st == "XMAS":
            self._run_flag_scan("xmas", Payloads.threaded_xmas_scan)

        elif st == "MAIMON":
            self._run_flag_scan("maimon", Payloads.threaded_maimon_scan)

        elif st == "FDD":
            self._run_flag_scan("fdd", Payloads.threaded_fdd_scan)

        elif st == "WINDOW":
            self._run_window_scan()

        elif st == "IPPROTO":
            self._run_ipproto_scan()

        elif st == "SCTP-INIT":
            self._run_sctp_scan()

        elif st == "IDLE":
            self._run_idle_scan()

        elif st == "FTP-BOUNCE":
            self._run_ftp_bounce_scan()

        else:
            self.threaded_tcp_3_ways_handshake()

    def _run_flag_scan(self, name, fn, custom=False):
        self.start_time = time.perf_counter()
        self.Proto = "tcp"
        self.scan_type = name

        base = (
            self.args.max_retries, self.lock, self.args.verbose, self.args.fragmente,
            self.args.recursively, self.socket_timeout, self.target_results,
            self.args.banner, self.max_threads, self.targetss, self.ports_to_scan,
            self.initialize_target_results, self.service_detection, self.version,
            self.args.ttl, self.args.hlim, self.args.sport, self.args.payload,
            self.args.id, self.args.ip_flags, self.interval,
            self.args.fragsize, self.args.D,
        )

        if custom:
            fn(*base, self.args.tcp_flag)
        else:
            fn(*base)

        self.end_time = time.perf_counter()




    def _run_window_scan(self):
        self.start_time = time.perf_counter()
        self.Proto = "tcp"
        self.scan_type = "window"
        Payloads.threaded_window_scan(
            self.args.max_retries, self.lock, self.args.verbose, self.args.fragmente,
            self.args.recursively, self.socket_timeout, self.target_results,
            self.args.banner, self.max_threads, self.targetss, self.ports_to_scan,
            self.initialize_target_results, self.service_detection, self.version,
            self.args.ttl, self.args.hlim, self.args.sport, self.args.payload,
            self.args.id, self.args.ip_flags, self.interval, self.args.I,
            self.args.fragsize, self.args.D)
        self.end_time = time.perf_counter()


    def _run_ipproto_scan(self):
        self.Proto = "ip"
        self.scan_type = "ipproto"
        if not self.args.Pip:
            self.protocols = list(range(256))
        else:
            self.ip_ping_protocols()

        self.start_time = time.perf_counter()
        Payloads.threaded_ip_scan(
            max_retries=self.args.max_retries,
            lock=self.lock,
            verbose=self.args.verbose,
            fragmente=self.args.fragmente,
            recursively=self.args.recursively,
            socket_timeout=self.socket_timeout,
            target_results=self.target_results,
            banner_option=self.args.banner,
            max_threads=self.max_threads,
            targetss=self.targetss,
            protocols_to_scan=self.protocols,
            initialize_target_results=self.initialize_target_results,
            service_detection=self.service_detection,
            version=self.version,
            ttl=self.args.ttl,
            hlim=self.args.hlim,
            sport=self.args.sport,
            payload=self.args.payload,
            id=self.args.id,
            flags=self.args.ip_flags,
            interval=self.interval,
            fg=self.args.fragsize,
            d=self.args.D)
        self.end_time = time.perf_counter()


    def _run_sctp_scan(self):
        self.start_time = time.perf_counter()
        self.Proto = "sctp"
        self.scan_type = "init"
        Payloads.threaded_sctp_init_scan(
            self.args.max_retries, self.lock, self.args.verbose, self.args.fragmente,
            self.args.recursively, self.socket_timeout, self.target_results,
            self.args.banner, self.max_threads, self.targetss, self.ports_to_scan,
            self.initialize_target_results, self.service_detection, self.version,
            self.args.ttl, self.args.hlim, self.args.sport, self.args.payload,
            self.args.id, self.args.ip_flags, self.interval,
            self.args.fragsize, self.args.D)
        self.end_time = time.perf_counter()


    def _run_idle_scan(self):
        zombie_ips = []
        if self.args.zombie:
            if "," in self.args.zombie:
                zombie_ips = [z.strip() for z in self.args.zombie.split(",") if z.strip()]
            else:
                zombie_ips = [self.args.zombie]

        if not zombie_ips:
            print(f"{red}[!] Idle scan requires --zombie <IP>{reset}")
            print(f"{yellow}[!] Example: Lightscan -T scanme.nmap.org --zombie 192.168.1.100 -st IDLE{reset}")
            sys.exit(1)

        self.Proto = "tcp"
        self.scan_type = "idle"
        self.start_time = time.perf_counter()

        print(f"{green}[+] Starting idle scan with {len(zombie_ips)} zombie(s){reset}")
        print(f"{green}[+] Zombies: {', '.join(zombie_ips)}{reset}")
        print(f"{green}[+] Scanning {len(self.ports_to_scan)} ports on {len(self.targetss)} targets{reset}")

        Payloads.threaded_idle_scan(
            max_retries=self.args.max_retries,
            lock=self.lock,
            verbose=self.args.verbose,
            socket_timeout=self.socket_timeout,
            target_results=self.target_results,
            banner_option=self.args.banner,
            max_threads=self.max_threads,
            targetss=self.targetss,
            ports_to_scan=self.ports_to_scan,
            initialize_target_results=self.initialize_target_results,
            service_detection=self.service_detection,
            version=6 if self.args.V6 else 4,
            zombie_ips=zombie_ips,
            ttl=self.args.ttl,
            sport=self.args.sport,
            payload=self.args.payload,
            id=self.args.id,
            flags=self.args.ip_flags,
            interval=self.interval,
            I=self.args.I,
            d=self.args.D)
        self.end_time = time.perf_counter()


    def _run_ftp_bounce_scan(self):
        if not self.args.ftp_server:
            print("[!] FTP Bounce scan requires --ftp-bounce <server>")
            sys.exit(1)

        self.start_time = time.perf_counter()
        Payloads.FTPBounceScan(
            target=self.args.target,
            ftpserver=self.args.ftp_server,
            ftp_port=21,
            imediate=self.args.I,
            interval=self.interval,
            port_range=self.ports_to_scan,
            max_retries=self.args.max_retries if self.args.max_retries else 2,
            verbose=self.args.verbose,
            socket_timeout=self.args.timeout if self.args.timeout else 5,
            lock=self.lock,
            target_results=self.target_results,
            initialize_target_results=self.initialize_target_results,
            service_detection=self.service_detection,
            version=6 if self.args.V6 else 4)
        self.end_time = time.perf_counter()

    def _flush_output_file(self):
        sys.stdout = self.old_stdout
        output = self.capture_buffer.getvalue()
        from LightSave import main
        for ext in self.args.save.split(","):
            main(self._output_filename + f".{ext.lower()}", ext.lower(),output, self.target_results, self.targetss)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.append("-h")

    try:
        Scanner = Lightscan()
        Scanner.Start()
    except KeyboardInterrupt:
        print(f"\n{yellow}[!] Scan interrupted by user{reset}")
    except Exception as e:
        print(f"\n{red}[!] Unexpected error: {e}{reset}")
