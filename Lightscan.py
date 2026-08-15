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
from scapy.config import conf
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6TimeExceeded
from concurrent.futures import ThreadPoolExecutor, as_completed
from VersionParser import VersionParser
from scapy.contrib.igmp import IGMP
import ipaddress
import time
import socket
import argparse
from banner_grabber import Banner
from Services import Lightscan_Service_List, top_1000_ports, top_100_ports, top_20_tcp_ports, top_20_udp_ports
from LightEngine import Payloads
from LightMirage import mirage
from Lightscan_os.core.engine import OSFingerprintEngine
from LightPacket.utils.CIDR import parse_targets, TargetParser
from Decoration.Colors import *
import pyfiglet
import json
import os
import sys
import threading
import warnings
import logging
import random
import platform
from Versions import *

class VersionManager:
    FRAMEWORK = __framework__
    LIGHTSCAN = __lightscan__
    LSSE = __lsse__
    LIGHTSAVE = __lightsave__
    LIGHTPANEL_WIN = __lightpanelwin__
    LIGHTPANEL_LIN = __lightpanellin__
    LIGHTSNIFF = __lightsniff__
    MINT = __mint__
    LIGHTPACKET = __lightpacket__
    LIGHTLAB = __lightlab__
    LIGHTBIN = __lightbin__
    LIGHTHEX = __lighthex__

    @classmethod
    def show_banner(cls):
        print(f"""
╔══════════════════════════════════════════╗
║         Light-Scan Framework             ║
║            v{cls.FRAMEWORK}                        ║
╠══════════════════════════════════════════╣
║ Core Scanner    : v{cls.LIGHTSCAN}                 ║
║ LSSE Engine     : v{cls.LSSE}                 ║
║ LightSave       : v{cls.LIGHTSAVE}                 ║
║ LightSniff      : v{cls.LIGHTSNIFF}                 ║
║ LightLab        : v{cls.LIGHTLAB}                 ║
║ LightPanel (Win): v{cls.LIGHTPANEL_WIN}                 ║
║ LightPanel (Lin): v{cls.LIGHTPANEL_LIN}                 ║
║ Mint            : v{cls.MINT}                 ║
║ LightPacket     : v{cls.LIGHTPACKET}                 ║
║ LightBin        : v{cls.LIGHTBIN}                   ║
║ LightHex        : v{cls.LIGHTHEX}                   ║
╚══════════════════════════════════════════╝
        """)

red = RED
green = GREEN
reset = RESET
yellow = YELLOW

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

class Lightscan:
    __slots__ = [
        'speed_presets', 'host_ext', 'Proto', 'scan_type', 'version','lsse_ports_to_scan',
        'max_threads', 'socket_timeout', 'args', 'parser','pp','valid',
        'targetss', 'ports_to_scan', 'target_results', 'targets','dns','rff_targets',
        'profile_dir',
        'start_time', 'end_time','lock','capture_buffer','old_stdout','__weakref__','E','EE','timeout_count','user_os','LSSE',"protocols","saving"
    ]

    def __init__(self):
        self.speed_presets = {
            'paranoid':{'threads': 2,'timeout': 4.5},
            'slow': {'threads': 30, 'timeout': 3.3},
            'normal': {'threads': 60, 'timeout': 2.8},
            'fast': {'threads': 120, 'timeout': 2.8},
            'insane': {'threads': 240, 'timeout': 1.5},
            'Light-mode': {'threads': 400, 'timeout': 1.5}
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
        self.version = "1.1.8"
        self.dns = None
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
        banner = pyfiglet.figlet_format("Lightscan", font="slant")
        print(BLUE)
        print(banner)
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
        total_ports = len(self.ports_to_scan)

        if total_ports == 0:
            return

        filtered = len(results['filtered_ports']) / total_ports
        closed = len(results['closed_ports']) / total_ports
        open_filtered = len(results['open_filtered_ports']) / total_ports

        print(f"\n[!] Firewall Analysis for {target}:")
        if self.scan_type == "fdd":
            pass
        else:
            print(f"    Total ports scanned: {total_ports}")
            print(f"    Open ports: {len(results['open_ports'])}")
            print(f"    Closed ports: {len(results['closed_ports'])}")
            print(f"    Filtered ports: {len(results['filtered_ports'])}")
        if self.scan_type == "null":
            print(f"    Null Scan (Open | Filtered ports): {len(results['null_ports'])}\n")
        elif self.scan_type == "ack":
            print(f"    Unfiltered ports: {len(results['unfiltered_ports'])}\n")
        elif self.scan_type == "fdd":
            print(f"    Defended ports: {len(results['defended_ports'])}")
            print(f"    Undefended ports: {len(results['undefended_ports'])}")
        else:
            print(f"    Open | Filtered ports: {len(results['open_filtered_ports'])}\n")

        if self.scan_type == "null":
            if len(results['null_ports']) <= 10:
                print("    [+] NO FIREWALL DETECTED: Null scan can get a lop of Open | Filtered ports\n")
            elif len(results['null_ports']) >= 11:
                print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif self.scan_type == "fdd":
            if len(results['defended_ports']) < len(results['undefended_ports']):
                print("    [-] NO STRONG FIREWALL: Most ports are undefended (normal behavior)\n")
            else:
                print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif self.timeout_count > 0:
            if self.timeout_count == len(results['open_filtered_ports']) or self.timeout_count >= 50:
                print("    [+] NO FIREWALL DETECTED: (Timeout can lead Light-Scan to False-Positive Responses)\n")
        elif len(results['open_filtered_ports']) >= 11:
            if len(results['open_filtered_ports']) >= 21:
                print("    [+] STRONG FIREWALL DETECTED: Most ports are filtered\n")
            else:
                print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif len(results['filtered_ports']) >= 11:
            if len(results['filtered_ports']) >= 21:
                print("    [+] STRONG FIREWALL DETECTED: Most ports are filtered\n")
            else:
                print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif filtered > 0.8 and closed < 0.1:
            print("    [+] STRONG FIREWALL DETECTED: Most ports are filtered\n")
        elif open_filtered > 0.05:
            print("    [+] STRONG FIREWALL DETECTED: Most ports are filtered\n")
        elif filtered > 0.5:
            print("    [+] FIREWALL DETECTED: Significant port filtering\n")
        elif len(results['closed_ports']) > len(results['open_ports']) + len(results['filtered_ports']):
            print("    [-] NO STRONG FIREWALL: Most ports are closed (normal behavior)\n")
        elif len(results['filtered_ports']) == 0 and len(results['open_filtered_ports']) == 0:
            print("    [+] NO FIREWALL DETECTED : no such filtered or open | filtered ports\n")
        elif self.scan_type == "ack":
            if len(results['filtered_ports']) >= len(results['unfiltered_ports']):
                print("    [+] FIREWALL DETECTED: Significant port filtering\n")
            else:
                print("    [-] NO STRONG FIREWALL: Most ports are closed (normal behavior)\n")
        else:
            print("    [?] INCONCLUSIVE: Mixed response patterns\n")

    def args_parse(self):
        self.parser = argparse.ArgumentParser(description="Lightscan Port Scanner")
        self.parser.add_argument("-T", "--target", required=False, help="Target IP or Hostname")
        self.parser.add_argument("--rff", required=False,type=str, help="Read Target/s from a file")
        self.parser.add_argument("--daemon", required=False,action="store_true", help="Run Lightscan as a background task")
        self.parser.add_argument("-V6", required=False, help="used when the target is an IPv6",action="store_true")
        self.parser.add_argument("-p","--port", required=False, help="Port/s to scan")
        self.parser.add_argument("-pp","--ping-port",help="Port/s to Ping on it")
        self.parser.add_argument("-s", "--speed", required=False, default="normal",
                                 choices=['paranoid', 'slow', 'normal', 'fast', 'insane', 'Light-mode'],
                                 help="Scan speed preset")
        self.parser.add_argument("--save",required=False, choices=["txt", "light", "html", "xml", "csv", "json", "pdf", "yaml","toml","hex-str"],
                            help="Saving Format (txt,light,html,xml,csv,json,pdf,yaml,toml,hex-str)")
        self.parser.add_argument("-v", "--verbose",action="store_true", help="Show verbose output ")
        self.parser.add_argument("-n",action="store_true",help="Disable reverse dns")
        self.parser.add_argument("-V", "--version", action="store_true", help="show Light-Scan version with all additionnal tools")
        self.parser.add_argument("-st","--scan-type",default="TCP", help="Scan types {TCP,SYN,UDP,NULL,FIN,ACK,XMAS,WINDOW,MAIMON,FDD,FTP-BOUNCE,IPPROTO,PING,IDLE,SCTP-INIT}")
        self.parser.add_argument("--zombie", type=str, help="Zombie IP for idle scan (required for --st IDLE)")
        self.parser.add_argument("-sn",action="store_true", help="do only a host discovery without port scaning")
        self.parser.add_argument('--ftp-bounce', dest='ftp_server',help='FTP server for bounce scan (required for --st FTP-BOUNCE)')
        self.parser.add_argument("-F",action="store_true",help="Scan The Top 100 ports for fast scanning")
        self.parser.add_argument("-mx","--max-retries",type=int,help="Max number of retries if port show a no response",default=1)
        self.parser.add_argument("-t","--threads",type=int,help="Number of threads to use")
        self.parser.add_argument("-lst",action="store_true",help="List all targets")
        self.parser.add_argument("--lsse-lst", action="store_true", help="List all LSSE Scripts")
        self.parser.add_argument("--profiles-lst", action="store_true", help="List all scan profiles from Profiles directory")
        self.parser.add_argument("-tm","--timeout",type=float,help="Timeout with second")
        self.parser.add_argument("-Rc","--recursively",action="store_true",help="recursively scan host that shown to be down or not responding and disable flags like -v,-Pn,etc ...")
        self.parser.add_argument("-f","--fragmente",action="store_true",help="fragment the sending packet for more stealth ")
        self.parser.add_argument("-Pn","--no-ping",action="store_true",help="Do not ping the target/s")
        self.parser.add_argument("-b","--banner",action="store_true",help="Banner Grabing")
        self.parser.add_argument("-O","--os",action="store_true",help="OS Fingerprint ")
        self.parser.add_argument("--min-score",type=float,default=50.0,help="Minimum OS Fingerprint Score")
        self.parser.add_argument("--min-confi",type=float,default=15.0,help="Minimum OS Confidence Score")
        self.parser.add_argument("-mac",action="store_true",help="Light-Scan will skip getting the target mac on Local Networks")
        self.parser.add_argument("--load-profile", type=str, help="Load the scan profile from Profiles/ directory")
        self.parser.add_argument("--save-profile", type=str, help="Save the scan profile to Profiles/ directory")
        self.parser.add_argument("-ttl",type=int,help="Time To Live for IPv4 packets")
        self.parser.add_argument("-hlim",type=int,help="Hop Limit for IPv6 packets")
        self.parser.add_argument("-sport",type=int,help="Source Port")
        self.parser.add_argument("-payload",type=str,help="Add a raw custum Payload")
        self.parser.add_argument("-id",type=int,help="ID Field for IPv4 packets")
        self.parser.add_argument("-ip-flags",type=int,help="IP Flags Field for IPv4 packets (DF=2,MF=1,None=0)")
        self.parser.add_argument("-Pan","--local-ping",action="store_true",help="Performe an ARP Ping on Local Networks by default or NDP Ping on Local Networks for IPv6 mode")
        self.parser.add_argument("-Pi","--ip-ping",action="store_true",help="IP Protocol Ping")
        self.parser.add_argument("-Pip",type=str,help="For Specefiy The IP Protocols that -Pi is going to use rather then default")
        self.parser.add_argument("-A","--agressive",action="store_true",help="Agressive scan activate all of OS Fingerprints, Banner Grabing, Insane Speed , SYN Scan and Scan Top 100 Ports")
        self.parser.add_argument("-Pt","--tcp-ping",action="store_true",help="Do a TCP Ping")
        self.parser.add_argument("-Ps","--syn-ping",action="store_true",help="Do a Syn Ping")
        self.parser.add_argument("-Pk","--ack-ping",action="store_true",help="DO a ACK Ping")
        self.parser.add_argument("-Pu","--udp-ping",action="store_true",help="Do a UDP Ping")
        self.parser.add_argument("-PIt","--icmp-timestamp-ping",action="store_true",help="Do scan a ICMP Timestamp Ping")
        self.parser.add_argument("-PA","--icmp-address-ping",action="store_true",help="Do scan a ICMP Address Ping")
        self.parser.add_argument("-Pin","--icmp-information-ping",action="store_true",help="Do scan a ICMP Information Ping")
        self.parser.add_argument("-Pas","--icmp-solicitation-ping",action="store_true",help="Do scan a ICMP Solicitation Ping on the network")
        self.parser.add_argument("-Pg","--igmp-ping",action="store_true",help="Do scan a IGMP Ping on the network")
        self.parser.add_argument("-q","--quiet",action="store_true",help="Quiet mode {does't print the Tool Banner}")
        self.parser.add_argument("--script",type=str,help="LSSE Script ,Ex: --script http-cert")
        self.parser.add_argument("--domain",type=str,help="Domain for http/https and Dns based scripts ")
        self.parser.add_argument("--dns-server",type=str,help="dns server that Light-Scan is going to use (Is Set by Default ")
        self.parser.add_argument("-W","--wordlist",type=str,help="Wordlist for scripts ")
        self.parser.add_argument("--extensions",type=str,help="Extensions for web based scripts ")
        self.parser.add_argument("--status-codes",type=str,help="Status Codes for web based scripts ")
        self.parser.add_argument("--redirect",action="store_true",help="Redirect http/https requests for http scripts")
        self.parser.add_argument("--url",type=str,help="Victime URL")
        self.parser.add_argument("--mxp",help="max pages to get")
        self.parser.add_argument("--mxd", help="max depth to crawl")
        self.parser.add_argument("-sp",help="Port/s that are going to use by scripts")
        self.parser.add_argument("--starget",type=str,help="Targets for scripts")
        self.parser.add_argument("--username",type=str,help="Single username for LSSE scripts")
        self.parser.add_argument("--password",type=str,help="Single password for LSSE scripts")
        self.parser.add_argument("--userlist",type=str,help="Userlist for LSSE scripts")
        self.parser.add_argument("--passwordlist",type=str,help="Passwordlist for LSSE scripts")
        self.parser.add_argument("--lsse",action="store_true",help="Use that flag when you want just to performe a script")
        self.args = self.parser.parse_args()

    def ver_ttl(self, ttl):
        if ttl <= 0:
            print(f"{YELLOW}\n[!] ttl cant be 0 or less, (default ttl=64){RESET}\n")
            self.args.ttl=64
        elif ttl > 255:
            print(f"{YELLOW}\n[!] ttl cant be more then 255, (default ttl=64){RESET}\n")
            self.args.ttl = 64

    def ver_ip_flags(self,ipf):
        if ipf in [0,1,2]:
            pass
        else:
            print(f"{YELLOW}\n[!] Invalid ip flag, (default DF=2){RESET}")
            self.args.ip_flags='DF'

    def ver_ip_id(self,ID):
        if ID < 0 or ID > 65535:
            print(f"{YELLOW}\n[!] Invalid ip id, (default 0){RESET}")
            self.args.id = 0
        else:
            pass

    def ver_hlim(self, hlim):
        if hlim <= 0:
            print(f"{YELLOW}\n[!] hlim cant be 0 or less, (default ttl=64){RESET}\n")
            self.args.hlim=64
        elif hlim > 255:
            print(f"{YELLOW}\n[!] hlim cant be more then 255, (default ttl=64){RESET}\n")
            self.args.hlim = 64

    def list_targets(self):
        for target in self.targets:
            print("Target: " + target)

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
        self.target_validation()

    def rff(self, filename):
        with open(filename, 'r') as file:
            for line in file:
                self.rff_targets.append(line.strip())

    def save_profile(self, profile_name):
        if not os.path.exists(self.profile_dir):
            os.makedirs(self.profile_dir)

        profile_path = os.path.join(self.profile_dir, f"{profile_name}.json")

        profile_data = {
            "name": profile_name,
            "description": f"Light-Scan profile: {profile_name}",
            "settings": {}
        }

        args = self.args

        if hasattr(args, 'target') and args.target:
            profile_data["settings"]["target"] = args.target

        if hasattr(args, 'scan_type') and args.scan_type:
            profile_data["settings"]["scan_type"] = args.scan_type

        if hasattr(args, 'speed') and args.speed:
            profile_data["settings"]["speed"] = args.speed

        if hasattr(args, 'port') and args.port:
            profile_data["settings"]["ports"] = args.port

        if hasattr(args, 'threads') and args.threads:
            profile_data["settings"]["threads"] = args.threads

        if hasattr(args, 'timeout') and args.timeout:
            profile_data["settings"]["timeout"] = args.timeout

        if hasattr(args, 'max_retries') and args.max_retries:
            profile_data["settings"]["max_retries"] = args.max_retries

        advanced_settings = ['ttl', 'hlim', 'sport', 'id', 'ip_flags', 'payload']
        for setting in advanced_settings:
            if hasattr(args, setting) and getattr(args, setting):
                profile_data["settings"][setting] = getattr(args, setting)

        bool_flags = [
            'banner', 'os', 'F', 'fragmente', 'no_ping',
            'recursively', 'verbose', 'quiet', 'Pn', 'O'
        ]
        for flag in bool_flags:
            if hasattr(args, flag) and getattr(args, flag):
                profile_data["settings"][flag] = True

        try:
            with open(profile_path, 'w', encoding='utf-8') as f:
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
            with open(profile_path, 'r') as f:
                profile = json.load(f)

            settings = profile.get("settings", {})

            if "target" in settings and not self.args.target:
                self.args.target = settings["target"]

            if "scan_type" in settings and (not hasattr(self.args, 'scan_type') or self.args.scan_type == "TCP"):
                self.args.scan_type = settings["scan_type"]

            if "speed" in settings and (not hasattr(self.args, 'speed') or self.args.speed == "normal"):
                self.args.speed = settings["speed"]

            if "ports" in settings and not self.args.port:
                self.args.port = settings["ports"]

            if "threads" in settings and not self.args.threads:
                self.args.threads = settings["threads"]

            if "timeout" in settings and not self.args.timeout:
                self.args.timeout = settings["timeout"]

            numeric_flags = ['ttl', 'hlim', 'sport', 'id', 'ip_flags', 'max_retries']
            for flag in numeric_flags:
                if flag in settings:
                    setattr(self.args, flag, settings[flag])

            string_flags = ['payload']
            for flag in string_flags:
                if flag in settings:
                    setattr(self.args, flag, settings[flag])

            bool_flags = ['banner', 'os', 'F', 'fragmente', 'no_ping', 'recursively', 'verbose', 'quiet']
            for flag in bool_flags:
                if settings.get(flag) and not getattr(self.args, flag, False):
                    setattr(self.args, flag, settings[flag])

            print(f"{green}[+] Loaded profile: {profile.get('name', profile_name)}{reset}")
            if profile.get('description'):
                print(f"    {yellow}{profile['description']}{reset}")

        except json.JSONDecodeError as e:
            print(f"{red}[!] Invalid profile JSON: {e}{reset}")
            sys.exit(1)
        except Exception as e:
            print(f"{red}[!] Error loading profile: {e}{reset}")
            sys.exit(1)

    def target_validation(self):

        for target in self.targets:
            Target = target.replace(".", "")
            if Target.isdigit():
                if TargetParser.validate_ip(ip=target, version=4):
                    self.valid.append(target)

            elif "::" in Target or ":" in Target:
                if TargetParser.validate_ip(ip=target,version=6):
                    self.valid.append(target)

            elif Target.isalpha():
                try:
                    resolved = TargetParser.resolve_hostname(target)
                    if resolved is not None:
                        self.valid.append(resolved)
                    else:
                        print(f"{yellow}\n[!] Failed to resolve ({target}) {reset}")
                except:
                    print(f"{red}\n[!] Invalid Target IP or Hostname {target}{reset}\n")
                    exit(1)

            elif Target.isalnum():
                for ext in self.host_ext:
                    if ext in target:
                        try:
                            resolved = TargetParser.resolve_hostname(target)
                            if resolved is not None:
                                self.valid.append(resolved)
                            else:
                                print(f"{yellow}\n[!] Failed to resolve ({target}) {reset}")
                        except:
                            print(f"{red}\n[!] Invalid Target IP or Hostname {target}{reset}\n")
                            exit(1)

                        break
                    else:
                        try:
                            resolved = TargetParser.resolve_hostname(target)
                            if resolved is not None:
                                self.valid.append(resolved)
                            else:
                                print(f"{yellow}\n[!] Failed to resolve ({target}) {reset}")
                        except:
                            print(f"\n{red}[!] Invalid Target IP or Hostname {target}{reset}\n")
                            exit(1)

            else:
                print(f"{red}\n[!] Invalid Target IP or Hostname {target}{reset}\n")
                exit(1)

        self.targets.clear()
        for v in self.valid:
            self.targets.append(v)

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

    def show_network_info(self):
        if len(self.targets) > 1:
            print(f"[+] Network Scan Mode Activated")
            print(f"    Total targets: {len(self.targets)} hosts\n")

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

    def port_parse(self):
        if self.args.F:
            self.ports_to_scan = top_100_ports

        elif self.args.port is None:
            self.ports_to_scan = top_1000_ports

        elif "-" in self.args.port and "," not in self.args.port:
            try:
                sport , eport = self.args.port.split("-")
                sport = int(sport)
                eport = int(eport)
                self.port_validation_1(sport, eport)
                if type(sport) == int and type(eport) == int:
                    self.ports_to_scan = list(range(int(sport), int(eport) + 1))
                else:
                    print(f"{red}\n[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
                    self.ports_to_scan = top_1000_ports
            except:
                print(f"{red}\n[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
                self.ports_to_scan = top_1000_ports

        elif "," in self.args.port and "-" not in self.args.port:
            try:
                port_list = self.args.port.split(",")
                for port in port_list:
                    port = int(port)
                    self.port_validation_2(port)
                    if type(port) == int :
                        self.ports_to_scan.append(port)
                    else:
                        print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
        elif "," in self.args.port and "-" in self.args.port:
            try:
                port_list = self.args.port.split(",")
                for port in port_list:
                    if "-" in port:
                        try:
                            sport, eport = port.split("-")
                            sport = int(sport)
                            eport = int(eport)
                            self.port_validation_1(sport, eport)
                            if type(sport) == int and type(eport) == int:
                                self.ports_to_scan.extend(list(range(int(sport), int(eport) + 1)))
                            else:
                                print(f"\n{red}[!] Invalid ports range {reset}\n")
                                exit(1)
                        except:
                            print(f"\n{red}[!] Invalid ports range {reset}\n")
                            exit(1)
                    else:
                        port = int(port)
                        self.port_validation_2(port)
                        if type(port) == int :
                            self.ports_to_scan.append(port)
                        else:
                            print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")

        else:
            try:
                self.args.port = int(self.args.port)
                self.port_validation_2(self.args.port)
                if type(self.args.port) == int :
                    self.ports_to_scan.append(int(self.args.port))
                else:
                    print(f"\n{red}[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
                    self.ports_to_scan = top_1000_ports
            except:
                print(f"\n{red}[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
                self.ports_to_scan = top_1000_ports

        if len(self.ports_to_scan) <= 0:
            print(f"\n{red}[!] Invalid Port/s, Lightscan is going to use default values {reset}")
            self.ports_to_scan = top_1000_ports
        else:
            pass

    def ip_ping_protocols(self):
        if self.args.Pip == None:
            self.protocols = [1,2,4]

        elif "-" in self.args.Pip and "," not in self.args.Pip:
            try:
                sport , eport = self.args.Pip.split("-")
                sport = int(sport)
                eport = int(eport)
                if sport > eport:
                    self.protocols = [1,2,4]
                if sport <= 0 or eport <= 0:
                    self.protocols = [1,2,4]
                if sport == eport:
                    self.protocols.append(eport)
                if eport > 255:
                    self.protocols = [1,2,4]
                if type(sport) == int and type(eport) == int:
                    self.protocols = list(range(int(sport), int(eport) + 1))
                else:
                    self.protocols = [1,2,4]
            except:
                self.protocols = [1,2,4]

        elif "," in self.args.Pip and "-" not in self.args.Pip:
            try:
                port_list = self.args.Pip.split(",")
                for port in port_list:
                    port = int(port)
                    if port > 255:
                        self.protocols = [1,2,4]
                    if port <= 0:
                        self.protocols = [1,2,4]
                    if type(port) == int :
                        self.protocols.append(port)
                    else:
                        print(f"\n{red}[!] Invalid Protocol, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                self.protocols = [1,2,4]
        elif "," in self.args.Pip and "-" in self.args.Pip:
            try:
                port_list = self.args.Pip.split(",")
                for port in port_list:
                    if "-" in port:
                        try:
                            sport, eport = port.split("-")
                            sport = int(sport)
                            eport = int(eport)
                            if sport > eport:
                                self.protocols = [1, 2, 4]
                            if sport <= 0 or eport <= 0:
                                self.protocols = [1, 2, 4]
                            if sport == eport:
                                self.protocols.append(eport)
                            if eport > 255:
                                self.protocols = [1, 2, 4]
                            if type(sport) == int and type(eport) == int:
                                self.protocols.extend(list(range(int(sport), int(eport) + 1)))
                            else:
                                self.protocols = [1, 2, 4]
                        except:
                            self.protocols = [1, 2, 4]
                    else:
                        port = int(port)
                        if port > 255:
                            self.protocols = [1, 2, 4]
                        if port <= 0:
                            self.protocols = [1, 2, 4]
                        if type(port) == int:
                            self.protocols.append(port)
                        else:
                            print(f"\n{red}[!] Invalid Protocol, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[!] Invalid Protocol, Lightscan is going to skip that one <{port}>{reset}\n")

        else:
            try:
                if self.args.Pip == None:
                    self.protocols = [1,2,4]
                else:
                    self.args.Pip = int(self.args.Pip)
                    if self.args.Pip > 255:
                        self.protocols = [1, 2, 4]
                    if self.args.Pip <= 0:
                        self.protocols = [1, 2, 4]
                    if type(self.args.Pip) == int:
                        self.protocols.append(self.args.Pip)
                    else:
                        self.protocols = [1,2,4]

            except:
                self.protocols = [1,2,4]

        if len(self.protocols) <= 0:
            self.protocols = [1,2,4]
        else:
            pass

    def script_port_parse(self):

        if self.args.sp is None:
            print(f"\n{yellow}[LSSE] No port/s was assagned for the script {reset}\n")
            exit()

        elif "-" in self.args.sp and "," not in self.args.sp:
            try:
                sport , eport = self.args.sp.split("-")
                sport = int(sport)
                eport = int(eport)
                self.port_validation_1(sport, eport)
                if type(sport) == int and type(eport) == int:
                    self.lsse_ports_to_scan = list(range(int(sport), int(eport) + 1))
                else:
                    print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                    exit()
            except:
                print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                exit()

        elif "," in self.args.sp and "-" not in self.args.sp:
            try:
                port_list = self.args.sp.split(",")
                for port in port_list:
                    port = int(port)
                    self.port_validation_2(port)
                    if type(port) == int :
                        self.lsse_ports_to_scan.append(port)
                    else:
                        print(f"\n{red}[LSSE] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[LSSE] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
        elif "," in self.args.sp and "-" in self.args.sp:
            try:
                port_list = self.args.sp.split(",")
                for port in port_list:
                    if "-" in port:
                        try:
                            sport, eport = port.split("-")
                            sport = int(sport)
                            eport = int(eport)
                            self.port_validation_1(sport, eport)
                            if type(sport) == int and type(eport) == int:
                                self.lsse_ports_to_scan.extend(list(range(int(sport), int(eport) + 1)))
                            else:
                                print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                                exit()
                        except:
                            print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                            exit()
                    else:
                        port = int(port)
                        self.port_validation_2(port)
                        if type(port) == int :
                            self.lsse_ports_to_scan.append(port)
                        else:
                            print(f"\n{red}[LSSE] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[LSSE] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")

        else:
            try:
                self.args.sp = int(self.args.sp)
                self.port_validation_2(self.args.sp)
                if type(self.args.sp) == int :
                    self.lsse_ports_to_scan.append(int(self.args.sp))
                else:
                    print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                    exit()
            except:
                print(f"\n{red}[LSSE] Invalid ports range {reset}\n")
                exit()

        if len(self.lsse_ports_to_scan) <= 0:
            print(f"\n{yellow}[LSSE] No port/s was assagned for script {reset}\n")
            exit()
        else:
            pass

    def ping_port_parse(self):
        if "-" in self.args.ping_port and "," not in self.args.ping_port:
            try:
                sport , eport = self.args.ping_port.split("-")
                sport = int(sport)
                eport = int(eport)
                self.port_validation_1(sport, eport)
                if type(sport) == int and type(eport) == int:
                    self.pp = list(range(int(sport), int(eport) + 1))
                else:
                    print(f"\n{red}[!] Invalid ports range {reset}\n")
                    exit()
            except:
                print(f"\n{red}[!] Invalid ports range {reset}\n")
                exit()

        elif "," in self.args.ping_port and "-" not in self.args.ping_port:
            try:
                port_list = self.args.ping_port.split(",")
                for port in port_list:
                    port = int(port)
                    self.port_validation_2(port)
                    if type(port) == int :
                        self.pp.append(port)
                    else:
                        print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
        elif "," in self.args.ping_port and "-" in self.args.ping_port:
            try:
                port_list = self.args.ping_port.split(",")
                for port in port_list:
                    if "-" in port:
                        try:
                            sport, eport = port.split("-")
                            sport = int(sport)
                            eport = int(eport)
                            self.port_validation_1(sport, eport)
                            if type(sport) == int and type(eport) == int:
                                self.pp.extend(list(range(int(sport), int(eport) + 1)))
                            else:
                                print(f"\n{red}[!] Invalid ports range {reset}\n")
                                exit()
                        except:
                            print(f"\n{red}[!] Invalid ports range {reset}\n")
                            exit()
                    else:
                        port = int(port)
                        self.port_validation_2(port)
                        if type(port) == int :
                            self.pp.append(port)
                        else:
                            print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            except:
                print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")

        else:
            try:
                self.port_validation_2(int(self.args.ping_port))
                self.pp.append(int(self.args.ping_port))
            except:
                print(f"\n{red}[!] Invalid ports range {reset}\n")
                exit()

        if len(self.pp) <= 0:
            print(f"\n{yellow}[!] No port/s was assagned for hostdiscovery {reset}\n")
            exit()
        else:
            pass


    def port_validation_1(self,sport,eport):
        if sport < 0:
            print(f"\n{red}[!] Invalid Starting Port{reset}\n")
            exit(1)
        elif eport < 0:
            print(f"\n{red}[!] Invalid Ending Port{reset}\n")
            exit(1)
        elif eport < sport:
            print(f"\n{red}[!] Invalid Port Range{reset}\n")
            exit(1)
        elif eport > 65535:
            print(f"\n{red}[!] Invalid Ending Port{reset}\n")
            exit(1)
        else:
            pass

    def port_validation_2(self,port):
        if port < 0 or port > 65535:
            print(f"\n{red}[!] Invalid Starting Port{reset}\n")
            exit(1)
        elif type(port) != int:
            print(f"\n{red}[!] Invalid Starting Port{reset}\n")
            exit(1)
        else:
            pass


    def udp_scan(self, port, target):
        for attempt in range(self.args.max_retries):
            try:
                if self.args.V6:
                    version = 6
                else:
                    version = 4

                if self.args.payload == None:
                    payloads = mirage.random_payload()
                else:
                    payloads = self.args.payload

                self.Proto = "udp"
                self.scan_type = "udp"

                if self.args.ttl:
                    ttl = self.args.ttl
                else:
                    ttl = mirage.ipv4_ttl()

                if self.args.hlim:
                    hlim = self.args.hlim
                else:
                    hlim = mirage.ipv6_hlim()

                if self.args.sport:
                    sport = self.args.sport
                else:
                    sport = mirage.udp_sport()

                if port == 53:
                    packet = mirage.dns_payload_udp(target,version)
                elif port == 22:
                    packet = mirage.ssh_payload_udp(target,version)
                elif port == 21:
                    packet = mirage.ftp_payload_udp(target,version)
                else:
                    if self.args.V6:
                        packet = IPv6(dst=target,nh=17,hlim=hlim) / scapy.UDP(dport=port, sport=sport)/scapy.Raw(load=payloads)
                    else:
                        if self.args.id:
                            id = self.args.id
                        else:
                            id = mirage.ipv4_id()
                        if self.args.ip_flags:
                            flags = self.args.ip_flags
                        else:
                            flags = mirage.ipv4_flags()
                        packet = scapy.IP(dst=target,id=id,ttl=ttl,flags=flags) / scapy.UDP(dport=port, sport=sport)/scapy.Raw(load=payloads)
                if self.args.fragmente:
                    if self.args.recursively:
                        if version == 6:
                            response = Payloads.fragementation(packet, self.Proto, self.scan_type, self.args.verbose,v6=True)
                        else:
                            response = Payloads.fragementation(packet, self.Proto, self.scan_type, self.args.verbose)
                        if self.args.verbose:
                            print("[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if self.args.verbose:
                            print(f"{yellow}[+] Fragmentation is Forbiden with UDP packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
                else:
                    if self.args.timeout:

                        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
                    else:
                        response = scapy.sr1(packet, timeout=5, verbose=0)

                service = self.service_detection(port)
                if response is None:
                    if attempt == self.args.max_retries - 1:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['open_filtered_ports'].append(port)
                            self.target_results[target]['open_filtered_ports_services'].append(service)
                    else:
                        if self.args.verbose:
                            print(
                                f"{yellow}[!] No response from UDP port {port}, retrying... (attempt {attempt + 1}/{self.args.max_retries}){reset}")
                        time.sleep(0.1)
                        continue

                elif response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    if code == 4:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['closed_ports'].append(port)
                            self.target_results[target]['closed_ports_services'].append(service)
                        break
                    elif code == 1:

                        with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                        break
                    else:
                        with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    if self.args.V6:
                        pass
                    else:
                        icmp_type = response.getlayer(scapy.ICMP).type
                        icmp_code = response.getlayer(scapy.ICMP).code

                        if icmp_type == 3 and icmp_code == 3:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['closed_ports'].append(port)
                                self.target_results[target]['closed_ports_services'].append(service)
                            break

                        elif icmp_type == 3 and icmp_code in [1,2,9,10,13]:
                            with self.lock:
                                    if target not in self.target_results:
                                        self.initialize_target_results(target)
                                    self.target_results[target]['filtered_ports'].append(port)
                                    self.target_results[target]['filtered_ports_services'].append(service)
                            break

                        else:
                            with self.lock:
                                    if target not in self.target_results:
                                        self.initialize_target_results(target)
                                    self.target_results[target]['filtered_ports'].append(port)
                                    self.target_results[target]['filtered_ports_services'].append(service)
                            break


                elif response.haslayer(scapy.UDP):
                    with self.lock:
                        if target not in self.target_results:
                            self.initialize_target_results(target)
                        self.target_results[target]['open_ports'].append(port)
                        self.target_results[target]['opened_ports_services'].append(service)

                    if self.args.banner:

                        banner = Banner.grab(
                            target,
                            port,
                            protocol="udp",
                            timeout=3,
                            verbose=self.args.verbose,
                            version=version
                        )
                        try:
                            if banner['banner'] is not None and banner['service'] is not None:
                                with self.lock:
                                    self.target_results[target]['banners'].append(banner['banner'])
                                    self.target_results[target]['banners_ports'].append(port)
                                    self.target_results[target]['opened_ports_services'].append(banner['service'])
                            else:
                                self.target_results[target]['opened_ports_services'].append(service)
                        except TypeError:
                                self.target_results[target]['opened_ports_services'].append(service)
                    else:
                        self.target_results[target]['opened_ports_services'].append(service)
                    break
                else:
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if self.args.verbose:
                    print(f"{red}[!] UDP scan failed? That's weird. Heretic fixed this bug?{reset}")
                if attempt == self.args.max_retries - 1:
                    service = self.service_detection(port)
                    with self.lock:
                        if target not in self.target_results:
                            self.initialize_target_results(target)
                        if port in self.target_results[target]['open_ports']:
                            pass
                        else:
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                else:
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
                        time.sleep(0.02)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] UDP scan error: {e}{reset}")

        self.end_time = time.perf_counter()

    def tcp_syn_scan(self, port, target):
        for attempt in range(self.args.max_retries):
            try:
                if self.args.V6:
                    version = 6
                else:
                    version = 4
                self.Proto = "tcp"
                self.scan_type = "syn"
                if self.args.payload == None:
                    payloads = mirage.random_payload()
                else:
                    payloads = self.args.payload
                if self.args.ttl:
                    ttl = self.args.ttl
                else:
                    ttl = mirage.ipv4_ttl()

                if self.args.hlim:
                    hlim = self.args.hlim
                else:
                    hlim = mirage.ipv6_hlim()

                if self.args.sport:
                    sport = self.args.sport
                else:
                    sport = mirage.tcp_sport()

                if port == 22:
                    packet = mirage.ssh_payload_tcp(target,version)
                elif port == 21:
                    packet = mirage.ftp_payload_tcp(target,version)
                elif port in [80, 443, 8080, 8000, 8443, 8888]:
                    packet = mirage.http_payload_tcp(target, version, port)
                else:
                    if self.args.V6:
                        packet = IPv6(dst=target, hlim=hlim,nh=6) / scapy.TCP(dport=port, sport=sport,
                                                                  window=mirage.tcp_window(),seq=mirage.tcp_seq(),
                                                                  options=mirage.Stealth_tcp_options(), flags="S") / scapy.Raw(load=payloads)

                    else :
                        if self.args.id:
                            id = self.args.id
                        else:
                            id = mirage.ipv4_id()
                        if self.args.ip_flags:
                            flags = self.args.ip_flags
                        else:
                            flags = mirage.ipv4_flags()
                        packet = scapy.IP(dst=target, id=id, ttl=ttl,flags=flags) / scapy.TCP(dport=port, sport=sport,seq=mirage.tcp_seq(),window=mirage.tcp_window(),options=mirage.Stealth_tcp_options(), flags="S") / scapy.Raw(load=payloads)
                if self.args.fragmente:
                    if self.args.recursively:
                        if version == 6:
                            response = Payloads.fragementation(packet, self.Proto, self.scan_type, self.args.verbose,v6=True)
                        else:
                            response = Payloads.fragementation(packet, self.Proto, self.scan_type, self.args.verbose)
                        if self.args.verbose:
                            print("[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if self.args.verbose:
                            print(f"{yellow}[+] Fragmentation is Forbiden with SYN packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)

                service = self.service_detection(port)

                if response is None:
                    if attempt == self.args.max_retries - 1:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                    else:
                        if self.args.verbose:
                            print(f"{yellow}[!] No response from TCP(SYN) port {port}, retrying... (attempt {attempt + 1}/{self.args.max_retries}){reset}")
                        time.sleep(0.1)
                        continue

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x12:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['open_ports'].append(port)
                        
                        if self.args.banner:

                            banner = Banner.grab(
                                target,
                                port,
                                protocol="tcp",
                                timeout=3,
                                verbose=self.args.verbose,
                                version=version
                            )
                            try:
                                if banner['banner'] is not None and banner['service'] is not None:
                                    with self.lock:
                                        self.target_results[target]['banners'].append(banner['banner'])
                                        self.target_results[target]['banners_ports'].append(port)
                                        self.target_results[target]['opened_ports_services'].append(banner['service'])
                                else:
                                    self.target_results[target]['opened_ports_services'].append(service)
                            except TypeError:
                                self.target_results[target]['opened_ports_services'].append(service)
                        else:
                            self.target_results[target]['opened_ports_services'].append(service)

                        if self.args.V6:
                            scapy.send(IPv6(dst=target) / scapy.TCP(dport=port, flags="R"), verbose=0)
                        else:
                            scapy.send(scapy.IP(dst=target) / scapy.TCP(dport=port, flags="R"), verbose=0)
                        break


                    elif response.haslayer(ICMPv6DestUnreach):
                        code = response.getlayer(ICMPv6DestUnreach).code
                        if code == 4:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['closed_ports'].append(port)
                                self.target_results[target]['closed_ports_services'].append(service)
                            break
                        elif code == 1:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                            break
                        else:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                            break

                    elif flags == 0x14 or flags == 0x04:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['closed_ports'].append(port)
                            self.target_results[target]['closed_ports_services'].append(service)
                        break

                    else:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if self.args.verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == self.args.max_retries - 1:
                    service = self.service_detection(port)
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            if port in self.target_results[target]['open_ports']:
                                pass
                            else:
                                print("ddddddddddddddddddddddddddddddddddddd")
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    def tcp_3_ways_handshake(self, port, target):
        for attempt in range(self.args.max_retries):
            try:
                if self.args.V6:
                    version = 6
                else:
                    version = 4
                self.Proto = "tcp"
                self.scan_type = "tcp"
                if self.args.payload == None:
                    payloads = mirage.random_payload()
                else:
                    payloads = self.args.payload
                if self.args.ttl:
                    ttl = self.args.ttl
                else:
                    ttl = mirage.ipv4_ttl()

                if self.args.hlim:
                    hlim = self.args.hlim
                else:
                    hlim = mirage.ipv6_hlim()

                if self.args.sport:
                    sport = self.args.sport
                else:
                    sport = mirage.tcp_sport()
                if port == 22:
                    packet = mirage.ssh_payload_tcp(target,version)
                elif port == 21:
                    packet = mirage.ftp_payload_tcp(target,version)
                elif port in [80, 443, 8080, 8000, 8443, 8888]:
                    packet = mirage.http_payload_tcp(target, version, port)
                else:
                    if self.args.V6:
                        packet = IPv6(dst=target, nh=6, hlim=hlim) / scapy.TCP(dport=port, sport=sport,
                                                                  seq=mirage.tcp_seq(),
                                                                  window=mirage.tcp_window(),
                                                                  options=mirage.Stealth_tcp_options(), flags="S") / scapy.Raw(load=payloads)
                    else:
                        if self.args.id:
                            id = self.args.id
                        else:
                            id = mirage.ipv4_id()
                        if self.args.ip_flags:
                            flags = self.args.ip_flags
                        else:
                            flags = mirage.ipv4_flags()
                        packet = scapy.IP(dst=target, id=id, ttl=ttl,
                                          flags=flags) / scapy.TCP(dport=port, sport=sport,
                                                                  seq=mirage.tcp_seq(),
                                                                  window=mirage.tcp_window(),
                                                                  options=mirage.Stealth_tcp_options(), flags="S") / scapy.Raw(load=payloads)
                response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
                service = self.service_detection(port)

                if response is None:
                    if attempt == self.args.max_retries - 1:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                    else:
                        if self.args.verbose:
                            print(f"{yellow}[!] No response from TCP(SYN) port {port}, retrying... (attempt {attempt + 1}/{self.args.max_retries}){reset}")
                        time.sleep(0.1)
                        continue

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x12:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['open_ports'].append(port)
                            self.target_results[target]['opened_ports_services'].append(service)

                        if self.args.V6:
                            ack_packet = (IPv6(dst=target,hlim=hlim) /
                                          scapy.TCP(dport=port,sport=sport, flags="A",
                                                    seq=response[scapy.TCP].ack,
                                                    ack=response[scapy.TCP].seq + 1))
                        else:
                            ack_packet = (scapy.IP(dst=target,ttl=ttl) /
                                        scapy.TCP(dport=port,sport=sport, flags="A",
                                                  seq=response[scapy.TCP].ack,
                                                  ack=response[scapy.TCP].seq + 1))
                        if self.args.fragmente:
                            if version == 6:
                                ack_responses = Payloads.fragementation(ack_packet, self.Proto, self.scan_type,
                                                                        self.args.verbose,v6=True)
                            else:
                                ack_responses = Payloads.fragementation(ack_packet, self.Proto, self.scan_type, self.args.verbose)

                            if self.args.verbose:
                                if ack_responses:
                                    print(f"[+] Successfully sent fragemented ACK to {target}, {ack_responses} responses received from {target}")
                                else:
                                    print(f"[+] Successfully sent fragmented ACK to {target} (no responses)")

                        else:
                            scapy.send(ack_packet, verbose=False)


                        if self.args.banner:

                            banner = Banner.grab(
                                target,
                                port,
                                protocol="tcp",
                                timeout=3,
                                verbose=self.args.verbose,
                                version=version
                            )
                            try:
                                if banner['banner'] is not None and banner['service'] is not None:
                                    with self.lock:
                                        self.target_results[target]['banners'].append(banner['banner'])
                                        self.target_results[target]['banners_ports'].append(port)
                                        self.target_results[target]['opened_ports_services'].append(banner['service'])
                                else:
                                    self.target_results[target]['opened_ports_services'].append(service)
                            except TypeError:
                                self.target_results[target]['opened_ports_services'].append(service)

                        if self.args.V6:
                            scapy.send(IPv6(dst=target,hlim=hlim) / scapy.TCP(dport=port, flags="R"), verbose=0)
                        else:
                            scapy.send(scapy.IP(dst=target,ttl=ttl) / scapy.TCP(dport=port, flags="R"), verbose=0)
                        break


                    elif response.haslayer(ICMPv6DestUnreach):
                        code = response.getlayer(ICMPv6DestUnreach).code
                        if code == 4:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['closed_ports'].append(port)
                                self.target_results[target]['closed_ports_services'].append(service)
                            break
                        elif code == 1:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                            break
                        else:
                            with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                            break

                    elif flags == 0x14 or flags == 0x04:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['closed_ports'].append(port)
                            self.target_results[target]['closed_ports_services'].append(service)
                        break

                    else:
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type

                    if icmp_type == 11:
                        self.timeout_count += 1
                        with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['open_filtered_ports'].append(port)
                            self.target_results[target]['open_filtered_ports_services'].append(service)
                        break
                    else:
                        with self.lock:
                                if target not in self.target_results:
                                    self.initialize_target_results(target)
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            self.target_results[target]['filtered_ports'].append(port)
                            self.target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if self.args.verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == self.args.max_retries - 1:
                    service = self.service_detection(port)
                    with self.lock:
                            if target not in self.target_results:
                                self.initialize_target_results(target)
                            if port in self.target_results[target]['open_ports']:
                                pass
                            else:
                                self.target_results[target]['filtered_ports'].append(port)
                                self.target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    def Udp_host_discovery(self,Target,port):
        payloads = mirage.random_payload()
        if self.args.ttl:
            ttl = self.args.ttl
        else:
            ttl = mirage.ipv4_ttl()
        if self.args.hlim:
            hlim = self.args.hlim
        else:
            hlim = mirage.ipv6_hlim()

        if self.args.sport:
            sport = self.args.sport
        else:
            sport = mirage.udp_sport()
        if self.args.V6:
            packet = IPv6(dst=Target, nh=17, hlim=hlim) / scapy.UDP(dport=port, sport=sport) / scapy.Raw(
                load=payloads)
        else:
            if self.args.id:
                id = self.args.id
            else:
                id = mirage.ipv4_id()
            if self.args.ip_flags:
                flags = self.args.ip_flags
            else:
                flags = mirage.ipv4_flags()
            packet = scapy.IP(dst=Target, id=id, ttl=ttl,
                              flags=flags) / scapy.UDP(dport=port, sport=sport)/scapy.Raw(load=payloads)

        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
        if len(self.targets) == 1:
            if response:
                    if response.haslayer(scapy.UDP):
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    elif self.args.V6:
                        if response.haslayer(ICMPv6DestUnreach):
                            code = response.getlayer(ICMPv6DestUnreach).code
                            if code == 4:
                                print(f"[UDP] Host {Target}:{port} is up! ")
                                if Target not in self.targetss:
                                    self.targetss.append(Target)
                                self.target_results[Target]['up'] += 1

                            elif code == 1:
                                print(f"[UDP] Host {Target}:{port} is up! ")
                                if Target not in self.targetss:
                                    self.targetss.append(Target)
                                self.target_results[Target]['up'] += 1

                            else:
                                if Target not in self.targetss:
                                    self.targetss.append(Target)
                                self.target_results[Target]['up'] += 1
                    elif response.haslayer(scapy.ICMP):
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1

                    else:
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
            else:
                pass
        else:
            if response:
                    if response.haslayer(scapy.UDP):
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    elif self.args.V6:
                        if response.haslayer(ICMPv6DestUnreach):
                            code = response.getlayer(ICMPv6DestUnreach).code
                            if code == 4:
                                print(f"[UDP] Host {Target}:{port} is up! ")
                                if Target not in self.targetss:
                                    self.targetss.append(Target)
                                self.target_results[Target]['up'] += 1

                            elif code == 1:
                                if Target not in self.targetss:
                                    self.targetss.append(Target)

                            else:
                                if Target not in self.targetss:
                                    self.targetss.append(Target)
                    elif response.haslayer(scapy.ICMP):
                        print(f"[UDP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    else:
                        if Target not in self.targetss:
                            self.targetss.append(Target)

            else:
                pass

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
                            time.sleep(0.02)
                            futures.append(future)
                    else:
                        for port in top_20_udp_ports:
                            future = executor.submit(
                                self.Udp_host_discovery,target,port
                            )
                            time.sleep(0.02)
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

    def Syn_host_discovery(self,Target, port):
        self.Proto = "tcp"
        if self.args.ttl:
            ttl = self.args.ttl
        else:
            ttl = mirage.ipv4_ttl()
        if self.args.hlim:
            hlim = self.args.hlim
        else:
            hlim = mirage.ipv6_hlim()

        if self.args.sport:
            sport = self.args.sport
        else:
            sport = mirage.tcp_sport()
        if self.args.V6:
            packet = IPv6(dst=Target, nh=6, hlim=hlim) / scapy.TCP(dport=port, sport=sport,
                                                      seq=mirage.tcp_seq(),
                                                      window=mirage.tcp_window(),
                                                      options=mirage.Stealth_tcp_options(), flags="S")
        else:
            if self.args.id:
                id = self.args.id
            else:
                id = mirage.ipv4_id()
            if self.args.ip_flags:
                flags = self.args.ip_flags
            else:
                flags = mirage.ipv4_flags()
            packet = scapy.IP(dst=Target, id=id, ttl=ttl,
                                  flags=flags) / scapy.TCP(dport=port, sport=sport,
                                                          seq=mirage.tcp_seq(),
                                                          window=mirage.tcp_window(),
                                                          options=mirage.Stealth_tcp_options(), flags="S")
        response = scapy.sr1(packet, timeout=self.socket_timeout, verbose=0)
        if len(self.targets) == 1:
            if response != None:

                    if response.haslayer(scapy.TCP):
                        flags = response.getlayer(scapy.TCP).flags

                        if flags == 0x12:
                            print(f"[SYN] Host {Target}:{port} is up! ")
                            if Target not in self.targetss:
                                self.targetss.append(Target)
                            self.target_results[Target]['up'] += 1
                        else:
                            if Target not in self.targetss:
                                self.targetss.append(Target)
                            self.target_results[Target]['up'] += 1
                    else:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
            else:
                if Target not in self.targetss:
                    self.targetss.append(Target)
        else:
            if response != None:
                if response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x12:
                        print(f"[SYN] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    else:
                        pass
                else:
                    pass
            else:
                pass

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
                            time.sleep(0.02)
                            futures.append(future)
                    else:
                        for port in top_20_tcp_ports:
                            future = executor.submit(
                                self.Syn_host_discovery,target,port
                            )
                            time.sleep(0.02)
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

    def Tcp_host_discovery(self,Target,port):
        self.Proto = "tcp"
        if self.args.V6:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.socket_timeout)
        result = s.connect_ex((Target, port))
        if self.args.recursively:
            if len(self.targets) == 1:
                if result == 0:
                    print(f"[TCP] Host {Target}:{port} is up! ")
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1
                elif result in [61, 111, 10061]:
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1
                else:
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1

                if len(self.ports_to_scan) == 0:
                    print(f"[TCP] Host {Target} is shown to be down or not responding")
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1
                    self.ports_to_scan = []
            else:
                if self.args.verbose:
                    if result == 0:
                        print(f"[TCP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    elif result in [61, 111, 10061]:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    else:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    if len(self.ports_to_scan) == 0:
                        print(f"[TCP] Host {Target} is shown to be down or not responding, <Skip it>")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                        self.ports_to_scan = []
                else:
                    if result == 0:
                        print(f"[TCP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    elif result in [61, 111, 10061]:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    else:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                    if len(self.ports_to_scan) == 0:
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1
                        self.ports_to_scan = []
        else:
            if len(self.targets) == 1:
                if result == 0:
                    print(f"[TCP] Host {Target}:{port} is up! ")
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1

                elif result in [61, 111, 10061]:
                    pass
                else:
                    pass
                if len(self.ports_to_scan) == 0:
                    print(f"[TCP] Host {Target} is shown to be down or not responding")
                    if Target not in self.targetss:
                        self.targetss.append(Target)
                    self.target_results[Target]['up'] += 1
                    self.ports_to_scan = []
            else:
                if self.args.verbose:
                    if result == 0:
                        print(f"[TCP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1

                    elif result in [61, 111, 10061]:
                        pass
                    else:
                        pass
                    if len(self.ports_to_scan) == 0:
                        print(f"[TCP] Host {Target} is shown to be down or not responding, <Skip it>")
                        self.ports_to_scan = []
                else:
                    if result == 0:
                        print(f"[TCP] Host {Target}:{port} is up! ")
                        if Target not in self.targetss:
                            self.targetss.append(Target)
                        self.target_results[Target]['up'] += 1

                    elif result in [61, 111, 10061]:
                        pass
                    else:
                        pass
                    if len(self.ports_to_scan) == 0:
                        self.ports_to_scan = []

        self.targetss = list(set(self.targetss))

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
                            time.sleep(0.02)
                            futures.append(future)
                    else:
                        for port in top_20_tcp_ports:
                            future = executor.submit(
                                self.Tcp_host_discovery,target,port
                            )
                            time.sleep(0.02)
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

    def igmp_host_discovery(self):

        if self.args.ttl:
            ttl = self.args.ttl
        else:
            ttl = mirage.ipv4_ttl()

        if self.args.id:
            id = self.args.id
        else:
            id = mirage.ipv4_id()

        if self.args.ip_flags:
            flags = self.args.ip_flags
        else:
            flags = mirage.ipv4_flags()

        packet = scapy.Ether(dst="01:00:5e:00:00:01") / \
                 scapy.IP(dst="224.0.0.1", id=id, ttl=ttl, flags=flags) / \
                 IGMP(type=0x11, mrcode=10, gaddr="0.0.0.0")

        if hasattr(packet[IGMP], 'igmpize'):
            packet[IGMP].igmpize()

        response = scapy.srp1(packet,
                        timeout=self.socket_timeout,
                        verbose=0,
                        filter="igmp")

        if response:
            if IGMP in response:
                src_ip = response[scapy.IP].src
                igmp_type = response[IGMP].type

                version = "Unknown"
                if igmp_type == 0x12:
                    version = "v1"
                elif igmp_type == 0x16:
                    version = "v2"
                elif igmp_type == 0x22:
                    version = "v3"

                print(f"[+] Found host: {src_ip} (IGMP{version})")

        else:
            print(f"{yellow}[!] No IGMP response received{reset}")

    def host_discovery_4(self):
        icmp_id = random.randint(1, 65535)
        icmp_seq = random.randint(1, 65535)
        if self.args.ttl:
            ttl = self.args.ttl
        else:
            ttl = mirage.ipv4_ttl()

        if self.args.id:
            id = self.args.id
        else:
            id = mirage.ipv4_id()

        if self.args.ip_flags:
            flags = self.args.ip_flags
        else:
            flags = mirage.ipv4_flags()

        Address = scapy.Ether(dst="01:00:5e:00:00:02") / \
                  scapy.IP(dst="224.0.0.2", id=id, ttl=ttl, flags=flags) / \
                  scapy.ICMP(type=10, code=0, id=icmp_id, seq=icmp_seq)

        response = scapy.srp1(Address,
                        timeout=self.socket_timeout,
                        verbose=0)

        is_alive = False
        router_ip = None
        router_mac = None

        if response:
            if response.haslayer(scapy.ICMP):
                icmp_type = response[scapy.ICMP].type
                if icmp_type == 9:
                    is_alive = True

                    if response.haslayer(scapy.IP):
                        router_ip = response[scapy.IP].src

                    if response.haslayer(scapy.Ether):
                        router_mac = response[scapy.Ether].src

                        print(f"[+] Router Advertisement received:")
                        print(f"    IP: {router_ip}")
                        print(f"    MAC: {router_mac}")

                        if hasattr(response[scapy.ICMP], 'payload'):
                            payload = bytes(response[scapy.ICMP].payload)
                            if len(payload) >= 4:
                                num_addrs = payload[0]
                                lifetime = int.from_bytes(payload[1:4], 'big')
                                print(f"    Lifetime: {lifetime} seconds")
                                print(f"    Address entries: {num_addrs}")

                                offset = 4
                                for i in range(num_addrs):
                                    if offset + 8 <= len(payload):
                                        addr = ".".join(str(b) for b in payload[offset:offset + 4])
                                        pref = int.from_bytes(payload[offset + 4:offset + 8], 'big')
                                        print(f"      [{i + 1}] Router: {addr} Preference: {pref}")
                                        offset += 8
            else:
                print(f"[!] Received non-router advertisement response from {response[scapy.IP].src}")

        if self.args.recursively:
            if len(self.targets) == 1:
                if is_alive:
                    print(f"[SOLT] Router {router_ip} is up! (IRDP)")
                else:
                    print(f"[SOLT] No router discovered via ICMP solicitation")
            else:
                if self.args.verbose:
                    if is_alive:
                        print(f"[SOLT] Router {router_ip} is up! (IRDP)")
                    else:
                        print(f"[SOLT] No router discovered via ICMP solicitation")
                else:
                    if is_alive:
                        print(f"[SOLT] Router {router_ip} is up! (IRDP)")
                    else:
                        print(f"[SOLT] No router discovered via ICMP solicitation")
        else:
            if len(self.targets) == 1:
                if is_alive:
                    print(f"[SOLT] Router {router_ip} is up! (IRDP)")
                else:
                    print(f"[SOLT] No router discovered via ICMP solicitation")
            else:
                if self.args.verbose:
                    if is_alive:
                        print(f"[SOLT] Router {router_ip} is up! (IRDP)")
                    else:
                        print(f"[SOLT] No router discovered via ICMP solicitation, <Skip it>")
                else:
                    if is_alive:
                        print(f"[SOLT] Router {router_ip} is up! (IRDP)")
                    else:
                        print(f"{yellow}[SOLT] No router discovered via ICMP solicitation{reset}")

        return is_alive

    def host_discovery_3(self, Target):
            icmp_id = random.randint(1, 65535)
            icmp_seq = random.randint(1, 65535)
            if self.args.ttl:
                ttl = self.args.ttl
            else:
                ttl = mirage.ipv4_ttl()
            if self.args.id:
                id = self.args.id
            else:
                id = mirage.ipv4_id()
            if self.args.ip_flags:
                flags = self.args.ip_flags
            else:
                flags = mirage.ipv4_flags()
            Address = scapy.IP(dst=Target, id=id, ttl=ttl,flags=flags) / scapy.ICMP(type=15,seq=icmp_seq,id=icmp_id, code=0)
            response = scapy.sr1(Address, timeout=self.socket_timeout, verbose=0)
            if self.args.recursively:
                if len(self.targets) == 1:
                    if response:
                        print(f"[INFO] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[INFO] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.Tcp_host_discovery(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[INFO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[INFO] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                            self.Tcp_host_discovery(Target)
                    else:
                        if response:
                            print(f"[INFO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            self.Tcp_host_discovery(Target)
            else:
                if len(self.targets) == 1:
                    if response:
                        print(f"[INFO] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[INFO] Host {Target} is shown to be down or not responding")
                        self.targetss.append(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[INFO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[INFO] Host {Target} is shown to be down or not responding, <Skip it>")
                    else:
                        if response:
                            print(f"[INFO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            pass
            self.targetss = list(set(self.targetss))

    def host_discovery_2(self, Target):
            icmp_id = random.randint(1, 65535)
            icmp_seq = random.randint(1, 65535)
            if self.args.ttl:
                ttl = self.args.ttl
            else:
                ttl = mirage.ipv4_ttl()
            if self.args.id:
                id = self.args.id
            else:
                id = mirage.ipv4_id()
            if self.args.ip_flags:
                flags = self.args.ip_flags
            else:
                flags = mirage.ipv4_flags()
            Address = scapy.IP(dst=Target, id=id, ttl=ttl,flags=flags) / scapy.ICMP(type=17,seq=icmp_seq,id=icmp_id, code=0)
            response = scapy.sr1(Address, timeout=self.socket_timeout, verbose=0)
            if self.args.recursively:
                if len(self.targets) == 1:
                    if response:
                        print(f"[ADDR] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[ADDR] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.Tcp_host_discovery(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[ADDR] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[ADDR] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                            self.Tcp_host_discovery(Target)
                    else:
                        if response:
                            print(f"[ADDR] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            self.Tcp_host_discovery(Target)
            else:
                if len(self.targets) == 1:
                    if response:
                        print(f"[ADDR] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[ADDR] Host {Target} is shown to be down or not responding")
                        self.targetss.append(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[ADDR] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[ADDR] Host {Target} is shown to be down or not responding, <Skip it>")
                    else:
                        if response:
                            print(f"[ADDR] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            pass
            self.targetss = list(set(self.targetss))

    def host_discovery_1(self, Target):
            icmp_id = random.randint(1, 65535)
            icmp_seq = random.randint(1, 65535)
            if self.args.ttl:
                ttl = self.args.ttl
            else:
                ttl = mirage.ipv4_ttl()
            if self.args.id:
                id = self.args.id
            else:
                id = mirage.ipv4_id()
            if self.args.ip_flags:
                flags = self.args.ip_flags
            else:
                flags = mirage.ipv4_flags()
            TimeStamp = scapy.IP(dst=Target, id=id, ttl=ttl,flags=flags) / scapy.ICMP(type=13,seq=icmp_seq,id=icmp_id,code=0)
            response = scapy.sr1(TimeStamp, timeout=self.socket_timeout, verbose=0)
            if self.args.recursively:
                if len(self.targets) == 1:
                    if response:
                        print(f"[TIME STAMP] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[TIME STAMP] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.Tcp_host_discovery(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[TIME STAMP] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[TIME STAMP] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                            self.Tcp_host_discovery(Target)
                    else:
                        if response:
                            print(f"[TIME STAMP] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            self.Tcp_host_discovery(Target)
            else:
                if len(self.targets) == 1:
                    if response:
                        print(f"[TIME STAMP] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[TIME STAMP] Host {Target} is shown to be down or not responding")
                        self.targetss.append(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[TIME STAMP] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[TIME STAMP] Host {Target} is shown to be down or not responding, <Skip it>")
                    else:
                        if response:
                            print(f"[TIME STAMP] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            pass
            self.targetss = list(set(self.targetss))

    def host_discovery_ipv6(self, Target):
        if self.args.hlim:
            hlim = self.args.hlim
        else:
            hlim = mirage.ipv6_hlim()
        Echo = IPv6(dst=Target,hlim=hlim) / ICMPv6EchoRequest()
        response = scapy.sr1(Echo, timeout=self.socket_timeout, verbose=0)
        if self.args.recursively:
            if len(self.targets) == 1:
                if response is None:
                    print(
                        f"[ECHOv6] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                    self.targetss.append(Target)
                elif response.haslayer(ICMPv6EchoReply):
                    print(f"[ECHOv6] Host {Target} is up! ")
                    self.targetss.append(Target)
                elif response.haslayer(ICMPv6TimeExceeded):
                    print(f"[ECHOv6] Host {Target} is up! ")
                    self.targetss.append(Target)
                elif response.haslayer(ICMPv6DestUnreach):
                    code = response[ICMPv6DestUnreach].code
                    if code == 4:
                        print(f"[ECHOv6] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(
                            f"[ECHOv6] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.targetss.append(Target)
                else:
                    print(
                        f"[ECHOv6] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                    self.Tcp_host_discovery(Target)
            else:
                if self.args.verbose:
                    if response is None:
                        print(
                            f"[ECHOv6] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.targetss.append(Target)
                    elif response.haslayer(ICMPv6EchoReply):
                        print(f"[ECHOv6] Host {Target} is up! ")
                        self.targetss.append(Target)
                    elif response.haslayer(ICMPv6TimeExceeded):
                        print(f"[ECHOv6] Host {Target} is up! ")
                        self.targetss.append(Target)
                    elif response.haslayer(ICMPv6DestUnreach):
                        code = response[ICMPv6DestUnreach].code
                        if code == 4:
                            print(f"[ECHOv6] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(
                                f"[ECHOv6] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                            self.targetss.append(Target)
                    else:
                        print(
                            f"[ECHOv6] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.Tcp_host_discovery(Target)
                else:
                        if response is None:
                            self.targetss.append(Target)
                        elif response.haslayer(ICMPv6EchoReply):
                            print(f"[ECHOv6] Host {Target} is up! ")
                            self.targetss.append(Target)
                        elif response.haslayer(ICMPv6TimeExceeded):
                            print(f"[ECHOv6] Host {Target} is up! ")
                            self.targetss.append(Target)
                        elif response.haslayer(ICMPv6DestUnreach):
                            code = response[ICMPv6DestUnreach].code
                            if code == 4:
                                print(f"[ECHOv6] Host {Target} is up! ")
                                self.targetss.append(Target)
                            else:
                                self.targetss.append(Target)
                        else:
                            self.Tcp_host_discovery(Target)
        else:
            if len(self.targets) == 1:
                if response is None:
                    print(
                        f"[ECHOv6] Host {Target} is shown to be down or not responding")
                elif response.haslayer(ICMPv6EchoReply):
                    print(f"[ECHOv6] Host {Target} is up! ")
                    self.targetss.append(Target)
                elif response.haslayer(ICMPv6TimeExceeded):
                    print(f"[ECHOv6] Host {Target} is up! ")
                    self.targetss.append(Target)
                elif response.haslayer(ICMPv6DestUnreach):
                    code = response[ICMPv6DestUnreach].code
                    if code == 4:
                        print(f"[ECHOv6] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(
                            f"[ECHOv6] Host {Target} is shown to be down or not responding")
                else:
                    print(
                        f"[ECHOv6] Host {Target} is shown to be down or not responding")
            else:
                if self.args.verbose:
                    if response is None:
                        print(
                            f"[ECHOv6] Host {Target} is shown to be down or not responding,")
                    elif response.haslayer(ICMPv6EchoReply):
                        print(f"[ECHOv6] Host {Target} is up! ")
                        self.targetss.append(Target)
                    elif response.haslayer(ICMPv6TimeExceeded):
                        print(f"[ECHOv6] Host {Target} is up! ")
                        self.targetss.append(Target)
                    elif response.haslayer(ICMPv6DestUnreach):
                        code = response[ICMPv6DestUnreach].code
                        if code == 4:
                            print(f"[ECHOv6] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(
                                f"[ECHOv6] Host {Target} is shown to be down or not responding")
                    else:
                        print(
                            f"[ECHOv6] Host {Target} is shown to be down or not responding")
                else:
                    if response is None:
                        pass
                    elif response.haslayer(ICMPv6EchoReply):
                        print(f"[ECHOv6] Host {Target} is up! ")
                        self.targetss.append(Target)
                    elif response.haslayer(ICMPv6TimeExceeded):
                        print(f"[ECHOv6] Host {Target} is up! ")
                        self.targetss.append(Target)
                    elif response.haslayer(ICMPv6DestUnreach):
                        code = response[ICMPv6DestUnreach].code
                        if code == 4:
                            print(f"[ECHOv6] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            pass
                    else:
                        pass
        self.targetss = list(set(self.targetss))

    def host_discovery(self, Target):
            icmp_id = random.randint(1, 65535)
            icmp_seq = random.randint(1, 65535)
            if self.args.ttl:
                ttl = self.args.ttl
            else:
                ttl = mirage.ipv4_ttl()
            if self.args.id:
                id = self.args.id
            else:
                id = mirage.ipv4_id()
            if self.args.ip_flags:
                flags = self.args.ip_flags
            else:
                flags = mirage.ipv4_flags()
            Echo = scapy.IP(dst=Target, id=id, ttl=ttl,flags=flags) / scapy.ICMP(type=8,id=icmp_id,seq=icmp_seq, code=0)
            response = scapy.sr1(Echo, timeout=self.socket_timeout, verbose=0)
            if self.args.recursively:
                if len(self.targets) == 1:
                    if response:
                        print(f"[ECHO] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[ECHO] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                        self.Tcp_host_discovery(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[ECHO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[ECHO] Host {Target} is shown to be down or not responding, <Swithch to TCP Host Discovery>")
                            self.Tcp_host_discovery(Target)
                    else:
                        if response:
                            print(f"[ECHO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            self.Tcp_host_discovery(Target)
            else:
                if len(self.targets) == 1:
                    if response:
                        print(f"[ECHO] Host {Target} is up! ")
                        self.targetss.append(Target)
                    else:
                        print(f"[ECHO] Host {Target} is shown to be down or not responding")
                        self.targetss.append(Target)
                else:
                    if self.args.verbose:
                        if response:
                            print(f"[ECHO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            print(f"[ECHO] Host {Target} is shown to be down or not responding, <Skip it>")
                    else:
                        if response:
                            print(f"[ECHO] Host {Target} is up! ")
                            self.targetss.append(Target)
                        else:
                            pass
            self.targetss = list(set(self.targetss))

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
                        time.sleep(0.02)
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
                        time.sleep(0.02)
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
                        time.sleep(0.02)
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
                        time.sleep(0.02)
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
                        time.sleep(0.02)
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
                        time.sleep(0.02)
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
                        time.sleep(0.02)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if self.args.verbose:
                            print(f"{red}[!] TCP SYN scan error: {e}{reset}")

        self.end_time = time.perf_counter()

    def check_network_config(self):
        try:
            import netifaces
            gateways = netifaces.gateways()
            default_gateway = gateways.get('default', {})

            if not default_gateway:
                print(f"\n{red}[!] Warning: No default gateway found. Network scanning may have issues.")
                print(f"[!] Scapy will use broadcast MAC addresses which may generate warnings.{reset}")
        except ImportError:
            pass

    def Scan_details(self):
        duration = self.end_time - self.start_time
        D = self.EE - self.E

        for target in self.targetss:
            if target in self.target_results:
                self._sync_and_deduplicate_ports(target)

        print(f"\n[*] Scan completed in {duration:.2f} seconds")
        print(f"\n[*] Total Time in {D:.2f} seconds")

        for target in self.targetss:

            if target not in self.target_results:
                print(f"\n[-] No results for target: {target}")
                continue

            ip_status = Payloads.is_private_ip(target)
            Mac = None
            if self.args.n:
                pass
            else:
                rdns = self.reverse_dns_lookup(target)

            if ip_status == "Local":
                if not self.args.mac:
                    if self.args.V6:
                        Mac = Payloads.NDP_Get_MAC(target)
                    else:
                        Mac = Payloads.ARP_Scan(target)

            results = self.target_results[target]

            print(f"\n{'=' * 60}")
            print(f"[+] Scan result for : {target}")
            print(f"[+] Scan Type: {self.scan_type.upper()} | Protocol: {self.Proto.upper()}")
            if self.args.n:
                pass
            else:
                print(f"[+] Reverse DNS: {rdns}")
            if ip_status == "Local":
                print(f"[+] IP Status: {ip_status}")
                if not self.args.mac and Mac:
                    print(f"[+] Mac Address: {Mac}")
            elif ip_status == "Public":
                print(f"[+] IP Status: {ip_status}")
            print(f"{'=' * 60}")

            if self.scan_type == "ipproto":

                    proto_names = {
                    0: "HOPOPT",
                    1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP",
                    10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS",
                    17: "UDP", 18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1",
                    24: "TRUNK-2", 25: "LEAF-1", 26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4",
                    30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP", 34: "3PC", 35: "IDPR",
                    36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++", 40: "IL", 41: "IPv6", 42: "SDRP",
                    43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR",
                    49: "BNA", 50: "ESP", 51: "AH", 52: "I-NLSP", 53: "SWIPE", 54: "NARP", 55: "MOBILE",
                    56: "TLSP", 57: "SKIP", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts", 61: "AnyHost",
                    62: "CFTP", 63: "AnyLocal", 64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC",
                    68: "AnyDistFS", 69: "SAT-MON", 70: "VISA", 71: "IPCV", 72: "CPNX", 73: "CPHB", 74: "WSN",
                    75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP",
                    81: "VMTP", 82: "SECURE-VMTP", 83: "VINES", 84: "TTP", 85: "NSFNET-IGP", 86: "DGP",
                    87: "TCF", 88: "EIGRP", 89: "OSPF", 90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25",
                    94: "IPIP", 95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 99: "AnyPrivate",
                    100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS", 106: "QNX",
                    107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer", 111: "IPX-in-IP", 112: "VRRP",
                    113: "PGM", 114: "Any0-hop", 115: "L2TP", 116: "DDX", 117: "IATP", 118: "STP", 119: "SRP",
                    120: "UTI", 121: "SMP", 122: "SM", 123: "PTP", 124: "ISIS-over-IPv4", 125: "FIRE",
                    126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE", 129: "IPLT", 130: "SPS", 131: "PIPE",
                    132: "SCTP", 133: "FC", 134: "RSVP-E2E-IGNORE", 135: "Mobility-Header", 136: "UDPLite",
                    137: "MPLS-in-IP", 138: "manet", 139: "HIP", 140: "Shim6", 141: "WESP", 142: "ROHC",
                    143: "Ethernet", 144: "AGGFRAG", 145: "NSH", 146: "unassigned", 147: "unassigned",
                    148: "unassigned", 149: "unassigned", 150: "unassigned", 151: "unassigned", 152: "unassigned",
                    153: "unassigned", 154: "unassigned", 155: "unassigned", 156: "unassigned", 157: "unassigned",
                    158: "unassigned", 159: "unassigned", 160: "unassigned", 161: "unassigned", 162: "unassigned",
                    163: "unassigned", 164: "unassigned", 165: "unassigned", 166: "unassigned", 167: "unassigned",
                    168: "unassigned", 169: "unassigned", 170: "unassigned", 171: "unassigned", 172: "unassigned",
                    173: "unassigned", 174: "unassigned", 175: "unassigned", 176: "unassigned", 177: "unassigned",
                    178: "unassigned", 179: "unassigned", 180: "unassigned", 181: "unassigned", 182: "unassigned",
                    183: "unassigned", 184: "unassigned", 185: "unassigned", 186: "unassigned", 187: "unassigned",
                    188: "unassigned", 189: "unassigned", 190: "unassigned", 191: "unassigned", 192: "unassigned",
                    193: "unassigned", 194: "unassigned", 195: "unassigned", 196: "unassigned", 197: "unassigned",
                    198: "unassigned", 199: "unassigned", 200: "unassigned", 201: "unassigned", 202: "unassigned",
                    203: "unassigned", 204: "unassigned", 205: "unassigned", 206: "unassigned", 207: "unassigned",
                    208: "unassigned", 209: "unassigned", 210: "unassigned", 211: "unassigned", 212: "unassigned",
                    213: "unassigned", 214: "unassigned", 215: "unassigned", 216: "unassigned", 217: "unassigned",
                    218: "unassigned", 219: "unassigned", 220: "unassigned", 221: "unassigned", 222: "unassigned",
                    223: "unassigned", 224: "unassigned", 225: "unassigned", 226: "unassigned", 227: "unassigned",
                    228: "unassigned", 229: "unassigned", 230: "unassigned", 231: "unassigned", 232: "unassigned",
                    233: "unassigned", 234: "unassigned", 235: "unassigned", 236: "unassigned", 237: "unassigned",
                    238: "unassigned", 239: "unassigned", 240: "unassigned", 241: "unassigned", 242: "unassigned",
                    243: "unassigned", 244: "unassigned", 245: "unassigned", 246: "unassigned", 247: "unassigned",
                    248: "unassigned", 249: "unassigned", 250: "unassigned", 251: "unassigned", 252: "unassigned",
                    253: "unassigned", 254: "unassigned", 255: "RAW"
                }

                    print(f"\n[+] OPEN Protocols: {len(results.get('open_protocols', []))}")
                    for i, proto in enumerate(results['open_protocols'][:20]):
                        proto_name = proto_names.get(proto, f"Proto{proto}")
                        print(f"     Protocol {proto:3} ({proto_name:12}) : OPEN")
                    if len(results['open_protocols']) > 20:
                        print(f"     ... and {len(results['open_protocols']) - 20} more")


                    print(f"\n[+] CLOSED Protocols: {len(results.get('closed_protocols', []))}")
                    if results.get('closed_protocols'):
                        for i, proto in enumerate(results['closed_protocols'][:20]):
                            proto_name = proto_names.get(proto, f"Proto{proto}")
                            print(f"     Protocol {proto:3} ({proto_name:12}) : CLOSED")
                        if len(results['closed_protocols']) > 20:
                            print(f"     ... and {len(results['closed_protocols']) - 20} more")

                    print(f"\n[+] FILTERED Protocols: {len(results.get('filtered_protocols', []))}")
                    if results.get('filtered_protocols'):
                        for i, proto in enumerate(results['filtered_protocols'][:20]):
                            proto_name = proto_names.get(proto, f"Proto{proto}")
                            print(f"     Protocol {proto:3} ({proto_name:12}) : FILTERED")
                        if len(results['filtered_protocols']) > 20:
                            print(f"     ... and {len(results['filtered_protocols']) - 20} more")

                    print(f"\n[+] OPEN|FILTERED Protocols: {len(results.get('open_filtered_protocols', []))}")
                    if results.get('open_filtered_protocols'):
                        for i, proto in enumerate(results['open_filtered_protocols'][:20]):
                            proto_name = proto_names.get(proto, f"Proto{proto}")
                            print(f"     Protocol {proto:3} ({proto_name:12}) : OPEN|FILTERED")
                        if len(results['open_filtered_protocols']) > 20:
                            print(f"     ... and {len(results['open_filtered_protocols']) - 20} more")

            elif self.scan_type in ["tcp", "syn", "udp","init"]:
                    print(f"\n[+] Open Ports: {len(results['open_ports'])}")
                    display_ports = results['open_ports'][:20]
                    for i in range(len(display_ports)):
                        service = results['opened_ports_services'][i] if i < len(
                            results['opened_ports_services']) else "unknown"
                        print(f"     Port {display_ports[i]} {service}\\{self.Proto}")
                    if len(results['open_ports']) > 20:
                        print(f"     ... and {len(results['open_ports']) - 20} more")

                    print(f"\n[+] Closed Ports: {len(results['closed_ports'])}")
                    if results.get('closed_ports'):
                        for i in range(min(len(results['closed_ports']), 20)):
                            service = results['closed_ports_services'][i].lower() if i < len(
                                results['closed_ports_services']) else "unknown"
                            print(f"     Port {results['closed_ports'][i]} {service}\\{self.Proto}")

                    print(f"\n[+] Filtered Ports: {len(results['filtered_ports'])}")
                    if results.get('filtered_ports'):
                        for i in range(min(len(results['filtered_ports']), 20)):
                            service = results['filtered_ports_services'][i].lower() if i < len(
                                results['filtered_ports_services']) else "unknown"
                            print(f"     Port {results['filtered_ports'][i]} {service}\\{self.Proto}")

            elif self.scan_type in ["idle"]:
                    print(f"\n[+] Open Ports: {len(results['open_ports'])}")
                    display_ports = results['open_ports'][:20]
                    for i in range(len(display_ports)):
                        service = results['opened_ports_services'][i].lower() if i < len(
                            results['opened_ports_services']) else "unknown"
                        print(f"     Port {display_ports[i]} {service}\\{self.Proto}")
                    if len(results['open_ports']) > 20:
                        print(f"     ... and {len(results['open_ports']) - 20} more")

                    print(f"\n[+] Closed|Filtered Ports: {len(results['closed_ports'])}")
                    if results.get('closed_filtered_ports'):
                        for i in range(min(len(results['closed_filtered_ports']), 20)):
                            service = results['closed_filtered_ports_services'][i].lower() if i < len(
                                results['closed_filtered_ports_services']) else "unknown"
                            print(f"     Port {results['closed_filtered_ports'][i]} {service}\\{self.Proto}")

                    print(f"\n[+] Filtered Ports: {len(results['filtered_ports'])}")
                    if results.get('filtered_ports'):
                        for i in range(min(len(results['filtered_ports']), 20)):
                            service = results['filtered_ports_services'][i].lower() if i < len(
                                results['filtered_ports_services']) else "unknown"
                            print(f"     Port {results['filtered_ports'][i]} {service}\\{self.Proto}")

            if self.scan_type in ["syn", "udp"]:
                    print(f"\n[+] Open|Filtered Ports: {len(results.get('open_filtered_ports', []))}")
                    if results.get('open_filtered_ports') and self.args.verbose:
                        for i in range(min(len(results['open_filtered_ports']), 20)):
                            service = results['open_filtered_ports_services'][i].lower() if i < len(
                                results['open_filtered_ports_services']) else "unknown"
                            print(f"     Port {results['open_filtered_ports'][i]} {service}\\{self.Proto}")

            elif self.scan_type == "null":
                print(f"\n[+] Closed Ports: {len(results['closed_ports'])}")
                if results.get('closed_ports'):
                    for i in range(min(len(results['closed_ports']), 20)):
                        service = results['closed_ports_services'][i].lower() if i < len(
                            results['closed_ports_services']) else "unknown"
                        print(f"     Port {results['closed_ports'][i]} {service}\\{self.Proto}")

                print(f"\n[+] Filtered Ports: {len(results['filtered_ports'])}")
                if results.get('filtered_ports'):
                    for i in range(min(len(results['filtered_ports']), 20)):
                        service = results['filtered_ports_services'][i].lower() if i < len(
                            results['filtered_ports_services']) else "unknown"
                        print(f"     Port {results['filtered_ports'][i]} {service}\\{self.Proto}")
                print(f"\n[+] (NULL Scan) Open|Filtered Ports: {len(results.get('null_ports', []))}")
                if results.get('null_ports'):
                    for i in range(min(len(results['null_ports']), 20)):
                        service = results['null_ports_services'][i].lower() if i < len(
                            results['null_ports_services']) else "unknown"
                        print(f"     Port {results['null_ports'][i]} {service}\\{self.Proto}")

            elif self.scan_type == "fin":
                print(f"\n[+] Closed Ports: {len(results['closed_ports'])}")
                if results.get('closed_ports'):
                    for i in range(min(len(results['closed_ports']), 20)):
                        service = results['closed_ports_services'][i].lower() if i < len(
                            results['closed_ports_services']) else "unknown"
                        print(f"     Port {results['closed_ports'][i]} {service}\\{self.Proto}")

                print(f"\n[+] Filtered Ports: {len(results['filtered_ports'])}")
                if results.get('filtered_ports'):
                    for i in range(min(len(results['filtered_ports']), 20)):
                        service = results['filtered_ports_services'][i].lower() if i < len(
                            results['filtered_ports_services']) else "unknown"
                        print(f"     Port {results['filtered_ports'][i]} {service}\\{self.Proto}")
                print(f"\n[+] (FIN Scan) Open|Filtered Ports: {len(results.get('fin_ports', []))}")
                if results.get('fin_ports'):
                    for i in range(min(len(results['fin_ports']), 20)):
                        service = results['fin_ports_services'][i].lower() if i < len(
                            results['fin_ports_services']) else "unknown"
                        print(f"     Port {results['fin_ports'][i]} {service}\\{self.Proto}")

            elif self.scan_type == "xmas":
                print(f"\n[+] Closed Ports: {len(results['closed_ports'])}")
                if results.get('closed_ports'):
                    for i in range(min(len(results['closed_ports']), 20)):
                        service = results['closed_ports_services'][i].lower() if i < len(
                            results['closed_ports_services']) else "unknown"
                        print(f"     Port {results['closed_ports'][i]} {service}\\{self.Proto}")

                print(f"\n[+] Filtered Ports: {len(results['filtered_ports'])}")
                if results.get('filtered_ports'):
                    for i in range(min(len(results['filtered_ports']), 20)):
                        service = results['filtered_ports_services'][i].lower() if i < len(
                            results['filtered_ports_services']) else "unknown"
                        print(f"     Port {results['filtered_ports'][i]} {service}\\{self.Proto}")
                print(f"\n[+] (XMAS Scan) Open|Filtered Ports: {len(results.get('open_filtered_ports', []))}")
                if results.get('open_filtered_ports'):
                    for i in range(min(len(results['open_filtered_ports']), 20)):
                        service = results['open_filtered_ports_services'][i].lower() if i < len(
                            results['open_filtered_ports_services']) else "unknown"
                        print(f"     Port {results['open_filtered_ports'][i]} {service}\\{self.Proto}")

            elif self.scan_type == "ack":
                print(f"\n[+] Filtered Ports: {len(results.get('filtered_ports', []))}")
                if results.get('filtered_ports') and self.args.verbose:
                    for i in range(min(len(results['filtered_ports']), 20)):
                        service = results['filtered_ports_services'][i].lower() if i < len(
                            results['filtered_ports_services']) else "unknown"
                        print(f"     Port {results['filtered_ports'][i]} {service}\\{self.Proto}")

                print(f"\n[+] Unfiltered Ports: {len(results.get('unfiltered_ports', []))}")
                if results.get('unfiltered_ports'):
                    for i in range(min(len(results['unfiltered_ports']), 20)):
                        service = results['unfiltered_ports_services'][i].lower() if i < len(
                            results['unfiltered_ports_services']) else "unknown"
                        print(f"     Port {results['unfiltered_ports'][i]} {service}\\{self.Proto}")

            elif self.scan_type == "maimon":
                print(f"\n[+] Closed Ports: {len(results['closed_ports'])}")
                if results.get('closed_ports'):
                    for i in range(min(len(results['closed_ports']), 20)):
                        service = results['closed_ports_services'][i].lower() if i < len(
                            results['closed_ports_services']) else "unknown"
                        print(f"     Port {results['closed_ports'][i]} {service}\\{self.Proto}")

                print(f"\n[+] Filtered Ports: {len(results['filtered_ports'])}")
                if results.get('filtered_ports'):
                    for i in range(min(len(results['filtered_ports']), 20)):
                        service = results['filtered_ports_services'][i].lower() if i < len(
                            results['filtered_ports_services']) else "unknown"
                        print(f"     Port {results['filtered_ports'][i]} {service}\\{self.Proto}")
                print(f"\n[+] (MAIMON Scan) Open|Filtered Ports: {len(results.get('open_filtered_ports', []))}")
                if results.get('open_filtered_ports') and self.args.verbose:
                    for i in range(min(len(results['open_filtered_ports']), 20)):
                        service = results['open_filtered_ports_services'][i].lower() if i < len(
                            results['open_filtered_ports_services']) else "unknown"
                        print(f"     Port {results['open_filtered_ports'][i]} {service}\\{self.Proto}")

            elif self.scan_type == "window":
                print(f"\n[+] Open Ports: {len(results['open_ports'])}")
                display_ports = results['open_ports'][:20]
                for i in range(len(display_ports)):
                    service = results['opened_ports_services'][i].lower() if i < len(
                        results['opened_ports_services']) else "unknown"
                    print(f"     Port {display_ports[i]} {service}\\{self.Proto}")
                if len(results['open_ports']) > 20:
                    print(f"     ... and {len(results['open_ports']) - 20} more")

                print(f"\n[+] Closed Ports: {len(results['closed_ports'])}")
                if results.get('closed_ports'):
                    for i in range(min(len(results['closed_ports']), 20)):
                        service = results['closed_ports_services'][i].lower() if i < len(
                            results['closed_ports_services']) else "unknown"
                        print(f"     Port {results['closed_ports'][i]} {service}\\{self.Proto}")

                print(f"\n[+] Filtered Ports: {len(results['filtered_ports'])}")
                if results.get('filtered_ports'):
                    for i in range(min(len(results['filtered_ports']), 20)):
                        service = results['filtered_ports_services'][i].lower() if i < len(
                            results['filtered_ports_services']) else "unknown"
                        print(f"     Port {results['filtered_ports'][i]} {service}\\{self.Proto}")
                print(f"\n[+] (WINDOW Scan) Open|Filtered Ports: {len(results.get('open_filtered_ports', []))}")
                if results.get('open_filtered_ports') and self.args.verbose:
                    for i in range(min(len(results['open_filtered_ports']), 20)):
                        service = results['open_filtered_ports_services'][i].lower() if i < len(
                            results['open_filtered_ports_services']) else "unknown"
                        print(f"     Port {results['open_filtered_ports'][i]} {service}\\{self.Proto}")

            elif self.scan_type == "fdd":
                print(f"\n[+] Defended Ports: {len(results.get('defended_ports', []))}")
                if results.get('defended_ports'):
                    for i in range(min(len(results['defended_ports']), 20)):
                        service = results['defended_ports_services'][i].lower() if i < len(
                            results['defended_ports_services']) else "unknown"
                        print(f"     Port {results['defended_ports'][i]} {service}\\{self.Proto}")

                print(f"\n[+] Undefended Ports: {len(results.get('undefended_ports', []))}")
                if results.get('undefended_ports'):
                    for i in range(min(len(results['undefended_ports']), 20)):
                        service = results['undefended_ports_services'][i].lower() if i < len(
                            results['undefended_ports_services']) else "unknown"
                        print(f"     Port {results['undefended_ports'][i]} {service}\\{self.Proto}")

            elif self.scan_type == "ftp-bounce" or self.scan_type == "FTP-BOUNCE":
                    print(f"\n[+] FTP Bounce Scan Results:")
                    print(f"    FTP Server: {self.args.ftp_server if hasattr(self.args, 'ftp_server') else 'Unknown'}")
                    print(f"    Target: {target}")

                    print(f"\n[+] Open Ports (via FTP bounce): {len(results.get('open_ports', []))}")
                    if results.get('open_ports'):
                        for i in range(min(len(results['open_ports']), 20)):
                            service = results['opened_ports_services'][i].lower() if i < len(
                                results['opened_ports_services']) else "unknown"
                            print(f"     Port {results['open_ports'][i]} {service}\\{self.Proto}")
                        if len(results['open_ports']) > 20:
                            print(f"     ... and {len(results['open_ports']) - 20} more")

                    if self.args.verbose:
                        print(f"\n[+] Closed Ports: {len(results.get('closed_ports', []))}")
                        print(f"[+] Filtered Ports: {len(results.get('filtered_ports', []))}")

            self.Firewall_detection(target, results)

            if self.args.banner and results.get('banners'):
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
                        version_info = VersionParser.parse_version(results['banners'][i], results['banners_ports'][i])
                    if version_info:
                        print(f"\n          [+] Version: {version_info.get('product')} {version_info.get('version')}\n")
                    print("=" * 60)
                    print(f"     {results['banners'][i]}")
                    print("=" * 60)
                    print()

            if self.args.os:
                try:

                    engine = OSFingerprintEngine(min_score=self.args.min_score, min_report_confidence=self.args.min_confi)

                    if self.args.V6:
                        version = 6
                    else:
                        version = 4
                    
                    if len(results['open_ports']) > 0:
                        result = engine.fingerprint(
                            target=target,
                            open_ports=results.get('open_ports', []),
                            banners=results.get('banners', []),
                            services=results.get('opened_ports_services', []),
                            version=version,
                            use_icmp=True,
                            use_udp=True,
                        )
                    
                        if version == 4:
                            print("\n[+] OS Fingerprint Results (IPv4):\n----------------------------------------")
                        else:
                            print("\n[+] OS Fingerprint Results (IPv6):\n----------------------------------------")

                        for match in result.matches:
                            print(f"    [+] {match.name}: {match.confidence:.1f}% (score: {match.score:.1f})")
                            if match.version:
                                print(f"        └─ Version: {match.version}\n")
                        
                except Exception as e:
                    print(f"\n[+] OS Detection Error: {e}")

            if self.args.script:
                from LSSE import lsse_og
                from LSSE.lsse_og import sscripts, dscripts
                try:
                    if self.args.script in dscripts:
                        print(f"\n[+] LSSE Response for {self.args.url or self.args.domain}: ")
                    else:
                        self.script_port_parse()
                        if self.args.script in sscripts:
                            print(f"\n[+] LSSE Response for {self.args.starget}: ")
                        else:
                            print(f"\n[+] LSSE Response for {self.args.domain}: ")

                    lsse_og.Lsse.script_list(
                        self.args.script,
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
                        passwordlist=self.args.passwordlist
                    )
                    print(f"\n[+] LSSE run successfully\n")
                except Exception as e:
                    print(f"\n{red}[+] Script Error with {self.args.script} : {e}{reset}")

        print(f"\n[+] Lightscan scanned {len(self.targetss)} target(s) successfully\n")

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

        if self.args.daemon:
            self.daemon()
            return

        if self.args.save:
            current = time.localtime()
            filename = f"Lightscan_Output_{time.strftime('%Y-%m-%d_%H-%M-%S', current)}.{self.args.save.lower()}"
            import sys
            from io import StringIO
            self.capture_buffer = StringIO()
            self.old_stdout = sys.stdout
            sys.stdout = self.capture_buffer

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

        if self.args.version:
            import sys
            VersionManager.show_banner()
            sys.exit(0)

        if self.args.ttl:
            self.ver_ttl(self.args.ttl)
        if self.args.hlim:
            self.ver_hlim(self.args.hlim)
        if self.args.ip_flags:
            self.ver_ip_flags(self.args.ip_flags)
        if self.args.id:
            self.ver_ip_id(self.args.id)

        if self.args.rff:
            self.rff(self.args.rff)
        if self.args.load_profile:
            self.load_profile(self.args.load_profile)
        if self.args.save_profile:
            self.save_profile(self.args.save_profile)

        if self.args.quiet:
            print()
        else:
            self.Banner()
        if self.args.profiles_lst:
            self.list_profiles()
            sys.exit(0)
        if self.args.lsse_lst:
            print(f"""
{green}[+] LSSE Scripts (LightScan Scripting Engine){reset}
{'-' * 50}

{yellow}[1] spider{reset}
    Required:   --url
    Optional:   --mxd, --mxp
    Category:   safe/discovery/http_https
    Description: Recursively crawls websites for links, forms, and resources

{yellow}[2] http-robots{reset}
    Required:   --domain, -sp
    Optional:   None
    Category:   safe/discovery/http_https
    Description: Fetches and parses robots.txt for hidden paths

{yellow}[3] http-cert{reset}
    Required:   --domain, -sp
    Optional:   None
    Category:   safe/analysis/https
    Description: Grabs SSL/TLS certificate information

{yellow}[4] script{reset}
    Required:   --url
    Optional:   None
    Category:   safe/discovery/http_https
    Description: Detects Script tags in HTML pages

{yellow}[5] http-title{reset}
    Required:   --domain, -sp
    Optional:   --redirect
    Category:   safe/discovery/http_https
    Description: Extracts webpage titles

{yellow}[6] http-dir{reset}
    Required:   --url
    Optional:   --wordlist, --status-codes, --extensions
    Category:   medium/discovery/http_https
    Description: Brute forces directories and files

{yellow}[7] dns-subdomain-fuzzing{reset}
    Required:   --domain
    Optional:   --wordlist, --dns-server
    Category:   medium/discovery/dns
    Description: Brute forces subdomains using wordlist

{yellow}[8] dns-lookup{reset}
    Required:   --domain
    Optional:   --dns-server
    Category:   safe/discovery/dns
    Description: Do fast dns-lookup for IPv4 ,IPv6 address

{yellow}[9] dns-ns{reset}
    Required:   --domain
    Optional:   --dns-server
    Category:   safe/discovery/dns
    Description: Get Name-Server (NS) Record of a domain

{yellow}[10] dns-zone-transfer{reset}
    Required:   --domain
    Optional:   --dns-server
    Category:   medium/extracting/dns
    Description: Attempts AXFR zone transfer to enumerate all DNS records

{yellow}[11] http-headers{reset}
    Required:   --domain, -sp
    Optional:   --redirect
    Category:   safe/analysis/http_https
    Description: Fetches HTTP headers and checks for missing security headers

{yellow}[12] http-methods{reset}
    Required:   --domain, -sp
    Optional:   None
    Category:   safe/discovery/http_https
    Description: Checks which HTTP methods are allowed by the server

{yellow}[13] http-cookie{reset}
    Required:   --domain , -sp
    Optional:   --redirect
    Category:   safe/analysis/http_https
    Description: Checks cookies for Secure and HttpOnly flags

{yellow}[14] firewall-detection{reset}
    Required:   --starget , -sp
    Optional:   None
    Category:   medium/analysis/firewall
    Description: firewall detection using multiple probe techniques on a single port

{yellow}[15] ssh-auth-methods{reset}
    Required:   --starget , -sp
    Optional:   None
    Category:   safe/extracting/ssh
    Description: enumerates ssh authentication methods with detailed analysis

{yellow}[16] whois-domain{reset}
    Required:   --domain
    Optional:   None
    Category:   safe/discovery/dns
    Description: Gathers domain registration information via WHOIS

{yellow}[17] http-past-pages{reset}
    Required:   --domain
    Optional:   None
    Category:   safe/discovery/http_https
    Description: Check Wayback Machine for historical page changes

{yellow}[18] ssh-brute{reset}
    Required:   --starget, -sp
    Optional:   --userlist, --username, --password, --passwordlist
    Category:   medium/discovery/ssh
    Description: run a ssh brute-force to guess correct login credentials 

{'-' * 50}
{green}[+] Usage: Lightscan --lsse --script <name> {reset}
        """)
            import sys
            sys.exit(0)

        if self.args.lsse:
            from LSSE import lsse_og
            from LSSE.lsse_og import sscripts, dscripts
            try:
                if self.args.script in dscripts:
                    print(f"\n[+] LSSE Response for {self.args.domain}: ")
                else:
                    self.script_port_parse()
                    if self.args.script in sscripts:
                        print(f"\n[+] LSSE Response for {self.args.starget}: ")

                    else:
                        print(f"\n[+] LSSE Response for {self.args.domain}: ")
                lsse_og.Lsse.script_list(self.args.script,t=self.args.starget, ports=self.lsse_ports_to_scan,redirect=self.args.redirect,domain=self.args.domain,dns=self.args.dns_server,wordlist=self.args.wordlist,url=self.args.url,
                                          max_pages=self.args.mxp,max_depth=self.args.mxd,extensions=self.args.extensions,
                                      status_codes=self.args.status_codes,
                                      user=self.args.username,
                                      userlist=self.args.userlist,
                                      password=self.args.password,
                                      passwordlist=self.args.passwordlist)
                print(f"\n[+] LSSE run successfully\n")
            except Exception as e:
                print(f"\n{red}[+] Script Error with {self.args.script} : {e}{reset}")

        else:
            self.agressive_scan_config()
            if self.args.os:
                if self.args.banner:
                    pass
                if self.args.recursively:
                    pass
                if self.args.banner == False and self.args.recursively == False:
                    print(f"\n{yellow}[!] OS Fingerprint need banner grabbing (-b,--banner){reset}\n")
                    exit(1)

            if self.args.icmp_solicitation_ping:
                try:
                    self.host_discovery_4()
                    exit(0)
                except Exception as e:
                    print(f"{red}[!] Error while ICMP Solicitation <skip>{reset}\n")
                    exit(0)
            elif self.args.igmp_ping:
                try:
                    self.igmp_host_discovery()
                    exit(0)
                except Exception as e:
                    print(f"{red}[!] Error while IGMP Ping <skip>{reset}\n")
                    exit(0)

            self.target_parse()
            if self.args.lst:
                print()
                self.list_targets()
                print()
                exit(0)
            self.configure_speed()
            self.port_parse()
            if self.args.ping_port:
                self.ping_port_parse()
            self.check_network_config()

            if len(self.targets) > 1:
                self.show_network_info()

            for target in self.targets:
                self.initialize_target_results(target)

            self.version = 4

            if self.args.V6:
                self.version = 6
            else:
                self.version = 4

            if self.args.scan_type == "PING":
                if self.version == 4:
                    self.threaded_host_discovery()
                    self.threded_Tcp_host_discovery()
                    Payloads.threaded_ack_ping(self.max_threads, self.targets, self.args.ping_port, self.pp,
                                               self.target_results, self.socket_timeout, self.targetss,
                                               self.args.verbose, len(self.targets), self.version, self.args.ttl,
                                               self.args.hlim, self.args.sport, self.args.id, self.args.ip_flags)
                    self.threaded_host_discovery_1()
                    self.threded_Syn_host_discovery()
                else:
                    self.threaded_host_discovery_ipv6()
                    self.threded_Tcp_host_discovery()
                    Payloads.threaded_ack_ping(self.max_threads, self.targets, self.args.ping_port, self.pp,
                                               self.target_results, self.socket_timeout, self.targetss,
                                               self.args.verbose, len(self.targets), self.version, self.args.ttl,
                                               self.args.hlim, self.args.sport, self.args.id, self.args.ip_flags)
                    self.threded_Syn_host_discovery()
                print(f"\n[+] Lightscan Ping scan finnish successfully\n")
                exit(0)

            if self.args.no_ping:
                if self.args.verbose:
                    if self.args.recursively:
                        print(f"\n{yellow}[!] Skipping flag -Pn because flag -Rc is active {reset}")
                        try:
                            self.threaded_host_discovery()
                        except:
                            self.threded_Tcp_host_discovery()
                    else:
                        print(f"\n{yellow}[!] Disabeling Host discovery{reset}")
                        self.targetss = self.targets
                else:
                    if self.args.recursively:
                        try:
                            self.threaded_host_discovery()
                        except:
                            self.threded_Tcp_host_discovery()
                    else:
                        self.targetss = self.targets
            else:
                if self.args.tcp_ping:
                    try:
                        self.threded_Tcp_host_discovery()
                    except:
                        print(f"\n{red}[!] Error while TCP Ping <skip>{reset}\n")
                elif self.args.ack_ping:
                    try:
                        Payloads.threaded_ack_ping(self.max_threads,self.targets,self.args.ping_port,self.pp,self.target_results,self.socket_timeout,self.targetss,self.args.verbose,len(self.targets),self.version,self.args.ttl,self.args.hlim,self.args.sport,self.args.id,self.args.ip_flags)
                    except:
                        print(f"\n{red}[!] Error while ACK Ping <skip>{reset}\n")
                elif self.args.udp_ping:
                    try:
                        self.threded_Udp_host_discovery()
                    except:
                        print(f"\n{red}[!] Error while UDP Ping <skip>{reset}\n")

                elif self.args.icmp_timestamp_ping:
                    try:
                        self.threaded_host_discovery_1()
                    except:
                        print(f"\n{red}[!] Error while ICMP Timestap Ping <skip>{reset}\n")
                elif self.args.icmp_information_ping:
                    try:
                        self.threaded_host_discovery_3()
                    except:
                        print(f"\n{red}[!] Error while ICMP Information Ping <skip>{reset}\n")
                elif self.args.icmp_address_ping:
                    try:
                        self.threaded_host_discovery_2()
                    except:
                        print(f"\n{red}[!] Error while ICMP Address Ping <skip>{reset}\n")
                elif self.args.syn_ping:
                    try:
                        self.threded_Syn_host_discovery()
                    except:
                        print(f"\n{red}[!] Error while SYN Ping <skip>{reset}\n")
                elif self.args.local_ping:
                    try:
                        if self.args.V6:
                            Payloads.threaded_ndp_scan(self.max_threads, self.targets ,self.args.verbose,self.targetss,len(self.targets))
                        else:
                            Payloads.threaded_arp_scan(self.max_threads, self.targets ,self.args.verbose,self.targetss,len(self.targets))
                    except Exception as e:
                        print(f"{red}[!] ARP/NDP Ping error: {e}{reset}")
                elif self.args.ip_ping:
                    try:
                        self.ip_ping_protocols()
                        Payloads.threaded_ip_ping(self.max_threads,self.args.verbose,self.socket_timeout,self.targets,self.targetss,self.protocols,self.target_results,self.args.ttl,self.args.hlim,self.args.id,self.args.ip_flags,self.args.V6)
                    except Exception as e:
                        print(f"\n{red}[!] IP Ping Error <skip>{e}{reset}\n")
                else:
                    try:
                        if self.args.V6:
                            self.threaded_host_discovery_ipv6()
                        else:
                            self.threaded_host_discovery()
                    except:
                        print(f"\n{red}[!] Error while ICMP Ping <skip>{reset}\n")

            if self.args.sn:
                print(f"\n[+] Lightscan Host Discovery did finnish successfully\n")
                exit(0)

            for target in self.targetss:
                self.initialize_target_results(target)

            if self.args.scan_type == "TCP":
                self.threaded_tcp_3_ways_handshake()
            elif self.args.scan_type == "SYN":
                self.threaded_tcp_syn_scan()
            elif self.args.scan_type == "NULL":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "null"
                Payloads.threaded_null_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection,self.version,self.args.ttl,self.args.hlim,self.args.sport,self.args.payload,self.args.id,self.args.ip_flags)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "IPPROTO":
                self.Proto = "ip"
                self.scan_type = "ipproto"
                if not self.args.Pip:
                    self.protocols = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255]
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
                    flags=self.args.ip_flags
                )
                self.end_time = time.perf_counter()
            elif self.args.scan_type == 'FTP-BOUNCE':
                if not self.args.ftp_server:
                    print("[!] FTP Bounce scan requires --ftp-bounce <server>")
                    sys.exit(1)
                self.start_time = time.perf_counter()

                Payloads.FTPBounceScan(
                    target=self.args.target,
                    ftpserver=self.args.ftp_server,
                    ftp_port=21,
                    port_range=self.ports_to_scan,
                    max_retries=self.args.max_retries if self.args.max_retries else 2,
                    verbose=self.args.verbose,
                    socket_timeout=self.args.timeout if self.args.timeout else 5,
                    lock=self.lock,
                    target_results=self.target_results,
                    initialize_target_results=self.initialize_target_results,
                    service_detection=self.service_detection,
                    version=6 if self.args.V6 else 4
                )
                self.end_time = time.perf_counter()

            elif self.args.scan_type == "IDLE":
                zombie_ips = []
                if self.args.zombie:
                    if "," in self.args.zombie:
                        zombie_ips = [z.strip() for z in self.args.zombie.split(",") if z.strip()]
                    else:
                        zombie_ips = [self.args.zombie]

                if not zombie_ips:
                    print(f"{red}[!] Idle scan requires --zombie <IP>{reset}")
                    print(f"{yellow}[!] Example: Lightscan -T scanme.nmap.org --zombie 192.168.1.100 -st IDLE{reset}")
                    print(f"{yellow}[!] Multiple zombies: --zombie 192.168.1.100,192.168.1.101,192.168.1.102{reset}")
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
                    flags=self.args.ip_flags
                )

                self.end_time = time.perf_counter()
            elif self.args.scan_type == "SCTP-INIT":
                self.start_time = time.perf_counter()
                self.Proto = "sctp"
                self.scan_type = "init"
                Payloads.threaded_sctp_init_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection,self.version,self.args.ttl,self.args.hlim,self.args.sport,self.args.payload,self.args.id,self.args.ip_flags)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "FIN":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "fin"
                Payloads.threaded_fin_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection,self.version,self.args.ttl,self.args.hlim,self.args.sport,self.args.payload,self.args.id,self.args.ip_flags)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "ACK":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "ack"
                Payloads.threaded_ack_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection,self.version,self.args.ttl,self.args.hlim,self.args.sport,self.args.payload,self.args.id,self.args.ip_flags)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "WINDOW":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "window"
                Payloads.threaded_window_scan(self.args.max_retries, self.lock, self.args.verbose, self.args.fragmente,
                                            self.args.recursively, self.socket_timeout, self.target_results,
                                            self.args.banner, self.max_threads, self.targetss, self.ports_to_scan,
                                            self.initialize_target_results, self.service_detection,self.version,self.args.ttl,self.args.hlim,self.args.sport,self.args.payload,self.args.id,self.args.ip_flags)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "XMAS":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "xmas"
                Payloads.threaded_xmas_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection,self.version,self.args.ttl,self.args.hlim,self.args.sport,self.args.payload,self.args.id,self.args.ip_flags)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "MAIMON":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "maimon"
                Payloads.threaded_maimon_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection,self.version,self.args.ttl,self.args.hlim,self.args.sport,self.args.payload,self.args.id,self.args.ip_flags)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "FDD":
                self.start_time = time.perf_counter()
                self.Proto = "tcp"
                self.scan_type = "fdd"
                Payloads.threaded_fdd_scan(self.args.max_retries,self.lock,self.args.verbose,self.args.fragmente,self.args.recursively,self.socket_timeout,self.target_results,self.args.banner,self.max_threads,self.targetss,self.ports_to_scan,self.initialize_target_results,self.service_detection,self.version,self.args.ttl,self.args.hlim,self.args.sport,self.args.payload,self.args.id,self.args.ip_flags)
                self.end_time = time.perf_counter()
            elif self.args.scan_type == "UDP":
                self.threaded_udp_scan()
            else:
                self.threaded_tcp_3_ways_handshake()
            self.EE = time.perf_counter()
            self.Scan_details()


            if self.args.save:
                sys.stdout = self.old_stdout
                output = self.capture_buffer.getvalue()
                from LightSave import main
                main(filename,self.args.save,output)

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
