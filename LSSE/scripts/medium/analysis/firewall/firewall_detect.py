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
Script Name : firewall-detection
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --starget
----> -sp
Categorie : medium/analysis/firewall
"""

import time
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP


class FirewallDetect:
    def __init__(self, target, port):
        self.target = target
        self.port = port
        self.results = {
            'firewall_detected': False,
            'firewall_type': None,
            'fdd': False,
            'filtering_behavior': None,
            'detection_methods': []
        }
        self.probes = []

    def tcp_flag_probe(self):
        flags = ['F', '', 'FPU', 'A']
        responses = {}

        for flag in flags:
            pkt = IP(dst=self.target) / TCP(dport=self.port, flags=flag)
            reply = sr1(pkt, timeout=2, verbose=False)
            responses[flag] = reply

        return responses

    def fdd_scan_probe(self):
        flag = 'U'

        pkt = IP(dst=self.target) / TCP(dport=self.port, flags=flag)
        reply = sr1(pkt, timeout=2, verbose=False)
        responses = reply

        return responses

    def icmp_probe(self):
        pkt = IP(dst=self.target) / ICMP(type=8)
        reply = sr1(pkt, timeout=2, verbose=False)

        pkt2 = IP(dst=self.target) / ICMP(type=13)
        reply2 = sr1(pkt2, timeout=2, verbose=False)

        return {'echo': reply, 'timestamp': reply2}

    def ttl_probe(self):
        ttl_values = [1, 2, 4, 8, 16, 32, 64, 128]
        responses = {}

        for ttl in ttl_values:
            pkt = IP(dst=self.target, ttl=ttl) / TCP(dport=self.port, flags='S')
            reply = sr1(pkt, timeout=1, verbose=False)
            responses[ttl] = reply

        return responses

    def fragmentation_probe(self):
        pkt1 = IP(dst=self.target, flags='MF') / TCP(dport=self.port, flags='S')
        pkt2 = IP(dst=self.target) / TCP(dport=self.port, flags='S')

        send(pkt1, verbose=False)
        time.sleep(0.1)
        reply = sr1(pkt2, timeout=2, verbose=False)

        return reply

    def timing_analysis(self):
        timings = []

        for i in range(10):
            start = time.time()
            pkt = IP(dst=self.target) / TCP(dport=self.port, flags='S')
            reply = sr1(pkt, timeout=2, verbose=False)
            elapsed = time.time() - start
            timings.append(elapsed)

        avg_time = sum(timings) / len(timings)

        return avg_time

    def run(self):
        results = {
            'tcp_flags': self.tcp_flag_probe(),
            'icmp': self.icmp_probe(),
            'ttl': self.ttl_probe(),
            'fragmentation': self.fragmentation_probe(),
            'timing': self.timing_analysis(),
            'fdd': self.fdd_scan_probe()
        }

        self.analyze_results(results)

        return self.results

    def analyze_results(self, results):
        tcp_flags = results['tcp_flags']
        fdd = results['fdd']
        icmp = results['icmp']
        timing = results['timing']

        if all(flags is None for flags in tcp_flags.values()):
            self.results['firewall_detected'] = True
            self.results['firewall_type'] = 'Stateful Firewall'
            self.results['filtering_behavior'] = 'Drop all '

        elif any(flags is None for flags in tcp_flags.values()):
            self.results['firewall_detected'] = True
            self.results['firewall_type'] = 'Stateless Firewall'
            self.results['filtering_behavior'] = 'Selective filtering'

        elif all(flags is not None for flags in tcp_flags.values()):
            self.results['firewall_detected'] = False
            self.results['firewall_type'] = 'No Firewall'
            self.results['filtering_behavior'] = 'Direct host access'

        if icmp['echo'] is None and icmp['timestamp'] is None:
            self.results['icmp_behavior'] = 'Blocked'
        else:
            self.results['icmp_behavior'] = 'Allowed'

        if timing > 0.5:
            self.results['inspection'] = 'Deep Packet Inspection detected'
        elif timing > 0.2:
            self.results['inspection'] = 'Moderate inspection'
        else:
            self.results['inspection'] = 'Minimal inspection'

        if fdd is None:
            self.results['fdd'] = True

        self.classify_firewall()

    def classify_firewall(self):
        if self.results['firewall_detected']:
            if self.results['icmp_behavior'] == 'Blocked':
                self.results['firewall_type'] += ' (Strict)'
            elif self.results['inspection'] == 'Deep Packet Inspection detected':
                self.results['firewall_type'] += ' (IDS/IPS Enabled)'

        self.results['detection_methods'] = [
            'TCP Flag Analysis',
            'ICMP Probe',
            'TTL Manipulation',
            'Fragmentation Test',
            'Timing Analysis',
            'FDD Scan'
        ]

def main(target, port):
    detector = FirewallDetect(target, port)
    results = detector.run()

    print(f"\n[+] Firewall Detection Results for {target}:{port}\n")
    print(f"    Firewall Detected: {results['firewall_detected']}")
    print(f"    FDD Scan Detection: {results.get('fdd', 'Unknown')}")
    print(f"    Type: {results.get('firewall_type', 'Unknown')}")
    print(f"    Filtering: {results.get('filtering_behavior', 'Unknown')}")
    print(f"    ICMP Behavior: {results.get('icmp_behavior', 'Unknown')}")
    print(f"    Inspection: {results.get('inspection', 'Unknown')}")
    print(f"    Methods Used: {', '.join(results.get('detection_methods', []))}")