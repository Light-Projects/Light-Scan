# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
LightPacket Linux Interface Enumeration
Full IPv4 + IPv6 support using Linux APIs
"""

import socket
import subprocess
import re
from typing import Dict, List, Optional, Any

try:
    import netifaces
except ImportError:
    netifaces = None


class NetworkInterfaces:
    
    COLORS = {
        'green': '\033[92m',
        'blue': '\033[94m',
        'cyan': '\033[96m',
        'yellow': '\033[93m',
        'purple': '\033[95m',
        'red': '\033[91m',
        'reset': '\033[0m',
        'bold': '\033[1m',
    }
    
    def __init__(self):
        self._interfaces = {}
        self._load_interfaces()
    
    def _load_interfaces(self):
        try:
            if netifaces:
                self._load_interfaces_netifaces()
            else:
                self._load_interfaces_legacy()
        except Exception as e:
            print(f"Error loading interfaces: {e}")
    
    def _load_interfaces_netifaces(self):
        for interface in netifaces.interfaces():
            if interface.startswith('lo'):
                continue
            
            addrs = netifaces.ifaddresses(interface)
            
            ips_v4 = []
            ips_v6 = []
            
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr:
                        ips_v4.append(addr['addr'])
            
            if netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    if 'addr' in addr:
                        ips_v6.append(addr['addr'])
            
            mac = self._get_mac_netifaces(interface)
            
            index = self._get_index(interface)
            
            self._interfaces[interface] = {
                'name': interface,
                'index': index,
                'mac': mac,
                'description': interface,
                'ips_v4': ips_v4,
                'ips_v6': ips_v6,
                'ips': ips_v4 + ips_v6,
            }
    
    def _load_interfaces_legacy(self):
        try:
            cmd = ['ip', 'link', 'show']
            output = subprocess.check_output(cmd, text=True)
            
            for line in output.splitlines():
                match = re.search(r'^(\d+): (\S+):', line)
                if match:
                    index = int(match.group(1))
                    interface = match.group(2)
                    
                    ips_v4 = self._get_ipv4_addresses(interface)
                    ips_v6 = self._get_ipv6_addresses(interface)
                    
                    mac = self._get_mac(interface)
                    
                    self._interfaces[interface] = {
                        'name': interface,
                        'index': index,
                        'mac': mac,
                        'description': interface,
                        'ips_v4': ips_v4,
                        'ips_v6': ips_v6,
                        'ips': ips_v4 + ips_v6,
                    }
        except Exception as e:
            print(f"Error loading interfaces: {e}")
    
    def _get_ipv4_addresses(self, interface: str) -> List[str]:
        try:
            cmd = ['ip', '-4', 'addr', 'show', interface]
            output = subprocess.check_output(cmd, text=True)
            ips = []
            for line in output.splitlines():
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/\d+', line)
                if match:
                    ips.append(match.group(1))
            return ips
        except Exception:
            return []
    
    def _get_ipv6_addresses(self, interface: str) -> List[str]:
        try:
            cmd = ['ip', '-6', 'addr', 'show', interface]
            output = subprocess.check_output(cmd, text=True)
            ips = []
            for line in output.splitlines():
                match = re.search(r'inet6\s+([0-9a-f:]+)/\d+', line, re.IGNORECASE)
                if match:
                    ips.append(match.group(1))
            return ips
        except Exception:
            return []
    
    def _get_mac(self, interface: str) -> str:
        try:
            with open(f'/sys/class/net/{interface}/address', 'r') as f:
                return f.read().strip()
        except Exception:
            return ""
    
    def _get_mac_netifaces(self, interface: str) -> str:
        try:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_LINK in addrs:
                for addr in addrs[netifaces.AF_LINK]:
                    if 'addr' in addr:
                        return addr['addr']
        except Exception:
            pass
        return ""
    
    def _get_index(self, interface: str) -> int:
        try:
            with open(f'/sys/class/net/{interface}/ifindex', 'r') as f:
                return int(f.read().strip())
        except Exception:
            return -1
    
    def default_interface(self) -> Optional[Dict[str, Any]]:
        try:
            if netifaces:
                gateways = netifaces.gateways()
                default_route = gateways['default'].get(netifaces.AF_INET)
                if default_route:
                    interface = default_route[1]
                    return self._interfaces.get(interface)
            
            cmd = ['ip', 'route', 'show', 'default']
            output = subprocess.check_output(cmd, text=True)
            match = re.search(r'dev (\S+)', output)
            if match:
                interface = match.group(1)
                return self._interfaces.get(interface)
        except Exception:
            pass
        return None
    
    def values(self):
        return self._interfaces.values()
    
    def keys(self):
        return self._interfaces.keys()
    
    def items(self):
        return self._interfaces.items()
    
    def get(self, key, default=None):
        return self._interfaces.get(key, default)
    
    def __getitem__(self, key):
        return self._interfaces[key]
    
    def __setitem__(self, key, value):
        self._interfaces[key] = value
    
    def __contains__(self, key):
        return key in self._interfaces
    
    def __len__(self):
        return len(self._interfaces)
    
    def __iter__(self):
        return iter(self._interfaces)
    
    def show(self):
        C = self.COLORS
        
        print(f"\n{C['bold']}=== Linux Interface Details ==={C['reset']}\n")
        
        for name, iface in self._interfaces.items():
            print(f"{C['green']}Name:{C['reset']} {name}")
            print(f"  {C['blue']}Index:{C['reset']} {iface.get('index', -1)}")
            print(f"  {C['blue']}MAC:{C['reset']} {iface.get('mac', 'N/A')}")
            
            ips_v4 = iface.get('ips_v4', [])
            print(f"  {C['blue']}IPv4:{C['reset']} {', '.join(ips_v4) if ips_v4 else 'N/A'}")
            
            ips_v6 = iface.get('ips_v6', [])
            print(f"  {C['blue']}IPv6:{C['reset']} {', '.join(ips_v6) if ips_v6 else 'N/A'}")
            
            print(f"  {C['blue']}Description:{C['reset']} {iface.get('description', 'N/A')}")
            print()
    
    def __repr__(self):
        lines = []
        lines.append("+-" + "-" * 4 + "-+" + "-" * 100 + "--+" + "-" * 22 + "+")
        lines.append(f"| {'Idx':<4} | {'Name':<100} | {'MAC':<20} |")
        lines.append("+-" + "-" * 4 + "-+" + "-" * 100 + "--+" + "-" * 22 + "+")

        for iface in self._interfaces.values():
            name = iface['name'][:100]
            mac = iface.get('mac', 'N/A')
            lines.append(f"| {iface['index']:<4} | {name:<100} | {mac:<20} |")

        lines.append("+-" + "-" * 4 + "-+" + "-" * 100 + "--+" + "-" * 22 + "+")
        return "\n".join(lines)


class SimpleInterfaces:
    
    def __init__(self):
        self._interfaces = {}
        self._load_interfaces()
    
    def _load_interfaces(self):
        try:
            if netifaces:
                for interface in netifaces.interfaces():
                    if interface.startswith('lo'):
                        continue
                    addrs = netifaces.ifaddresses(interface)
                    ips_v4 = []
                    ips_v6 = []
                    
                    if netifaces.AF_INET in addrs:
                        for addr in addrs[netifaces.AF_INET]:
                            ips_v4.append(addr['addr'])
                    
                    if netifaces.AF_INET6 in addrs:
                        for addr in addrs[netifaces.AF_INET6]:
                            ips_v6.append(addr['addr'])
                    
                    self._interfaces[interface] = {
                        'name': interface,
                        'ips_v4': ips_v4,
                        'ips_v6': ips_v6,
                        'ips': ips_v4 + ips_v6,
                    }
            else:
                cmd = ['ip', '-4', 'addr', 'show']
                output = subprocess.check_output(cmd, text=True)
                
                current_interface = None
                for line in output.splitlines():
                    match_iface = re.search(r'^\d+: (\S+):', line)
                    if match_iface:
                        current_interface = match_iface.group(1)
                        if current_interface.startswith('lo'):
                            current_interface = None
                            continue
                        if current_interface not in self._interfaces:
                            self._interfaces[current_interface] = {
                                'name': current_interface,
                                'ips_v4': [],
                                'ips_v6': [],
                                'ips': [],
                            }
                    elif current_interface and 'inet ' in line:
                        match_ip = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/\d+', line)
                        if match_ip:
                            self._interfaces[current_interface]['ips_v4'].append(match_ip.group(1))
                            self._interfaces[current_interface]['ips'].append(match_ip.group(1))
        except Exception as e:
            print(f"Error: {e}")
    
    def values(self):
        return self._interfaces.values()
    
    def keys(self):
        return self._interfaces.keys()
    
    def items(self):
        return self._interfaces.items()
    
    def get(self, key, default=None):
        return self._interfaces.get(key, default)
    
    def __getitem__(self, key):
        return self._interfaces[key]
    
    def __contains__(self, key):
        return key in self._interfaces
    
    def __len__(self):
        return len(self._interfaces)
    
    def __iter__(self):
        return iter(self._interfaces)
    
    def show(self):
        print("\n=== Available Interfaces ===\n")
        for name, iface in self._interfaces.items():
            print(f"Name: {name}")
            print(f"  IPv4: {', '.join(iface.get('ips_v4', [])) or 'N/A'}")
            print(f"  IPv6: {', '.join(iface.get('ips_v6', [])) or 'N/A'}")
            print()
    
    def __repr__(self):
        lines = []
        lines.append("+-" + "-" * 4 + "-+" + "-" * 33 + "--+" + "-" * 30 + "--+")
        lines.append(f"| {'Name':<40} | {'IPv4 Addresses':<30} |")
        lines.append("+-" + "-" * 4 + "-+" + "-" * 33 + "--+" + "-" * 30 + "--+")
        
        for name, iface in self._interfaces.items():
            name_short = name[:40]
            ips = ', '.join(iface.get('ips_v4', [])) or 'None'
            lines.append(f"| {name_short:<40} | {ips:<30} |")
        
        lines.append("+-" + "-" * 4 + "-+" + "-" * 40 + "--+" + "-" * 25 + "+")
        return "\n".join(lines)
