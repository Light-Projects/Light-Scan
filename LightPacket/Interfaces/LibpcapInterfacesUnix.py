# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
LightPacket BSD/Unix/MacOS Simple Interface Enumeration
Minimal IPv4 + IPv6 support using system APIs
"""

import socket
import subprocess
import re
import sys
from typing import Dict, List, Optional, Any
from .UnixInterfaces import get_interface_mac_bsd

IS_MACOS = sys.platform == 'darwin'
IS_BSD = sys.platform.startswith('freebsd') or sys.platform.startswith('openbsd') or sys.platform.startswith('netbsd') or sys.platform.startswith('dragonfly')


try:
    import netifaces
except ImportError:
    netifaces = None


class NetworkInterfaces:

    def __init__(self):
        self._interfaces = {}
        self._load_interfaces()

    def _load_interfaces(self):
        try:
            if netifaces:
                self._load_netifaces()
            else:
                self._load_ifconfig()
        except Exception as e:
            print(f"Error loading interfaces: {e}")

    def _load_netifaces(self):
        for interface in netifaces.interfaces():
            if interface.startswith('lo'):
                continue

            addrs = netifaces.ifaddresses(interface)
            ips_v4 = []
            ips_v6 = []

            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr and not addr['addr'].startswith('127.'):
                        ips_v4.append(addr['addr'])

            if netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    if 'addr' in addr:
                        ip = addr['addr']
                        if not ip.startswith('fe80::'):
                            ips_v6.append(ip)

            self._interfaces[interface] = {
                'name': interface,
                'ips_v4': ips_v4,
                'ips_v6': ips_v6,
                'ips': ips_v4 + ips_v6,
            }

    def _load_ifconfig(self):
        try:
            cmd = ['ifconfig']
            if IS_MACOS:
                cmd.append('-a')

            output = subprocess.check_output(cmd, text=True)

            current_interface = None
            ips_v4 = []
            ips_v6 = []

            for line in output.splitlines():
                match_iface = re.search(r'^(\S+):\s+flags=', line)
                if match_iface:
                    if current_interface:
                        self._interfaces[current_interface] = {
                            'name': current_interface,
                            'ips_v4': ips_v4,
                            'ips_v6': ips_v6,
                            'ips': ips_v4 + ips_v6,
                        }

                    current_interface = match_iface.group(1)
                    ips_v4 = []
                    ips_v6 = []
                    continue

                if current_interface and current_interface.startswith('lo'):
                    continue

                if current_interface:
                    match_v4 = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if match_v4:
                        ip = match_v4.group(1)
                        if not ip.startswith('127.'):
                            ips_v4.append(ip)

                    match_v6 = re.search(r'inet6\s+([0-9a-f:]+)', line, re.IGNORECASE)
                    if match_v6:
                        ip = match_v6.group(1)
                        if not ip.startswith('fe80::'):
                            ips_v6.append(ip)

            if current_interface and not current_interface.startswith('lo'):
                self._interfaces[current_interface] = {
                    'name': current_interface,
                    'ips_v4': ips_v4,
                    'ips_v6': ips_v6,
                    'ips': ips_v4 + ips_v6,
                }

        except Exception as e:
            print(f"Error with ifconfig: {e}")

    def default_interface(self) -> Optional[Dict[str, Any]]:
        try:
            if netifaces:
                gateways = netifaces.gateways()
                default_route = gateways.get('default', {})

                if netifaces.AF_INET in default_route:
                    interface = default_route[netifaces.AF_INET][1]
                    return self._interfaces.get(interface)

                if netifaces.AF_INET6 in default_route:
                    interface = default_route[netifaces.AF_INET6][1]
                    return self._interfaces.get(interface)

            else:
                cmd = ['route', '-n', 'get', 'default']
                output = subprocess.check_output(cmd, text=True)
                match = re.search(r'interface:\s+(\S+)', output)
                if match:
                    interface = match.group(1)
                    return self._interfaces.get(interface)
        except Exception:
            pass
        return None

    def get_by_index(self, index: int) -> Optional[Dict[str, Any]]:
        for iface in self._interfaces.values():
            if iface.get('index') == index:
                return iface
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

    def __contains__(self, key):
        return key in self._interfaces

    def __len__(self):
        return len(self._interfaces)

    def __iter__(self):
        return iter(self._interfaces)

    def show(self):
        print("\n=== BSD/Unix/MacOS Available Interfaces ===\n")
        for name, iface in self._interfaces.items():
            print(f"Name: {name}")
            print(f"  IPv4: {', '.join(iface.get('ips_v4', [])) or 'N/A'}")
            print(f"  IPv6: {', '.join(iface.get('ips_v6', [])) or 'N/A'}")
            print(f"  MAC : {get_interface_mac_bsd(iface.get('name', [])) or 'N/A'}")
            print()

    def __repr__(self):
        lines = []
        lines.append("+-" + "-" * 4 + "-+" + "-" * 53 + "--+" + "-" * 30 + "--+")
        lines.append(f"| {'Name':<40} | {'IPv4 Addresses    |  Mac Addresses':<50} |")
        lines.append("+-" + "-" * 4 + "-+" + "-" * 53 + "--+" + "-" * 30 + "--+")

        for name, iface in self._interfaces.items():
            name_short = name[:40]
            ips = ', '.join(iface.get('ips_v4', [])) or 'None'
            mac = get_interface_mac_bsd(iface.get('name', [])) or 'N/A'
            lines.append(f"| {name_short:<40} | {ips:<18} {mac:<19}             |")

        lines.append("+-" + "-" * 4 + "-+" + "-" * 60 + "---" + "-" * 25 + "+")
        return "\n".join(lines)


def get_bsd_simple_interfaces() -> NetworkInterfaces:
    return NetworkInterfaces()

def get_bsd_simple_interface_names() -> List[str]:
    interfaces = NetworkInterfaces()
    return list(interfaces.keys())


def get_bsd_simple_default_interface() -> Optional[Dict[str, Any]]:
    interfaces = NetworkInterfaces()
    return interfaces.default_interface()