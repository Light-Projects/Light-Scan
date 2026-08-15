# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
LightPacket BSD/Unix/MacOS Interface Enumeration using libpcap
Full IPv4 + IPv6 support using system APIs
"""

import ctypes
from ctypes import c_char_p, c_void_p, c_int, POINTER, Structure, byref
import socket
import struct
import subprocess
import re
import os
import sys
from typing import Dict, List, Optional, Any

IS_MACOS = sys.platform == 'darwin'
IS_BSD = sys.platform.startswith('freebsd') or sys.platform.startswith('openbsd') or sys.platform.startswith('netbsd')

try:
    if IS_MACOS:
        pcap = ctypes.CDLL("/usr/lib/libpcap.dylib")
    elif IS_BSD:
        pcap = ctypes.CDLL("libpcap.so")
    else:
        pcap = ctypes.CDLL("libpcap.so.1")
except OSError:
    try:
        pcap = ctypes.CDLL("libpcap.so")
    except OSError:
        raise RuntimeError("libpcap not found. Install libpcap")

PCAP_ERRBUF_SIZE = 256


class pcap_if(Structure):
    pass


class pcap_addr(Structure):
    pass


pcap_if._fields_ = [
    ('next', POINTER(pcap_if)),
    ('name', c_char_p),
    ('description', c_char_p),
    ('addresses', POINTER(pcap_addr)),
    ('flags', c_int)
]

pcap_addr._fields_ = [
    ('next', POINTER(pcap_addr)),
    ('addr', c_void_p),
    ('netmask', c_void_p),
    ('broadaddr', c_void_p),
    ('dstaddr', c_void_p)
]

pcap.pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
pcap.pcap_findalldevs.restype = c_int

pcap.pcap_freealldevs.argtypes = [POINTER(pcap_if)]
pcap.pcap_freealldevs.restype = None


class sockaddr_in(Structure):
    _fields_ = [
        ('sin_family', ctypes.c_ushort),
        ('sin_port', ctypes.c_ushort),
        ('sin_addr', ctypes.c_uint32),
        ('sin_zero', ctypes.c_char * 8)
    ]


class sockaddr_in6(Structure):
    _fields_ = [
        ('sin6_family', ctypes.c_ushort),
        ('sin6_port', ctypes.c_ushort),
        ('sin6_flowinfo', ctypes.c_uint32),
        ('sin6_addr', ctypes.c_byte * 16),
        ('sin6_scope_id', ctypes.c_uint32)
    ]


def get_libpcap_devices_bsd() -> List[Dict[str, str]]:
    errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    devices_pointer = POINTER(pcap_if)()

    result = pcap.pcap_findalldevs(byref(devices_pointer), errbuf)

    if result != 0:
        print(f"Error: {errbuf.value.decode()}")
        return []

    dev_list = []
    dev = devices_pointer

    while dev:
        name = dev.contents.name.decode() if dev.contents.name else ""
        desc = dev.contents.description.decode() if dev.contents.description else ""

        addresses = []
        addr = dev.contents.addresses
        while addr:
            addr_struct = ctypes.cast(addr, POINTER(pcap_addr)).contents
            if addr_struct.addr:
                sockaddr = ctypes.cast(addr_struct.addr, POINTER(ctypes.c_ushort))
                family = sockaddr.contents.value

                if family == socket.AF_INET:
                    sin = ctypes.cast(addr_struct.addr, POINTER(sockaddr_in)).contents
                    ip_bytes = struct.pack('I', sin.sin_addr)
                    ip_str = socket.inet_ntop(socket.AF_INET, ip_bytes)
                    addresses.append(ip_str)
                elif family == socket.AF_INET6:
                    sin6 = ctypes.cast(addr_struct.addr, POINTER(sockaddr_in6)).contents
                    ip_bytes = bytes(sin6.sin6_addr)[:16]
                    ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)
                    if sin6.sin6_scope_id:
                        ip_str = f"{ip_str}%{sin6.sin6_scope_id}"
                    addresses.append(ip_str)

            addr = addr_struct.next

        dev_list.append({
            "name": name,
            "description": desc,
            "addresses": addresses
        })
        dev = dev.contents.next

    pcap.pcap_freealldevs(devices_pointer)
    return dev_list


def get_interface_mac_bsd(interface_name: str) -> str:
    try:
        if IS_MACOS:
            cmd = ['ifconfig', interface_name]
            output = subprocess.check_output(cmd, text=True)
            match = re.search(r'ether\s+([0-9a-f:]+)', output, re.IGNORECASE)
            if match:
                return match.group(1)
        elif IS_BSD:
            cmd = ['ifconfig', interface_name]
            output = subprocess.check_output(cmd, text=True)
            match = re.search(r'ether\s+([0-9a-f:]+)', output, re.IGNORECASE)
            if match:
                return match.group(1)
        else:
            cmd = ['ifconfig', interface_name]
            output = subprocess.check_output(cmd, text=True)
            match = re.search(r'ether\s+([0-9a-f:]+)', output, re.IGNORECASE)
            if match:
                return match.group(1)


    except Exception:
        pass
    return ""


def get_interface_ipv4_addresses_bsd(interface_name: str) -> List[str]:
    try:
        if IS_MACOS or IS_BSD:
            cmd = ['ifconfig', interface_name]
            output = subprocess.check_output(cmd, text=True)
            ips = []
            matches = re.findall(r'inet\s+(\d+\.\d+\.\d+\.\d+)', output)
            ips.extend(matches)
            return ips
        else:
            cmd = ['ip', '-4', 'addr', 'show', interface_name]
            output = subprocess.check_output(cmd, text=True)
            ips = []
            for line in output.splitlines():
                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/\d+', line)
                if match:
                    ips.append(match.group(1))
            return ips
    except Exception:
        return []


def get_interface_ipv6_addresses_bsd(interface_name: str) -> List[str]:
    try:
        if IS_MACOS or IS_BSD:
            cmd = ['ifconfig', interface_name]
            output = subprocess.check_output(cmd, text=True)
            ips = []
            matches = re.findall(r'inet6\s+([0-9a-f:]+)', output, re.IGNORECASE)
            ips.extend(matches)
            return ips
        else:
            cmd = ['ip', '-6', 'addr', 'show', interface_name]
            output = subprocess.check_output(cmd, text=True)
            ips = []
            for line in output.splitlines():
                match = re.search(r'inet6\s+([0-9a-f:]+)/\d+', line, re.IGNORECASE)
                if match:
                    ips.append(match.group(1))
            return ips
    except Exception:
        return []


def get_default_interface_bsd() -> Optional[Dict[str, Any]]:
    try:
        if IS_MACOS:
            cmd = ['route', '-n', 'get', 'default']
            output = subprocess.check_output(cmd, text=True)
            match = re.search(r'interface:\s+(\S+)', output)
            if match:
                interface = match.group(1)
                return get_interface_info_bsd(interface)
        elif IS_BSD:
            cmd = ['route', '-n', 'get', 'default']
            output = subprocess.check_output(cmd, text=True)
            match = re.search(r'interface:\s+(\S+)', output)
            if match:
                interface = match.group(1)
                return get_interface_info_bsd(interface)

        cmd = ['netstat', '-rn']
        output = subprocess.check_output(cmd, text=True)
        lines = output.splitlines()
        for line in lines:
            if 'default' in line or '0.0.0.0' in line:
                parts = line.split()
                if len(parts) >= 4:
                    interface = parts[-1]
                    return get_interface_info_bsd(interface)
    except Exception:
        pass
    return None


def get_default_gateway_bsd() -> Optional[str]:
    try:
        if IS_MACOS or IS_BSD:
            cmd = ['route', '-n', 'get', 'default']
            output = subprocess.check_output(cmd, text=True)
            match = re.search(r'gateway:\s+(\S+)', output)
            if match:
                return match.group(1)

        cmd = ['netstat', '-rn']
        output = subprocess.check_output(cmd, text=True)
        lines = output.splitlines()
        for line in lines:
            if 'default' in line or '0.0.0.0' in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
    except Exception:
        pass
    return None


def get_interface_info_bsd(interface_name: str) -> Dict[str, Any]:
    mac = get_interface_mac_bsd(interface_name)
    ips_v4 = get_interface_ipv4_addresses_bsd(interface_name)
    ips_v6 = get_interface_ipv6_addresses_bsd(interface_name)

    index = -1
    try:
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
        libc.if_nametoindex.argtypes = [c_char_p]
        libc.if_nametoindex.restype = ctypes.c_uint
        idx = libc.if_nametoindex(interface_name.encode())
        if idx > 0:
            index = idx
    except Exception:
        pass

    description = interface_name
    try:
        if IS_MACOS:
            cmd = ['system_profiler', 'SPNetworkDataType']
            output = subprocess.check_output(cmd, text=True)
            cmd = ['ifconfig', interface_name]
            output = subprocess.check_output(cmd, text=True)
            for line in output.splitlines():
                if 'flags' in line and '(' in line:
                    desc = line.strip()
                    description = desc
                    break
    except Exception:
        pass

    return {
        'name': interface_name,
        'index': index,
        'mac': mac,
        'description': description,
        'ips_v4': ips_v4,
        'ips_v6': ips_v6,
        'ips': ips_v4 + ips_v6,
    }


def get_bsd_adapter_list() -> List[Dict[str, Any]]:
    adapters = []

    pcap_devices = get_libpcap_devices_bsd()

    for dev in pcap_devices:
        interface_name = dev['name']

        info = get_interface_info_bsd(interface_name)
        adapters.append(info)

    return adapters


def get_bsd_available_interfaces() -> Dict[str, Dict[str, Any]]:
    adapters = get_bsd_adapter_list()

    pcap_devices = get_libpcap_devices_bsd()

    pcap_by_name = {}
    for dev in pcap_devices:
        pcap_by_name[dev['name']] = dev

    active_adapters = {}
    for adapter in adapters:
        name = adapter['name']
        pcap_dev = pcap_by_name.get(name, {})

        info = {
            'pcap_name': name,
            'pcap_description': pcap_dev.get('description', ''),
            'name': name,
            'description': adapter.get('description', ''),
            'index': adapter.get('index', -1),
            'mac': adapter.get('mac', ''),
            'ips_v4': adapter.get('ips_v4', []),
            'ips_v6': adapter.get('ips_v6', []),
            'ips': adapter.get('ips', []),
        }

        active_adapters[name] = info

    return active_adapters


def get_bsd_available_interfaces_pretify() -> Dict[str, Dict[str, Any]]:
    interfaces = get_bsd_available_interfaces()

    print("\n" + "=" * 80)
    print("Available libpcap Interfaces (BSD/Unix/MacOS):")
    print("=" * 80)

    for name, info in interfaces.items():
        print(f"\n{name}")
        print(f"  Description: {info['description']}")
        print(f"  MAC:         {info['mac']}")
        print(f"  IPv4:        {', '.join(info['ips_v4']) or 'N/A'}")
        print(f"  IPv6:        {', '.join(info['ips_v6']) or 'N/A'}")
        print(f"  Index:       {info['index']}")

    return interfaces


def get_best_route_bsd(dest_ip: str) -> Optional[Dict[str, Any]]:
    try:
        is_ipv6 = ':' in dest_ip

        if IS_MACOS or IS_BSD:
            if is_ipv6:
                cmd = ['route', '-n', 'get', '-inet6', dest_ip]
            else:
                cmd = ['route', '-n', 'get', dest_ip]
        else:
            if is_ipv6:
                cmd = ['ip', '-6', 'route', 'get', dest_ip]
            else:
                cmd = ['ip', '-4', 'route', 'get', dest_ip]

        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

        result = {'destination': dest_ip}

        if 'route: not in table' in output:
            return None

        for line in output.splitlines():
            parts = line.strip().split()
            for i, part in enumerate(parts):
                if part == 'interface:' and i + 1 < len(parts):
                    result['interface'] = parts[i + 1]
                elif part == 'gateway:' and i + 1 < len(parts):
                    result['gateway'] = parts[i + 1]
                elif part == 'source:' and i + 1 < len(parts):
                    result['source_ip'] = parts[i + 1]

        if 'interface' in result:
            return result

    except Exception:
        pass

    return None


get_loopback_interface_name = lambda: "lo"