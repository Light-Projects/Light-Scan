# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
LightPacket Linux Interface Enumeration using libpcap
Full IPv4 + IPv6 support using Linux system APIs
"""

import ctypes
from ctypes import c_char_p, c_void_p, c_int, POINTER, Structure, byref
import socket
from ..Layers.IPtoa import inet_ntoa
import struct
import subprocess
import re
from typing import Dict, List, Optional, Any

try:
    pcap = ctypes.CDLL("libpcap.so.1")
except OSError:
    try:
        pcap = ctypes.CDLL("libpcap.so")
    except OSError:
        raise RuntimeError("libpcap not found. Install libpcap-dev")

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

pcap.pcap_lookupdev.argtypes = [c_char_p]
pcap.pcap_lookupdev.restype = c_char_p

pcap.pcap_lookupnet.argtypes = [c_char_p, POINTER(c_int), POINTER(c_int), c_char_p]
pcap.pcap_lookupnet.restype = c_int


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


def get_libpcap_devices() -> List[Dict[str, str]]:
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
                    ip_str = inet_ntoa(ip_bytes)
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


def get_interface_mac_linux(interface_name: str) -> str:
    try:
        with open(f'/sys/class/net/{interface_name}/address', 'r') as f:
            return f.read().strip()
    except Exception:
        return ""


def get_interface_ipv4_addresses(interface_name: str) -> List[str]:
    try:
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


def get_interface_ipv6_addresses(interface_name: str) -> List[str]:

    try:
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


def get_default_interface_linux() -> Optional[Dict[str, Any]]:
    try:
        cmd = ['ip', 'route', 'show', 'default']
        output = subprocess.check_output(cmd, text=True)
        
        match = re.search(r'default via \S+ dev (\S+)', output)
        if match:
            interface = match.group(1)
            return get_interface_info(interface)
    except Exception:
        pass
    
    return None


def get_default_gateway_ipv4_linux() -> Optional[str]:
    try:
        cmd = ['ip', 'route', 'show', 'default']
        output = subprocess.check_output(cmd, text=True)
        
        match = re.search(r'default via (\S+)', output)
        if match:
            return match.group(1)
    except Exception:
        pass
    
    return None


def get_default_gateway_ipv6_linux() -> Optional[str]:
    try:
        cmd = ['ip', '-6', 'route', 'show', 'default']
        output = subprocess.check_output(cmd, text=True)
        
        match = re.search(r'default via (\S+)', output)
        if match:
            return match.group(1)
    except Exception:
        pass
    
    return None


def get_interface_info(interface_name: str) -> Dict[str, Any]:
    mac = get_interface_mac_linux(interface_name)
    
    ips_v4 = get_interface_ipv4_addresses(interface_name)
    ips_v6 = get_interface_ipv6_addresses(interface_name)
    
    try:
        with open(f'/sys/class/net/{interface_name}/ifindex', 'r') as f:
            index = int(f.read().strip())
    except Exception:
        index = -1
    
    try:
        with open(f'/sys/class/net/{interface_name}/device/uevent', 'r') as f:
            for line in f:
                if line.startswith('ID_MODEL='):
                    desc = line.strip().split('=')[1]
                    break
            else:
                desc = interface_name
    except Exception:
        desc = interface_name
    
    return {
        'name': interface_name,
        'index': index,
        'mac': mac,
        'description': desc,
        'ips_v4': ips_v4,
        'ips_v6': ips_v6,
        'ips': ips_v4 + ips_v6,
    }


def get_linux_adapter_list_linux() -> List[Dict[str, Any]]:
    adapters = []
    
    pcap_devices = get_libpcap_devices()
    
    for dev in pcap_devices:
        interface_name = dev['name']
        
        if interface_name.startswith('lo'):
            continue
        
        info = get_interface_info(interface_name)
        adapters.append(info)
    
    return adapters


def get_libpcap_available_interfaces_linux() -> Dict[str, Dict[str, Any]]:
    adapters = get_linux_adapter_list_linux()
    
    pcap_devices = get_libpcap_devices()
    
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

def get_libpcap_available_interfaces_pretify_linux() -> Dict[str, Dict[str, Any]]:
    interfaces = get_libpcap_available_interfaces_linux()
    
    print("\n" + "=" * 80)
    print("Available libpcap Interfaces:")
    print("=" * 80)
    
    for name, info in interfaces.items():
        print(f"\n{name}")
        print(f"  Description: {info['description']}")
        print(f"  MAC:         {info['mac']}")
        print(f"  IPv4:        {', '.join(info['ips_v4']) or 'N/A'}")
        print(f"  IPv6:        {', '.join(info['ips_v6']) or 'N/A'}")
        print(f"  Index:       {info['index']}")
    
    return interfaces

def get_default_interface_name_linux() -> Optional[str]:
    default = get_default_interface_linux()
    return default['name'] if default else None


def get_default_interface_mac_linux() -> str:
    default = get_default_interface_linux()
    return default['mac'] if default else ""


def get_default_interface_ip_linux() -> str:
    default = get_default_interface_linux()
    if default and default.get('ips_v4'):
        return default['ips_v4'][0]
    return ""

def get_loopback_interface_pcap_name_linux() -> str:
    return "lo"

def get_best_route_linux(dest_ip: str) -> Optional[Dict[str, Any]]:
    try:
        is_ipv6 = ':' in dest_ip
        if is_ipv6:
            cmd = ['ip', '-6', 'route', 'get', dest_ip]
        else:
            cmd = ['ip', '-4', 'route', 'get', dest_ip]

        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)

        parts = output.strip().split()
        result = {'destination': dest_ip}

        for i, part in enumerate(parts):
            if part == 'dev' and i + 1 < len(parts):
                result['interface'] = parts[i + 1]
            elif part == 'src' and i + 1 < len(parts):
                result['source_ip'] = parts[i + 1]
            elif part == 'via' and i + 1 < len(parts):
                result['gateway'] = parts[i + 1]
            elif part == 'from' and i + 1 < len(parts):
                result['source'] = parts[i + 1]
            elif i == 0:
                result['destination'] = part

        if is_ipv6:
            for i, part in enumerate(parts):
                if part == 'dev' and i + 2 < len(parts):
                    if parts[i + 2] == 'scope':
                        result['scope'] = parts[i + 3]

        if 'interface' in result:
            return result

    except Exception:
        pass

    return None
