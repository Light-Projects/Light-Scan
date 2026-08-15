# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
LightPacket Windows Interface Enumeration
Full IPv4 + IPv6 support using Windows API
"""

import ctypes
from ctypes import wintypes, byref, POINTER, Structure
import socket
import struct
from typing import Dict, List, Optional, Tuple, Union
from .NpcapInterfacesWin import get_npcap_devices_windows
from ..Layers.IPtoa import ipv6_bytes_to_str

AF_INET = 2
AF_INET6 = 23
AF_UNSPEC = 0

ERROR_SUCCESS = 0
ERROR_BUFFER_OVERFLOW = 111
ERROR_INSUFFICIENT_BUFFER = 122
GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x0100
MIB_IPPROTO_OTHER = 1
MIB_IPPROTO_LOCAL = 2
MIB_IPPROTO_NETMGMT = 3
MIB_IPPROTO_ICMP = 4
MIB_IPPROTO_EGP = 5
MIB_IPPROTO_GGP = 6
MIB_IPPROTO_HELLO = 7
MIB_IPPROTO_RIP = 8
MIB_IPPROTO_ISIS = 9
MIB_IPPROTO_ESIS = 10
MIB_IPPROTO_CISCO = 11
MIB_IPPROTO_BBN = 12
MIB_IPPROTO_OSPF = 13
MIB_IPPROTO_BGP = 14
MIB_IPPROTO_NT_AUTOSTATIC = 10002
MIB_IPPROTO_NT_STATIC = 10006
MIB_IPPROTO_NT_STATIC_NON_DOD = 10007

class SOCKET_ADDRESS(Structure):
    _fields_ = [
        ('lpSockaddr', ctypes.c_void_p),
        ('iSockaddrLength', wintypes.INT),
    ]

class IP_ADAPTER_UNICAST_ADDRESS(Structure):
    pass

class IP_ADAPTER_ADDRESSES(Structure):
    pass

class MIB_IPFORWARDROW(Structure):
    _fields_ = [
        ('dwForwardDest', wintypes.DWORD),
        ('dwForwardMask', wintypes.DWORD),
        ('dwForwardPolicy', wintypes.DWORD),
        ('dwForwardNextHop', wintypes.DWORD),
        ('dwForwardIfIndex', wintypes.DWORD),
        ('dwForwardType', wintypes.DWORD),
        ('dwForwardProto', wintypes.DWORD),
        ('dwForwardAge', wintypes.DWORD),
        ('dwForwardNextHopAS', wintypes.DWORD),
        ('dwForwardMetric1', wintypes.DWORD),
        ('dwForwardMetric2', wintypes.DWORD),
        ('dwForwardMetric3', wintypes.DWORD),
        ('dwForwardMetric4', wintypes.DWORD),
        ('dwForwardMetric5', wintypes.DWORD),
    ]

IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ('Length', wintypes.ULONG),
    ('Flags', wintypes.DWORD),
    ('Next', POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ('Address', SOCKET_ADDRESS),
    ('PrefixOrigin', ctypes.c_int),
    ('SuffixOrigin', ctypes.c_int),
    ('DadState', ctypes.c_int),
    ('ValidLifetime', wintypes.ULONG),
    ('PreferredLifetime', wintypes.ULONG),
    ('LeaseLifetime', wintypes.ULONG),
    ('OnLinkPrefixLength', ctypes.c_uint8),
]

IP_ADAPTER_ADDRESSES._fields_ = [
    ('Length', wintypes.ULONG),
    ('IfIndex', wintypes.DWORD),
    ('Next', POINTER(IP_ADAPTER_ADDRESSES)),
    ('AdapterName', ctypes.c_char_p),
    ('FirstUnicastAddress', POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ('FirstAnycastAddress', ctypes.c_void_p),
    ('FirstMulticastAddress', ctypes.c_void_p),
    ('FirstDnsServerAddress', ctypes.c_void_p),
    ('DnsSuffix', ctypes.c_wchar_p),
    ('Description', ctypes.c_wchar_p),
    ('FriendlyName', ctypes.c_wchar_p),
    ('PhysicalAddress', ctypes.c_ubyte * 8),
    ('PhysicalAddressLength', wintypes.DWORD),
    ('Flags', wintypes.DWORD),
    ('Mtu', wintypes.DWORD),
    ('IfType', wintypes.DWORD),
    ('OperStatus', ctypes.c_int),
    ('Ipv6IfIndex', wintypes.DWORD),
    ('ZoneIndices', wintypes.DWORD * 16),
    ('FirstPrefix', ctypes.c_void_p),
]

iphlpapi = ctypes.windll.iphlpapi
GetAdaptersAddresses = iphlpapi.GetAdaptersAddresses
GetAdaptersAddresses.argtypes = [
    wintypes.ULONG,
    wintypes.DWORD,
    ctypes.c_void_p,
    POINTER(IP_ADAPTER_ADDRESSES),
    POINTER(wintypes.ULONG),
]
GetAdaptersAddresses.restype = wintypes.DWORD

GetBestRoute = iphlpapi.GetBestRoute
GetBestRoute.argtypes = [
    wintypes.DWORD,
    wintypes.DWORD,
    POINTER(MIB_IPFORWARDROW)
]
GetBestRoute.restype = wintypes.DWORD


class sockaddr_in(Structure):
    _fields_ = [
        ('sin_family', wintypes.USHORT),
        ('sin_port', wintypes.USHORT),
        ('sin_addr', wintypes.ULONG),
        ('sin_zero', ctypes.c_char * 8)
    ]

class sockaddr_in6(Structure):
    _fields_ = [
        ('sin6_family', wintypes.USHORT),
        ('sin6_port', wintypes.USHORT),
        ('sin6_flowinfo', wintypes.ULONG),
        ('sin6_addr', ctypes.c_byte * 16),
        ('sin6_scope_id', wintypes.ULONG),
    ]

class sockaddr_inet(Structure):
    _fields_ = [
        ('Ipv4', sockaddr_in),
        ('Ipv6', sockaddr_in6),
        ('si_family', wintypes.USHORT),
    ]

class IP_ADDRESS_PREFIX(Structure):
    _fields_ = [
        ('Prefix', sockaddr_inet),
        ('PrefixLength', ctypes.c_uint8),
    ]

class MIB_IPFORWARD_ROW2(Structure):
    _fields_ = [
        ('InterfaceLuid', ctypes.c_ulonglong),
        ('InterfaceIndex', wintypes.DWORD),
        ('DestinationPrefix', IP_ADDRESS_PREFIX),
        ('NextHop', sockaddr_inet),
        ('SitePrefixLength', ctypes.c_uint8),
        ('ValidLifetime', wintypes.DWORD),
        ('PreferredLifetime', wintypes.DWORD),
        ('Metric', wintypes.DWORD),
        ('Protocol', wintypes.DWORD),
        ('Loopback', wintypes.BOOL),
        ('AutoconfigureAddress', wintypes.BOOL),
        ('Publish', wintypes.BOOL),
        ('Immortal', wintypes.BOOL),
        ('Age', wintypes.DWORD),
        ('Origin', wintypes.DWORD),
    ]

GetBestRoute2 = iphlpapi.GetBestRoute2
GetBestRoute2.argtypes = [
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    POINTER(MIB_IPFORWARD_ROW2),
    ctypes.c_void_p,
]
GetBestRoute2.restype = wintypes.DWORD

def extract_ip_from_sockaddr(sockaddr_ptr) -> Optional[Tuple[str, int]]:
    if not sockaddr_ptr:
        return None

    try:
        family = ctypes.cast(sockaddr_ptr, POINTER(wintypes.USHORT)).contents.value

        if family == AF_INET:
            addr = ctypes.cast(sockaddr_ptr, POINTER(sockaddr_in)).contents
            ip_bytes = struct.pack('I', addr.sin_addr)
            return (socket.inet_ntoa(ip_bytes), 4)

        elif family == AF_INET6:
            addr = ctypes.cast(sockaddr_ptr, POINTER(sockaddr_in6)).contents
            ip_bytes = bytes(addr.sin6_addr)[:16]
            ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)

            if addr.sin6_scope_id:
                ip_str = f"{ip_str}%{addr.sin6_scope_id}"
            return (ip_str, 6)

    except Exception:
        pass

    return None


def get_default_gateway_ipv4_windows() -> Optional[str]:
    dest_addr = 0
    source_addr = 0
    route = MIB_IPFORWARDROW()

    result = GetBestRoute(dest_addr, source_addr, byref(route))
    if result == 0:
        ip_bytes = struct.pack('I', route.dwForwardNextHop)
        gateway = socket.inet_ntoa(ip_bytes)
        return gateway
    else:
        return None


def get_default_gateway_ipv6_windows() -> Optional[str]:

    try:
        dest_addr = sockaddr_inet()
        dest_addr.si_family = AF_INET6
        dest_addr.Ipv6.sin6_addr = (ctypes.c_byte * 16)(*[0] * 16)
        route = MIB_IPFORWARD_ROW2()

        result = GetBestRoute2(
            AF_INET6,
            0,
            0,
            None,
            byref(dest_addr),
            0,
            byref(route),
            None
        )

        if result == 0:
            next_hop_bytes = bytes(route.NextHop.Ipv6.sin6_addr)[:16]
            if any(b != 0 for b in next_hop_bytes):
                gateway = ipv6_bytes_to_str(next_hop_bytes)
                if route.NextHop.Ipv6.sin6_scope_id and gateway.startswith('fe80:'):
                    gateway = f"{gateway}%{route.NextHop.Ipv6.sin6_scope_id}"

                return gateway

        return None

    except Exception as e:
        print(f"Error getting default IPv6 gateway: {e}")
        return None

def get_npcap_available_interfaces_windows() -> Dict:
    win_adapters = get_windows_adapter_list_windows()

    npcap_devices = get_npcap_devices_windows()

    win_by_guid = {}
    for adapter in win_adapters:
        guid = adapter.get('guid')
        if guid:
            win_by_guid[guid] = adapter

    active_adapters = {}
    for npcap_dev in npcap_devices:
        npcap_name = npcap_dev.get('name', '')
        npcap_desc = npcap_dev.get('description', '')

        guid = npcap_name.replace("rpcap://\\Device\\NPF_","")
        win_adapter = win_by_guid.get(guid) if guid else None

        info = {
            'npcap_name': npcap_name,
            'guid': guid,
            'name': win_adapter.get('name') if win_adapter else (npcap_desc or npcap_name),
            'description': win_adapter.get('description') if win_adapter else npcap_desc,
            'index': win_adapter.get('index') if win_adapter else None,
            'mac': win_adapter.get('mac') if win_adapter else '',
            'ips_v4': win_adapter.get('ips_v4', []) if win_adapter else [],
            'ips_v6': win_adapter.get('ips_v6', []) if win_adapter else [],
            'ips': win_adapter.get('ips', []) if win_adapter else [],
        }

        active_adapters[npcap_name] = info

    return active_adapters

def get_interface_mac_windows(interface):
    interfgaces = get_npcap_available_interfaces_windows()
    for name, info in interfgaces.items():
        if info['name'] == interface:
            return info['mac']

    return None

def get_npcap_available_interfaces_pretify_windows() -> Dict:
    interfaces = get_npcap_available_interfaces_windows()
    for npcap_name, info in interfaces.items():
        print(f"{npcap_name}")
        print(f"  GUID       : {info['guid']}")
        print(f"  Name       : {info['name']}")
        print(f"  IPs        : {info['ips']}")

    return interfaces

def get_default_interface_windows() -> Optional[Dict]:
    route = MIB_IPFORWARDROW()
    result = GetBestRoute(0, 0, byref(route))
    if result != 0:
        return None

    ifindex = route.dwForwardIfIndex

    adapters = get_windows_adapter_list_windows()
    for adapter in adapters:
        if adapter['index'] == ifindex:
            return adapter
    return None

def get_default_interface_mac_windows() -> str:
    adapter = get_default_interface_windows()
    mac = adapter['mac']
    return mac

def get_default_interface_ip_windows() -> str:
    adapter = get_default_interface_windows()
    ip = adapter['ips_v4'][0]
    return ip

def get_default_interface_npcap_name_windows() -> str:
    adapter = get_default_interface_windows()
    name = adapter['guid']
    return r'\Device\NPF_' + name

def get_loopback_interface_npcap_name_windows() -> str:
    return r'\Device\NPF_Loopback'

def get_default_interface_name_windows() -> str:
    adapter = get_default_interface_windows()
    return adapter['name'] if adapter else None

def get_windows_adapter_list_windows() -> List[Dict]:

    adapters = []

    buffer_size = wintypes.ULONG(0)
    result = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_ALL_INTERFACES,
        None,
        None,
        byref(buffer_size)
    )

    if result not in (ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER):
        return adapters

    buffer = ctypes.create_string_buffer(buffer_size.value)
    adapter_addresses = ctypes.cast(buffer, POINTER(IP_ADAPTER_ADDRESSES))

    result = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_ALL_INTERFACES,
        None,
        adapter_addresses,
        byref(buffer_size)
    )

    if result != ERROR_SUCCESS:
        return adapters


    current = adapter_addresses
    while current:
        adapter_name = current.contents.AdapterName
        guid_str = adapter_name.decode("ascii", errors="replace") if adapter_name else ""

        friendly_name = current.contents.FriendlyName or ""
        description = current.contents.Description or ""

        mac_parts = []
        for i in range(min(current.contents.PhysicalAddressLength, 6)):
            mac_parts.append(f"{current.contents.PhysicalAddress[i]:02X}")
        mac = ":".join(mac_parts) if mac_parts else ""

        ips_v4 = []
        ips_v6 = []
        unicast = current.contents.FirstUnicastAddress

        while unicast:
            addr_info = extract_ip_from_sockaddr(unicast.contents.Address.lpSockaddr)
            if addr_info:
                ip, version = addr_info
                if version == 4:
                    if ip not in ips_v4:
                        ips_v4.append(ip)
                elif version == 6:
                    if ip not in ips_v6:
                        ips_v6.append(ip)
            unicast = unicast.contents.Next

        adapter_info = {
            'adapter_name': current.contents,
            'index': current.contents.IfIndex,
            'guid': guid_str,
            'name': friendly_name,
            'description': description,
            'mac': mac,
            'ips_v4': ips_v4,
            'ips_v6': ips_v6,
            'ips': ips_v4 + ips_v6,
        }
        adapters.append(adapter_info)

        current = current.contents.Next

    return adapters

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
        self._guid_to_interface = {}
        self._load_interfaces()

    def _load_interfaces(self):
        try:
            adapters = get_windows_adapter_list_windows()

            if not adapters:
                print("Warning: No Windows adapters found. Using fallback.")
                adapters = self._fallback_interfaces()

            for adapter in adapters:
                name = adapter['name'] if adapter['name'] else f"Interface_{adapter['index']}"

                iface = {
                    'name': name,
                    'guid': adapter['guid'],
                    'index': adapter['index'],
                    'mac': adapter['mac'],
                    'description': adapter['description'],
                    'ips_v4': adapter.get('ips_v4', []),
                    'ips_v6': adapter.get('ips_v6', []),
                    'ips': adapter.get('ips', []),
                }

                self._interfaces[name] = iface
                if adapter['guid']:
                    self._guid_to_interface[adapter['guid']] = iface

        except Exception as e:
            print(f"Error loading interfaces: {e}")
            self._load_fallback()

    def _load_fallback(self):
        try:
            hostname = socket.gethostname()
            ips = []
            for addr_info in socket.getaddrinfo(hostname, None):
                ip = addr_info[4][0]
                if ip and not ip.startswith('127.'):
                    if ':' in ip:
                        continue
                    else:
                        ips.append(ip)

            if ips:
                self._interfaces['Default'] = {
                    'name': 'Default',
                    'guid': None,
                    'index': -1,
                    'mac': '',
                    'ips_v4': ips,
                    'ips_v6': [],
                    'ips': ips,
                    'description': 'Default interface (fallback)',
                }
        except Exception:
            pass

    def _fallback_interfaces(self) -> List[Dict]:
        try:
            hostname = socket.gethostname()
            ips_v4 = []
            ips_v6 = []

            for addr_info in socket.getaddrinfo(hostname, None):
                ip = addr_info[4][0]
                if ip.startswith('127.'):
                    continue
                if ':' in ip:
                    ips_v6.append(ip)
                else:
                    ips_v4.append(ip)

            return [{
                'name': 'Default',
                'guid': None,
                'index': -1,
                'mac': '',
                'description': 'Default interface (fallback)',
                'ips_v4': ips_v4,
                'ips_v6': ips_v6,
                'ips': ips_v4 + ips_v6,
            }]
        except Exception:
            return []

    def default_interface(self):
        default_adapter = get_default_interface_windows()
        if not default_adapter:
            return None

        for iface in self._interfaces.values():
            if iface.get('index') == default_adapter['index']:
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

    def __setitem__(self, key, value):
        self._interfaces[key] = value

    def __contains__(self, key):
        return key in self._interfaces

    def __len__(self):
        return len(self._interfaces)

    def __iter__(self):
        return iter(self._interfaces)

    def dev_from_name(self, name: str) -> Optional[Dict]:
        return self._interfaces.get(name)

    def dev_from_guid(self, guid: str) -> Optional[Dict]:
        return self._guid_to_interface.get(guid)

    def show(self):
        C = self.COLORS

        print(f"\n{C['bold']}=== Interface Details ==={C['reset']}\n")

        for name, iface in self._interfaces.items():
            print(f"{C['green']}Name:{C['reset']} {name}")
            print(f"  {C['blue']}GUID:{C['reset']} {iface.get('guid', 'N/A')}")
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
            adapters = get_windows_adapter_list_windows()
            for adapter in adapters:
                name = adapter['name'] if adapter['name'] else f"Interface_{adapter['index']}"
                self._interfaces[name] = adapter
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

    def show(self):
        C = NetworkInterfaces.COLORS

        print(f"\n{C['bold']}=== Available Interfaces ==={C['reset']}\n")
        for name, iface in self._interfaces.items():
            print(f"{C['green']}Name:{C['reset']} {name}")
            print(f"  {C['blue']}GUID:{C['reset']} {iface.get('guid', 'N/A')}")
            print(f"  {C['blue']}Index:{C['reset']} {iface.get('index', -1)}")
            print(f"  {C['blue']}MAC:{C['reset']} {iface.get('mac', 'N/A')}")
            print(f"  {C['blue']}IPv4:{C['reset']} {', '.join(iface.get('ips_v4', [])) or 'N/A'}")
            print(f"  {C['blue']}IPv6:{C['reset']} {', '.join(iface.get('ips_v6', [])) or 'N/A'}")
            print()


