# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import sys

def GetMac():
    mac = None
    if sys.platform == "win32":
        from LightPacket.LightPacketWin import get_default_interface_mac_windows
        mac = get_default_interface_mac_windows()
    elif sys.platform == "linux":
        from LightPacket.LightPacketLin import get_default_interface_mac_linux
        mac = get_default_interface_mac_linux()
    else:
        from LightPacket.LightPacketUnix import get_interface_mac_bsd, get_default_interface_bsd
        try:
            mac = get_interface_mac_bsd(get_default_interface_bsd()['name'])
        except Exception:
            mac = None
    return mac if mac else "00:00:00:00:00:00"

def GetMacGateway():
    from LightPacket.utils.Nsec.arp_resolution import arp_ping,ARP

    if sys.platform == "win32":
        from LightPacket.LightPacketWin import get_default_gateway_ipv4_windows
        return arp_ping(get_default_gateway_ipv4_windows(),verbose=False)[ARP].macsrc
    elif sys.platform == "linux":
        from LightPacket.LightPacketLin import get_default_gateway_ipv4_linux
        return arp_ping(get_default_gateway_ipv4_linux(),verbose=False)[ARP].macsrc
    else:
        from LightPacket.LightPacketUnix import get_default_gateway_bsd
        return arp_ping(get_default_gateway_bsd(),verbose=False)[ARP].macsrc

def GetMacByIP(ip):
    from LightPacket.utils.Nsec.arp_resolution import arp_ping,ARP

    if sys.platform == "win32":
        from LightPacket.LightPacketWin import get_default_gateway_ipv4_windows
        return arp_ping(ip,verbose=False)[ARP].macsrc
    elif sys.platform == "linux":
        from LightPacket.LightPacketLin import get_default_gateway_ipv4_linux
        return arp_ping(ip,verbose=False)[ARP].macsrc
    else:
        from LightPacket.LightPacketUnix import get_default_gateway_bsd
        return arp_ping(ip,verbose=False)[ARP].macsrc

def GetMacByInt(interface):
    if sys.platform == "win32":
        from LightPacket.LightPacketWin import get_interface_mac_windows
        return get_interface_mac_windows(interface)
    elif sys.platform == "linux":
        from LightPacket.LightPacketLin import get_interface_mac_linux
        return get_interface_mac_linux(interface)
    else:
        from LightPacket.LightPacketUnix import get_interface_mac_bsd
        return get_interface_mac_bsd(interface)

def GetDefInterface():
    if sys.platform == "win32":
        from LightPacket.LightPacketWin import get_default_interface_name_windows
        return get_default_interface_name_windows()
    elif sys.platform == "linux":
        from LightPacket.LightPacketLin import get_default_interface_name_linux
        return get_default_interface_name_linux()
    else:
        from LightPacket.LightPacketUnix import get_default_interface_bsd
        return get_default_interface_bsd()['name']