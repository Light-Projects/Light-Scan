# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import sys

def GetMac():
    if sys.platform == "win32":
        from .LightPacketWin import get_default_interface_mac_windows
        return get_default_interface_mac_windows()
    elif sys.platform == "linux":
        from .LightPacketLin import get_default_interface_mac_linux
        return get_default_interface_mac_linux()
    else:
        from .LightPacketUnix import get_interface_mac_bsd, get_default_interface_bsd
        return get_interface_mac_bsd(get_default_interface_bsd()['name'])

def GetMacGateway():
    from LightPacket.utils.Nsec.arp_resolution import arp_ping,ARP

    if sys.platform == "win32":
        from .LightPacketWin import get_default_gateway_ipv4_windows
        return arp_ping(get_default_gateway_ipv4_windows(),verbose=False)[ARP].macsrc
    elif sys.platform == "linux":
        from .LightPacketLin import get_default_gateway_ipv4_linux
        return arp_ping(get_default_gateway_ipv4_linux(),verbose=False)[ARP].macsrc
    else:
        from .LightPacketUnix import get_default_gateway_bsd
        return arp_ping(get_default_gateway_bsd(),verbose=False)[ARP].macsrc

def GetMacByInt(interface):
    if sys.platform == "win32":
        from .LightPacketWin import get_interface_mac_windows
        return get_interface_mac_windows(interface)
    elif sys.platform == "linux":
        from .LightPacketLin import get_interface_mac_linux
        return get_interface_mac_linux(interface)
    else:
        from .LightPacketUnix import get_interface_mac_bsd
        return get_interface_mac_bsd(interface)

def GetDefInterface():
    if sys.platform == "win32":
        from .LightPacketWin import get_default_interface_name_windows
        return get_default_interface_name_windows()
    elif sys.platform == "linux":
        from .LightPacketLin import get_default_interface_name_linux
        return get_default_interface_name_linux()
    else:
        from .LightPacketUnix import get_default_interface_bsd
        return get_default_interface_bsd()['name']