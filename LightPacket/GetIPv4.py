# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import sys

def GetIPv4():
    ip = None
    if sys.platform == "win32":
        from LightPacket.LightPacketWin import get_default_interface_ip_windows
        ip = get_default_interface_ip_windows()
    elif sys.platform == "linux":
        from LightPacket.LightPacketLin import get_default_interface_ip_linux
        ip = get_default_interface_ip_linux()
    else:
        from LightPacket.LightPacketUnix import get_default_interface_bsd
        try:
            ip = get_default_interface_bsd()['ips_v4']
        except Exception:
            ip = None
    return ip if ip else "0.0.0.0"

def GetIPv4Gateway():
    ip = None
    if sys.platform == "win32":
        from LightPacket.LightPacketWin import get_default_gateway_ipv4_windows
        ip = get_default_gateway_ipv4_windows()
    elif sys.platform == "linux":
        from LightPacket.LightPacketLin import get_default_gateway_ipv4_linux
        ip = get_default_gateway_ipv4_linux()
    else:
        from LightPacket.LightPacketUnix import get_default_gateway_bsd
        try:
            ip = get_default_gateway_bsd()
        except Exception:
            ip = None
    return ip if ip else "0.0.0.0"