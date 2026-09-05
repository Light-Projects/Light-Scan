# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import sys

def GetIPv4():
    if sys.platform == "win32":
        from .LightPacketWin import get_default_interface_ip_windows
        return get_default_interface_ip_windows()
    elif sys.platform == "linux":
        from .LightPacketLin import get_default_interface_ip_linux
        return get_default_interface_ip_linux()
    else:
        from .LightPacketUnix import get_default_interface_bsd
        return get_default_interface_bsd()['ips_v4']

def GetIPv4Gateway():
    if sys.platform == "win32":
        from .LightPacketWin import get_default_gateway_ipv4_windows
        return get_default_gateway_ipv4_windows()
    elif sys.platform == "linux":
        from .LightPacketLin import get_default_gateway_ipv4_linux
        return get_default_gateway_ipv4_linux()
    else:
        from .LightPacketUnix import get_default_gateway_bsd
        return get_default_gateway_bsd()