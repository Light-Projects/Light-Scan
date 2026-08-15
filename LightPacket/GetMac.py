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