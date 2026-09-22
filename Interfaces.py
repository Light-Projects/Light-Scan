import sys

interfaces = []
pl = sys.platform

if pl == 'win32':
    from LightPacket.LightPacketWin import get_windows_adapter_list_windows
    for i in get_windows_adapter_list_windows():
        interfaces.append(i['name'])
elif pl == 'linux':
    from LightPacket.LightPacketLin import get_libpcap_devices
    for i in get_libpcap_devices():
        interfaces.append(i['name'])
else:
    from LightPacket.LightPacketUnix import get_libpcap_devices_bsd
    for i in get_libpcap_devices_bsd():
        interfaces.append(i['name'])