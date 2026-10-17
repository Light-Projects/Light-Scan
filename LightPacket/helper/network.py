# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import subprocess
import ipaddress
import sys
import json
from LightPacket.GetMac import GetDefInterface
from LightPacket.GetIPv4 import GetIPv4

def is_ip_locale(ipaddr):
    try:
        ip = ipaddress.ip_address(ipaddr)
        return ip.is_private or ip.is_link_local or ip.is_loopback
    except ValueError:
        return "Invalid IP address"


def is_in_same_network(target_ip):
    network = ipaddress.ip_network(f"{GetIPv4()}/{subnetmask(Interface=GetDefInterface())[1]}", strict=False)

    target = ipaddress.ip_address(target_ip)

    return target in network

def subnetmask(Interface=None):
    if sys.platform == "win32":
        cmd = "PowerShell -Command \"Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias, IPv4Address, IPAddress | ConvertTo-Json\""
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        interfaces_list = []
        if result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                    interfaces_list.append((item["InterfaceAlias"], item["IPAddress"]))

        if Interface:
            for i in interfaces_list:
                if i[0] == Interface:
                    return i
        return interfaces_list
    else:
        command = "ifconfig | awk '/^[a-zA-Z0-9]/ {interface=$1} /netmask/ {print interface, $4}'"
        process = subprocess.run(command, shell=True, capture_output=True, text=True)
        interfaces_list = []
        for line in process.stdout.strip().split("\n"):
            if line:
                parts = line.split()
                if len(parts) == 2:
                    interface = parts[0].rstrip(":")
                    netmask = parts[1]
                    interfaces_list.append((interface, netmask))

        if Interface:
            for i in interfaces_list:
                if i[0] == Interface:
                    return i
        return interfaces_list

