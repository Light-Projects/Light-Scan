# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Adam Boulaaz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""
Light-Scan Scripting Engine (LSSE)
Script Name : dhcp-discover
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> None
--> Optional Arguments
----> None
Categorie : safe/discovery/dhcp
"""


from LightPacket import GetMac
import sys
from datetime import datetime, timezone

from scapy.all import (
    Ether, IP, UDP, BOOTP, DHCP,
    RandInt, srp, conf
)


DHCP_OPTION_NAMES = {
    1: "subnet_mask",
    3: "router",
    6: "domain_name_server",
    12: "hostname",
    15: "domain_name",
    28: "broadcast_address",
    51: "lease_time",
    53: "message_type",
    54: "server_id",
    58: "renewal_time_t1",
    59: "rebinding_time_t2",
    252: "wpad",
}

DHCP_MESSAGE_TYPES = {
    1: "DHCPDISCOVER",
    2: "DHCPOFFER",
    3: "DHCPREQUEST",
    4: "DHCPDECLINE",
    5: "DHCPACK",
    6: "DHCPNAK",
    7: "DHCPRELEASE",
    8: "DHCPINFORM",
}


def build_discover(xid: int) -> Ether:
    """Construct a DHCP DISCOVER packet for the given interface."""
    mac = GetMac.GetMac()

    packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=xid, flags=0x8000) /
        DHCP(options=[
            ("message-type", "discover"),
            ("param_req_list", [1, 3, 6, 15, 28, 51, 54, 58, 59]),
            "end",
        ])
    )
    return packet


def parse_dhcp_options(dhcp_layer: DHCP) -> dict:
    """Turn a scapy DHCP options list into a clean dict."""
    parsed = {}
    for opt in dhcp_layer.options:
        if opt == "end" or opt == "pad":
            continue
        if not isinstance(opt, tuple):
            continue

        name, value = opt[0], opt[1] if len(opt) > 1 else None

        if name == "message-type":
            parsed["message_type"] = DHCP_MESSAGE_TYPES.get(value, f"unknown({value})")
        elif name == "lease_time":
            parsed["lease_time_seconds"] = value
            parsed["lease_time_human"] = _seconds_to_human(value)
        elif name == "renewal_time":
            parsed["renewal_time_seconds"] = value
        elif name == "rebinding_time":
            parsed["rebinding_time_seconds"] = value
        elif name in ("name_server", "domain-name-server"):
            parsed["domain_name_server"] = value if isinstance(value, list) else [value]
        else:
            parsed[name] = value
    return parsed


def _seconds_to_human(seconds) -> str:
    if seconds is None:
        return "n/a"
    seconds = int(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return "".join(parts)


def parse_offer(pkt) -> dict:
    """Extract everything useful from a single DHCP OFFER packet."""
    bootp = pkt.getlayer(BOOTP)
    dhcp = pkt.getlayer(DHCP)

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "offered_ip": bootp.yiaddr if bootp else None,
        "server_ip": pkt[IP].src if pkt.haslayer(IP) else None,
        "server_mac": pkt[Ether].src if pkt.haslayer(Ether) else None,
        "transaction_id": hex(bootp.xid) if bootp else None,
        "your_client_mac": bootp.chaddr[:6].hex(":") if bootp else None,
    }

    if dhcp:
        result["options"] = parse_dhcp_options(dhcp)

    return result


def discover(timeout: int = 5, count: int = 1, verbose: bool = False):
    """
    Send `count` DHCP DISCOVER packets (useful for spotting rogue/multiple
    DHCP servers) and collect + parse every OFFER received.
    """
    conf.checkIPaddr = False
    offers = []

    for i in range(count):
        xid = RandInt()._fix()
        pkt = build_discover(xid)

        if verbose:
            print(f"[*] Sending DISCOVER #{i + 1}/{count} (xid={hex(xid)}) ...",
                  file=sys.stderr)

        answered, _ = srp(pkt, timeout=timeout, verbose=0, multi=True)

        for _, reply in answered:
            if reply.haslayer(DHCP):
                offers.append(parse_offer(reply))

    return offers


def main():
    offers = discover()

    if not offers:
        print("[-] No DHCP OFFER received. Check interface, permissions, or network.",
              file=sys.stderr)
        sys.exit(1)


    print(f"\n[+] Received {len(offers)} offer(s):\n")
    for idx, offer in enumerate(offers, 1):
        opts = offer.get("options", {})
        print(f"--- Offer {idx} ---")
        print(f"  Offered IP        : {offer['offered_ip']}")
        print(f"  DHCP Server       : {offer['server_ip']} ({offer['server_mac']})")
        print(f"  Message Type      : {opts.get('message_type')}")
        print(f"  Subnet Mask       : {opts.get('subnet_mask')}")
        print(f"  Router / Gateway  : {opts.get('router')}")
        print(f"  DNS Servers       : {opts.get('domain_name_server')}")
        print(f"  Domain Name       : {opts.get('domain')}")
        print(f"  Lease Time        : {opts.get('lease_time_human')} "
              f"({opts.get('lease_time_seconds')}s)")
        print(f"  Server Identifier : {opts.get('server_id')}")
        print(f"  Transaction ID    : {offer['transaction_id']}")
        print()


    distinct_servers = {o["server_ip"] for o in offers}
    if len(distinct_servers) > 1:
        print(f"[!] WARNING: {len(distinct_servers)} distinct DHCP servers responded: "
              f"{', '.join(distinct_servers)}")
        print("    This may indicate a rogue DHCP server on the network.")


