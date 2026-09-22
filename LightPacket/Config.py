# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import sys


class _NetworkConfig:
    """Defaults for raw sockets (L2Socket / L2SocketL / L2Packet) and sniffing."""

    # pcap/AF_PACKET capture defaults (mirrors current hardcoded values)
    SNAPLEN: int = 65535
    PROMISC: bool = True
    TIMEOUT_MS: int = 100          # pcap_set_timeout, ms
    MONITOR_MODE: bool = False     # 802.11 monitor mode
    NON_STOP: bool = True
    INTERFACE: str |  None = None

    # Sniffer() defaults
    SNIFF_COUNT: int = 0           # 0 = unlimited
    SNIFF_TIMEOUT = None           # seconds, None = unlimited
    SNIFF_POLL_INTERVAL: float = 0.25  # per-recv poll slice used by Sniffer.stream()

    # srp/srp1 default response wait
    SEND_RECV_TIMEOUT: float = 3.0
    ARP_PING_TIMEOUT: float = 2.0

    # ARP scan (arp_resolution.py)
    ARP_SCAN_MAX_WORKERS: int = 200
    ARP_SCAN_DEFAULT_TARGET: str = "10.148.175.0/24"

    # CIDR/target expansion safety limit (utils/CIDR.py)
    MAX_HOSTS: int = 65536

    # Default link-layer type for pcap file writing (pcapwriter.py)
    DEFAULT_LINKTYPE: int = 1  # PCAP_LINKTYPE_ETHERNET


class _LoggingConfig:
    """Defaults for LightLogger / verbose protocol printing."""

    VERBOSE: bool = False          # default verbosity for parser .load_as_*_layer(verbose=...) calls
    USE_COLOR: bool = sys.stdout.isatty()
    LOG_LEVEL: str = "DEBUG"       # matches logging module level names
    LOGGER_NAME: str = "LightPacket"


class _MiscConfig:
    """Other cross-cutting constants."""

    # Ethernet/DIX split point: ethertype vs 802.3 length field
    ETHERTYPE_MIN: int = 0x0600
    ETHERTYPE_LEN_MAX: int = 0x05DC

    # pcap linktypes this build knows how to dispatch on (Detect_layer.py)
    LINKTYPE_ETHERNET: int = 1
    LINKTYPE_PPP: int = 9
    LINKTYPE_LINUX_SLL: int = 113
    LINKTYPE_LINUX_SLL2: int = 276
    LINKTYPE_RAW_IP: int = 101
    LINKTYPE_IEEE802_11: int = 105

    # Broadcast/null addressing
    BROADCAST_MAC: str = "ff:ff:ff:ff:ff:ff"
    NULL_MAC: str = "00:00:00:00:00:00"


class Config:
    """Top-level namespace grouping all LightPacket configuration sections."""

    def __init__(self):
        self.network = _NetworkConfig()
        self.logging = _LoggingConfig()
        self.misc = _MiscConfig()

    def __repr__(self):
        return (f"<Config network={vars(self.network)} "
                f"logging={vars(self.logging)} "
                f"misc={vars(self.misc)}>")


# Singleton instance imported throughout the library, e.g.:
#   from LightPacket.Config import config
config = Config()