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
Windows family signatures: desktop (XP -> 11) and Server (2000 -> 2022).
"""

from .base import OSSignature, VersionRule

WINDOWS = OSSignature(
    name="Windows",
    family="windows",
    common_orders=[
        ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK', 'NOP', 'NOP'],
        ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK'],
        ['WScale', 'MSS', 'SAckOK', 'Timestamp'],
        ['MSS', 'NOP', 'WScale', 'SAckOK', 'NOP', 'NOP', 'Timestamp'],
        ['MSS', 'SAckOK', 'Timestamp', 'WScale'],
        ['MSS', 'WScale', 'SAckOK'],
        ['MSS', 'NOP', 'SAckOK', 'Timestamp'],
        ['MSS', 'NOP', 'NOP', 'SAckOK'],
    ],
    windows=[64240, 65535, 8192, 16384, 32768, 25600, 51200, 5840],
    ttl_range=(65, 128),
    hlim_range=(65, 128),
    wscale_values=[8, 2],
    mss_values=[1460, 65495, 65160],
    timestamp_high=False,
    icmp_default_ttl=128,
    udp_closed_port_quirk="icmp_ttl_128_no_extra_data",
    banner_keywords=[
        ("microsoft", 15),
        ("iis", 15),
        ("windows", 12),
        ("microsoft ftp service", 15),
        ("cerberus", 15),
        ("microsoft-httpapi", 25),
        ("83 00 00 01 8f", 25),  # raw SMB2 negotiate quirk seen in some banner dumps
        ("05 00 0d 03",25)  # raw MSRPC response seen from some Windows 10
    ],
    service_keywords=[
        ("msrpc", 25),
        ("microsoft-ds", 12.5),
        ("netbios-ssn", 10),
    ],
    exclusive_banner_keywords=["server: microsoft-httpapi", "microsoft-ds"],
    version_rules=[

        # --- This section is based on my analysis for Windows 10 ---
        VersionRule("Windows 10 (build 17000+)",ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'WScale', 'SAckOK']),

        # --- Windows 11 ---
        VersionRule("Windows 11 (build 22000+)", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK']),
        VersionRule("Windows 11 (build 22621+) / Server 2022", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'WScale', 'NOP', 'NOP', 'SAckOK', 'NOP', 'NOP']),
        VersionRule("Windows 11 (build 22631+)", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'NOP', 'WScale', 'NOP', 'SAckOK', 'NOP', 'Timestamp']),
        VersionRule("Windows 11 (build 22000-22621)", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'SAckOK', 'Timestamp', 'WScale']),

        # --- Windows 10 ---
        VersionRule("Windows 10 (build 10240-10586)", ttl=128, wscale=8, mss=65495, window=64240,
                    option_order=['MSS', 'WScale', 'SAckOK']),
        VersionRule("Windows 10 (build 15063+)", ttl=128, wscale=8, mss=65495, window=64240,
                    option_order=['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK']),
        VersionRule("Windows 10 (build 22H2 - 19045)", ttl=128, wscale=8, mss=65495, window=5840),
        VersionRule("Windows 10 (build 1709-1803)", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK']),
        VersionRule("Windows 10 (build 1903-1909)", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'NOP', 'WScale', 'NOP', 'SAckOK', 'NOP', 'Timestamp']),
        VersionRule("Windows 10 (build 1703)", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'NOP', 'WScale', 'Timestamp', 'SAckOK']),
        VersionRule("Windows 10 (build 1809)", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'NOP', 'WScale', 'NOP', 'SAckOK']),
        VersionRule("Windows 10 (build 2004+)", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'WScale', 'Timestamp', 'SAckOK']),

        # --- Windows 8.x ---
        VersionRule("Windows 8 (build 9200)", ttl=128, wscale=8, mss=65495, window=8192),
        VersionRule("Windows 8.1 (build 9600)", ttl=128, wscale=8, mss=65495, window=16384),
        VersionRule("Windows 8.1 (build 9600, Update 1)", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'WScale', 'NOP', 'NOP', 'SAckOK']),

        # --- Windows 7 ---
        VersionRule("Windows 7 (build 7600, RTM)", ttl=128, mss=1460, window=65535,
                    wscale=None, option_order=['MSS', 'SAckOK', 'Timestamp']),
        VersionRule("Windows 7 (build 7601, SP1)", ttl=128, mss=1460, window=65535,
                    wscale=None, option_order=['MSS', 'NOP', 'SAckOK', 'Timestamp']),
        VersionRule("Windows 7 (build 7600, small window)", ttl=128, mss=1460, window=8192, wscale=None),
        VersionRule("Windows 7 (build 7601, wscale enabled)", ttl=128, mss=1460, window=65535, wscale=2),

        # --- Vista ---
        VersionRule("Windows Vista (build 6000, RTM)", ttl=128, mss=1460, window=65535, wscale=None,
                    option_order=['MSS', 'NOP', 'SAckOK', 'NOP', 'Timestamp']),
        VersionRule("Windows Vista (build 6001, SP1)", ttl=128, mss=1460, window=65535, wscale=None,
                    option_order=['MSS', 'SAckOK', 'NOP', 'NOP', 'Timestamp']),
        VersionRule("Windows Vista (build 6002, SP2)", ttl=128, mss=1460, window=65535, wscale=None,
                    option_order=['MSS', 'NOP', 'SAckOK', 'NOP', 'NOP', 'Timestamp']),
        VersionRule("Windows Vista (build 6000, default window)", ttl=128, mss=1460, window=16384, wscale=None),

        # --- XP / 2000 ---
        VersionRule("Windows XP (build 2600, RTM)", ttl=128, mss=1460, window=65535, wscale=None,
                    option_order=['MSS', 'NOP', 'SAckOK']),
        VersionRule("Windows XP (build 2600, SP1)", ttl=128, mss=1460, window=65535, wscale=None,
                    option_order=['MSS', 'NOP', 'NOP', 'SAckOK']),
        VersionRule("Windows XP (build 2600, SP2)", ttl=128, mss=1460, window=65535, wscale=None,
                    option_order=['MSS', 'NOP', 'NOP', 'NOP', 'SAckOK']),
        VersionRule("Windows XP (build 2600, SP3)", ttl=128, mss=1460, window=65535, wscale=None,
                    option_order=['MSS', 'NOP', 'SAckOK', 'NOP', 'Timestamp']),
        VersionRule("Windows XP (with TCP window-scaling patch)", ttl=128, mss=1460, window=65535, wscale=2),
        VersionRule("Windows 2000 (build 2195, RTM)", ttl=128, mss=1460, window=16384, wscale=None,
                    option_order=['MSS', 'NOP', 'SAckOK']),
        VersionRule("Windows 2000 (build 2195, SP1+)", ttl=128, mss=1460, window=16384, wscale=None,
                    option_order=['MSS', 'NOP', 'NOP', 'SAckOK']),

        # --- Server ---
        VersionRule("Windows Server 2022 (build 20348)", ttl=128, wscale=8, mss=65495, window=65535,
                    option_order=['MSS', 'WScale', 'NOP', 'NOP', 'SAckOK', 'NOP', 'NOP']),
        VersionRule("Windows Server 2019 (build 17763)", ttl=128, wscale=8, mss=65495, window=8192),
        VersionRule("Windows Server 2016 (build 14393)", ttl=128, wscale=8, mss=65495, window=16384),

        # --- Banner-based fallbacks (used when banner text is available) ---
        VersionRule("Windows 11", banner_contains="windows 11"),
        VersionRule("Windows 10", banner_contains="windows 10"),
        VersionRule("Windows 10/11 (NT 10.0)", banner_contains="windows nt 10.0"),
        VersionRule("Windows 8.1 (NT 6.3)", banner_contains="windows nt 6.3"),
        VersionRule("Windows 8 (NT 6.2)", banner_contains="windows nt 6.2"),
        VersionRule("Windows 7 (NT 6.1)", banner_contains="windows nt 6.1"),
        VersionRule("Windows Vista (NT 6.0)", banner_contains="windows nt 6.0"),
        VersionRule("Windows XP (NT 5.1)", banner_contains="windows nt 5.1"),
        VersionRule("Windows 2000 (NT 5.0)", banner_contains="windows nt 5.0"),
        VersionRule("Windows Server 2022", banner_contains="windows server 2022"),
        VersionRule("Windows Server 2019", banner_contains="windows server 2019"),
        VersionRule("Windows Server 2016", banner_contains="windows server 2016"),
        VersionRule("Windows Server 2012 R2", banner_contains="windows server 2012 r2"),
        VersionRule("Windows Server 2012", banner_contains="windows server 2012"),
        VersionRule("Windows Server 2008 R2", banner_contains="windows server 2008 r2"),
        VersionRule("Windows Server 2008", banner_contains="windows server 2008"),
        VersionRule("Windows (SMB 3.1.1, 10/11/Server 2016+)", banner_contains="smb 3.1.1"),
        VersionRule("Windows (SMB 3.0, 8/Server 2012+)", banner_contains="smb 3.0"),
        VersionRule("Windows (SMB 2.1, 7/Server 2008 R2)", banner_contains="smb 2.1"),
        VersionRule("Windows (SMB 2.0, Vista/Server 2008)", banner_contains="smb 2.0"),
        VersionRule("Windows (SMB 1.x, XP/2000)", banner_contains="smb 1."),
        VersionRule("Windows 8/10/11/Server 2012+ (HTTPAPI 2.0)", banner_contains="microsoft-httpapi/2.0"),
    ],
)

SIGNATURES = [WINDOWS]