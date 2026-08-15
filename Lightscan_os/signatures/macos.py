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
macOS (Darwin/BSD-derived) family signature.
"""

from .base import OSSignature, VersionRule

MACOS = OSSignature(
    name="macOS",
    family="macos",
    common_orders=[
        ['MSS', 'NOP', 'NOP', 'SAckOK', 'Timestamp', 'NOP', 'WScale'],
        ['MSS', 'SAckOK', 'Timestamp', 'WScale'],
        ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'Timestamp', 'SAckOK'],
    ],
    windows=[65535, 32768, 131072, 262144],
    ttl_range=(63, 64),
    hlim_range=(63, 64),
    wscale_values=[5, 6],
    mss_values=[1460],
    timestamp_high=True,
    icmp_default_ttl=64,
    udp_closed_port_quirk="icmp_ttl_64_darwin_style",
    banner_keywords=[
        ("darwin", 20),
        ("macos", 20),
        ("mac os x", 20),
        ("afpovertcp", 15),
        ("apple", 10),
        ("cups/", 8),
    ],
    service_keywords=[
        ("afp", 12),
        ("airplay", 12),
        ("raop", 10),
    ],
    exclusive_banner_keywords=["darwin", "mac os x", "afpovertcp"],
    version_rules=[
        VersionRule("macOS (Sonoma/Sequoia era, OpenSSH 9.x)", banner_contains="openssh_9"),
        VersionRule("macOS (Monterey/Ventura era, OpenSSH 8.6-8.9)", banner_contains="openssh_8"),
        VersionRule("macOS (Catalina/Big Sur era, OpenSSH 7.9-8.1)", banner_contains="openssh_7"),
        VersionRule("macOS (older, OpenSSH 6.x)", banner_contains="openssh_6"),
    ],
)

SIGNATURES = [MACOS]