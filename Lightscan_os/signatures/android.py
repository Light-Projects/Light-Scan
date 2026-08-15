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
Android (Linux kernel derivative) signature. Kept separate from the
generic Linux signature because Android's userspace networking stack
(dnsmasq tethering, mDNSResponder-lite, ADB) gives distinct banner and
service tells that a stock desktop/server Linux box won't show.
"""

from .base import OSSignature, VersionRule

ANDROID = OSSignature(
    name="Android",
    family="android",
    common_orders=[
        ['MSS', 'SAckOK', 'Timestamp', 'NOP', 'WScale'],
        ['MSS', 'SAckOK', 'Timestamp', 'WScale'],
        ['MSS', 'NOP', 'WScale', 'NOP', 'SAckOK', 'Timestamp'],
    ],
    windows=[65535, 29200, 64240, 14600, 32120, 8760],
    ttl_range=(64, 64),
    hlim_range=(64, 64),
    wscale_values=[8],
    mss_values=[1460],
    timestamp_high=True,
    ip_id_zero=True,
    icmp_default_ttl=64,
    udp_closed_port_quirk="icmp_ttl_64_quoted_payload",
    banner_keywords=[
        ("dnsmasq", 15),
        ("android", 20),
        ("adb", 15),
    ],
    service_keywords=[
        ("adb", 20),
        ("dnsmasq", 10),
    ],
    exclusive_banner_keywords=["android", "adb"],
    version_rules=[
        VersionRule("Android (from banner)", banner_contains="android"),
        VersionRule("Android tethering hotspot (dnsmasq)", banner_contains="dnsmasq"),
        VersionRule("Android debug bridge exposed (adb)", banner_contains="adb"),
    ],
)

SIGNATURES = [ANDROID]