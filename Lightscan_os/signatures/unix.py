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
Generic commercial/SysV Unix signature: Solaris, AIX, HP-UX and similar.
These are grouped together because they're rare in the wild today and
share the hallmark trait of shipping with a high default TTL (255) and
conservative/legacy TCP option sets.
"""

from .base import OSSignature, VersionRule

UNIX = OSSignature(
    name="Unix (Solaris/AIX/HP-UX)",
    family="unix",
    common_orders=[
        ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'Timestamp', 'SAckOK'],
        ['MSS', 'SAckOK'],
        ['MSS', 'NOP', 'NOP', 'SAckOK'],
    ],
    windows=[8760, 24820, 49152, 65535],
    ttl_range=(200, 255),
    hlim_range=(200, 255),
    wscale_values=[0, 1],
    mss_values=[1460, 1380],
    timestamp_high=False,
    icmp_default_ttl=255,
    udp_closed_port_quirk="icmp_ttl_255_sysv_style",
    banner_keywords=[
        ("solaris", 20),
        ("sunos", 20),
        ("aix", 20),
        ("hp-ux", 20),
        ("ibm", 8),
    ],
    service_keywords=[
        ("rpcbind", 6),
        ("nfs", 4),
    ],
    exclusive_banner_keywords=["solaris", "sunos", "aix", "hp-ux"],
    version_rules=[
        VersionRule("Oracle Solaris (from banner)", banner_contains="solaris"),
        VersionRule("SunOS (from banner)", banner_contains="sunos"),
        VersionRule("IBM AIX (from banner)", banner_contains="aix"),
        VersionRule("HP-UX (from banner)", banner_contains="hp-ux"),
    ],
)

SIGNATURES = [UNIX]