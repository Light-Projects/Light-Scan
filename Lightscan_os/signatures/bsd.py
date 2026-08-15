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
BSD family signature (FreeBSD / OpenBSD / NetBSD). FreeBSD version pinning
uses the OpenSSH portable release date embedded in some banner strings,
same technique the original single-file version used.
"""

from .base import OSSignature, VersionRule

BSD = OSSignature(
    name="BSD",
    family="bsd",
    common_orders=[
        ['MSS', 'NOP', 'WScale', 'SAckOK', 'Timestamp'],
        ['MSS', 'SAckOK', 'Timestamp', 'WScale'],
        ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK', 'Timestamp'],
        ['MSS', 'WScale', 'SAckOK', 'Timestamp'],
        ['MSS', 'NOP', 'WScale', 'Timestamp', 'SAckOK'],
    ],
    windows=[65535, 57344, 29200, 16384, 8760, 17520],
    ttl_range=(64, 64),
    hlim_range=(64, 64),
    wscale_values=[6],
    mss_values=[1460],
    timestamp_high=True,
    ip_id_sequential=True,
    icmp_default_ttl=64,
    udp_closed_port_quirk="icmp_ttl_64_bsd_style",
    banner_keywords=[
        ("freebsd", 20),
        ("openbsd", 20),
        ("netbsd", 20),
        ("hpn13v11", 15),
        ("hpn14v", 15),
    ],
    service_keywords=[
        ("pf", 3),
    ],
    exclusive_banner_keywords=["freebsd", "openbsd", "netbsd"],
    version_rules=[
        # FreeBSD OpenSSH portable release-date tags
        VersionRule("FreeBSD 10.4-RELEASE", banner_contains="20170902"),
        VersionRule("FreeBSD 10.3-RELEASE", banner_contains="20160310"),
        VersionRule("FreeBSD 9.3-RELEASE | 10.1-10.2-RELEASE", banner_contains="20140420"),
        VersionRule("FreeBSD 9.2-RELEASE", banner_contains="20140131"),
        VersionRule("FreeBSD 9.1-RELEASE", banner_contains="20130630"),
        VersionRule("FreeBSD 9.0-RELEASE", banner_contains="20121220"),
        VersionRule("FreeBSD 8.3-RELEASE", banner_contains="20120630"),
        VersionRule("FreeBSD 8.2-RELEASE", banner_contains="20111222"),
        VersionRule("FreeBSD 8.1-RELEASE", banner_contains="20110225"),
        VersionRule("FreeBSD 8.0-RELEASE", banner_contains="20101124"),
        VersionRule("FreeBSD 7.2-RELEASE", banner_contains="20091128"),
        VersionRule("FreeBSD 7.1-RELEASE", banner_contains="20090104"),
        VersionRule("FreeBSD 7.0-RELEASE", banner_contains="20080228"),
        VersionRule("FreeBSD 9.x/10.x (OpenSSH 6.6)", banner_contains="openssh_6.6"),
        VersionRule("FreeBSD 10.4-RELEASE (OpenSSH 7.3)", banner_contains="openssh_7.3"),
        VersionRule("FreeBSD 10.3-RELEASE (OpenSSH 7.2)", banner_contains="openssh_7.2"),
        VersionRule("FreeBSD 8.x (OpenSSH 5.x)", banner_contains="openssh_5"),
        VersionRule("FreeBSD 7.x (OpenSSH 4.x)", banner_contains="openssh_4"),
        VersionRule("OpenBSD (from banner)", banner_contains="openbsd"),
        VersionRule("NetBSD (from banner)", banner_contains="netbsd"),
        VersionRule("FreeBSD (unknown version)", banner_contains="freebsd"),
    ],
)

SIGNATURES = [BSD]