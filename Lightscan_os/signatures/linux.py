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
Linux family signature. Kernel-version pinning from raw TCP fingerprints
alone is unreliable (distros patch net/ipv4 differently), so version hints
here lean on service banners (OpenSSH string, distro tags) rather than
guessing a kernel build number from window size.
"""

from .base import OSSignature, VersionRule

LINUX = OSSignature(
    name="Linux",
    family="linux",
    common_orders=[
        ['MSS', 'SAckOK', 'Timestamp', 'WScale'],
        ['MSS', 'SAckOK', 'Timestamp', 'NOP', 'WScale'],
        ['MSS', 'WScale', 'SAckOK', 'Timestamp'],
        ['MSS', 'NOP', 'WScale', 'NOP', 'NOP', 'SAckOK', 'Timestamp'],
        ['MSS', 'Timestamp', 'SAckOK', 'WScale'],
        ['MSS', 'SAckOK', 'Timestamp', 'NOP', 'NOP', 'WScale'],
    ],
    windows=[5720, 29200, 65535, 64240, 32120, 65160, 14600],
    ttl_range=(60, 64),
    hlim_range=(60, 64),
    wscale_values=[7, 13, 14],
    mss_values=[1380, 1460],
    timestamp_high=True,
    icmp_default_ttl=64,
    udp_closed_port_quirk="icmp_ttl_64_quoted_payload",
    banner_keywords=[
        ("openssh", 10),
        ("gws",20),
        ("apache", 15),
        ("nginx", 15),
        ("vsftpd", 15),
        ("proftpd", 15),
        ("pure-ftpd", 15),
        ("ubuntu", 20),
        ("debian", 20),
        ("centos", 20),
        ("red hat", 18),
        ("fedora", 18),
        ("dnsmasq", 5),
    ],
    service_keywords=[
        ("ssh", 15),
        ("http", 10),
    ],
    exclusive_banner_keywords=["ubuntu", "debian", "centos", "red hat", "fedora"],
    version_rules=[
        VersionRule("Ubuntu (from banner)", banner_contains="ubuntu"),
        VersionRule("Debian (from banner)", banner_contains="debian"),
        VersionRule("CentOS (from banner)", banner_contains="centos"),
        VersionRule("Red Hat Enterprise Linux (from banner)", banner_contains="red hat"),
        VersionRule("Fedora (from banner)", banner_contains="fedora"),
        VersionRule("Linux w/ OpenSSH 9.x (kernel 5.x/6.x era)", banner_contains="openssh_9"),
        VersionRule("Linux w/ OpenSSH 8.x (kernel 4.x/5.x era)", banner_contains="openssh_8"),
        VersionRule("Linux w/ OpenSSH 7.x (kernel 3.x/4.x era)", banner_contains="openssh_7"),
        VersionRule("Linux w/ OpenSSH 6.x (older, kernel 2.6.x/3.x era)", banner_contains="openssh_6"),
    ],
)

SIGNATURES = [LINUX]
