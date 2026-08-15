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

import random

def random_payloads():
    payloads = ["PING", "URGENT", "!HHHH", "LIGHTSCAN", "UDP", "TCP", "-Pu", "KIWI", "-PE", "-PP", "-PM", "-PS", "-PA", "-PY",
     "-PO", "-sn", "-Pn", "-sL", "-n", "-R", "-sS", "-sT", "-sU", "-sN", "-sF", "-sX", "-sA", "-sW", "-sM", "-sZ",
     "-sO", "-sI", "--scanflags", "-b", "PWNED", "TESTING", "FUZZME", "BYPASS", "INJECT", "<script>", "\"><script>",
     "'; DROP TABLE--", "admin' OR '1'='1", "../etc/passwd", "%00", "%0d%0a", "\\x00", "\\x0d\\x0a", "AAAA", "BBBB",
     "CCCC", "ZZZZ", "ICMP", "DNS", "HTTP", "HTTPS", "FTP", "SSH", "TELNET", "SMTP", "SNMP", "RDP", "NTP", "DHCP",
     "RADIUS", "LDAP", "SMB", "NFS", "MYSQL", "POSTGRES", "REDIS", "MONGODB", "ORACLE", "SYBASE", "SQLITE", "JAVA",
     "PYTHON", "PHP", "RUBY", "PERL", "BASH", "POWERSHELL", "CMD", "SHELL", "ROOT", "ADMIN", "SYSTEM", "LOCALHOST",
     "127.0.0.1", "0.0.0.0", "::1", "localhost.localdomain"]

    return payloads

def random_payload():
    payloads = random_payloads()
    return random.choice(payloads)

def badsum():
    return random.randint(0, 0xFFFF)
