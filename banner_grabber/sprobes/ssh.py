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

ssh_clients = [
    b"SSH-2.0-OpenSSH_9.7\r\n",
    b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n",
    b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n",
    b"SSH-2.0-OpenSSH_8.9p1\r\n",
    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3\r\n",
    b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9\r\n",
    b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n",
    b"SSH-2.0-OpenSSH_7.4\r\n",
    b"SSH-2.0-OpenSSH_7.4p1 Raspbian-10+deb9u7\r\n",
    b"SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u8\r\n",
    b"SSH-2.0-OpenSSH_for_Windows_8.1\r\n",
    b"SSH-2.0-dropbear_2022.83\r\n",
    b"SSH-2.0-dropbear_2020.81\r\n",
    b"SSH-2.0-dropbear_2019.78\r\n",
    b"SSH-2.0-dropbear_2016.74\r\n",
    b"SSH-2.0-PuTTY_Release_0.81\r\n",
    b"SSH-2.0-PuTTY_Release_0.78\r\n",
    b"SSH-2.0-libssh_0.10.6\r\n",
    b"SSH-2.0-libssh2_1.11.0\r\n",
    b"SSH-2.0-libssh-0.9.6\r\n",
    b"SSH-2.0-Cisco-1.25\r\n",
    b"SSH-2.0-mpSSH_0.2.1\r\n",
    b"SSH-2.0-ROSSSH\r\n",
    b"SSH-2.0-WeOnlyDo 2.1.4\r\n",
    b"SSH-2.0-Go\r\n",
    b"SSH-2.0-paramiko_3.4.0\r\n",
    b"SSH-2.0-JSCH-0.1.55\r\n",
]

SSH_PROBES = {
    1: lambda : random.choice(ssh_clients)
}