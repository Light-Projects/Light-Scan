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

def ipv6_hlim():
    return random.randint(32,255)

def ipv6_random():
    return f"{random.randint(0, 0xFFFF):04x}:{random.randint(0, 0xFFFF):04x}:{random.randint(0, 0xFFFF):04x}:{random.randint(0, 0xFFFF):04x}:{random.randint(0, 0xFFFF):04x}:{random.randint(0, 0xFFFF):04x}:{random.randint(0, 0xFFFF):04x}:{random.randint(0, 0xFFFF):04x}"

def ipv6_flow():
    return random.randint(0,0xFFFFF)

def ipv6_tclass():
    return random.randint(0,0xFF)