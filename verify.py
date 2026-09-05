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

from Decoration.Colors import YELLOW, RESET

def ver_ttl(ttl) -> int:
    if ttl <= 0:
        print(f"{YELLOW}\n[!] ttl cant be 0 or less, (default ttl=64){RESET}\n")
        return 64
    elif ttl > 255:
        print(f"{YELLOW}\n[!] ttl cant be more then 255, (default ttl=64){RESET}\n")
        return 64
    return ttl

def ver_ip_flags(ipf):
    if ipf in [0 ,1 ,2]:
        return ipf
    else:
        print(f"{YELLOW}\n[!] Invalid ip flag, (default DF=2){RESET}")
        return 'DF'

def ver_ip_id(ID):
    if ID < 0 or ID > 65535:
        print(f"{YELLOW}\n[!] Invalid ip id, (default 0){RESET}")
        return 0
    else:
        return ID

def ver_hlim(hlim):
    if hlim <= 0:
        print(f"{YELLOW}\n[!] hlim cant be 0 or less, (default ttl=64){RESET}\n")
        return 64
    elif hlim > 255:
        print(f"{YELLOW}\n[!] hlim cant be more then 255, (default ttl=64){RESET}\n")
        return 64

    return hlim