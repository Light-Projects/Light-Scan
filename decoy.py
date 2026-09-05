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

from typing import List
from LightMirage import mirage
import random

def decoy(decoy_str: str,version: int) -> List[str]:
    try:
        if "RANDOM-" in decoy_str:
            decoy_str = int(decoy_str.replace("RANDOM-",""))
            decoy_machines = []
            for i in range(decoy_str):
                if version == 4:
                    decoy_machines.append(mirage.ipv4_random())
                else:
                    decoy_machines.append(mirage.ipv6_random())
        else:
            decoy_machines = decoy_str.split(",")

        return decoy_machines
    except:
        if version == 4:
            return [mirage.ipv4_random()]
        else:
            return [mirage.ipv6_random()]

def decoy_order(decoy_machines: List[str]):
    num = len(decoy_machines)
    if num == 1:
        fol = random.choice([1,2])
        if fol == 1:
            return True,False,0
        else:
            return False,True,0
    else:
        fol = random.choice(range(num))
        if fol == num:
            fol = random.choice([1, 2])
            if fol == 1:
                return True, False, 0
            else:
                return False, True, 0
        elif fol == 0:
            fol = random.choice([1, 2])
            if fol == 1:
                return True, False, 0
            else:
                return False, True, 0
        else:
            return True, True, fol