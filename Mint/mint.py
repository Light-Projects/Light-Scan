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

from .Attacks.syn_flood import syn_flood_attack
from .Attacks.mac_flood import mac_flood_attack
from .portparser import port_parse, fisher_yates_shuffle

def main(Target,Count,Ports,att,hide=False,shufle=False):


    print("\n[+] Start Mint ")
    
    try:
        if att == "syn-flood":
            if shufle:
                Ports = fisher_yates_shuffle(port_parse(Ports))
            else:
                Ports = port_parse(Ports)
            syn_flood_attack(Target,Ports,Count,hide)
            print("\n[-] Mint Syn Flood Attack run succesfully .\n\n")
        elif att == "mac-flood":
            mac_flood_attack(Count,target=Target,hidesrc=hide)
            print("\n[-] Mint Mac Flood Attack run succesfully .\n\n")
        else:
            raise NotImplementedError(f"This Type is not implemented {att}")
    except Exception as e:
        print(f"\n[!] Error: {e}\n")
