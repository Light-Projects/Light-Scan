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

from Decoration.Colors import RED, RESET
from Services import top_20_tcp_ports
import random

red = RED
reset = RESET

def port_parse(ports):
    if "-" in ports and "," not in ports:
        try:
            sport , eport = ports.split("-")
            sport = int(sport)
            eport = int(eport)
            port_validation_1(sport, eport)
            if type(sport) == int and type(eport) == int:
                ports_to_scan = list(range(int(sport), int(eport) + 1))
                return ports_to_scan
            else:
                print(f"{red}\n[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
                return top_20_tcp_ports
        except:
            print(f"{red}\n[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
            return top_20_tcp_ports

    elif "," in ports and "-" not in ports:
        try:
            port_list = ports.split(",")
            ports_to_scan = []
            for port in port_list:
                port = int(port)
                port_validation_2(port)
                if type(port) == int :
                    ports_to_scan.append(port)
                else:
                    print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            return ports_to_scan
        except:
            print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")

    elif "," in ports and "-" in ports:
        try:
            port_list = ports.split(",")
            ports_to_scan = []
            for port in port_list:
                if "-" in port:
                    try:
                        sport, eport = port.split("-")
                        sport = int(sport)
                        eport = int(eport)
                        port_validation_1(sport, eport)
                        if type(sport) == int and type(eport) == int:
                            ports_to_scan.extend(list(range(int(sport), int(eport) + 1)))
                        else:
                            print(f"\n{red}[!] Invalid ports range {reset}\n")
                            exit(1)
                    except:
                        print(f"\n{red}[!] Invalid ports range {reset}\n")
                        exit(1)
                else:
                    port = int(port)
                    port_validation_2(port)
                    if type(port) == int :
                        ports_to_scan.append(port)
                    else:
                        print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")
            return ports_to_scan
        except:
            print(f"\n{red}[!] Invalid port, Lightscan is going to skip that one <{port}>{reset}\n")

    else:
        try:
            port = int(ports)
            ports_to_scan = []
            port_validation_2(port)
            if type(port) == int :
                ports_to_scan.append(int(port))
            else:
                print(f"\n{red}[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
                ports_to_scan = top_20_tcp_ports
            return ports_to_scan
        except:
            print(f"\n{red}[!] Invalid ports range, Lightscan is going to use default values {reset}\n")
            ports_to_scan = top_20_tcp_ports
            return ports_to_scan

    if len(ports) <= 0:
        print(f"\n{red}[!] Invalid Port/s, Lightscan is going to use default values {reset}")
        ports_to_scan = top_20_tcp_ports
        return ports_to_scan
    else:
        pass

def port_validation_1(sport,eport):
        if sport < 0:
            print(f"\n{red}[!] Invalid Starting Port{reset}\n")
            exit(1)
        elif eport < 0:
            print(f"\n{red}[!] Invalid Ending Port{reset}\n")
            exit(1)
        elif eport < sport:
            print(f"\n{red}[!] Invalid Port Range{reset}\n")
            exit(1)
        elif eport > 65535:
            print(f"\n{red}[!] Invalid Ending Port{reset}\n")
            exit(1)
        else:
            pass

def port_validation_2(port):
        if port < 0 or port > 65535:
            print(f"\n{red}[!] Invalid Starting Port{reset}\n")
            exit(1)
        elif type(port) != int:
            print(f"\n{red}[!] Invalid Starting Port{reset}\n")
            exit(1)
        else:
            pass

def fisher_yates_shuffle(lst):
    for i in range(len(lst) - 1, 0, -1):
        j = random.randint(0, i)
        lst[i], lst[j] = lst[j], lst[i]
    return lst
