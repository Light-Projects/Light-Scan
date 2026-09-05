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
from .Attacks.udp_flood import udp_flood_attack
from .portparser import port_parse, fisher_yates_shuffle
from Decoration.Colors import RED, GREEN, YELLOW, CYAN, RESET
import time


class AttackStats:
    def __init__(self, target, mode):
        self.target = target
        self.mode = mode
        self.start_time = time.time()
        self.packets_sent = 0
        self.bytes_sent = 0
        self.errors = 0
        self.running = True

    def update(self, packet_size):
        self.packets_sent += 1
        self.bytes_sent += packet_size

    def display(self):
        elapsed = time.time() - self.start_time
        pps = self.packets_sent / elapsed if elapsed > 0 else 0
        mbps = (self.bytes_sent * 8) / (elapsed * 1000000) if elapsed > 0 else 0

        print(f"\r{CYAN}[Stats]\n{RESET}  {YELLOW}- Packets: {RESET}{self.packets_sent}\n"
              f"  {YELLOW}- PPS: {RESET}{pps:.1f}\n"
              f"  {YELLOW}- Data: {RESET}{self.bytes_sent / 1024:.1f} KB\n"
              f"  {YELLOW}- Duration: {RESET}{elapsed:.2f}s\n",
              f" {YELLOW}- Bandwidth: {RESET}{mbps:.2f} Mbps\n"
              f"  {YELLOW}- Errors: {RESET}{self.errors}\n")


def main(Target, Count, Ports, att, hide=False, shuffle=False,
         verbose=False, quiet=False,stats=False):


    print(f"{GREEN}[+] Starting Mint attack v1.0.1{RESET}")
    print(f"{CYAN}[+] Target: {Target}{RESET}")
    print(f"{CYAN}[+] Attack Mode: {att}{RESET}")

    port_list = []
    if Ports:
        try:
            port_list = port_parse(Ports)
            if shuffle:
                port_list = fisher_yates_shuffle(port_list)
            print(f"{CYAN}[+] Ports: {len(port_list)} ports{RESET}")
            if len(port_list) <= 10:
                print(f"{CYAN}[+] Ports: {port_list}{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error parsing ports: {e}{RESET}")
            return


    stats_obj = None
    if stats:
        stats_obj = AttackStats(Target, att)
        print(f"{CYAN}[+] Statistics enabled{RESET}")

    try:
        if att == "syn-flood":
            syn_flood_attack(
                target=Target,
                ports=port_list,
                count=Count,
                hidesrc=hide,
                stats=stats_obj
            )
            if not quiet:
                print(f"\n{GREEN}[-] Mint Syn Flood Attack completed successfully{RESET}")

        elif att == "udp-flood":
            udp_flood_attack(
                target=Target,
                ports=port_list,
                count=Count,
                hidesrc=hide,
                stats=stats_obj
            )
            if not quiet:
                print(f"\n{GREEN}[-] Mint UDP Flood Attack completed successfully{RESET}")

        elif att == "mac-flood":
            mac_flood_attack(
                count=Count,
                target=Target,
                hidesrc=hide,
                stats=stats_obj
            )
            if not quiet:
                print(f"\n{GREEN}[-] Mint Mac Flood Attack completed successfully{RESET}")

        else:
            raise NotImplementedError(f"This Type is not implemented {att}")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Attack stopped by user{RESET}")

    except Exception as e:
        print(f"\n{RED}[!] Error: {e}{RESET}")
        if verbose:
            import traceback
            traceback.print_exc()

    if stats_obj and stats_obj.packets_sent > 0:
        print(f"\n{GREEN}[+] Final Statistics:{RESET}\n")
        stats_obj.display()
