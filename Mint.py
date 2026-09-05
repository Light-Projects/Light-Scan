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

from Mint.mint import main
import argparse

parser = argparse.ArgumentParser(description="Mint Attack utility",
epilog="""
COMMON EXAMPLES:\n
  Mint.py -T example.com -p 443 --shufle -c 100
  Mint.py -T 00:1B:21:4A:8C:3F --attack-mode mac-flood -c 100 -hi
""",
formatter_class=argparse.RawDescriptionHelpFormatter)
basic = parser.add_argument_group("Basic Options")
basic.add_argument("-T", "--target", help="Target IP or Hostname")
basic.add_argument("-c", required=True,type=int, help="packet count per port")
basic.add_argument("-hi", required=False, help="Hide Source IP using random ones",action="store_true")
basic.add_argument("-p","--port", help="Port/s to Attack")
basic.add_argument("-s","--shufle",help="Shufle ports order",action="store_true")
basic.add_argument("-q", help="Quiet mode",action="store_true")
basic.add_argument("-v",help="Verbose mode",action="store_true")
basic.add_argument("--stats",help="Attack statistiques",action="store_true")
basic.add_argument("--attack-mode",help="type of attack used for testing",default="syn-flood",
                    choices=['syn-flood','mac-flood','udp-flood'])
args = parser.parse_args()

if __name__ == "__main__":
    main(
        Target=args.target,
        Count=args.c,
        Ports=args.port,
        att=args.attack_mode,
        hide=args.hi,
        shuffle=args.shufle,
        quiet=args.q,
        verbose=args.v,
        stats=args.stats,
    )
