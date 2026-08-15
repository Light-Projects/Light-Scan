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

parser = argparse.ArgumentParser(description="Mint Attack utility")
parser.add_argument("-T", "--target", help="Target IP or Hostname")
parser.add_argument("-c", required=True,type=int, help="packet count per port")
parser.add_argument("-hi", required=False, help="Hide Source IP using random ones",action="store_true")
parser.add_argument("-p","--port", help="Port/s to Attack")
parser.add_argument("-s","--shufle",help="Shufle ports order",action="store_true")
parser.add_argument("--attack-mode",help="type of attack used for testing",default="syn-flood",
                    choices=['syn-flood','mac-flood'])
args = parser.parse_args()

if __name__ == "__main__":
    main(args.target,args.c,args.port,args.attack_mode,args.hi,args.shufle)
