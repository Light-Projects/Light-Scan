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

import os
from pathlib import Path
from confparser import ds_parser
import yaml
import sys

reset = "\033[0m"
green = "\033[32m"
yellow = "\033[33m"
red = "\033[31m"

dscripts ,sscripts= ds_parser()
dscripts = [item.replace(" ", "") for item in dscripts]
sscripts = [item.replace(" ", "") for item in sscripts]

def script_list() -> None:
    confs = os.listdir(str(Path(__file__).parent) + "/metadata")
    i = 1
    print(f"""
{green}[+] LSSE Scripts (LightScan Scripting Engine){reset}
{'-' * 50}
    """)
    for conf in confs:
        with open(str(Path(__file__).parent) + f"/metadata/{conf}", 'r') as f:
            data = yaml.safe_load(f)
        print(f"""
{yellow}[{i}] {data['script_name']}{reset}
    Required:      {data['args']['required']}
    Optional:      {data['args']['optional']}
    Category:      {data['args']['category']}
    Description:   {data['description']}
""")
        i += 1
    print(f"""
{'-' * 50}
{green}[+] Usage: python Lightscan.py --lsse --script <name> {reset}
""")
    sys.exit(0)

def script_help(scriptstr: str) -> None:
    try:
        i = 1
        print(f"""
{green}[+] LSSE Scripts (LightScan Scripting Engine){reset}
{'-' * 50}
""")
        scripts = scriptstr.replace("-","_").split(",")
        for script in scripts:
            with open(str(Path(__file__).parent) + f"/metadata/{script}.yaml", 'r') as f:
                data = yaml.safe_load(f)
            print(f"""
{yellow}[{i}] {data['script_name']}{reset}
    Required:      {data['args']['required']}
    Optional:      {data['args']['optional']}
    Category:      {data['args']['category']}
    Description:   {data['description']}
        """)
            i += 1
        print(f"""
{'-' * 50}
{green}[+] Usage: python Lightscan.py --lsse --script <name> {reset}
        """)
        sys.exit(0)
    except Exception as e:
        print(e)
        sys.exit(0)
