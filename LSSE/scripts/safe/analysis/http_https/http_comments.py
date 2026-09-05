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

"""
Light-Scan Scripting Engine (LSSE)
Script Name : http-comments
Author : Adam Boulaaz, ognamgeek
Arguments
--> Required Arguments
----> --url
Categorie :safe/analysis/http_https
"""

import requests
from bs4 import BeautifulSoup
from bs4 import Comment

green = "\033[32m"
reset = "\033[0m"
yellow = "\033[33m"
red = "\033[31m"

class HttpComment:
    def __init__(self, url: str) -> None:
        self.url = url

    def start(self) -> None:
        print("\n[LSSE] Html Comments Detection Script ")

        try:
            response = requests.get(self.url, timeout=10, allow_redirects=True)
        except requests.exceptions.RequestException as exc:
            print(f"\n{red}[!] Request failed: {exc}{reset}")
            return

        if response.status_code != 200:
            print(
                f"\n{yellow}[!] Unexpected status code "
                f"{response.status_code} from {response.url}{reset}"
            )
            return

        soup = BeautifulSoup(response.content, 'html.parser')
        coms = soup.find_all(string=lambda text: isinstance(text, Comment))

        if not coms:
            print(f"\n{yellow}[!] No Comment has been Detected.{reset}")
            return

        print(f"\n{green}[+] Comment/s Detected ")
        print(f"[+] Final Url: {response.url} ")
        print(f"[+] Number of Comments {len(coms)} \n{reset}")
        for ns, script in enumerate(coms, 1):
            print(f"[#{ns}] {script}\n")

