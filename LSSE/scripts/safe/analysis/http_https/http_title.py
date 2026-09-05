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
Script Name : http-title
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --domain
----> -sp
--> Optional Arguments
----> --redirect
Categorie :safe/analysis/http-https
"""



import requests
import urllib3
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"
Data = {}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def init(port):
    global Data
    Data[port] = {
        'Data': ''
    }

def http_title(host, port, redirect=False):
        global Data
        Data[port]['Data'] += f"\n  [Port {port}]\n\n"

        for protocol in ['http', 'https']:
            url = f"{protocol}://{host}:{port}"

            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "DNT": "1",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                    "Cache-Control": "max-age=0",
                    "TE": "trailers",
                }
                response = requests.get(
                    url,
                    allow_redirects=redirect,
                    timeout=5,
                    verify=False,
                    headers=headers
                )

                server_header = response.headers.get('Server')

                Data[port]['Data'] += f"     [Protocole] {protocol.upper()} : [Status Code] {response.status_code} : [Server] {server_header} \n"

                if response.status_code:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title = soup.title
                    if title and title.string:
                        Data[port]['Data'] += f"     [Title] {title.string.strip()[:50]}...\n\n"
                    else:
                        Data[port]['Data'] += "     [Title] No title\n\n"
                else:
                    Data[port]['Data'] += f"   [Error] : No Response from {url}\n\n"

            except requests.exceptions.SSLError:
                Data[port]['Data'] += f"     [Protocole] {protocol.upper()}: {red}SSL Error{reset}\n\n"
            except requests.exceptions.ConnectionError:
                Data[port]['Data'] += f"     [Protocole] {protocol.upper()}: {yellow}Connection failed{reset}\n\n"
            except Exception as e:
                Data[port]['Data'] += f"     [Protocole] {protocol.upper()}: {red}{e}{reset}\n\n"

def threaded_http_title(host, ports, redirect=False):
    start = time.time()

    if redirect == None:
        redirect = False
    else:
        pass

    if host == None:
        print(f"\n{yellow}[LSSE] No url was assagned for script {reset}\n")
        exit()
    else:
        pass

    for port in ports:
        init(port)

    with ThreadPoolExecutor(max_workers=60) as executor:
        futures = []
        for port in ports:
            future = executor.submit(http_title, host, port,redirect)
            futures.append(future)

        for future in as_completed(futures):
            try:
                future.result(timeout=10)
            except Exception as e:
                print(f"{red}[!] Error in thread: {e}{reset}")

    for port in sorted(ports):
        print(Data[port]['Data'])

    end = time.time()
    elapsed = end - start
    print(f"\n[+] LSSE Finished in {elapsed:.2f} seconds")
