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
Script Name : http-past-pages
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --domain
Categorie : safe/discovery/http_https
"""

import requests

def get_wayback_snapshots(domain, limit=10):
    url = f"https://archive.org/wayback/available?url={domain}"

    try:
        response = requests.get(url, timeout=10)
        data = response.json()

        if 'archived_snapshots' in data:
            snapshots = []
            for timestamp, info in data['archived_snapshots'].items():
                snapshots.append({
                    'timestamp': timestamp,
                    'url': info['url'],
                    'status': info.get('status', 'unknown')
                })
            return snapshots[:limit]
        return []
    except Exception as e:
        print(f"[-] Wayback API error: {e}")
        return []

def main(domain):
    print(f"\n[*] Checking Wayback for: {domain}\n")

    snapshots = get_wayback_snapshots(domain)

    if snapshots:
        print(f"[+] Found {len(snapshots)} snapshots")
        for snap in snapshots:
            print(f"    - {snap['timestamp']}: {snap['url']}")
    else:
        print("[-] No snapshots found")
