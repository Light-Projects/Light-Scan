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
Script Name : http-methods
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --domain
----> -sp
Categorie : safe/discovery/http_https
"""

import requests

DANGEROUS_METHODS = {
    'PUT': 'Allows file uploads — risk of unauthorized file creation',
    'DELETE': 'Allows file deletion — risk of data loss',
    'TRACE': 'Allows XST attacks (Cross-Site Tracing)',
    'TRACK': 'Allows XST attacks (Cross-Site Tracing)',
    'CONNECT': 'Allows tunneling — risk of proxy abuse',
    'PATCH': 'Allows partial updates — risk of unauthorized modification'
}

SAFE_METHODS = {
    'GET': 'Retrieves resources (expected)',
    'HEAD': 'Retrieves headers only (expected)',
    'POST': 'Submits data (expected)',
    'OPTIONS': 'Returns allowed methods (expected)'
}

def check_methods(domain, port=80):
    protocol = 'https' if port == 443 else 'http'
    url = f"{protocol}://{domain}:{port}"

    print(f"\n[*] Testing methods on: {url}")

    try:
        options_response = requests.options(url, timeout=10)

        allowed = []
        if 'Allow' in options_response.headers:
            allow_header = options_response.headers['Allow']
            allowed = [m.strip().upper() for m in allow_header.split(',')]
        else:
            print("[*] No Allow header, testing individual methods...")
            common_methods = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH']
            for method in common_methods:
                try:
                    resp = requests.request(method, url, timeout=5)
                    if resp.status_code not in [405, 501]:
                        allowed.append(method)
                except:
                    pass

        if not allowed:
            print("  [!] No allowed methods detected (server may be down or blocking)")
            return False

        dangerous = []
        safe = []
        unknown = []

        for method in allowed:
            if method in DANGEROUS_METHODS:
                dangerous.append((method, DANGEROUS_METHODS[method]))
            elif method in SAFE_METHODS:
                safe.append((method, SAFE_METHODS[method]))
            else:
                unknown.append((method, 'Unknown method'))

        print(f"\n[+] HTTP Methods for {url}")
        print("-" * 50)

        print(f"\n  [+] Safe Methods ({len(safe)}):")
        for method, description in safe:
            print(f"      {method}: {description}")

        print(f"\n  [-] Dangerous Methods ({len(dangerous)}):")
        if dangerous:
            for method, risk in dangerous:
                print(f"      [!] {method}: {risk}")
        else:
            print("      [+] None found — good security posture!")

        if unknown:
            print(f"\n  [?] Unknown Methods ({len(unknown)}):")
            for method, _ in unknown:
                print(f"      {method}")


        if 'TRACE' in [m[0] for m in dangerous] or 'TRACK' in [m[0] for m in dangerous]:
            print("    [!!]  WARNING: TRACE/TRACK enabled — XST attacks possible!")
        if 'PUT' in [m[0] for m in dangerous]:
            print("    [!!]  WARNING: PUT enabled — unauthorized file uploads possible!")
        if 'DELETE' in [m[0] for m in dangerous]:
            print("    [!!]  WARNING: DELETE enabled — unauthorized file deletion possible!")

        return True

    except requests.exceptions.ConnectionError:
        print(f"  [!] Connection error: {url}")
        return False
    except requests.exceptions.Timeout:
        print(f"  [!] Timeout: {url}")
        return False
    except requests.exceptions.SSLError:
        print(f"  [!] SSL error: {url}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"  [!] Request error: {e}")
        return False
    except Exception as e:
        print(f"  [!] Error: {e}")
        return False

def run(domain, port=80):

    print(f"\n[+] HTTP Methods Scan for {domain}")
    print("-" * 50)

    success = check_methods(domain, port)

    if success:
        print("\n[+] HTTP methods scan completed successfully\n")
    else:
        print("\n[-] HTTP methods scan failed\n")


