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
Script Name : http-headers
Author : Adam Boulaaz
Arguments
--> Required Arguments
----> --domain
----> -sp
--> Optional Arguments
----> --redirect
Category:   safe/analysis/http_https
"""

import requests

SECURITY_HEADERS = {
    'Strict-Transport-Security': 'Enforces HTTPS (HSTS)',
    'X-Frame-Options': 'Prevents clickjacking',
    'X-Content-Type-Options': 'Prevents MIME type sniffing',
    'Referrer-Policy': 'Controls referrer information',
    'Content-Security-Policy': 'Prevents XSS and data injection',
    'X-XSS-Protection': 'Legacy XSS protection (older browsers)',
    'Permissions-Policy': 'Controls browser features (geolocation, camera, etc.)'
}

def check_security_headers(headers):
    present = []
    missing = []

    for header, description in SECURITY_HEADERS.items():
        if header in headers:
            present.append((header, headers[header], description))
        else:
            missing.append((header, description))

    return present, missing

def run(domain, port=80, redirect=False):
    protocol = 'https' if port == 443 else 'http'
    url = f"{protocol}://{domain}:{port}"

    print(f"\n[*] Fetching headers from: {url}")

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=redirect,
            verify=True
        )

        headers = response.headers
        status_code = response.status_code
        server = headers.get('Server', 'Unknown')
        content_type = headers.get('Content-Type', 'Unknown')

        print(f"\n[+] Headers for {url}")
        print("-" * 50)
        print(f"    Status Code: {status_code}")
        print(f"    Server: {server}")
        print(f"    Content-Type: {content_type}")
        print()

        print("[*] All Headers:")
        print("-" * 40)
        for key, value in sorted(headers.items()):
            print(f"    {key}: {value}")
        print()

        print("[+] Security Headers Analysis")
        print("-" * 50)

        present, missing = check_security_headers(headers)

        if present:
            print(f"\n  [+] Present ({len(present)} headers):")
            for header, value, description in present:
                print(f"      {header}: {value}")
                print(f"        → {description}")
        else:
            print("\n  [!!] No security headers found!")

        if missing:
            print(f"\n  [!] Missing ({len(missing)} headers):")
            for header, description in missing:
                print(f"      {header}")
                print(f"        → {description}")
        print()
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
