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
Author : Adam Boulaaz, ognamgeek
Arguments
--> Required Arguments
----> --domain
----> -sp
--> Optional Arguments
----> --redirect
Category:   safe/analysis/http_https
"""

import requests


def check_cookies(domain: str, port: int = 80, redirect: bool = False) -> bool:
    protocol = 'https' if port == 443 else 'http'
    url = f"{protocol}://{domain}:{port}"


    print(f"\n[*] Fetching cookies from: {url}")

    try:
        response = requests.get(url, timeout=10, allow_redirects=redirect)
        cookies = response.cookies

        if not cookies:
            print("\n[+] No cookies found")
            return True

        print(f"\n[+] Cookie Analysis for {url}")
        print("-" * 50)

        issues = []
        secure_count = 0
        httponly_count = 0
        total = len(cookies)

        for cookie in cookies:
            secure = cookie.secure
            httponly = cookie.has_nonstandard_attr('HttpOnly')

            print(f"\n [*] {cookie.name}")
            print(f"     Value: {cookie.value}")
            print(f"     Secure: {'+' if secure else '-'}")
            print(f"     HttpOnly: {'+' if httponly else '-'}")

            if secure:
                secure_count += 1
            else:
                issues.append(f"{cookie.name} missing Secure flag")

            if httponly:
                httponly_count += 1
            else:
                issues.append(f"{cookie.name} missing HttpOnly flag")

        print("\n[+] Summary:")
        print("-" * 50)
        print(f"    Total cookies: {total}")
        print(f"    Secure flag: {secure_count}/{total} ({secure_count/total*100:.1f}%)")
        print(f"    HttpOnly flag: {httponly_count}/{total} ({httponly_count/total*100:.1f}%)")

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

def run(domain: str, port: int = 80, redirect: bool = False) -> None:
    print(f"\n[+] Cookie Security Scan for {domain}")
    print("-" * 50)

    success = check_cookies(domain, port, redirect)

    if success:
        print("\n[+] Cookie scan completed successfully")
    else:
        print("\n[-] Cookie scan failed")

