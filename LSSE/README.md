# LSSE Documentation - Complete Guide

## Overview

LSSE (Light-Scan Scripting Engine) is a modular scripting framework that extends Lightscan's capabilities with Python-based scripts. It features a dynamic routing system, metadata-driven discovery, and a GUI manager for easy script creation and management.

---

# Part 1: Script List & Documentation

## Script Categories

| Category | Description |
|----------|-------------|
| **safe** | Non-intrusive scripts (information gathering) |
| **medium** | Potentially intrusive scripts (brute-force, enumeration) |
| **dangerous** | Exploitation scripts (reserved for future use) |

---

## HTTP/HTTPS Scripts

### 1. http-request
**Category:** `safe/analysis/http_https`

Send raw HTTP requests to a target.

**Required Arguments:**
- `--starget` - Target host
- `-sp` - Target port

**Optional Arguments:**
- `--request` - Raw HTTP request string
- `--file` - Path to file containing raw HTTP request
- `--ssl` - Enable SSL/TLS encryption

**Example:**
```bash
Lightscan.py --lsse --script http-request --starget example.com -sp 443 --ssl --file request.http
```

**File Format (`request.http`):**
```
GET / HTTP/1.1\r
Host: example.com\r
User-Agent: Mozilla/5.0\r
Connection: close\r\n\r\n
```

---

### 2. http-title
**Category:** `safe/discovery/http_https`

Extract webpage titles from HTTP/HTTPS ports.

**Required Arguments:**
- `--domain` - Target domain
- `-sp` - Target port(s)

**Optional Arguments:**
- `--redirect` - Follow redirects

**Example:**
```bash
Lightscan.py --lsse --script http-title --domain example.com -sp 80,443
```

**Output:**
```
[Port 80]
  [Protocol] HTTP : [Status Code] 200 : [Server] nginx/1.18.0
  [Title] Example Domain
```

---

### 3. http-headers
**Category:** `safe/analysis/http_https`

Fetch HTTP headers and check for missing security headers.

**Required Arguments:**
- `--domain` - Target domain
- `-sp` - Target port

**Optional Arguments:**
- `--redirect` - Follow redirects

**Example:**
```bash
Lightscan.py --lsse --script http-headers --domain example.com -sp 443
```

**Output:**
```
[+] Security Headers Analysis
  [+] Present:
      Strict-Transport-Security: max-age=31536000
        → Enforces HTTPS (HSTS)
  [!] Missing:
      X-Frame-Options
        → Prevents clickjacking
```

**Checked Security Headers:**
- `Strict-Transport-Security` (HSTS)
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Content-Security-Policy`
- `X-XSS-Protection`
- `Permissions-Policy`

---

### 4. http-cookie
**Category:** `safe/analysis/http_https`

Check cookies for Secure and HttpOnly flags.

**Required Arguments:**
- `--domain` - Target domain
- `-sp` - Target port

**Optional Arguments:**
- `--redirect` - Follow redirects

**Example:**
```bash
Lightscan.py --lsse --script http-cookie --domain example.com -sp 443
```

**Output:**
```
[+] Cookie Analysis for https://example.com:443
 [*] sessionid
     Value: abc123xyz
     Secure: +
     HttpOnly: +
 [*] user_pref
     Value: dark_mode
     Secure: -
     HttpOnly: -

[+] Summary:
    Total cookies: 2
    Secure flag: 1/2 (50.0%)
    HttpOnly flag: 1/2 (50.0%)
```

---

### 5. http-methods
**Category:** `safe/discovery/http_https`

Check which HTTP methods are allowed by the server.

**Required Arguments:**
- `--domain` - Target domain
- `-sp` - Target port

**Example:**
```bash
Lightscan.py --lsse --script http-methods --domain example.com -sp 80
```

**Output:**
```
[+] HTTP Methods for example.com:80
  [+] Safe Methods (3):
      GET: Retrieves resources (expected)
      HEAD: Retrieves headers only (expected)
      OPTIONS: Returns allowed methods (expected)
  [-] Dangerous Methods (2):
      [!] PUT: Allows file uploads — risk of unauthorized file creation
      [!] DELETE: Allows file deletion — risk of data loss
```

---

### 6. http-robots
**Category:** `safe/discovery/http_https`

Fetch and parse `robots.txt` for hidden paths.

**Required Arguments:**
- `--domain` - Target domain
- `-sp` - Target port(s)

**Example:**
```bash
Lightscan.py --lsse --script http-robots --domain example.com -sp 80,443
```

**Output:**
```
[Port 80]
  [Protocol] HTTP: [Status Code] 200
  [Analysis]
      [Disallowed Entries (3)]  ['/admin', '/private', '/backup']
      [Commented Disallows (0)] []
      [Allows Entries (1)]      ['/public']
      [Total Lines] 15
  [Robots.txt] :
User-agent: *
Disallow: /admin
Disallow: /private
Disallow: /backup
Allow: /public
```

---

### 7. http-dir
**Category:** `medium/discovery/http_https`

Brute-force directories and files on a web server.

**Required Arguments:**
- `--url` - Target URL

**Optional Arguments:**
- `--wordlist` - Custom wordlist file or comma-separated list
- `--status-codes` - Status codes to consider (default: 200,301,302,400,403)
- `--extensions` - File extensions to test (default: php,asp,aspx,jsp,html,txt)

**Example:**
```bash
Lightscan.py --lsse --script http-dir --url https://example.com --extensions php,html,txt --status-codes 200,301,302,403
```

**Output:**
```
[+] HTTP Directory Brute Force Started
[+] Target: https://example.com
[+] Wordlist: 2306 base paths × 3 extensions = 6918 total

[*] Progress: 6918/6918 (100.0%) | Found: 29

[200] Found 5 items:
    https://example.com/robots.txt (602 bytes)
    https://example.com/index.php (19640 bytes)
    https://example.com/admin.php (7308 bytes)

[301] Found 19 items:
    https://example.com/docs (302 bytes)
    https://example.com/images (304 bytes)
```

---

### 8. http-past-pages
**Category:** `safe/discovery/http_https`

Check Wayback Machine for historical page changes.

**Required Arguments:**
- `--domain` - Target domain

**Example:**
```bash
Lightscan.py --lsse --script http-past-pages --domain example.com
```

**Output:**
```
[*] Checking Wayback for: example.com

[+] Found 10 snapshots
    - 20240115120000: https://web.archive.org/web/20240115120000/https://example.com/
    - 20230120140000: https://web.archive.org/web/20230120140000/https://example.com/
```

---

### 9. http-comments
**Category:** `safe/analysis/http_https`

Detect HTML comments in web pages (useful for finding hidden developer notes).

**Required Arguments:**
- `--url` - Target URL

**Example:**
```bash
Lightscan.py --lsse --script http-comments --url https://example.com
```

**Output:**
```
[+] Comment/s Detected
[+] Final Url: https://example.com
[+] Number of Comments 3

[#1] <!-- TODO: Remove this debug endpoint before production -->
[#2] <!-- Admin panel at /admin_console -->
```

---

### 10. script
**Category:** `safe/discovery/http_https`

Detect `<script>` tags in HTML pages.

**Required Arguments:**
- `--url` - Target URL

**Example:**
```bash
Lightscan.py --lsse --script script --url https://example.com
```

**Output:**
```
[+] Script/s Detected
[+] Final Url: https://example.com
[+] Number of Scripts 12

[#1] <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
[#2] <script async src="https://www.googletagmanager.com/gtag/js?id=UA-123456-1"></script>
```

---

### 11. spider
**Category:** `safe/discovery/http_https`

Recursively crawl websites for links, forms, and resources.

**Required Arguments:**
- `--url` - Starting URL

**Optional Arguments:**
- `--mxd` - Maximum depth (default: 2)
- `--mxp` - Maximum pages to crawl (default: 5)

**Example:**
```bash
Lightscan.py --lsse --script spider --url https://example.com --mxd 3 --mxp 50
```

**Output:**
```
------------------------------------------------------------
Starting demo parallel spider at: https://example.com
Max pages: 50, Max depth: 3
------------------------------------------------------------
Crawling completed in 35.42 seconds!
Total pages crawled: 50
Pages per second: 1.41
------------------------------------------------------------

Depth 0 (1 pages):
   1. Example Domain
      https://example.com
      Links found: 115

Depth 1 (30 pages):
   1. About Us
      https://example.com/about
      Links found: 47
   ...
```

---

### 12. http-cert
**Category:** `safe/analysis/https`

Grab SSL/TLS certificate information.

**Required Arguments:**
- `--domain` - Target domain
- `-sp` - Target port(s)

**Example:**
```bash
Lightscan.py --lsse --script http-cert --domain example.com -sp 443
```

**Output:**
```
 [+] TLS/SSL Analysis for example.com on port 443

   [→] Version: TLSv1.3
   [→] Cipher: TLS_AES_128_GCM_SHA256 (128 bits)

   [→] Certificate:
       • Subject: example.com
       • Signature Algorithm: sha256WithRSAEncryption
       • Public Key: RSA 2048 bits
       • Issuer: Let's Encrypt
       • Valid: Jan 15 10:00:00 2026 GMT to Apr 15 09:59:59 2026 GMT
       • SANs: example.com, www.example.com
       • Serial: 054D06403C8093227AFD72705854F9970F88
       • CRL URLs: ('http://yr1.c.lencr.org/9.crl',)
       • MD5 FP: 20c1b79ba0b6b196abdb3f62daab63c2
       • SHA-1 FP: fdff190d6a1eb7a4b385721066d2c4acae0df75b
       • SHA-256 FP: 40b3d6749aeb408d45c018c36ab9ae97f0bc9b0bdaf207b41407dccd04be6119

   [→] Testing protocol support:
       • TLSv1.3: +
       • TLSv1.2: +
       • TLSv1.1: X
       • TLSv1.0: X

     [+] Security: Strong configuration
```

---

## DNS Scripts

### 13. dns-lookup
**Category:** `safe/discovery/dns`

Perform fast DNS lookup for IPv4 and IPv6 addresses.

**Required Arguments:**
- `--domain` - Target domain

**Optional Arguments:**
- `--dns-server` - Custom DNS server

**Example:**
```bash
Lightscan.py --lsse --script dns-lookup --domain example.com
```

**Output:**
```
[*] Looking up example.com using 8.8.8.8
  IPv4 → 93.184.216.34
  IPv6 → 2606:2800:220:1:248:1893:25c8:1946
```

---

### 14. dns-ns
**Category:** `safe/discovery/dns`

Get Name Server (NS) records for a domain.

**Required Arguments:**
- `--domain` - Target domain

**Optional Arguments:**
- `--dns-server` - Custom DNS server

**Example:**
```bash
Lightscan.py --lsse --script dns-ns --domain example.com
```

**Output:**
```
[+] NS Record Lookup for example.com
[*] Using DNS server: 8.8.8.8

[+] Found 4 nameserver(s):
    1. a.iana-servers.net
    2. b.iana-servers.net
    3. c.iana-servers.net
    4. d.iana-servers.net
```

---

### 15. dns-zone-transfer
**Category:** `medium/extracting/dns`

Attempt AXFR zone transfer to enumerate all DNS records.

**Required Arguments:**
- `--domain` - Target domain

**Optional Arguments:**
- `--dns-server` - Custom DNS server

**Example:**
```bash
Lightscan.py --lsse --script dns-zone-transfer --domain example.com
```

**Output:**
```
[+] Zone Transfer Scan for example.com
[*] Discovering authoritative nameservers...
[*] Found nameservers: a.iana-servers.net, b.iana-servers.net

  [*] Attempting AXFR from a.iana-servers.net
  [!] Transfer refused by a.iana-servers.net

  [*] Attempting AXFR from b.iana-servers.net
  [!] Transfer refused by b.iana-servers.net

[-] Zone transfer failed on all nameservers (secure configuration)
```

---

### 16. dns-subdomain-fuzzing
**Category:** `medium/discovery/dns`

Brute-force subdomains using a wordlist.

**Required Arguments:**
- `--domain` - Target domain

**Optional Arguments:**
- `--wordlist` - Custom wordlist file
- `--dns-server` - Custom DNS server

**Example:**
```bash
Lightscan.py --lsse --script dns-subdomain-fuzzing --domain example.com --wordlist subdomains.txt
```

**Output:**
```
   [*] Progress: 150/150 (100.0%) | Found: 12 | Elapsed: 45.2s

   [+] Target Domain: example.com
   [+] DNS Server: 8.8.8.8
   [+] Time Elapsed: 45.20 seconds
   [+] Subdomains Tested: 150
   [+] Valid Subdomains Found: 12

   Discovered Subdomains:
   ----------------------------------------

      [+] mail.example.com :
           IPv4 *A   : 192.168.1.10

      [+] www.example.com :
           IPv4 *A   : 93.184.216.34
           IPv6 *AAAA: 2606:2800:220:1:248:1893:25c8:1946

      [+] api.example.com :
           IPv4 *A   : 192.168.1.20
```

---

### 17. whois-domain
**Category:** `safe/discovery/dns`

Gather domain registration information via WHOIS.

**Required Arguments:**
- `--domain` - Target domain

**Example:**
```bash
Lightscan.py --lsse --script whois-domain --domain example.com
```

**Output:**
```
============================================================
WHOIS Domain Information: example.com
============================================================

  Registrar:       IANA
  Creation Date:   1990-01-01 00:00:00
  Expiry Date:     2030-01-01 00:00:00
  Updated Date:    2024-01-01 00:00:00

  Name Servers:
    - a.iana-servers.net
    - b.iana-servers.net

  Registrant:      Example Domain

  Domain Status:
    - clientDeleteProhibited
    - clientTransferProhibited
```

---

## SSH Scripts

### 18. ssh-auth-methods
**Category:** `safe/extracting/ssh`

Enumerate SSH authentication methods with detailed analysis.

**Required Arguments:**
- `--starget` - Target host
- `-sp` - Target port

**Example:**
```bash
Lightscan.py --lsse --script ssh-auth-methods --starget example.com -sp 22
```

**Output:**
```
[*] Probing example.com:22

[+] SSH Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
[+] Auth methods (from exception): ['publickey', 'password']

[+] SSH Authentication Methods Summary:
    Host: example.com:22
    Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
    Methods: publickey, password

[!] Security Assessment:
    - Password authentication: ENABLED
    - Publickey authentication: ENABLED
```

---

### 19. ssh-brute
**Category:** `medium/discovery/ssh`

Run an SSH brute-force to guess correct login credentials.

**Required Arguments:**
- `--starget` - Target host
- `-sp` - Target port

**Optional Arguments:**
- `--username` - Single username
- `--password` - Single password
- `--userlist` - Wordlist of usernames
- `--passwordlist` - Wordlist of passwords

**Example:**
```bash
Lightscan.py --lsse --script ssh-brute --starget example.com -sp 22 --userlist users.txt --passwordlist passwords.txt
```

**Output:**
```
============================================================
SSH Brute-Force
  Target: example.com:22
  Usernames: 25
  Passwords: 40
  Total Combos: 1000
  Threads: 10
  Timeout: 5s
============================================================
Progress: 500/1000 (50.0%) | Speed: 5.2/sec | Found: 1 | Errors: 12

============================================================
SUMMARY
  Total attempts: 1000
  Successful: 1
  Time: 192.5s
  Speed: 5.2/sec

  Found 1 credentials:
    admin:password123
```

---

### 20. ssh-info
**Category:** `safe/analysis/ssh`

Grab SSH key-exchange packet (SSH_MSG_KEXINIT) and parse it.

**Required Arguments:**
- `--starget` - Target host
- `-sp` - Target port

**Example:**
```bash
Lightscan.py --lsse --script ssh-info --starget example.com -sp 22
```

**Output:**
```
[+] Packet Info :
  <> Packet length: 1276
  <> Padding length: 10
  <> Message: SSH_MSG_KEXINIT
  <> Cookie: f4efda4600771fa1a5856a9b2e17ee6a

[+] Server Client:
  <> server-client: b'SSH-2.0-OpenSSH_7.4\r\n'

[+] Key Exchange Init Data:
  <> kex_algorithms: curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256
  <> server_host_key_algorithms: ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512
  <> encryption_algorithms_client_to_server: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
  <> encryption_algorithms_server_to_client: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
  <> mac_algorithms_client_to_server: umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com
  <> mac_algorithms_server_to_client: umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com
  <> compression_algorithms_client_to_server: none,zlib@openssh.com
  <> compression_algorithms_server_to_client: none,zlib@openssh.com
  <> first_kex_packet_follows: False
  <> reserved: 0
```

---

## Network Scripts

### 21. dhcp-discover
**Category:** `safe/discovery/dhcp`

Discover local DHCP servers and devices.

**Required Arguments:**
- None

**Example:**
```bash
Lightscan.py --lsse --script dhcp-discover
```

**Output:**
```
[+] Received 1 offer(s):

--- Offer 1 ---
  Offered IP        : 10.148.175.145
  DHCP Server       : 10.148.175.124 (16:93:03:9d:bf:1e)
  Message Type      : DHCPOFFER
  Subnet Mask       : 255.255.255.0
  Router / Gateway  : 10.148.175.124
  DNS Servers       : ['10.148.175.124']
  Domain Name       : None
  Lease Time        : 59m59s (3599s)
  Server Identifier : 10.148.175.124
  Transaction ID    : 0x552258de
```

---

### 22. firewall-detect
**Category:** `medium/analysis/firewall`

Firewall detection using multiple probe techniques on a single port.

**Required Arguments:**
- `--starget` - Target host
- `-sp` - Target port

**Example:**
```bash
Lightscan.py --lsse --script firewall-detect --starget example.com -sp 80
```

**Output:**
```
[+] Firewall Detection Results for example.com:80

    Firewall Detected: True
    FDD Scan Detection: True
    Type: Stateful Firewall (IDS/IPS Enabled)
    Filtering: Drop all
    ICMP Behavior: Blocked
    Inspection: Deep Packet Inspection detected
    Methods Used: TCP Flag Analysis, ICMP Probe, TTL Manipulation, Fragmentation Test, Timing Analysis, FDD Scan
```

---

### 23. eternalblue
**Category:** `safe/discovery/smb`

Scan for EternalBlue (CVE-2017-0144) SMBv1 vulnerability.

**Required Arguments:**
- `--starget` - Target host
- `-sp` - Target port

**Example:**
```bash
Lightscan.py --lsse --script eternalblue --starget 192.168.1.10 -sp 445
```

**Output:**
```
Checking 192.168.1.10 for MS17-010 -- CVE-2017-0144 (EternalBlue)...

[*] Connected to 192.168.1.10:445
[*] Session response: PRESENT
[*] Native OS: Windows 7 Enterprise 7601 Service Pack 1
[*] Native LAN Manager: Windows 7 Enterprise 6.1
[*] OS Version: b'Windows 7'

[!] 192.168.1.10 is VULNERABLE to MS17-010 (EternalBlue)!
     -> OS Version: b'Windows 7'
```

---

# Part 2: Adding Custom Scripts

There are **two supported paths** for adding a custom script to LSSE, depending on how you plan to register it. Pick the one that matches your workflow — do not mix the two for the same script.

| Path | Who it's for | Touches `lsse_og.py`? | `[SCRIPTS]` in `lsse.conf`? | `[VARS]` in `lsse.conf`? |
|------|---------------|------------------------|------------------------------|----------------------------|
| **A — Direct handler registration** | Developers comfortable editing the engine | ✅ Yes | ❌ No | ✅ Yes |
| **B — Config-only registration** | Non-professional / casual users | ❌ No | ✅ Yes | ✅ Yes |

The key rule: **if you register the script's handler directly inside `lsse_og.py`, you must NOT also add it to `[SCRIPTS]`.** The `[SCRIPTS]` section exists to tell the *generic* dispatcher how to route to a script it doesn't otherwise know about — but once you've written a handler by hand in `lsse_og.py`, that handler *is* the routing logic, and a duplicate `[SCRIPTS]` entry would conflict with it. In both paths, the script name still needs to go into `[VARS]` (`sscripts` or `dscripts`) so the CLI knows the script exists and how to parse its arguments.

---

## Directory Structure

```
LSSE/
├── metadata/
│   └── your_script.yaml
├── scripts/
│   └── category/
│       └── sub_category/
│           └── protocol/
│               └── your_script.py
└── slist.py
```

## Step 1: Create the Script File

**Path:** `LSSE/scripts/{category}/{sub_category}/{protocol}/{script_name}.py`

**Example Path:** `LSSE/scripts/safe/analysis/http_https/my_script.py`

### Entry Point Function

Your script's entry point can be named `main`, `run`, or `start` — LSSE doesn't require one specific name. What matters is that whichever function you use is the one referenced correctly wherever it's called (the `lsse_og.py` handler in Path A, or the generic dispatcher in Path B).

**The signature of that function differs by registration path:**

| Path | Entry point signature | Called by |
|------|------------------------|-----------|
| **A — Direct handler** | Whatever parameters you choose (e.g. `main(target, port)`) — you control both sides since you write the `lsse_og.py` handler that calls it | Your own handler code in `lsse_og.py` |
| **B — Config-only** | A single dictionary parameter, e.g. `main(args_dict)` / `run(args_dict)` / `start(args_dict)`, keyed by the **internal argument names** from the table in Step 2 (`args_dict['t']`, `args_dict['ports']`, `args_dict['domain']`, etc.) | The generic dispatcher, based on your `[SCRIPTS]` entry |

This distinction exists because in Path A you write the exact call yourself (`main(target=a.t, port=int(self._ports(a)[0]))`), so you're free to unpack whatever named parameters you like. In Path B there is no per-script handler — the generic dispatcher builds one dictionary of parsed arguments from `ScriptArgs` and passes the whole thing in, so your entry point must accept it as a single dict and pull out what it needs by internal name.

### Script Structure — Path A (custom handler, free-form parameters)

```python
# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Your Name
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

"""
Light-Scan Scripting Engine (LSSE)
Script Name : my-script
Author : Your Name
Arguments
--> Required Arguments
----> --starget
----> -sp
--> Optional Arguments
----> None
Category:   safe/analysis/http_https
"""

import requests

def main(target, port):
    """
    Entry point called directly by the lsse_og.py handler (Path A).
    Free-form parameters are fine here since you also write the call site.
    """
    print(f"\n[+] My Script Running Against {target}:{port}\n")
    
    try:
        response = requests.get(f"http://{target}:{port}/", timeout=5)
        print(f"[+] Status Code: {response.status_code}")
        print(f"[+] Server: {response.headers.get('Server', 'Unknown')}")
    except Exception as e:
        # Non-critical (single request failed) — log and return, don't kill the process
        print(f"[-] Error: {e}")
        return
```

### Script Structure — Path B (generic dispatcher, `args_dict` required)

```python
# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Your Name

"""
Light-Scan Scripting Engine (LSSE)
Script Name : my-script
Author : Your Name
Arguments
--> Required Arguments
----> --starget
----> -sp
--> Optional Arguments
----> None
Category:   safe/analysis/http_https
"""

import requests

def main(args_dict):
    """
    Entry point called by the generic dispatcher (Path B).
    Must accept a single dict keyed by internal argument names —
    see the "Available Arguments" table in Step 2 (e.g. 't' for --starget,
    'ports' for -sp, 'domain' for --domain, and so on).
    """
    target = args_dict['t']
    port = args_dict['ports']

    print(f"\n[+] My Script Running Against {target}:{port}\n")

    try:
        response = requests.get(f"http://{target}:{port}/", timeout=5)
        print(f"[+] Status Code: {response.status_code}")
        print(f"[+] Server: {response.headers.get('Server', 'Unknown')}")
    except Exception as e:
        # Non-critical (single request failed) — log and return, don't kill the process
        print(f"[-] Error: {e}")
        return
```

> **Note:** if an argument is optional and might not be present in `args_dict`, use `args_dict.get('redirect')` rather than `args_dict['redirect']` to avoid a `KeyError` on scripts run without that flag.

### Script Requirements

1. **Function Name:** `main`, `run`, or `start` are all acceptable — just be consistent with what your handler (Path A) or the dispatcher (Path B) expects
2. **Signature:** Path A — free-form parameters matching your handler's call. Path B — a single `args_dict` parameter keyed by internal argument names (`t`, `ports`, `domain`, `url`, etc.)
3. **Arguments:** Must match what's defined in metadata
4. **Error Handling:** Should handle exceptions gracefully
5. **Exit Codes:** Avoid `sys.exit()` inside your entry point except for critical, unrecoverable errors (target completely unreachable, required file missing). For recoverable errors, print and `return`. `sys.exit(0)`/`sys.exit(1)` belongs in the `lsse_og.py` handler (Path A) or is handled by the dispatcher itself (Path B)

---

## Step 2: Create Metadata File

**Path:** `LSSE/metadata/{script_name}.yaml`

**Example Path:** `LSSE/metadata/my-script.yaml`

```yaml
# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Your Name

script_name: "my-script"
description: "Description of what your script does"

args:
  required: "--starget, -sp"
  optional: "--redirect, --ssl"
  category: "safe/analysis/http_https"
```

### Metadata Fields

| Field | Description | Required |
|-------|-------------|----------|
| `script_name` | Script name (matches filename) | ✅ |
| `description` | Brief description of script purpose | ✅ |
| `args.required` | Comma-separated list of required args | ✅ |
| `args.optional` | Comma-separated list of optional args | ❌ |
| `args.category` | Category path (e.g., `safe/analysis/http_https`) | ✅ |

### Available Arguments

| CLI Argument | Internal Name | Description |
|--------------|---------------|-------------|
| `--domain` | `domain` | Target domain |
| `--starget` | `t` | Target host/IP |
| `-sp` | `ports` | Target port(s) |
| `--dns-server` | `dns` | Custom DNS server |
| `-W` | `wordlist` | Wordlist file |
| `--url` | `url` | Target URL |
| `--redirect` | `redirect` | Follow redirects |
| `--ssl` | `ssl` | Enable SSL/TLS |
| `--request` | `req` | Raw request string |
| `--file` | `file` | File path |
| `--username` | `user` | Single username |
| `--password` | `password` | Single password |
| `--userlist` | `userlist` | Username wordlist |
| `--passwordlist` | `passwordlist` | Password wordlist |
| `--extensions` | `extensions` | File extensions |
| `--status-codes` | `status_codes` | HTTP status codes |
| `--mxp` | `max_pages` | Max pages to crawl |
| `--mxd` | `max_depth` | Max depth to crawl |

---

## Step 3A: Register in `lsse.conf` — Path A (Direct Handler in `lsse_og.py`)

Use this path if you are writing the routing/handler code yourself inside `lsse_og.py` (see Step 4A below).

**Do NOT add an entry to `[SCRIPTS]`.** Your handler in `lsse_og.py` already performs the job `[SCRIPTS]` would otherwise do — adding both creates a duplicate/conflicting route for the same script name.

**Only add the script to `[VARS]`,** following the same `sscripts` / `dscripts` split used everywhere else:

```ini
[VARS]
# If your script uses -sp, add to sscripts
sscripts = ['my-script', ...]

# If your script does NOT use -sp, add to dscripts
dscripts = ['my-script', ...]
```

| List | When to use |
|------|-------------|
| `sscripts` | Script accepts `-sp` (port argument) |
| `dscripts` | Script does **not** accept `-sp` |

---

## Step 3B: Register in `lsse.conf` — Path B (Config-Only, No Engine Edits)

Use this path if you are **not** editing `lsse_og.py` at all — this is the recommended path for non-professional users, since the generic dispatcher will call your script based purely on the config file.

You must add the script to **both** `[SCRIPTS]` **and** `[VARS]`.

### Add to `[SCRIPTS]` Section

```ini
[SCRIPTS]
my-script = {args: t|ports->1, script-path: LSSE.scripts.safe.analysis.http_https.my-script}
```

#### Port Configuration

| Syntax | Meaning |
|--------|---------|
| `ports->1` | Script uses a single port (runs once per port) |
| `ports->+` | Script uses multiple ports (runs once with all ports) |
| No `ports->` | Script doesn't use ports |

### Add to `[VARS]` Section

Same `sscripts` / `dscripts` rule as Path A applies here too — this naming rule is consistent across both paths:

```ini
[VARS]
# If your script uses -sp, add to sscripts
sscripts = ['my-script', ...]

# If your script does NOT use -sp, add to dscripts
dscripts = ['my-script', ...]
```

> **Quick decision rule:** Are you hand-writing a handler method inside `lsse_og.py`? → Path A, skip `[SCRIPTS]`. Are you only touching `metadata/` and `lsse.conf`? → Path B, add to both `[SCRIPTS]` and `[VARS]`.

---

## Optional: `script_manager.py` — GUI for Path B

If you'd rather not hand-edit YAML and `lsse.conf` directly, LSSE ships with `script_manager.py`, a Tkinter-based GUI ("LSSE Script Manager") that automates the entire **Path B** workflow end to end.

**What it does when adding a script:**
- Presents a form for script name, description, category, sub-category, protocol, port support (and single vs. multi-port mode), and required/optional arguments (checkboxes drawn from the same argument table used in this doc)
- Lets you browse to your `.py` script file, then copies it into the correct `LSSE/scripts/{category}/{sub_category}/{protocol}/` path automatically
- Generates the matching `LSSE/metadata/{script_name}.yaml` file for you
- Writes the corresponding `[SCRIPTS]` entry and the `[VARS]` (`sscripts`/`dscripts`) entry into `Config/lsse.conf`
- Shows a confirmation summary before making any changes, and a success/error report after

**What it does when deleting a script:**
- Removes the script file from wherever it lives under `LSSE/scripts/`
- Removes the matching YAML metadata file
- Strips the script's entry out of `[SCRIPTS]` and out of `sscripts`/`dscripts` in `lsse.conf`
- Reports partial failures individually (e.g. if the metadata file was already missing) rather than failing silently

**Important:** the GUI only performs Path B (config-only) registration — it writes to `metadata/`, copies the script file, and edits `lsse.conf`. It does **not** touch `lsse_og.py`, so it cannot register a Path A direct handler for you. If you want Path A instead, write and register the handler yourself as described in Step 4A, and don't run a script you registered that way back through the GUI's "add" flow (it would create a conflicting `[SCRIPTS]` entry per Step 3A's rule).

Run it with:
```bash
python script_manager.py
```

---

## Step 4A: Register Handler in `lsse_og.py` (Path A only)

Skip this step entirely if you followed Path B.

### Add Import and Handler

```python
class LSSE:
    def __init__(self):
        self.handlers: dict[str, Callable[[ScriptArgs], None]] = {
            # ... existing handlers ...
            "my-script": self._my_script
        }

    def _my_script(self, a: ScriptArgs) -> None:
        """Description of what your script does."""
        from LSSE.scripts.safe.analysis.http_https.my_script import main
        
        try:
            main(target=a.t, port=int(self._ports(a)[0]))
        except Exception as e:
            print(f"\n{red}[!] {e}{reset}")
            sys.exit(1)
```

Registering the handler here means `lsse_og.py` now owns the dispatch logic for `my-script` directly — which is exactly why it must **not** also appear in `[SCRIPTS]` (Step 3A).

---

## Step 5: Test Your Script

```bash
# List all scripts to verify yours appears
Lightscan.py --lsse-lst

# Show help for your script
Lightscan.py --script-help my-script

# Run your script
Lightscan.py --lsse --script my-script --starget example.com -sp 80
```

---

## Rules for Script Development

### 1. Naming Conventions
- Script names must be **lowercase**
- Use **hyphens** instead of underscores (e.g., `my-script` not `my_script`)
- No spaces or special characters

### 2. File Structure
- Each script must have a **matching Python file** and **YAML metadata file**
- Python files go in `LSSE/scripts/{category}/{sub_category}/{protocol}/`
- YAML files go in `LSSE/metadata/`

### 3. Categories
- **safe** – Non-intrusive (information gathering, no modification)
- **medium** – Potentially intrusive (brute-force, enumeration)
- **dangerous** – Exploitation scripts (reserved for future use)

### 4. Sub-Categories
| Sub-Category | Description |
|--------------|-------------|
| `analysis` | Analyzing captured data |
| `discovery` | Discovering new information |
| `extracting` | Extracting specific data |
| `exploitation` | Exploiting vulnerabilities |

### 5. Protocols
| Protocol | Description |
|----------|-------------|
| `http_https` | Web services |
| `dns` | Domain Name System |
| `ssh` | Secure Shell |
| `smb` | Server Message Block |
| `dhcp` | Dynamic Host Configuration Protocol |
| `ftp` | File Transfer Protocol |
| `https` | HTTPS (specific) |
| `tcp` | Transmission Control Protocol |
| `udp` | User Datagram Protocol |
| `ssl` | Secure Sockets Layer |

### 6. Argument Handling
- Use `self._ports(a)` to get port list with validation
- Use `a.t` for target, `a.domain` for domain, `a.url` for URL
- Always validate required arguments
- Provide clear error messages

### 7. Error Handling
- Wrap main logic in `try/except`
- Print user-friendly error messages
- **Don't use `sys.exit()` freely inside your script's `main()`.** Reserve it for *critical* errors only — cases where the script genuinely cannot continue (e.g. the target is unreachable, a required file is missing, invalid input that makes the rest of the logic meaningless). For recoverable problems (a single failed request in a loop, one bad entry in a wordlist, a timeout on one of many targets), print the error and let the script continue or return normally instead of exiting.
- `sys.exit()` is appropriate **inside the `lsse_og.py` handler** (Path A) when wrapping the call to your script's `main()` — that's the top-level boundary where the engine expects a clean exit code to report success/failure back to the CLI. Your script's internal logic should raise or return; the handler is what translates that into `sys.exit(0)` / `sys.exit(1)`.
- Calling `sys.exit()` deep inside `main()` for non-critical errors kills the whole script (and, in Path A, can kill the engine process calling it) over something that should have just been logged and skipped

### 8. Output Formatting
- Use color codes: `red`, `green`, `yellow`, `reset`
- Be consistent with output format
- Show progress for long operations
- Include timestamps where relevant

### 9. `sys.exit()` Discipline
- Do **not** scatter `sys.exit()` calls throughout a script's `main()` logic
- Only call `sys.exit()` for **critical, unrecoverable** errors — the target is completely unreachable, a required file/argument is missing, or the script genuinely cannot proceed at all
- For everything else (a single failed request, one bad line in a wordlist, one target timing out among many), print the error and `return` or continue the loop
- The one place `sys.exit()` is always appropriate is **inside the `lsse_og.py` handler** (Path A) — that's the boundary where the engine translates your script's outcome into a process exit code for the CLI
- In Path B (config-only), the generic dispatcher handles exit-code reporting for you, so your script's `main()` should almost never call `sys.exit()` at all

### 10. Security Considerations
- Don't hardcode credentials
- Validate input to prevent command injection
- Respect target rate limits
- Don't modify target systems without explicit permission

### 11. Documentation
- Include a docstring at the top of the script
- Document all arguments and their types
- Provide example usage in metadata
- Keep description concise and accurate

### 12. Registration Path Consistency
- Never register the same script through both Path A and Path B
- If a handler exists in `lsse_og.py`, the script name must be absent from `[SCRIPTS]`
- If no handler exists in `lsse_og.py`, the script name must be present in `[SCRIPTS]`
- In either path, the script name always belongs in `[VARS]` (`sscripts` or `dscripts`, never both)

---

## Complete Example: nmap-lsse Script (Path A — Direct Handler)

### `LSSE/scripts/safe/discovery/tcp/nmap-lsse.py`

```python
# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Your Name

"""
Light-Scan Scripting Engine (LSSE)
Script Name : nmap-lsse
Author : Your Name
Arguments
--> Required Arguments
----> --starget
----> -sp
--> Optional Arguments
----> None
Category:   safe/discovery/tcp
"""

import socket
import sys

def main(target, port):
    print(f"\n[+] Nmap-LSSE Script Running Against {target}:{port}\n")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result == 0:
            print(f"[+] Port {port} is OPEN on {target}")
            print(f"[+] Service: {socket.getservbyport(port, 'tcp')}")
        else:
            print(f"[-] Port {port} is CLOSED on {target}")
            
    except Exception as e:
        # Non-critical — print and return, let the handler decide the exit code
        print(f"[-] Error: {e}")
        return
```

### `LSSE/metadata/nmap-lsse.yaml`

```yaml
script_name: "nmap-lsse"
description: "Check if a specific TCP port is open"

args:
  required: "--starget, -sp"
  optional: null
  category: "safe/discovery/tcp"
```

### `lsse.conf` (Path A — `[SCRIPTS]` intentionally omitted)

```ini
[VARS]
sscripts = ['nmap-lsse', ...]
```

> Note there is **no `[SCRIPTS]` entry** for `nmap-lsse` — the handler below in `lsse_og.py` takes care of routing.

### `lsse_og.py`

```python
class LSSE:
    def __init__(self):
        self.handlers: dict[str, Callable[[ScriptArgs], None]] = {
            # ... existing handlers ...
            "nmap-lsse": self._nmap_lsse
        }

    def _nmap_lsse(self, a: ScriptArgs) -> None:
        """Check if a specific TCP port is open."""
        from LSSE.scripts.safe.discovery.tcp.nmap_lsse import main
        
        try:
            main(target=a.t, port=int(self._ports(a)[0]))
        except Exception as e:
            print(f"\n{red}[!] {e}{reset}")
            sys.exit(1)
```

### Testing

```bash
# Show script in list
Lightscan.py --lsse-lst

# Run the script
Lightscan.py --lsse --script nmap-lsse --starget example.com -sp 80
```

---

## Complete Example: nmap-lsse Script (Path B — Config-Only, No Handler)

Same metadata file as above, but **no edits to `lsse_og.py`**, and the script itself is written differently — its entry point takes a single `args_dict` instead of named parameters, since the generic dispatcher (not a hand-written handler) is what calls it.

### `LSSE/scripts/safe/discovery/tcp/nmap-lsse.py` (Path B version)

```python
# Light-Scan Framework - Network Security Scanning Framework
# Copyright (C) 2026 Your Name

"""
Light-Scan Scripting Engine (LSSE)
Script Name : nmap-lsse
Author : Your Name
Arguments
--> Required Arguments
----> --starget
----> -sp
--> Optional Arguments
----> None
Category:   safe/discovery/tcp
"""

import socket

def main(args_dict):
    target = args_dict['t']
    port = int(args_dict['ports'])

    print(f"\n[+] Nmap-LSSE Script Running Against {target}:{port}\n")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            print(f"[+] Port {port} is OPEN on {target}")
            print(f"[+] Service: {socket.getservbyport(port, 'tcp')}")
        else:
            print(f"[-] Port {port} is CLOSED on {target}")

    except Exception as e:
        # Non-critical — the dispatcher handles the exit code, we just report
        print(f"[-] Error: {e}")
        return
```

### `lsse.conf` (Path B — `[SCRIPTS]` required)

```ini
[SCRIPTS]
nmap-lsse = {args: t|ports->1, script-path: LSSE.scripts.safe.discovery.tcp.nmap-lsse}

[VARS]
sscripts = ['nmap-lsse', ...]
```

### Testing

```bash
# Show script in list
Lightscan.py --lsse-lst

# Run the script
Lightscan.py --lsse --script nmap-lsse --starget example.com -sp 80
```

Both paths produce identical runtime behavior for the end user — the difference is in how the script's entry point is written and how the routing is wired internally: Path A's `main(target, port)` is called directly by a handler you write, while Path B's `main(args_dict)` is called by the generic dispatcher using internal argument names.

---

### NOTE
- `script_manager.py` is included with https://github.com/Light-Projects/Light-Scan only 

## Troubleshooting

### Script Not Showing in `--lsse-lst`
- Check metadata file exists in `LSSE/metadata/`
- Check YAML syntax is valid
- Check script name matches filename

### Script Not Running
- **Path A:** Check the handler is registered in `self.handlers` in `lsse_og.py`, and confirm the script name is **not** duplicated in `[SCRIPTS]`
- **Path B:** Check the script is listed in `[SCRIPTS]` in `lsse.conf`, and confirm no conflicting handler exists in `lsse_og.py`
- Both paths: Check the script is in `sscripts` or `dscripts` in `lsse.conf`
- Check script file exists in correct path

### Script Registered in Both Places (Conflict)
- If a script appears in both `[SCRIPTS]` and as a handler in `lsse_og.py`, remove it from `[SCRIPTS]` — the handler takes precedence and the duplicate entry serves no purpose
- Pick one path per script and stay consistent

### Port Not Recognized
- Check `ports->1` is set for single-port scripts (Path B `[SCRIPTS]` entry)
- Check `ports->+` is set for multi-port scripts (Path B `[SCRIPTS]` entry)
- Check script is in the correct `sscripts`/`dscripts` list (both paths)

### Import Errors
- Check import path matches script location
- Check all dependencies are installed
- Check Python path includes project root

---

## Best Practices

1. **Keep It Simple** – Scripts should do one thing well
2. **Handle Errors** – Never let exceptions bubble up
3. **Provide Feedback** – Show progress and results clearly
4. **Use Color** – Use `green` for success, `red` for errors, `yellow` for warnings
5. **Test Thoroughly** – Test with both valid and invalid inputs
6. **Document Clearly** – Write good docstrings and metadata
7. **Respect Resources** – Don't overwhelm targets with requests
8. **Be Safe** – Never execute arbitrary code on targets
9. **Pick One Registration Path** – Direct handler (Path A, no `[SCRIPTS]`) or config-only (Path B, `[SCRIPTS]` + `[VARS]`) — never both for the same script
10. **Use `sys.exit()` Sparingly** – Reserve it for critical, unrecoverable errors and for the `lsse_og.py` handler boundary; everywhere else, print and `return`
11. **Consider the GUI for Path B** – `script_manager.py` handles file placement, YAML generation, and `lsse.conf` edits for you, reducing manual mistakes

---

## Need More Help?

If you need assistance creating or debugging a script:

1. Check existing scripts in `LSSE/scripts/` for examples
2. Review the `lsse_og.py` handler logic
3. Check the `lsse.conf` routing configuration
4. Run with `-v` for verbose output

**Happy Scripting! 🚀**