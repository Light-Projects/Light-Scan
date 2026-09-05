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
Reverse DNS probe: performs a PTR lookup on the target IP address.
The resulting domain name can reveal cloud providers, hosting services,
or naming conventions that help identify the OS or environment.
"""

import socket
import dns.resolver
import dns.reversename
from typing import Optional, Dict

try:
    import dns.resolver
    import dns.reversename

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


def probe_rdns(target: str, timeout: float = 2.0, use_dnspython: bool = True) -> Optional[Dict[str, str]]:
    """
    Performs a reverse DNS lookup on the target IP address.

    Returns:
        {
            "hostname": str,           # Full PTR record value
            "domain": str,             # Top-level domain or main domain
            "cloud_provider": str,     # Detected cloud provider (if any)
            "source": str              # "dnspython" or "socket"
        }
        or None if lookup fails.
    """
    if not DNS_AVAILABLE or not use_dnspython:
        try:
            hostname = socket.gethostbyaddr(target)[0]
            return _parse_rdns_result(hostname, "socket")
        except (socket.herror, socket.gaierror, socket.timeout):
            return None

    try:
        rev_name = dns.reversename.from_address(target)

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        answers = resolver.resolve(rev_name, "PTR")

        if answers:
            hostname = str(answers[0]).rstrip('.')
            return _parse_rdns_result(hostname, "dnspython")

        return None

    except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.exception.DNSException):
        return None


def _parse_rdns_result(hostname: str, source: str) -> Dict[str, str]:
    """Parse the RDNS result to extract domain and cloud provider."""
    result = {
        "hostname": hostname,
        "domain": "",
        "cloud_provider": "",
        "source": source
    }

    parts = hostname.split('.')
    if len(parts) >= 2:
        if len(parts) >= 3:

            domain_parts = []
            for i in range(len(parts) - 1, -1, -1):
                domain_parts.insert(0, parts[i])
                candidate = '.'.join(domain_parts)
                if len(domain_parts) >= 2:
                    result["domain"] = candidate
                    break

    hostname_lower = hostname.lower()

    cloud_patterns = {
        "aws": ["amazonaws.com", "ec2-", "compute.amazonaws.com", "aws"],
        "gcp": ["googleapis.com", "compute.googleapis.com", "cloud.google.com", "1e100.net"],
        "azure": ["cloudapp.azure.com", "azure.com", "azurewebsites.net", "chinacloudapp.cn"],
        "digitalocean": ["digitalocean.com", "digitalocean"],
        "linode": ["linode.com", "linode"],
        "vultr": ["vultr.com"],
        "heroku": ["herokuapp.com", "heroku.com"],
        "cloudflare": ["cloudflare.com"],
        "akamai": ["akamai.net", "akamaiedge.net"],
        "fastly": ["fastly.net"],
        "alibaba": ["aliyuncs.com", "alicloud.com"],
        "oracle": ["oraclecloud.com", "oracle.com"],
        "ovh": ["ovh.net", "ovhcloud.com"],
        "scaleway": ["scaleway.com"],
        "sony": ["sony.com", "playstation.net"]
    }

    for provider, patterns in cloud_patterns.items():
        if any(pattern in hostname_lower for pattern in patterns):
            result["cloud_provider"] = provider
            break

    return result