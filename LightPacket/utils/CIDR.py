# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import ipaddress
import socket
import re
from typing import List, Optional, Union
from itertools import product


class TargetParser:
    """
    Parse and validate network targets (IPs, CIDR ranges, hyphen ranges, hostnames).

    Supports:
    - Single IPs: '192.168.1.1'
    - CIDR networks: '192.168.1.0/24'
    - Hyphen ranges: '192.168.1.1-254'
    - Full IP ranges: '192.168.1.1-192.168.1.254'
    - Mixed ranges: '192.168.1.1,192.168.1.2-10,192.168.2.0/24'
    - Hostnames: 'example.com'
    - IPv6 addresses: '::1', '2001:db8::1'
    - IPv6 CIDR: '2001:db8::/32'
    """

    # Common domain extensions for validation
    HOST_EXTENSIONS = {
        '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
        '.info', '.biz', '.name', '.pro', '.xyz', '.online', '.site',
        '.tech', '.store', '.app', '.dev', '.io', '.ai', '.cloud',
        '.us', '.uk', '.ca', '.au', '.de', '.fr', '.jp', '.cn', '.in',
        '.br', '.ru', '.mx', '.it', '.es', '.nl', '.se', '.no', '.ch',
        '.at', '.dk', '.fi', '.ie', '.nz', '.za', '.sg', '.kr', '.tw',
        '.hk', '.tr', '.ae', '.sa', '.eu', '.asia', '.africa',
        '.academy', '.school', '.college', '.university',
        '.business', '.company', '.co', '.shop', '.market',
        '.media', '.news', '.tv', '.film', '.music', '.games',
        '.law', '.legal', '.medical', '.health', '.finance',
        '.realestate', '.travel', '.restaurant', '.club',
        '.art', '.design', '.blog', '.social', '.space', '.world',
        '.expert', '.guru', '.agency', '.services',
        '.fitness', '.health', '.food', '.travel', '.cars', '.fashion'
    }

    @staticmethod
    def expand_network_range(range_str: str, max_hosts: int = 65536, include_all: bool = True) -> List[str]:
        """
        Expand a network range with multiple octet ranges like '192-193.168.1-2.0/24'.

        Supports:
        - Single range: '192-193.168.1.0/24'
        - Multiple ranges: '192-193.168.1-2.0/24'
        - All octets: '192-193.168-169.1-2.0-1/24'

        Args:
            range_str: The network range string
            max_hosts: Maximum hosts to expand
            include_all: Include network and broadcast addresses

        Returns:
            List of IP addresses
        """
        try:
            # Check if it has both hyphen AND slash
            if '-' in range_str and '/' in range_str:
                # Split into base and CIDR
                base, cidr = range_str.split('/')
                cidr = int(cidr)

                # Find all octets with ranges
                octets = base.split('.')

                if len(octets) != 4:
                    print(f"[!] Invalid IP format: {base}")
                    return []

                # Parse each octet, building a list of possible values for each position
                octet_options = []
                has_range = False

                for octet in octets:
                    if '-' in octet:
                        has_range = True
                        try:
                            start_str, end_str = octet.split('-')
                            start = int(start_str)
                            end = int(end_str)

                            if start > end:
                                print(f"[!] Invalid range: {start} > {end}")
                                return []

                            if start < 0 or end > 255:
                                print(f"[!] Octet values must be between 0-255: {start}-{end}")
                                return []

                            octet_options.append(list(range(start, end + 1)))
                        except ValueError:
                            print(f"[!] Invalid numeric values in octet: {octet}")
                            return []
                    else:
                        try:
                            val = int(octet)
                            if val < 0 or val > 255:
                                print(f"[!] Invalid octet value: {val}")
                                return []
                            octet_options.append([val])
                        except ValueError:
                            print(f"[!] Invalid octet: {octet}")
                            return []

                # If no ranges found, treat as normal CIDR
                if not has_range:
                    return TargetParser.expand_cidr(range_str, max_hosts, include_all)

                # Calculate total number of networks
                total_networks = 1
                for options in octet_options:
                    total_networks *= len(options)

                # Calculate total hosts
                hosts_per_network = 2 ** (32 - cidr)
                total_hosts = total_networks * hosts_per_network

                if total_hosts > max_hosts:
                    print(f"[!] Range {range_str} expands to {total_hosts:,} hosts (limit: {max_hosts:,})")
                    return []

                print(f"[+] Expanding {range_str} to {total_networks} networks ({total_hosts:,} hosts)...")

                # Generate all combinations using itertools.product
                all_ips = []
                count = 0

                # Use product to generate all octet combinations
                for combination in product(*octet_options):
                    # Create network string from combination
                    network_str = '.'.join(map(str, combination)) + '/' + str(cidr)

                    # Expand this network
                    ips = TargetParser.expand_cidr(network_str, max_hosts, include_all)
                    all_ips.extend(ips)

                    count += 1
                    if total_networks > 100 and count % 100 == 0:
                        print(f"    Generated {count}/{total_networks} networks...")

                print(f"[+] Expansion complete: {len(all_ips):,} hosts")
                return all_ips

            else:
                # No hyphen, treat as normal
                return TargetParser.parse_multi_target(range_str, max_hosts, include_all)

        except Exception as e:
            print(f"[!] Error expanding network range {range_str}: {e}")
            return []


    @staticmethod
    def expand_cidr(cidr: str, max_hosts: int = 65536, include_all: bool = True) -> List[str]:
        """
        Expand a CIDR network like '192.168.1.0/24'.

        Args:
            cidr: The CIDR network string
            max_hosts: Maximum number of hosts to allow (safety limit)
            include_all: If True, include network and broadcast addresses

        Returns:
            List of IP addresses in the network
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)

            # For /31 and /32, include all addresses (RFC 3021)
            if network.prefixlen >= 31:
                return [str(ip) for ip in network]

            num_hosts = network.num_addresses

            if num_hosts > max_hosts:
                print(f"[!] Network {cidr} has {num_hosts:,} hosts (limit: {max_hosts:,})")
                return []

            ip_list = []

            if include_all:
                # Include ALL addresses in the network (including .0 and .255)
                for ip in network:
                    ip_list.append(str(ip))
            else:
                # Exclude network and broadcast (standard behavior)
                for ip in network.hosts():
                    ip_list.append(str(ip))

            return ip_list

        except ValueError as e:
            print(f"[!] Invalid CIDR notation: {cidr} ({e})")
            return []

    @staticmethod
    def expand_hyphen_range(range_str: str, max_hosts: int = 65536) -> List[str]:
        """
        Expand a hyphen range like '192.168.1.1-254' or '192.168.1.1-192.168.1.254'.

        Args:
            range_str: The range string to expand
            max_hosts: Maximum number of hosts to allow (safety limit)

        Returns:
            List of expanded IP addresses
        """
        try:
            # Handle full IP range like '192.168.1.1-192.168.1.254'
            if range_str.count('.') >= 7:
                start_ip, end_ip = range_str.split('-')
                start = int(ipaddress.IPv4Address(start_ip.strip()))
                end = int(ipaddress.IPv4Address(end_ip.strip()))

                if end < start:
                    print(f"[!] Invalid range: start > end")
                    return []

                num_hosts = end - start + 1

                if num_hosts > max_hosts:
                    print(f"[!] Range {range_str} expands to {num_hosts:,} hosts (limit: {max_hosts:,})")
                    return []

                ip_list = []
                for i in range(start, end + 1):
                    ip_list.append(str(ipaddress.IPv4Address(i)))

                return ip_list

            # Handle CIDR-like notation with backslash
            if '\\' in range_str:
                base_ip, suffix = range_str.split('\\')
                ip_list = [base_ip]
                if '.' in suffix:
                    ip_list.append(suffix)
                else:
                    base_parts = base_ip.split('.')
                    base_parts[-1] = suffix
                    full_ip = '.'.join(base_parts)
                    ip_list.append(full_ip)
                return ip_list

            # Handle single octet range like '192.168.1.1-254'
            octets = range_str.split('.')
            if len(octets) != 4:
                print(f"[!] Invalid IP range format: {range_str}")
                return [range_str]

            ranges = []
            for octet in octets:
                if '-' in octet:
                    parts = octet.split("-")
                    if len(parts) != 2:
                        print(f"[!] Invalid range in octet: {octet}")
                        return [range_str]
                    try:
                        start, end = map(int, parts)
                        if start < 0 or end > 255 or start > end:
                            print(f"[!] Invalid range values in {octet} (must be 0-255, start <= end)")
                            return [range_str]
                        ranges.append(range(start, end + 1))
                    except ValueError:
                        print(f"[!] Invalid numeric values in {octet}")
                        return [range_str]
                else:
                    try:
                        val = int(octet)
                        if val < 0 or val > 255:
                            print(f"[!] Invalid octet value: {val} (must be 0-255)")
                            return [range_str]
                        ranges.append([val])
                    except ValueError:
                        print(f"[!] Invalid octet: {octet}")
                        return [range_str]

            num_hosts = 1
            for r in ranges:
                num_hosts *= len(r)

            if num_hosts > max_hosts:
                print(f"[!] Range {range_str} expands to {num_hosts:,} hosts (limit: {max_hosts:,})")
                return []

            ip_list = []
            count = 0
            for combination in product(*ranges):
                ip = '.'.join(map(str, combination))
                ip_list.append(ip)
                count += 1
                if num_hosts > 1000 and count % 10000 == 0:
                    print(f"    Generated {count:,}/{num_hosts:,} IPs...")

            return ip_list

        except Exception as e:
            print(f"[!] Error expanding range {range_str}: {e}")
            return []

    @staticmethod
    def parse_multi_target(target_str: str, max_hosts: int = 65536, include_all: bool = True) -> List[str]:
        """
        Parse a target string that may contain multiple targets.

        Supports:
        - Comma-separated lists: '192.168.1.1,192.168.1.2,192.168.1.3'
        - CIDR networks: '192.168.1.0/24'
        - Hyphen ranges: '192.168.1.1-254'
        - Mixed: '192.168.1.1,192.168.1.2-10,192.168.2.0/24'

        Args:
            target_str: The target string to parse
            max_hosts: Maximum hosts to expand
            include_all: If True, include network and broadcast addresses for CIDR

        Returns:
            List of individual IP addresses
        """
        if not target_str or target_str.strip() == '':
            return []

        target_str = target_str.strip()
        result = []

        # Check for network range with hyphen in any octet (e.g., '192-193.168.1-2.0/24')
        if '-' in target_str and '/' in target_str:
            if ',' in target_str:
                parts = target_str.split(',')
                for part in parts:
                    part = part.strip()
                    if not part:
                        continue

                    result.extend(TargetParser.expand_network_range(part, max_hosts, include_all))
                return list(dict.fromkeys(result))
            else:
                return TargetParser.expand_network_range(target_str, max_hosts, include_all)

        if ',' not in target_str:
            if '/' in target_str:
                return TargetParser.expand_cidr(target_str, max_hosts, include_all)
            elif '-' in target_str or '\\' in target_str:
                return TargetParser.expand_hyphen_range(target_str, max_hosts)
            else:
                return [target_str]

        parts = target_str.split(',')
        for part in parts:
            part = part.strip()
            if not part:
                continue

            if '/' in part:
                result.extend(TargetParser.expand_cidr(part, max_hosts, include_all))
            elif '-' in part or '\\' in part:
                result.extend(TargetParser.expand_hyphen_range(part, max_hosts))
            else:
                result.append(part)

        return list(dict.fromkeys(result))

    @staticmethod
    def validate_ip(ip: str, version: Optional[int] = None) -> bool:
        """
        Validate an IP address.

        Args:
            ip: The IP address to validate
            version: 4 for IPv4, 6 for IPv6, None for both

        Returns:
            True if valid, False otherwise
        """
        try:
            if version == 4 or version is None:
                ipaddress.IPv4Address(ip)
                return True
        except ValueError:
            pass

        try:
            if version == 6 or version is None:
                ipaddress.IPv6Address(ip)
                return True
        except ValueError:
            pass

        return False

    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        """
        Validate a hostname.

        Args:
            hostname: The hostname to validate

        Returns:
            True if valid, False otherwise
        """
        if not hostname or len(hostname) > 253:
            return False

        # Check for valid characters
        if not re.match(
                r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$',
                hostname):
            return False

        # Check for valid TLD
        for ext in TargetParser.HOST_EXTENSIONS:
            if hostname.endswith(ext):
                return True

        # Try resolving
        try:
            socket.gethostbyname(hostname)
            return True
        except:
            return False

    @staticmethod
    def validate_target(target: str, version: Optional[int] = None) -> bool:
        """
        Validate a target (IP or hostname).

        Args:
            target: The target to validate
            version: 4 for IPv4, 6 for IPv6, None for both

        Returns:
            True if valid, False otherwise
        """
        # Check if it's an IP
        if TargetParser.validate_ip(target, version):
            return True

        # Check if it's a hostname
        if TargetParser.validate_hostname(target):
            return True

        return False

    @staticmethod
    def resolve_hostname(hostname: str, dns_server: Optional[str] = None) -> Optional[str]:
        """
        Resolve a hostname to an IP address.

        Args:
            hostname: The hostname to resolve
            dns_server: Optional DNS server to use (not used in this implementation)

        Returns:
            The resolved IP address or None
        """
        try:
            return socket.gethostbyname(hostname)
        except:
            return None

    @staticmethod
    def parse_and_validate_targets(target_input: str,
                                   max_hosts: int = 65536,
                                   version: Optional[int] = None,
                                   verbose: bool = False,
                                   include_all: bool = True) -> List[str]:
        """
        Parse and validate targets from a string.

        Args:
            target_input: The target string (may contain multiple targets)
            max_hosts: Maximum hosts to expand
            version: 4 for IPv4, 6 for IPv6, None for both
            verbose: Print progress messages
            include_all: If True, include network and broadcast addresses for CIDR

        Returns:
            List of valid target IP addresses
        """
        targets = TargetParser.parse_multi_target(target_input, max_hosts, include_all)
        valid_targets = []

        for target in targets:
            if TargetParser.validate_target(target, version):
                valid_targets.append(target)
            else:
                # Try to resolve hostname
                resolved = TargetParser.resolve_hostname(target)
                if resolved:
                    valid_targets.append(resolved)
                    if verbose:
                        print(f"[+] Resolved {target} -> {resolved}")
                else:
                    if verbose:
                        print(f"[!] Invalid target: {target}")

        return valid_targets


"""
Convenience functions for simple use 
"""

def parse_targets_from_file(filename: str,
                            max_hosts: int = 65536
                            ,version: Optional[int] = None
                            ,verbose: bool = False,
                            include_all: bool = True) -> List[str]:
    """
        Parse and validate targets from a string.

        Args:
            filename: filename string (may contain multiple targets in separaete line or by comma)
            max_hosts: Maximum hosts to expand (safety limit)
            version: 4 for IPv4, 6 for IPv6, None for both
            verbose: Print progress messages
            include_all: If True, include network and broadcast addresses for CIDR

        Returns:
            List of valid target IP addresses using parse_targets function

        Examples:

        -- Lightscan_result.txt
        10.10.10.0/24
        example.com
        8.8.8.8-10,pizza.org
        192-193.168.1.0/32

        >>> parse_targets_from_file('Lightscan_result.txt')
        [returned list by parse_targets]

        """
    target_input = ""
    with open(filename, "r") as f:
        for line in f:
            target_input += line.strip() + ","

    return TargetParser.parse_and_validate_targets(
        target_input, max_hosts, version, verbose, include_all
    )

def parse_targets(target_input: str,
                  max_hosts: int = 65536,
                  version: Optional[int] = None,
                  verbose: bool = False,
                  include_all: bool = True) -> List[str]:
    """
    Parse and validate targets from a string.

    Args:
        target_input: The target string (may contain multiple targets)
        max_hosts: Maximum hosts to expand (safety limit)
        version: 4 for IPv4, 6 for IPv6, None for both
        verbose: Print progress messages
        include_all: If True, include network and broadcast addresses for CIDR

    Returns:
        List of valid target IP addresses

    Examples:
        >>> parse_targets('192.168.1.1')
        ['192.168.1.1']

        >>> parse_targets('192.168.1.0/24')
        ['192.168.1.0', '192.168.1.1', ..., '192.168.1.255']

        >>> parse_targets('192.168.1.0/24', include_all=False)
        ['192.168.1.1', '192.168.1.2', ..., '192.168.1.254']

        >>> parse_targets('192.168.1.1-254')
        ['192.168.1.1', '192.168.1.2', ..., '192.168.1.254']

        >>> parse_targets('192.168.1.1,192.168.1.2-10,10.0.0.0/24')
        ['192.168.1.1', '192.168.1.2', ..., '10.0.0.0', ..., '10.0.0.255']

        >>> parse_targets('example.com')
        ['93.184.216.34']
    """
    return TargetParser.parse_and_validate_targets(
        target_input, max_hosts, version, verbose, include_all
    )
