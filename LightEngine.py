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

import scapy.all as scapy
from scapy.layers.inet6 import (
    IPv6, ICMPv6DestUnreach, ICMPv6EchoReply, ICMPv6ParamProblem,
    ICMPv6TimeExceeded, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6EchoRequest,
)
from decoy import decoy, decoy_order
from LightPacket.utils.Nsec.arp_resolution import arp_scan
from LightPacket.Arp import ARP
from copy import deepcopy
import random
import time
import ipaddress
from LightMirage import mirage
from banner_grabber import Banner
from concurrent.futures import ThreadPoolExecutor, as_completed
from LightPacket.GetIPv4 import GetIPv4
from Services import top_20_tcp_ports

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"
green = "\033[32m"
cyan = "\033[36m"


def is_loopback(target):
    return (target == '127.0.0.1' or target == '::1' or
            target.startswith('127.') or target == 'localhost' or
            target == GetIPv4())

PORT_TO_SERVICES = {
    "open_ports":               "opened_ports_services",
    "closed_ports":             "closed_ports_services",
    "filtered_ports":           "filtered_ports_services",
    "open_filtered_ports":      "open_filtered_ports_services",
    "null_ports":               "null_ports_services",
    "fin_ports":                "fin_ports_services",
    "defended_ports":           "defended_ports_services",
    "undefended_ports":         "undefended_ports_services",
    "unfiltered_ports":         "unfiltered_ports_services",
    "closed_filtered_ports":    "closed_filtered_ports_services",
    "open_protocols":           "open_protocols_names",
    "closed_protocols":         "closed_protocols_names",
    "filtered_protocols":       "filtered_protocols_names",
    "open_filtered_protocols":  "open_filtered_protocols_names",
}

TCP_FLAG_SCANS = {
    "null": {
        "flags": "",
        "on_no_response":   "null_ports",
        "on_rst":           "closed_ports",
        "on_other_tcp":     "null_ports",
        "on_icmp":          "filtered_ports",
        "on_icmpv6_closed": "closed_ports",
        "on_icmpv6_other":  "filtered_ports",
    },
    "fin": {
        "flags": "F",
        "on_no_response":   "fin_ports",
        "on_rst":           "closed_ports",
        "on_other_tcp":     "filtered_ports",
        "on_icmp":          "filtered_ports",
        "on_icmpv6_closed": "closed_ports",
        "on_icmpv6_other":  "filtered_ports",
    },
    "custom": {
        "on_no_response":   "filtered_ports",
        "on_rst":           "closed_ports",
        "on_other_tcp":     "filtered_ports",
        "on_icmp":          "filtered_ports",
        "on_icmpv6_closed": "closed_ports",
        "on_icmpv6_other":  "filtered_ports",
    },
    "ack": {
        "flags": "A",
        "on_no_response":   "filtered_ports",
        "on_rst":           "unfiltered_ports",
        "on_other_tcp":     "filtered_ports",
        "on_icmp":          "filtered_ports",
        "on_icmpv6_closed": "closed_ports",
        "on_icmpv6_other":  "filtered_ports",
    },
    "xmas": {
        "flags": "FPU",
        "on_no_response":   "open_filtered_ports",
        "on_rst":           "closed_ports",
        "on_other_tcp":     "filtered_ports",
        "on_icmp":          "filtered_ports",
        "on_icmpv6_closed": "closed_ports",
        "on_icmpv6_other":  "filtered_ports",
    },
    "maimon": {
        "flags": "FA",
        "on_no_response":   "open_filtered_ports",
        "on_rst":           "closed_ports",
        "on_other_tcp":     "filtered_ports",
        "on_icmp":          "filtered_ports",
        "on_icmpv6_closed": "closed_ports",
        "on_icmpv6_other":  "filtered_ports",
    },
    "window": {
        "flags": "A",
        "on_no_response":   "filtered_ports",
        "on_rst":           "closed_ports",
        "on_other_tcp":     "filtered_ports",
        "on_icmp":          "filtered_ports",
        "on_icmpv6_closed": "closed_ports",
        "on_icmpv6_other":  "filtered_ports",
        "window_check": True,
    },
    "fdd": {
        "flags": "U",
        "on_no_response":   "defended_ports",
        "on_rst":           "undefended_ports",
        "on_other_tcp":     "undefended_ports",
        "on_icmp":          "defended_ports",
        "on_icmpv6_closed": "defended_ports",
        "on_icmpv6_other":  "defended_ports",
    },
}


class Payloads:
    def __init__(self):
        pass

    @staticmethod
    def Stealth_tcp_options():
        options = [
            ('MSS', random.randint(1000, 1440)),
            ('WScale', random.randint(2, 14)),
            ('Timestamp', (random.randint(1, 1000000000), 0)),
            ('SAckOK', ''),
            ('NOP', None),
            ('NOP', None),
            ('EOL', None)
        ]
        random.shuffle(options)
        for i, opt in enumerate(options):
            if opt[0] == 'MSS':
                options.insert(0, options.pop(i))
                break
        return options

    @staticmethod
    def fragementation(packet, Proto, scan_type, verbose, fragsize=None, v6=False):
        from IPfrag import fragementation
        fragementation(packet, Proto, scan_type, verbose, fragsize=fragsize, v6=v6)

    @staticmethod
    def is_private_ip(target):
        try:
            if target.lower() in ["localhost", "127.0.0.1", "::1"]:
                return "Local"

            ip = ipaddress.ip_address(target)
            if ip.is_private:
                return "Local"
            elif ip.is_loopback:
                return "Local"
            elif ip.is_link_local:
                return "Local"
            elif ip.is_multicast:
                return "Local"
            elif ip.is_reserved:
                return "Local"
            elif ip.is_unspecified:
                return "Local"
            else:
                return "Public"

        except ValueError:
            return "Invalid"

    @staticmethod
    def ARP_Scan(target):
        try:
            if target.lower() == "localhost" or target == "127.0.0.1":
                from LightPacket.GetMac import GetMac
                return GetMac()
            else:
                arp_request = scapy.ARP(pdst=target)
                ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether_frame / arp_request

                answered, unanswered = scapy.srp(packet, timeout=2, verbose=0)
                if answered:
                    for sent, received in answered:
                        return received.hwsrc
                else:
                    return None
        except Exception as e:
            print(f"{red}[!] MAC ADDR error: {e}{reset}")

    @staticmethod
    def NDP_Get_MAC(target_ipv6, interface=None):
        try:
            if target_ipv6.lower() == "localhost" or target_ipv6 == "::1":
                from LightPacket.GetMac import GetMac
                return GetMac()

            if target_ipv6.startswith("fe80::") and interface is None:
                print(f"{yellow}[!] Link-local IPv6 requires interface (e.g., fe80::1%eth0){reset}")
                return None

            ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            ns_packet = IPv6(
                dst=target_ipv6,
                hlim=255
            ) / ICMPv6ND_NS(tgt=target_ipv6)

            full_packet = ether / ns_packet

            answered, unanswered = scapy.srp(full_packet, timeout=2, iface=interface, verbose=0)

            for sent, received in answered:
                if received and received.haslayer(ICMPv6ND_NA):
                    return received.src

            return None

        except Exception as e:
            print(f"{red}[!] NDP MAC error: {e}{reset}")
            return None

    @staticmethod
    def ndp_scan(target_ipv6, targets, targets_num, interface=None):
        try:
            if target_ipv6.startswith("fe80::") and interface is None:
                if targets_num == 1:
                    print(f"{yellow}[!] Link-local IPv6 requires interface (e.g., fe80::1%eth0){reset}")
                return

            ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            ns_packet = IPv6(
                dst=target_ipv6,
                hlim=255
            ) / ICMPv6ND_NS(tgt=target_ipv6)

            full_packet = ether / ns_packet

            answered, unanswered = scapy.srp(full_packet, timeout=2, iface=interface, verbose=0)

            is_up = False
            mac = None

            for sent, received in answered:
                if received and received.haslayer(ICMPv6ND_NA):
                    is_up = True
                    mac = received.src
                    break

            if targets_num == 1:
                if is_up:
                    print(f"[NDP] Host {target_ipv6} is up (MAC: {mac})")
                    if target_ipv6 not in targets:
                        targets.append(target_ipv6)
                else:
                    print(f"[NDP] Host {target_ipv6} is down or not responding")
                    targets.append(target_ipv6)
            else:
                if is_up:
                    print(f"[NDP] Host {target_ipv6} is up (MAC: {mac})")
                    if target_ipv6 not in targets:
                        targets.append(target_ipv6)

        except Exception as e:
            if targets_num == 1:
                print(f"[!] NDP scan error for {target_ipv6}: {e}")

    @staticmethod
    def threaded_ndp_scan(max_threads, targets, verbose, Targets, Targets_num, interval, interface=None):
        if not targets:
            return

        if max_threads == 1:
            for target in targets:
                Payloads.ndp_scan(target, Targets, Targets_num, interface)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targets:
                    future = executor.submit(
                        Payloads.ndp_scan, target, Targets, Targets_num, interface
                    )
                    futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] NDP scan error: {e}{reset}")

    @staticmethod
    def arp_Scan(target, targets, targets_num):
        result = arp_scan(target_input=target, verbose=True)
        for res in result:
            if targets_num == 1:
                if res:
                    if ARP in res:
                        targets.append(target)
                else:
                    print(f"[ARP] Host {target} is shown to be down or not responding")
                    targets.append(target)
            else:
                if res:
                    if ARP in res:
                        targets.append(res[ARP].ipsrc)
                else:
                    pass

    @staticmethod
    def threaded_arp_scan(max_threads, targets, verbose, Targets, Targets_num, interval):

        if max_threads == 1:
            for target in targets:
                Payloads.arp_Scan(target, Targets, Targets_num)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targets:
                    future = executor.submit(
                        Payloads.arp_Scan, target, Targets, Targets_num
                    )
                    time.sleep(interval)
                    futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] ARP Ping error: {e}{reset}")

    @staticmethod
    def _record(target, port, bucket, service, banner_option, verbose, version,
                lock, target_results, initialize_target_results):
        services_key = PORT_TO_SERVICES.get(bucket, bucket + "_services")

        with lock:
            if target not in target_results:
                initialize_target_results(target)
            target_results[target][bucket].append(port)

        banner_text, banner_service = None, service
        if banner_option:
            try:
                b = Banner.grab(target, port, protocol="tcp", timeout=3,
                                verbose=verbose, version=version)
                if b and b.get('banner') and b.get('service'):
                    banner_text = b['banner']
                    banner_service = b['service']
            except Exception:
                pass

        with lock:
            if banner_text:
                target_results[target]['banners'].append(banner_text)
                target_results[target]['banners_ports'].append(port)
            target_results[target][services_key].append(banner_service)

    @staticmethod
    def _record_protocol(target, protocol, proto_name, bucket,
                         lock, target_results, initialize_target_results):
        services_key = PORT_TO_SERVICES.get(bucket, bucket + "_names")
        with lock:
            if target not in target_results:
                initialize_target_results(target)
            target_results[target][bucket].append(protocol)
            target_results[target][services_key].append(proto_name)

    @staticmethod
    def _decoy_meta(D, version):
        if not D:
            return None, None, None, None
        mach = decoy(D, version)
        first, last, index = decoy_order(mach)
        return mach, first, last, index

    @staticmethod
    def _send_decoys(packet, mach, start, end, version):
        if not mach:
            return
        for ma in mach[start:end]:
            if version == 6:
                packet[IPv6].src = ma
            else:
                packet[scapy.IP].src = ma
            scapy.send(packet, verbose=0)

    @staticmethod
    def _build_flag_packet(target, port, version, flags_str, payload,
                           ttl, hlim, sport, ip_id, ip_flags):
        if payload is None:
            payloads = mirage.random_payload()
        else:
            payloads = payload

        if version == 6:
            return IPv6(dst=target, nh=6, hlim=hlim) / scapy.TCP(
                dport=port, sport=sport,
                seq=mirage.tcp_seq(), window=mirage.tcp_window(),
                options=mirage.Stealth_tcp_options(),
                flags=flags_str) / scapy.Raw(load=payloads)

        return scapy.IP(dst=target, id=ip_id, ttl=ttl, flags=ip_flags) / scapy.TCP(
            dport=port, sport=sport,
            seq=mirage.tcp_seq(), window=mirage.tcp_window(),
            options=mirage.Stealth_tcp_options(),
            flags=flags_str) / scapy.Raw(load=payloads)

    @staticmethod
    def Flag_Scan(target, port, scan_name, max_retries, fragmente, recursively,
                  verbose, socket_timeout, lock, target_results, banner_option,
                  initialize_target_results, service_detection, version,
                  ttl, hlim, sport, payload, ip_id, ip_flags, fragsize, D,
                  immediate=False,custom=False,flag_str__=""):

        if custom:
            cfg = TCP_FLAG_SCANS["custom"]

            raw = (flag_str__ or "").upper()
            valid = set("FSRPAUECNGH")
            flags_str = "".join(ch for ch in raw if ch in valid)

            if not flags_str:
                if verbose:
                    print(f"{yellow}[!] Invalid or empty custom TCP flags "
                          f"({flag_str__!r}); defaulting to 'S'.{reset}")
                flags_str = "S"
        else:
            cfg = TCP_FLAG_SCANS[scan_name]
            flags_str = cfg["flags"]

        for attempt in range(max_retries):
            try:
                mach, first, last, index = Payloads._decoy_meta(D, version)

                TTL = ttl if ttl else mirage.ipv4_ttl()
                HLIM = hlim if hlim else mirage.ipv6_hlim()
                SPORT = sport if sport else mirage.tcp_sport()
                ID = ip_id if ip_id else mirage.ipv4_id()
                FLAGS = ip_flags if ip_flags is not None else mirage.ipv4_flags()

                packet = Payloads._build_flag_packet(
                    target, port, version, flags_str, payload,
                    TTL, HLIM, SPORT, ID, FLAGS)

                if first:
                    Payloads._send_decoys(packet, mach, 0, index, version)

                if fragmente and recursively:
                    if version == 6:
                        response = Payloads.fragementation(
                            packet, "tcp", scan_name, verbose,
                            fragsize=fragsize, v6=True)
                    else:
                        response = Payloads.fragementation(
                            packet, "tcp", scan_name, verbose,
                            fragsize=fragsize)
                    if verbose:
                        print("\n[+] Demo Fragementation (if you find an error while "
                              "using it leave it in our github for future updates)\n")
                elif fragmente:
                    if verbose:
                        print(f"\n{yellow}[+] Fragmentation is Forbiden with "
                              f"{scan_name.upper()} packets (use -Rc){reset}\n")
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                if last:
                    Payloads._send_decoy_phase_after(packet, mach, index, version)

                service = service_detection(port)

                if response is None:
                    Payloads._record(target, port, cfg["on_no_response"], service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                if response.haslayer(scapy.TCP):
                    tcp_flags = response.getlayer(scapy.TCP).flags

                    if tcp_flags in (0x14, 0x04):
                        if cfg.get("window_check"):
                            window = response.getlayer(scapy.TCP).window
                            if window == 0:
                                Payloads._record(
                                    target, port, "closed_ports", service,
                                    banner_option, verbose, version,
                                    lock, target_results, initialize_target_results)
                            else:
                                if immediate:
                                    print(f"[+] Port {port} is open .")
                                Payloads._record(
                                    target, port, "open_ports", service,
                                    banner_option, verbose, version,
                                    lock, target_results, initialize_target_results)
                            return

                        Payloads._record(target, port, cfg["on_rst"], service,
                                         banner_option, verbose, version,
                                         lock, target_results, initialize_target_results)
                        return

                    if tcp_flags == 0x12:
                        Payloads._record(
                            target, port, "open_ports", service,
                            banner_option, verbose, version,
                            lock, target_results, initialize_target_results)
                        return

                    if verbose:
                        print(tcp_flags)
                    Payloads._record(target, port, cfg["on_other_tcp"], service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                if response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    bucket = (cfg["on_icmpv6_closed"] if code == 4
                              else cfg["on_icmpv6_other"])
                    Payloads._record(target, port, bucket, service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                if response.haslayer(scapy.ICMP):
                    Payloads._record(target, port, cfg["on_icmp"], service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                Payloads._record(target, port, cfg["on_icmp"], service,
                                 banner_option, verbose, version,
                                 lock, target_results, initialize_target_results)
                return

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port} ({scan_name}): {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        if port in target_results[target]['open_ports']:
                            return
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    return
                time.sleep(0.1)
                continue

    @staticmethod
    def _send_decoy_phase_after(packet, mach, index, version):
        if not mach:
            return
        for ma in mach[index:]:
            if version == 6:
                packet[IPv6].src = ma
            else:
                packet[scapy.IP].src = ma
            scapy.send(packet, verbose=0)

    @staticmethod
    def Null_Scan(target, port, max_retries, fragmente, recursively, verbose,
                  socket_timeout, lock, target_results, banner_option,
                  initialize_target_results, service_detection, version, ttl, hlim,
                  sport, payload, id, flags, fragsize, D):
        Payloads.Flag_Scan(target, port, "null", max_retries, fragmente, recursively,
                           verbose, socket_timeout, lock, target_results, banner_option,
                           initialize_target_results, service_detection, version,
                           ttl, hlim, sport, payload, id, flags, fragsize, D)

    @staticmethod
    def Custom_Scan(target, port, max_retries, fragmente, recursively, verbose,
                    socket_timeout, lock, target_results, banner_option,
                    initialize_target_results, service_detection, version, ttl, hlim,
                    sport, payload, id, flags, fragsize, D, c, flagss):
        Payloads.Flag_Scan(target, port, "custom",
                           max_retries, fragmente, recursively,
                           verbose, socket_timeout, lock, target_results, banner_option,
                           initialize_target_results, service_detection, version,
                           ttl, hlim, sport, payload, id, flags, fragsize, D,
                           custom=True, flag_str__=flagss)

    @staticmethod
    def Fin_Scan(target, port, max_retries, fragmente, recursively, verbose,
                 socket_timeout, lock, target_results, banner_option,
                 initialize_target_results, service_detection, version, ttl, hlim,
                 sport, payload, id, flags, fragsize, D):
        Payloads.Flag_Scan(target, port, "fin", max_retries, fragmente, recursively,
                           verbose, socket_timeout, lock, target_results, banner_option,
                           initialize_target_results, service_detection, version,
                           ttl, hlim, sport, payload, id, flags, fragsize, D)

    @staticmethod
    def Ack_Scan(target, port, max_retries, fragmente, recursively, verbose,
                 socket_timeout, lock, target_results, banner_option,
                 initialize_target_results, service_detection, version, ttl, hlim,
                 sport, payload, id, flags, fragsize, D):
        Payloads.Flag_Scan(target, port, "ack", max_retries, fragmente, recursively,
                           verbose, socket_timeout, lock, target_results, banner_option,
                           initialize_target_results, service_detection, version,
                           ttl, hlim, sport, payload, id, flags, fragsize, D)

    @staticmethod
    def Xmas_Scan(target, port, max_retries, fragmente, recursively, verbose,
                  socket_timeout, lock, target_results, banner_option,
                  initialize_target_results, service_detection, version, ttl, hlim,
                  sport, payload, id, flags, fragsize, D):
        Payloads.Flag_Scan(target, port, "xmas", max_retries, fragmente, recursively,
                           verbose, socket_timeout, lock, target_results, banner_option,
                           initialize_target_results, service_detection, version,
                           ttl, hlim, sport, payload, id, flags, fragsize, D)

    @staticmethod
    def Maimon_Scan(target, port, max_retries, fragmente, recursively, verbose,
                    socket_timeout, lock, target_results, banner_option,
                    initialize_target_results, service_detection, version, ttl, hlim,
                    sport, payload, id, flags, fragsize, D):
        Payloads.Flag_Scan(target, port, "maimon", max_retries, fragmente, recursively,
                           verbose, socket_timeout, lock, target_results, banner_option,
                           initialize_target_results, service_detection, version,
                           ttl, hlim, sport, payload, id, flags, fragsize, D)

    @staticmethod
    def Window_Scan(target, port, max_retries, fragmente, recursively, verbose,
                    socket_timeout, lock, target_results, banner_option,
                    initialize_target_results, service_detection, version, ttl, hlim,
                    sport, payload, id, flags, I, fragsize, D):
        Payloads.Flag_Scan(target, port, "window", max_retries, fragmente, recursively,
                           verbose, socket_timeout, lock, target_results, banner_option,
                           initialize_target_results, service_detection, version,
                           ttl, hlim, sport, payload, id, flags, fragsize, D,
                           immediate=I)

    @staticmethod
    def Fdd_Scan(target, port, max_retries, fragmente, recursively, verbose,
                 socket_timeout, lock, target_results, banner_option,
                 initialize_target_results, service_detection, version, ttl, hlim,
                 sport, payload, id, flags, fragsize, D):
        Payloads.Flag_Scan(target, port, "fdd", max_retries, fragmente, recursively,
                           verbose, socket_timeout, lock, target_results, banner_option,
                           initialize_target_results, service_detection, version,
                           ttl, hlim, sport, payload, id, flags, fragsize, D)

    @staticmethod
    def _threaded_flag_scan(scan_fn, max_retries, lock, verbose, fragmente, recursively,
                            socket_timeout, target_results, banner_option, max_threads,
                            targetss, ports_to_scan, i, s, version, ttl, hlim, sport,
                            payload, id, flags, interval, fs, d, extra_after_flags=None,
                            c=False, f=""):

        def work(target, port):
            base = [target, port, max_retries, fragmente, recursively,
                    verbose, socket_timeout, lock, target_results,
                    banner_option, i, s, version, ttl, hlim, sport, payload,
                    id, flags]

            if c:
                scan_fn(*base, fs, d, c, f)
            elif extra_after_flags is not None:
                scan_fn(*base, extra_after_flags, fs, d)
            else:
                scan_fn(*base, fs, d)

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    work(target, port)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        futures.append(executor.submit(work, target, port))
                        time.sleep(interval)
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Flag scan error: {e}{reset}")

    @staticmethod
    def threaded_null_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                           target_results, banner_option, max_threads, targetss, ports_to_scan,
                           i, s, version, ttl, hlim, sport, payload, id, flags, interval, fs, d):
        Payloads._threaded_flag_scan(
            Payloads.Null_Scan, max_retries, lock, verbose, fragmente, recursively,
            socket_timeout, target_results, banner_option, max_threads, targetss,
            ports_to_scan, i, s, version, ttl, hlim, sport, payload, id, flags,
            interval, fs, d)

    @staticmethod
    def threaded_custom_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                           target_results, banner_option, max_threads, targetss, ports_to_scan,
                           i, s, version, ttl, hlim, sport, payload, id, flags, interval, fs, d, flagss):
        Payloads._threaded_flag_scan(
            Payloads.Custom_Scan, max_retries, lock, verbose, fragmente, recursively,
            socket_timeout, target_results, banner_option, max_threads, targetss,
            ports_to_scan, i, s, version, ttl, hlim, sport, payload, id, flags,
            interval, fs, d, c=True,f=flagss)

    @staticmethod
    def threaded_fin_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                          target_results, banner_option, max_threads, targetss, ports_to_scan,
                          i, s, version, ttl, hlim, sport, payload, id, flags, interval, fg, d):
        Payloads._threaded_flag_scan(
            Payloads.Fin_Scan, max_retries, lock, verbose, fragmente, recursively,
            socket_timeout, target_results, banner_option, max_threads, targetss,
            ports_to_scan, i, s, version, ttl, hlim, sport, payload, id, flags,
            interval, fg, d)

    @staticmethod
    def threaded_ack_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                          target_results, banner_option, max_threads, targetss, ports_to_scan,
                          i, s, version, ttl, hlim, sport, payload, id, flags, interval, fg, d):
        Payloads._threaded_flag_scan(
            Payloads.Ack_Scan, max_retries, lock, verbose, fragmente, recursively,
            socket_timeout, target_results, banner_option, max_threads, targetss,
            ports_to_scan, i, s, version, ttl, hlim, sport, payload, id, flags,
            interval, fg, d)

    @staticmethod
    def threaded_xmas_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                           target_results, banner_option, max_threads, targetss, ports_to_scan,
                           i, s, version, ttl, hlim, sport, payload, id, flags, interval, fg, d):
        Payloads._threaded_flag_scan(
            Payloads.Xmas_Scan, max_retries, lock, verbose, fragmente, recursively,
            socket_timeout, target_results, banner_option, max_threads, targetss,
            ports_to_scan, i, s, version, ttl, hlim, sport, payload, id, flags,
            interval, fg, d)

    @staticmethod
    def threaded_maimon_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                             target_results, banner_option, max_threads, targetss, ports_to_scan,
                             i, s, version, ttl, hlim, sport, payload, id, flags, interval, fg, d):
        Payloads._threaded_flag_scan(
            Payloads.Maimon_Scan, max_retries, lock, verbose, fragmente, recursively,
            socket_timeout, target_results, banner_option, max_threads, targetss,
            ports_to_scan, i, s, version, ttl, hlim, sport, payload, id, flags,
            interval, fg, d)

    @staticmethod
    def threaded_window_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                             target_results, banner_option, max_threads, targetss, ports_to_scan,
                             i, s, version, ttl, hlim, sport, payload, id, flags, interval, I, fg, d):
        Payloads._threaded_flag_scan(
            Payloads.Window_Scan, max_retries, lock, verbose, fragmente, recursively,
            socket_timeout, target_results, banner_option, max_threads, targetss,
            ports_to_scan, i, s, version, ttl, hlim, sport, payload, id, flags,
            interval, fg, d, extra_after_flags=I)

    @staticmethod
    def threaded_fdd_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                          target_results, banner_option, max_threads, targetss, ports_to_scan,
                          i, s, version, ttl, hlim, sport, payload, id, flags, interval, fg, d):
        Payloads._threaded_flag_scan(
            Payloads.Fdd_Scan, max_retries, lock, verbose, fragmente, recursively,
            socket_timeout, target_results, banner_option, max_threads, targetss,
            ports_to_scan, i, s, version, ttl, hlim, sport, payload, id, flags,
            interval, fg, d)

    @staticmethod
    def _build_ip_proto_packet(target, protocol, version, ttl, hlim, sport, ip_id, ip_flags, payloads):
        if version == 6:
            packet = IPv6(dst=target, nh=protocol, hlim=hlim, fl=0)
        else:
            packet = scapy.IP(dst=target, proto=protocol, ttl=ttl, id=ip_id, flags=ip_flags)

        if protocol == 1 and version != 6:
            packet = packet / scapy.ICMP(type=8, code=0) / scapy.Raw(load=random.choice(payloads))
        elif protocol == 58 and version == 6:
            packet = packet / ICMPv6EchoRequest(data=b"ping") / scapy.Raw(load=random.choice(payloads))
        elif protocol == 6:
            packet = packet / scapy.TCP(sport=sport, dport=random.randint(1, 65535),
                                        flags="S", seq=random.randint(1, 4294967295)) \
                / scapy.Raw(load=random.choice(payloads))
        elif protocol == 17:
            packet = mirage.dns_payload_udp(target, version)
        elif protocol == 132:
            try:
                from scapy.layers.sctp import SCTP, SCTPChunkInit
                packet = packet / SCTP(sport=sport, dport=80) / SCTPChunkInit() \
                    / scapy.Raw(load=random.choice(payloads))
            except ImportError:
                pass
        elif protocol == 47:
            packet = packet / b"\x00\x00\x00\x00"
        elif protocol == 50:
            packet = packet / b"\x00\x00\x00\x01\x00\x00\x00\x00"
        elif protocol == 51:
            packet = packet / b"\x00\x00\x00\x00\x00\x00\x00\x00"
        elif protocol == 89:
            packet = packet / b"\x01\x00\x00\x00"

        return packet

    @staticmethod
    def IP_Scan(target, protocol, max_retries, fragmente, recursively, verbose, socket_timeout,
                lock, target_results, banner_option, initialize_target_results, service_detection,
                version, ttl, hlim, sport, payload, id, flags, fragsize, D):
        proto_names = _IP_PROTOCOL_NAMES
        proto_name = proto_names.get(protocol, f"Proto{protocol}")
        is_localhost = target in ["127.0.0.1", "::1", "localhost"]

        for attempt in range(max_retries):
            try:
                mach, first, last, index = Payloads._decoy_meta(D, version)

                TTL = ttl if ttl else mirage.ipv4_ttl()
                HLIM = hlim if hlim else mirage.ipv6_hlim()
                SPORT = sport if sport else mirage.tcp_sport()
                ID = id if id else mirage.ipv4_id()
                FLAGS = flags if flags is not None else mirage.ipv4_flags()

                if payload is None:
                    payloads = ["PING", "URGENT", "!HHHH", "LIGHTSCAN", "UDP", "TCP", "-Pu", "KIWI"]
                else:
                    payloads = [payload]

                packet = Payloads._build_ip_proto_packet(
                    target, protocol, version, TTL, HLIM, SPORT, ID, FLAGS, payloads)

                if first:
                    for ma in mach[:index]:
                        Pipo = deepcopy(packet)
                        if version == 6:
                            Pipo[IPv6].src = ma
                        else:
                            Pipo[scapy.IP].src = ma
                        scapy.send(Pipo, verbose=0)

                if fragmente and recursively:
                    if version == 6:
                        response = Payloads.fragementation(packet, "ip", "ipproto", verbose,
                                                           fragsize=fragsize, v6=True)
                    else:
                        response = Payloads.fragementation(packet, "ip", "ipproto", verbose,
                                                           fragsize=fragsize)
                    if verbose:
                        print("\n[+] Fragmentation enabled for IP Protocol scan\n")
                elif fragmente:
                    if verbose:
                        print(f"\n{yellow}[+] Fragmentation not supported for IP Protocol scan (use -Rc){reset}\n")
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                if last:
                    for ma in mach[index:]:
                        if version == 4:
                            packet[scapy.IP].src = ma
                        else:
                            packet[IPv6].src = ma
                        scapy.send(packet, verbose=0)

                if response and response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code == 2:
                        Payloads._record_protocol(target, protocol, proto_name,
                                                  "closed_protocols", lock,
                                                  target_results, initialize_target_results)
                        return
                    elif icmp_type == 0:
                        Payloads._record_protocol(target, protocol, proto_name,
                                                  "open_protocols", lock,
                                                  target_results, initialize_target_results)
                        return
                    elif icmp_type == 3 and icmp_code in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]:
                        Payloads._record_protocol(target, protocol, proto_name,
                                                  "filtered_protocols", lock,
                                                  target_results, initialize_target_results)
                        return

                if response and response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    bucket = "closed_protocols" if code == 4 else "filtered_protocols"
                    Payloads._record_protocol(target, protocol, proto_name, bucket,
                                              lock, target_results, initialize_target_results)
                    return

                if response and (response.haslayer(scapy.TCP) or response.haslayer(scapy.UDP)):
                    Payloads._record_protocol(target, protocol, proto_name,
                                              "open_protocols", lock,
                                              target_results, initialize_target_results)
                    return

                if response is None:
                    Payloads._record_protocol(target, protocol, proto_name,
                                              "open_filtered_protocols", lock,
                                              target_results, initialize_target_results)
                    return

                # Proto field match → open_filtered (or closed for localhost)
                proto_field = response.nh if version == 6 else response.proto
                if proto_field == protocol:
                    bucket = "closed_protocols" if is_localhost else "open_filtered_protocols"
                    Payloads._record_protocol(target, protocol, proto_name, bucket,
                                              lock, target_results, initialize_target_results)
                    return

                Payloads._record_protocol(target, protocol, proto_name,
                                          "closed_protocols", lock,
                                          target_results, initialize_target_results)
                return

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning protocol {protocol}: {e}{reset}")
                if attempt == max_retries - 1:
                    Payloads._record_protocol(target, protocol, proto_name,
                                              "filtered_protocols", lock,
                                              target_results, initialize_target_results)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_ip_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                         target_results, banner_option, max_threads, targetss, protocols_to_scan,
                         initialize_target_results, service_detection, version, ttl, hlim, sport,
                         payload, id, flags, interval, fg, d):
        if max_threads == 1:
            for target in targetss:
                for protocol in protocols_to_scan:
                    Payloads.IP_Scan(target, protocol, max_retries, fragmente, recursively,
                                     verbose, socket_timeout, lock, target_results,
                                     banner_option, initialize_target_results, service_detection,
                                     version, ttl, hlim, sport, payload, id, flags, fg, d)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for protocol in protocols_to_scan:
                        future = executor.submit(
                            Payloads.IP_Scan, target, protocol, max_retries, fragmente,
                            recursively, verbose, socket_timeout, lock, target_results,
                            banner_option, initialize_target_results, service_detection,
                            version, ttl, hlim, sport, payload, id, flags, fg, d)
                        time.sleep(interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] IP Protocol scan error: {e}{reset}")

    @staticmethod
    def IP_Ping(target, protocol, verbose, socket_timeout,
                target_results, ttl, hlim, id, flags, D, v6=False):
        version = 6 if v6 else 4
        mach, first, last, index = Payloads._decoy_meta(D, version)

        for i in range(2):
            try:
                TTL = ttl if ttl else mirage.ipv4_ttl()
                HLIM = hlim if hlim else mirage.ipv6_hlim()
                ID = id if id else mirage.ipv4_id()
                FLAGS = flags if flags is not None else mirage.ipv4_flags()

                if v6:
                    packet = IPv6(dst=target, nh=protocol, hlim=HLIM, fl=0)
                else:
                    packet = scapy.IP(dst=target, proto=protocol, ttl=TTL, id=ID, flags=FLAGS)

                if first:
                    for ma in mach[:index]:
                        if version == 4:
                            scapy.send(scapy.IP(dst=target, src=ma, proto=protocol, ttl=TTL,
                                                id=ID, flags=FLAGS), verbose=0)
                        else:
                            scapy.send(IPv6(dst=target, src=ma, nh=protocol, hlim=HLIM, fl=0), verbose=0)

                response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                if last:
                    for ma in mach[index:]:
                        if version == 4:
                            packet[scapy.IP].src = ma
                        else:
                            packet[IPv6].src = ma
                        scapy.send(packet, verbose=0)

                if response:
                    bucket = Payloads._classify_ip_ping_response(response, protocol, v6)
                else:
                    bucket = "down"

                target_results[target][bucket] += 1

            except Exception as e:
                if verbose:
                    print(f"{red}[!] IP Ping Error (IPv6={v6}, protocol={protocol}): {e}{reset}")
                target_results[target]['filtered'] += 1

    @staticmethod
    def _classify_ip_ping_response(response, protocol, v6):
        if v6:
            if response.haslayer(ICMPv6DestUnreach):
                code = response.getlayer(ICMPv6DestUnreach).code
                return "up" if code in [1, 3, 4] else "filtered"
            if response.haslayer(ICMPv6EchoReply):
                return "up"
            if response.haslayer(ICMPv6TimeExceeded):
                return "filtered"
            if response.haslayer(ICMPv6ParamProblem):
                return "filtered"
            if response.haslayer(scapy.TCP):
                return "up"
            if response.haslayer(scapy.UDP):
                return "up"
            return "up"

        if response.haslayer(scapy.ICMP):
            icmp = response.getlayer(scapy.ICMP)
            if icmp.type == 3:
                if icmp.code in [13, 1, 2, 9, 10]:
                    return "filtered"
                if icmp.code == 3:
                    return "up"
                return "down"
            if icmp.type in [0, 14, 18]:
                return "up"
            if icmp.type == 11:
                return "filtered"
            return "up"

        if response.haslayer(scapy.TCP):
            return "up"
        if response.haslayer(scapy.UDP):
            return "up"
        return "up"

    @staticmethod
    def threaded_ip_ping(max_threads, verbose, socket_timeout, targets,
                         Target, protocols, target_results, ttl, hlim, id, flags, v6, interval, d):
        for target in targets:
            target_results[target] = {'up': 0, 'down': 0, 'filtered': 0}

        if max_threads == 1:
            for target in targets:
                for protocol in protocols:
                    Payloads.IP_Ping(target, protocol, verbose, socket_timeout,
                                     target_results, ttl, hlim, id, flags, d, v6)
        else:
            futures = []
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                for target in targets:
                    for protocol in protocols:
                        future = executor.submit(
                            Payloads.IP_Ping, target, protocol, verbose,
                            socket_timeout, target_results, ttl, hlim, id, flags, d, v6)
                        time.sleep(interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Error: {e}{reset}")

        for target in targets:
            up = target_results[target]['up']
            down = target_results[target]['down']
            filtered = target_results[target]['filtered']
            single = (len(targets) == 1)

            if up > down and up > filtered:
                print(f"[IP] Host {target} is up! ({up} up, {down} down)")
                if target not in Target:
                    Target.append(target)
            elif down > up and down > filtered:
                print(f"[IP] Host {target} appears down ({up} up, {down} down)")
                if single and target not in Target:
                    Target.append(target)
            elif filtered > up and filtered > down:
                print(f"[IP] Host {target} appears to be not responding "
                      f"({up} up, {down} down, {filtered} filtered)")
                if single and target not in Target:
                    Target.append(target)
            else:
                print(f"[IP] Host {target}: Inconclusive ({up} up, {down} down, {filtered} filtered)")
                if single and target not in Target:
                    Target.append(target)

    @staticmethod
    def Ack_ping(target, port, socket_timeout, targets_num, target_results, targetss,
                 ttl, hlim, sport, id, flags, version, D):
        mach, first, last, index = Payloads._decoy_meta(D, version)

        TTL = ttl if ttl else mirage.ipv4_ttl()
        HLIM = hlim if hlim else mirage.ipv6_hlim()
        SPORT = sport if sport else mirage.tcp_sport()
        ID = id if id else mirage.ipv4_id()
        FLAGS = flags if flags is not None else mirage.ipv4_flags()

        if version == 6:
            packet = IPv6(dst=target, hlim=HLIM, nh=6) / scapy.TCP(
                dport=port, sport=SPORT, seq=mirage.tcp_seq(),
                window=mirage.tcp_window(), options=mirage.Stealth_tcp_options(), flags="A")
        else:
            packet = scapy.IP(dst=target, id=ID, ttl=TTL, flags=FLAGS) / scapy.TCP(
                dport=port, sport=SPORT, seq=mirage.tcp_seq(),
                window=mirage.tcp_window(), options=mirage.Stealth_tcp_options(), flags="A")

        if first:
            for ma in mach[:index]:
                if version == 4:
                    scapy.send(scapy.IP(dst=target, src=ma, id=mirage.ipv4_id(),
                                        ttl=TTL, flags=mirage.ipv4_flags()) / scapy.TCP(
                        dport=port, sport=SPORT, seq=mirage.tcp_seq(),
                        window=mirage.tcp_window(), options=mirage.Stealth_tcp_options(),
                        flags="A"), verbose=0)
                else:
                    scapy.send(IPv6(dst=target, src=ma, hlim=HLIM, nh=6) / scapy.TCP(
                        dport=port, sport=SPORT, seq=mirage.tcp_seq(),
                        window=mirage.tcp_window(), options=mirage.Stealth_tcp_options(),
                        flags="A"), verbose=0)

        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

        if last:
            for ma in mach[index:]:
                if version == 4:
                    packet[scapy.IP].src = ma
                else:
                    packet[IPv6].src = ma
                scapy.send(packet, verbose=0)

        if response:
            target_results[target]['up'] += 1
            with_lock = target not in targetss
            if len(targets_num) == 1:
                if version == 6 and response.haslayer(ICMPv6DestUnreach):
                    print(f"[ACK] Host {target}:{port} is up! (ICMPv6)")
                elif response.haslayer(scapy.TCP):
                    fl = response.getlayer(scapy.TCP).flags
                    if fl in (0x04, 0x14):
                        print(f"[ACK] Host {target}:{port} is up! (RST response)")
                    else:
                        print(f"[ACK] Host {target}:{port} is up! (Unexpected flags: {fl})")
                elif response.haslayer(scapy.ICMP):
                    print(f"[ACK] Host {target}:{port} is up! (ICMP response)")
                else:
                    print(f"[ACK] Host {target}:{port} is up! (Unknown response)")

            if target not in targetss:
                targetss.append(target)
        else:
            if len(targets_num) == 1 and target not in targetss:
                targetss.append(target)

    @staticmethod
    def threaded_ack_ping(max_threads, targets, ping_port, pp, target_results, socket_timeout,
                          targetss, verbose, num, version, ttl, hlim, sport, id, flags, interval, d):
        if max_threads == 1:
            for Target in targets:
                if ping_port:
                    for port in pp:
                        Payloads.Ack_ping(Target, port, socket_timeout, num, target_results,
                                          targetss, ttl, hlim, sport, id, flags, version, d)
                else:
                    for port in top_20_tcp_ports:
                        Payloads.Ack_ping(Target, port, socket_timeout, targets, target_results,
                                          targetss, ttl, hlim, sport, id, flags, version, d)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for Target in targets:
                    ports = pp if ping_port else top_20_tcp_ports
                    num_arg = num if ping_port else targets
                    for port in ports:
                        future = executor.submit(
                            Payloads.Ack_ping, Target, port, socket_timeout, num_arg,
                            target_results, targetss, ttl, hlim, sport, id, flags, version, d)
                        time.sleep(interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] ACK ping error: {e}{reset}")

        for target in targets:
            time.sleep(0.01)
            if target_results[target]['up'] >= 1:
                pass
            else:
                print(f"[ACK] Host {target} is shown to be down or not responding")

    @staticmethod
    def Idle_Scan(target, port, zombie_ip, max_retries, verbose, socket_timeout,
                  lock, target_results, banner_option, initialize_target_results,
                  service_detection, version, ttl, sport, payload, id, flags, I, D):
        for attempt in range(max_retries):
            try:
                mach, first, last, index = Payloads._decoy_meta(D, version=4)

                TTL = ttl if ttl else mirage.ipv4_ttl()
                SPORT = sport if sport else mirage.tcp_sport()

                if payload is not None:
                    probe_pkt = scapy.IP(dst=zombie_ip) / scapy.TCP(dport=445, flags="SA") \
                        / scapy.Raw(load=payload)
                else:
                    probe_pkt = scapy.IP(dst=zombie_ip) / scapy.TCP(dport=445, flags="SA")

                if first:
                    for ma in mach[:index]:
                        Pipo = deepcopy(probe_pkt)
                        Pipo[scapy.IP].src = ma
                        scapy.send(Pipo, verbose=0)

                reply1 = scapy.sr1(probe_pkt, timeout=socket_timeout, verbose=0)
                service = service_detection(port)

                if not reply1 or not reply1.haslayer(scapy.IP):
                    Payloads._record(target, port, "filtered_ports", service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                if version == 6:
                    if verbose:
                        print(f"\n{yellow}[!] Idle Scan doesn't work with IPv6 {reset}\n")
                    Payloads._record(target, port, "filtered_ports", service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                id1 = reply1[scapy.IP].id
                ID = id if id else mirage.ipv4_id()
                FLAGS = flags if flags is not None else mirage.ipv4_flags()

                spoofed = scapy.IP(src=zombie_ip, dst=target, id=ID, ttl=TTL, flags=FLAGS) \
                    / scapy.TCP(dport=port, sport=SPORT, seq=mirage.tcp_seq(), flags="S",
                                window=mirage.tcp_window(),
                                options=mirage.Stealth_tcp_options())
                scapy.send(spoofed, verbose=0)
                time.sleep(0.3)

                reply2 = scapy.sr1(probe_pkt, timeout=socket_timeout, verbose=0)

                if not reply2 or not reply2.haslayer(scapy.IP):
                    Payloads._record(target, port, "filtered_ports",
                                     "zombie_unreachable_after",
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                diff = (reply2[scapy.IP].id - id1) % 65536

                if diff == 1:
                    Payloads._record(target, port, "closed_filtered_ports", service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                elif diff == 2:
                    if I:
                        print(f"[+] Port {port} is open .")
                    Payloads._record(target, port, "open_ports", service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                else:
                    Payloads._record(target, port, "filtered_ports", service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                return

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Idle scan error on port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        if port not in target_results[target]['open_ports']:
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                    return
                time.sleep(0.2)
                continue

    @staticmethod
    def threaded_idle_scan(max_retries, lock, verbose, socket_timeout, target_results,
                           banner_option, max_threads, targetss, ports_to_scan,
                           initialize_target_results, service_detection, version,
                           zombie_ips, ttl, sport, payload, id, flags, interval, I, d):

        if isinstance(zombie_ips, str):
            zombie_ips = [zombie_ips]

        if not zombie_ips:
            print(f"{red}[!] No zombie(s) specified for idle scan{reset}")
            return

        good_zombies = []
        print(f"{green}[+] Testing {len(zombie_ips)} zombie(s)...{reset}")

        for zombie in zombie_ips:
            test_pkt = scapy.IP(dst=zombie) / scapy.TCP(dport=445, flags="SA")
            test_reply = scapy.sr1(test_pkt, timeout=socket_timeout, verbose=0)

            if test_reply and test_reply.haslayer(scapy.IP):
                good_zombies.append(zombie)
                print(f"{green}[+] Zombie {zombie} is responding (IP ID: {test_reply[scapy.IP].id}){reset}")
            else:
                print(f"{red}[-] Zombie {zombie} is not responding, skipping{reset}")

        if not good_zombies:
            print(f"{red}[!] No responsive zombies found{reset}")
            return

        print(f"{green}[+] Using {len(good_zombies)} zombie(s){reset}")

        ports_per_zombie = len(ports_to_scan) // len(good_zombies)
        zombie_ports = {}

        for i, zombie in enumerate(good_zombies):
            start_idx = i * ports_per_zombie
            end_idx = start_idx + ports_per_zombie if i < len(good_zombies) - 1 else len(ports_to_scan)
            zombie_ports[zombie] = ports_to_scan[start_idx:end_idx]

            if verbose:
                print(f"{green}[+] Zombie {zombie} -> {len(zombie_ports[zombie])} ports{reset}")

        if max_threads == 1:
            for target in targetss:
                for zombie, ports in zombie_ports.items():
                    for port in ports:
                        Payloads.Idle_Scan(target, port, zombie, max_retries, verbose,
                                           socket_timeout, lock, target_results,
                                           banner_option, initialize_target_results,
                                           service_detection, version, ttl, sport,
                                           payload, id, flags, I, d)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for zombie, ports in zombie_ports.items():
                        for port in ports:
                            future = executor.submit(
                                Payloads.Idle_Scan, target, port, zombie, max_retries,
                                verbose, socket_timeout, lock, target_results,
                                banner_option, initialize_target_results,
                                service_detection, version, ttl, sport,
                                payload, id, flags, I, d)
                            time.sleep(interval)
                            futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Idle scan thread error: {e}{reset}")

    @staticmethod
    def Sctp_init_Scan(target, port, max_retries, fragmente, recursively, verbose,
                       socket_timeout, lock, target_results, banner_option,
                       initialize_target_results, service_detection, version, ttl, hlim,
                       sport, payload, id, flags, fragsize, D):
        for attempt in range(max_retries):
            try:
                mach, first, last, index = Payloads._decoy_meta(D, version)

                TTL = ttl if ttl else mirage.ipv4_ttl()
                HLIM = hlim if hlim else mirage.ipv6_hlim()
                SPORT = sport if sport else mirage.sctp_sport()
                ID = id if id else mirage.ipv4_id()
                FLAGS = flags if flags is not None else mirage.ipv4_flags()

                init_chunk = scapy.SCTPChunkInit(
                    a_rwnd=65535, init_tag=12345678,
                    n_out_streams=10, n_in_streams=10, init_tsn=1000)

                if version == 6:
                    packet = IPv6(dst=target, nh=6, hlim=HLIM) \
                        / scapy.SCTP(sport=SPORT, dport=port, tag=0) / init_chunk
                else:
                    packet = scapy.IP(dst=target, id=ID, ttl=TTL, flags=FLAGS) \
                        / scapy.SCTP(sport=SPORT, dport=port, tag=0) / init_chunk

                if payload is not None:
                    packet = packet / scapy.Raw(load=payload)

                if first:
                    for ma in mach[:index]:
                        Pipo = deepcopy(packet)
                        if version == 6:
                            Pipo[IPv6].src = ma
                        else:
                            Pipo[scapy.IP].src = ma
                        scapy.send(Pipo, verbose=0)

                if fragmente and recursively:
                    if version == 6:
                        response = Payloads.fragementation(packet, "sctp", "init", verbose,
                                                           fragsize=fragsize, v6=True)
                    else:
                        response = Payloads.fragementation(packet, "sctp", "init", verbose,
                                                           fragsize=fragsize)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                if last:
                    for ma in mach[index:]:
                        if version == 4:
                            packet[scapy.IP].src = ma
                        else:
                            packet[IPv6].src = ma
                        scapy.send(packet, verbose=0)

                service = service_detection(port)

                if response is None:
                    Payloads._record(target, port, "filtered_ports", service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                if response.haslayer(scapy.SCTPChunkInitAck):
                    Payloads._record(target, port, "open_ports", service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                if response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    bucket = "closed_ports" if code == 4 else "filtered_ports"
                    Payloads._record(target, port, bucket, service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                if response.haslayer(scapy.ICMP):
                    Payloads._record(target, port, "filtered_ports", service,
                                     banner_option, verbose, version,
                                     lock, target_results, initialize_target_results)
                    return

                Payloads._record(target, port, "filtered_ports", service,
                                 banner_option, verbose, version,
                                 lock, target_results, initialize_target_results)
                return

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        if port not in target_results[target]['open_ports']:
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                    return
                time.sleep(0.1)
                continue

    @staticmethod
    def threaded_sctp_init_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                                target_results, banner_option, max_threads, targetss, ports_to_scan,
                                i, s, version, ttl, hlim, sport, payload, id, flags, interval, fg, d):
        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Sctp_init_Scan(target, port, max_retries, fragmente, recursively,
                                            verbose, socket_timeout, lock, target_results,
                                            banner_option, i, s, version, ttl, hlim, sport,
                                            payload, id, flags, fg, d)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Sctp_init_Scan, target, port, max_retries,
                            fragmente, recursively, verbose, socket_timeout, lock,
                            target_results, banner_option, i, s, version, ttl, hlim,
                            sport, payload, id, flags, fg, d)
                        time.sleep(interval)
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] SCTP INIT scan error: {e}{reset}")

    @staticmethod
    def FTPBounceScan(target, ftpserver, ftp_port, port_range, interval, max_retries=2,
                      imediate=None, fragment=False, recursively=False,
                      verbose=False, socket_timeout=5, lock=None, target_results=None,
                      banner_option=False, initialize_target_results=None,
                      service_detection=None, version=4):

        import socket

        def encode_ip(ip, ver=4):
            if ver == 6:
                return f"|2|{ip}|"
            return ",".join(ip.split("."))

        def encode_port(p):
            return f"{p // 256},{p % 256}"

        def read_until_response(sock, timeout=5):
            sock.settimeout(timeout)
            response = ""
            while True:
                try:
                    data = sock.recv(1024).decode(errors='ignore')
                    if not data:
                        break
                    response += data
                    if len(response) >= 4 and response[3] == ' ':
                        break
                    if len(response) >= 4 and response[3] == '-' and '\n' + response[:3] + ' ' in response:
                        break
                except socket.timeout:
                    break
            return response

        def send_eprt(ftp_control, target_ip, target_port, ver=4):
            if ver == 6:
                eprt_cmd = f"EPRT |2|{target_ip}|{target_port}\r\n"
                ftp_control.send(eprt_cmd.encode())
                resp = read_until_response(ftp_control, socket_timeout)
                return "200" in resp
            else:
                ip_comma = encode_ip(target_ip, ver=4)
                port_code = encode_port(target_port)
                port_cmd = f"PORT {ip_comma},{port_code}\r\n"
                ftp_control.send(port_cmd.encode())
                resp = read_until_response(ftp_control, socket_timeout)
                return "200" in resp

        def setup_data_channel(ftp_control, target_ip, target_port, ver=4):
            listen_sock = None
            try:
                listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listen_sock.settimeout(socket_timeout)
                listen_sock.bind(('', 0))
                listen_sock.listen(1)
                local_port = listen_sock.getsockname()[1]

                if not send_eprt(ftp_control, target_ip, local_port, ver=ver):
                    listen_sock.close()
                    return None

                ftp_control.send(b"LIST\r\n")
                list_resp = read_until_response(ftp_control, socket_timeout)

                if "150" not in list_resp:
                    listen_sock.close()
                    return ("filtered", target_port)

                try:
                    data_sock, addr = listen_sock.accept()
                    data_sock.settimeout(socket_timeout)
                    data_sock.recv(1024)
                    data_sock.close()
                except socket.timeout:
                    listen_sock.close()
                    return ("filtered", target_port)

                final_resp = read_until_response(ftp_control, socket_timeout)
                listen_sock.close()

                if "226" in final_resp:
                    return ("open", target_port)
                elif "425" in final_resp:
                    return ("closed", target_port)
                return ("filtered", target_port)

            except Exception:
                try:
                    listen_sock.close()
                except Exception:
                    pass
                return None

        if isinstance(port_range, tuple):
            ports = list(range(port_range[0], port_range[1] + 1))
        elif isinstance(port_range, list):
            ports = port_range
        else:
            ports = [port_range]

        if version == 6:
            try:
                ipaddress.IPv6Address(target)
            except Exception:
                if verbose:
                    print(f"{red}[!] Invalid IPv6 address: {target}{reset}")
                return False

        if verbose:
            print(f"\n{cyan}[+] FTP Bounce Scan: {ftpserver}:{ftp_port} -> {target} (IPv{version}){reset}")
            print(f"{cyan}[+] Testing {len(ports)} ports{reset}")

        ftp_control = None
        for attempt in range(max_retries):
            try:
                family = socket.AF_INET6 if version == 6 else socket.AF_INET
                ftp_control = socket.socket(family, socket.SOCK_STREAM)
                ftp_control.settimeout(socket_timeout)
                ftp_control.connect((ftpserver, ftp_port))

                banner = read_until_response(ftp_control, socket_timeout)
                if verbose and attempt == 0:
                    first_line = banner.splitlines()[0] if banner else 'None'
                    print(f"{green}[+] FTP Banner: {first_line}{reset}")

                ftp_control.send(b"USER anonymous\r\n")
                read_until_response(ftp_control, socket_timeout)
                ftp_control.send(b"PASS test@\r\n")
                resp = read_until_response(ftp_control, socket_timeout)

                if "230" not in resp:
                    raise Exception("FTP login failed - anonymous not allowed")

                if verbose:
                    print(f"{green}[+] Connected to FTP server {ftpserver}:{ftp_port} (anonymous){reset}")
                break

            except Exception as e:
                if ftp_control:
                    ftp_control.close()
                    ftp_control = None
                if verbose:
                    print(f"{yellow}[-] FTP connection attempt {attempt + 1} failed: {e}{reset}")
                if attempt == max_retries - 1:
                    print(f"{red}[-] Cannot connect to FTP server {ftpserver}:{ftp_port}{reset}")
                    return False
                time.sleep(1)

        if ftp_control is None:
            return False

        for idx, port in enumerate(ports):
            try:
                if verbose:
                    print(f"  [{idx + 1}/{len(ports)}] Testing port {port}...", end=" ")

                result = setup_data_channel(ftp_control, target, port, version)

                if result:
                    status, port_num = result
                else:
                    status = "filtered"
                    port_num = port

                service = service_detection(port_num) if service_detection else f"port_{port_num}"

                if lock and target_results and initialize_target_results:
                    bucket = {"open": "open_ports",
                              "closed": "closed_ports"}.get(status, "filtered_ports")
                    if status == "open" and imediate:
                        print(f"[+] Port {port_num} is open .")
                    Payloads._record(target, port_num, bucket, service,
                                     False, verbose, version,
                                     lock, target_results, initialize_target_results)

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error testing port {port}: {e}{reset}")
            time.sleep(interval)
        try:
            ftp_control.send(b"QUIT\r\n")
            read_until_response(ftp_control, socket_timeout)
            ftp_control.close()
        except Exception:
            pass

        return True

_IP_PROTOCOL_NAMES = {
    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 5: "ST", 6: "TCP",
    7: "CBT", 8: "EGP", 9: "IGP", 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP",
    13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP", 18: "MUX",
    19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1",
    24: "TRUNK-2", 25: "LEAF-1", 26: "LEAF-2", 27: "RDP", 28: "IRTP",
    29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP",
    34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++",
    40: "IL", 41: "IPv6", 42: "SDRP", 43: "IPv6-Route", 44: "IPv6-Frag",
    45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR", 49: "BNA", 50: "ESP",
    51: "AH", 52: "I-NLSP", 53: "SWIPE", 54: "NARP", 55: "MOBILE", 56: "TLSP",
    57: "SKIP", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts", 61: "AnyHost",
    62: "CFTP", 63: "AnyLocal", 64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD",
    67: "IPPC", 68: "AnyDistFS", 69: "SAT-MON", 70: "VISA", 71: "IPCV",
    72: "CPNX", 73: "CPHB", 74: "WSN", 75: "PVP", 76: "BR-SAT-MON",
    77: "SUN-ND", 78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP",
    82: "SECURE-VMTP", 83: "VINES", 84: "TTP", 85: "NSFNET-IGP", 86: "DGP",
    87: "TCF", 88: "EIGRP", 89: "OSPF", 90: "Sprite-RPC", 91: "LARP",
    92: "MTP", 93: "AX.25", 94: "IPIP", 95: "MICP", 96: "SCC-SP",
    97: "ETHERIP", 98: "ENCAP", 99: "AnyPrivate", 100: "GMTP", 101: "IFMP",
    102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS", 106: "QNX", 107: "A/N",
    108: "IPComp", 109: "SNP", 110: "Compaq-Peer", 111: "IPX-in-IP",
    112: "VRRP", 113: "PGM", 114: "Any0-hop", 115: "L2TP", 116: "DDX",
    117: "IATP", 118: "STP", 119: "SRP", 120: "UTI", 121: "SMP", 122: "SM",
    123: "PTP", 124: "ISIS-over-IPv4", 125: "FIRE", 126: "CRTP", 127: "CRUDP",
    128: "SSCOPMCE", 129: "IPLT", 130: "SPS", 131: "PIPE", 132: "SCTP",
    133: "FC", 134: "RSVP-E2E-IGNORE", 135: "Mobility-Header", 136: "UDPLite",
    137: "MPLS-in-IP", 138: "manet", 139: "HIP", 140: "Shim6", 141: "WESP",
    142: "ROHC", 143: "Ethernet", 144: "AGGFRAG", 145: "NSH",
}

for _p in range(146, 255):
    _IP_PROTOCOL_NAMES.setdefault(_p, "unassigned")
_IP_PROTOCOL_NAMES[255] = "RAW"