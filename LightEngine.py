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
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, ICMPv6EchoReply, ICMPv6ParamProblem, ICMPv6TimeExceeded, \
    ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6EchoRequest
from LightPacket.utils.Nsec.arp_resolution import arp_scan
from LightPacket.Arp import ArpLayer
import random
import time
import ipaddress
from LightMirage import mirage
from banner_grabber import Banner
from concurrent.futures import ThreadPoolExecutor, as_completed
from Services import top_20_tcp_ports

red = "\033[31m"
reset = "\033[0m"
yellow = "\033[33m"
green = "\033[32m"
cyan = "\033[36m"


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
    def fragementation(packet, Proto, scan_type, verbose, v6=False):
        from IPfrag import fragementation
        fragementation(packet, Proto, scan_type, verbose, v6=v6)

    @staticmethod
    def is_private_ip(target):
        try:
            if target.lower() in ["localhost", "127.0.0.1","::1"]:
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
    def threaded_ndp_scan(max_threads, targets, verbose, Targets, Targets_num, interface=None):
        if not targets:
            return

        if max_threads == 1:
            for target in targets:
                Payloads.ndp_scan(target, Targets, Targets_num, interface)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {
                    executor.submit(Payloads.ndp_scan, target, Targets, Targets_num, interface): target
                    for target in targets
                }

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] NDP scan error: {e}{reset}")

    @staticmethod
    def arp_Scan(target, targets, targets_num):
        result = arp_scan(target_input=target,verbose=True)
        for res in result:
            if targets_num == 1:
                if res:
                    if ArpLayer in res:
                        targets.append(target)
                else:
                    print(f"[ARP] Host {target} is shown to be down or not responding")
                    targets.append(target)
            else:
                if res:
                    if ArpLayer in res:
                        targets.append(res[ArpLayer].ipsrc)
                else:
                    pass

    @staticmethod
    def threaded_arp_scan(max_threads, targets, verbose, Targets, Targets_num):

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
                    futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] ARP Ping error: {e}{reset}")

    @staticmethod
    def Null_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,
                  banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport, payload, id,
                  flags):
        for attempt in range(max_retries):
            try:
                Proto = "tcp"
                scan_type = "null"
                if payload == None:
                    payloads = mirage.random_payload()
                else:
                    payloads = payload
                if ttl:
                    TTL = ttl
                else:
                    TTL = mirage.ipv4_ttl()

                if hlim:
                    HLIM = hlim
                else:
                    HLIM = mirage.ipv6_hlim()

                if sport:
                    SPORT = sport
                else:
                    SPORT = mirage.tcp_sport()
                if version == 6:
                    packet = IPv6(dst=target, nh=6, hlim=HLIM) / scapy.TCP(dport=port, sport=SPORT,
                                                                           seq=mirage.tcp_seq(),
                                                                           window=mirage.tcp_window(),
                                                                           options=mirage.Stealth_tcp_options(),
                                                                           flags="") / scapy.Raw(
                        load=payloads)
                else:
                    if id:
                        ID = id
                    else:
                        ID = mirage.ipv4_id()
                    if flags:
                        FLAGS = flags
                    else:
                        FLAGS = mirage.ipv4_flags()
                    packet = scapy.IP(dst=target, id=ID, ttl=TTL, flags=FLAGS) / scapy.TCP(dport=port, sport=SPORT,
                                                                                           seq=mirage.tcp_seq(),
                                                                                           window=mirage.tcp_window(),
                                                                                           options=mirage.Stealth_tcp_options(),
                                                                                           flags="") / scapy.Raw(
                        load=payloads)
                if fragmente:
                    if recursively:
                        if version == 6:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose, v6=True)
                        else:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(
                                f"\n{yellow}[+] Fragmentation is Forbiden with NULL packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['null_ports'].append(port)

                    if banner_option:
                        banner = Banner.grab(
                            target,
                            port,
                            protocol="tcp",
                            timeout=3,
                            verbose=verbose,
                            version=version
                        )

                        if banner:
                            with lock:
                                target_results[target]['banners'].append(banner['banner'])
                                target_results[target]['banners_ports'].append(port)
                                target_results[target]['null_ports_services'].append(banner['service'])
                        else:
                            target_results[target]['null_ports_services'].append(service)

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x14 or flags == 0x04:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)

                    else:
                        print(flags)
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['null_ports'].append(port)
                            target_results[target]['null_ports_services'].append(service)
                        break

                elif response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    if code == 4:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)
                        break
                    elif code == 1:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break
                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break


                else:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)

                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_null_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout, target_results,
                           banner_option, max_threads, targetss, ports_to_scan, i, s, version, ttl, hlim, sport,
                           payload, id, flags):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Null_Scan(target, port, max_retries, fragmente, recursively,
                                       verbose, socket_timeout, lock, target_results,
                                       banner_option, i, s, version, ttl, hlim, sport, payload,
                                       id, flags
                                       )
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Null_Scan,
                            target, port, max_retries, fragmente, recursively,
                            verbose, socket_timeout, lock, target_results,
                            banner_option, i, s, version, ttl, hlim, sport, payload, id, flags
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Null scan error: {e}{reset}")

    @staticmethod
    def Fin_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,
                 banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport, payload, id,
                 flags):
        for attempt in range(max_retries):
            try:
                Proto = "tcp"
                scan_type = "fin"
                if payload == None:
                    payloads = mirage.random_payload()
                else:
                    payloads = payload
                if ttl:
                    TTL = ttl
                else:
                    TTL = mirage.ipv4_ttl()

                if hlim:
                    HLIM = hlim
                else:
                    HLIM = mirage.ipv6_hlim()

                if sport:
                    SPORT = sport
                else:
                    SPORT = mirage.tcp_sport()
                if version == 6:
                    packet = IPv6(dst=target, nh=6, hlim=HLIM) / scapy.TCP(dport=port, sport=SPORT,
                                                                           seq=mirage.tcp_seq(),
                                                                           window=mirage.tcp_window(),
                                                                           options=mirage.Stealth_tcp_options(),
                                                                           flags="F") / scapy.Raw(
                        load=payloads)
                else:
                    if id:
                        ID = id
                    else:
                        ID = mirage.ipv4_id()
                    if flags:
                        FLAGS = flags
                    else:
                        FLAGS = mirage.ipv4_flags()
                    packet = scapy.IP(dst=target, id=ID, ttl=TTL,
                                      flags=FLAGS) / scapy.TCP(dport=port, sport=SPORT,
                                                               seq=mirage.tcp_seq(),
                                                               window=mirage.tcp_window(),
                                                               options=mirage.Stealth_tcp_options(),
                                                               flags="F") / scapy.Raw(load=payloads)
                if fragmente:
                    if recursively:
                        if version == 6:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose, v6=True)
                        else:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(
                                f"\n{yellow}[+] Fragmentation is Forbiden with FIN packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['fin_ports'].append(port)

                    if banner_option:
                        banner = Banner.grab(
                            target,
                            port,
                            protocol="tcp",
                            timeout=3,
                            verbose=verbose,
                            version=version
                        )

                        if banner:
                            with lock:
                                target_results[target]['banners'].append(banner['banner'])
                                target_results[target]['banners_ports'].append(port)
                                target_results[target]['fin_ports_services'].append(banner['service'])
                        else:
                            target_results[target]['fin_ports_services'].append(service)

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x14 or flags == 0x04:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)

                    else:
                        print(flags)
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    if code == 4:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)
                        break
                    elif code == 1:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break
                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_fin_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout, target_results,
                          banner_option, max_threads, targetss, ports_to_scan, i, s, version, ttl, hlim, sport, payload,
                          id, flags):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Fin_Scan(target, port, max_retries, fragmente, recursively,
                                      verbose, socket_timeout, lock, target_results,
                                      banner_option, i, s, version, ttl, hlim, sport, payload,
                                      id, flags
                                      )
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Fin_Scan,
                            target, port, max_retries, fragmente, recursively,
                            verbose, socket_timeout, lock, target_results,
                            banner_option, i, s, version, ttl, hlim, sport, payload, id, flags
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Fin scan error: {e}{reset}")

    @staticmethod
    def Ack_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,
                 banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport, payload, id,
                 flags):
        for attempt in range(max_retries):
            try:
                Proto = "tcp"
                scan_type = "ack"
                if payload == None:
                    payloads = mirage.random_payload()
                else:
                    payloads = payload
                if ttl:
                    TTL = ttl
                else:
                    TTL = mirage.ipv4_ttl()

                if hlim:
                    HLIM = hlim
                else:
                    HLIM = mirage.ipv6_hlim()

                if sport:
                    SPORT = sport
                else:
                    SPORT = mirage.tcp_sport()
                if version == 6:
                    packet = IPv6(dst=target, nh=6, hlim=HLIM) / scapy.TCP(dport=port, sport=SPORT,
                                                                           seq=mirage.tcp_seq(),
                                                                           window=mirage.tcp_window(),
                                                                           options=mirage.Stealth_tcp_options(),
                                                                           flags="A") / scapy.Raw(
                        load=payloads)
                else:
                    if id:
                        ID = id
                    else:
                        ID = mirage.ipv4_id()
                    if flags:
                        FLAGS = flags
                    else:
                        FLAGS = mirage.ipv4_flags()
                    packet = scapy.IP(dst=target, id=ID, ttl=TTL,
                                      flags=FLAGS) / scapy.TCP(dport=port, sport=SPORT,
                                                               seq=mirage.tcp_seq(),
                                                               window=mirage.tcp_window(),
                                                               options=mirage.Stealth_tcp_options(),
                                                               flags="A") / scapy.Raw(load=payloads)
                if fragmente:
                    if recursively:
                        if version == 6:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose, v6=True)
                        else:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(
                                f"\n{yellow}[+] Fragmentation is Forbiden with ACK packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)

                    if banner_option:
                        banner = Banner.grab(
                            target,
                            port,
                            protocol="tcp",
                            timeout=3,
                            verbose=verbose,
                            version=version
                        )

                        if banner:
                            with lock:
                                target_results[target]['banners'].append(banner['banner'])
                                target_results[target]['banners_ports'].append(port)
                                target_results[target]['filtered_ports_services'].append(banner['service'])
                        else:
                            target_results[target]['filtered_ports_services'].append(service)

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x14 or flags == 0x04:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['unfiltered_ports'].append(port)
                            target_results[target]['unfiltered_ports_services'].append(service)

                    else:
                        print(flags)
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    if code == 4:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)
                        break
                    elif code == 1:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break
                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_ack_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout, target_results,
                          banner_option, max_threads, targetss, ports_to_scan, i, s, version, ttl, hlim, sport, payload,
                          id, flags):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Ack_Scan(target, port, max_retries, fragmente, recursively,
                                      verbose, socket_timeout, lock, target_results,
                                      banner_option, i, s, version, ttl, hlim, sport, payload, id, flags)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Ack_Scan,
                            target, port, max_retries, fragmente, recursively,
                            verbose, socket_timeout, lock, target_results,
                            banner_option, i, s, version, ttl, hlim, sport, payload, id, flags
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Ack scan error: {e}{reset}")

    @staticmethod
    def Xmas_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,
                  banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport, payload, id,
                  flags):
        for attempt in range(max_retries):
            try:
                Proto = "tcp"
                scan_type = "xmas"
                if payload == None:
                    payloads = mirage.random_payload()
                else:
                    payloads = payload
                if ttl:
                    TTL = ttl
                else:
                    TTL = mirage.ipv4_ttl()

                if hlim:
                    HLIM = hlim
                else:
                    HLIM = mirage.ipv6_hlim()

                if sport:
                    SPORT = sport
                else:
                    SPORT = mirage.tcp_sport()
                if version == 6:
                    packet = IPv6(dst=target, nh=6, hlim=HLIM) / scapy.TCP(dport=port, sport=SPORT,
                                                                           seq=mirage.tcp_seq(),
                                                                           window=mirage.tcp_window(),
                                                                           options=mirage.Stealth_tcp_options(),
                                                                           flags="FPU") / scapy.Raw(
                        load=payloads)
                else:
                    if id:
                        ID = id
                    else:
                        ID = mirage.ipv4_id()
                    if flags:
                        FLAGS = flags
                    else:
                        FLAGS = mirage.ipv4_flags()
                    packet = scapy.IP(dst=target, id=ID, ttl=TTL,
                                      flags=FLAGS) / scapy.TCP(dport=port, sport=SPORT,
                                                               seq=mirage.tcp_seq(),
                                                               window=mirage.tcp_window(),
                                                               options=mirage.Stealth_tcp_options(),
                                                               flags="FPU") / scapy.Raw(load=payloads)
                if fragmente:
                    if recursively:
                        if version == 6:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose, v6=True)
                        else:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(
                                f"\n{yellow}[+] Fragmentation is Forbiden with XMAS packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['open_filtered_ports'].append(port)

                    if banner_option:
                        banner = Banner.grab(
                            target,
                            port,
                            protocol="tcp",
                            timeout=3,
                            verbose=verbose,
                            version=version
                        )

                        if banner:
                            with lock:
                                target_results[target]['banners'].append(banner['banner'])
                                target_results[target]['banners_ports'].append(port)
                                target_results[target]['open_filtered_ports_services'].append(banner['service'])
                        else:
                            target_results[target]['open_filtered_ports_services'].append(service)

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x14 or flags == 0x04:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    if code == 4:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)
                        break
                    elif code == 1:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break
                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)

                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_xmas_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout, target_results,
                           banner_option, max_threads, targetss, ports_to_scan, i, s, version, ttl, hlim, sport,
                           payload, id, flags):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Xmas_Scan(target, port, max_retries, fragmente, recursively,
                                       verbose, socket_timeout, lock, target_results,
                                       banner_option, i, s, version, ttl, hlim, sport, payload,
                                       id, flags
                                       )
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Xmas_Scan,
                            target, port, max_retries, fragmente, recursively,
                            verbose, socket_timeout, lock, target_results,
                            banner_option, i, s, version, ttl, hlim, sport, payload, id, flags
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Xmas scan error: {e}{reset}")

    @staticmethod
    def IP_Scan(target, protocol, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,
                banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport, payload, id,
                flags):
        if ttl:
            TTL = ttl
        else:
            TTL = mirage.ipv4_ttl()
        if payload == None:
            payloads = ["PING", "URGENT", "!HHHH", "LIGHTSCAN", "UDP", "TCP", "-Pu", "KIWI"]
        else:
            payloads = [payload]

        if hlim:
            HLIM = hlim
        else:
            HLIM = mirage.ipv6_hlim()

        if sport:
            SPORT = sport
        else:
            SPORT = mirage.tcp_sport()
        for attempt in range(max_retries):
            try:
                Proto = "ip"
                scan_type = "ipproto"

                proto_names = {
                    0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IPv4", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP",
                    9: "IGP",
                    10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS",
                    17: "UDP", 18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1",
                    24: "TRUNK-2", 25: "LEAF-1", 26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4",
                    30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP", 34: "3PC", 35: "IDPR",
                    36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++", 40: "IL", 41: "IPv6", 42: "SDRP",
                    43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GRE", 48: "DSR",
                    49: "BNA", 50: "ESP", 51: "AH", 52: "I-NLSP", 53: "SWIPE", 54: "NARP", 55: "MOBILE",
                    56: "TLSP", 57: "SKIP", 58: "ICMPv6", 59: "IPv6-NoNxt", 60: "IPv6-Opts", 61: "AnyHost",
                    62: "CFTP", 63: "AnyLocal", 64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC",
                    68: "AnyDistFS", 69: "SAT-MON", 70: "VISA", 71: "IPCV", 72: "CPNX", 73: "CPHB", 74: "WSN",
                    75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP",
                    81: "VMTP", 82: "SECURE-VMTP", 83: "VINES", 84: "TTP", 85: "NSFNET-IGP", 86: "DGP",
                    87: "TCF", 88: "EIGRP", 89: "OSPF", 90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25",
                    94: "IPIP", 95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 99: "AnyPrivate",
                    100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS", 106: "QNX",
                    107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer", 111: "IPX-in-IP", 112: "VRRP",
                    113: "PGM", 114: "Any0-hop", 115: "L2TP", 116: "DDX", 117: "IATP", 118: "STP", 119: "SRP",
                    120: "UTI", 121: "SMP", 122: "SM", 123: "PTP", 124: "ISIS-over-IPv4", 125: "FIRE",
                    126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE", 129: "IPLT", 130: "SPS", 131: "PIPE",
                    132: "SCTP", 133: "FC", 134: "RSVP-E2E-IGNORE", 135: "Mobility-Header", 136: "UDPLite",
                    137: "MPLS-in-IP", 138: "manet", 139: "HIP", 140: "Shim6", 141: "WESP", 142: "ROHC",
                    143: "Ethernet", 144: "AGGFRAG", 145: "NSH", 146: "unassigned", 147: "unassigned",
                    148: "unassigned", 149: "unassigned", 150: "unassigned", 151: "unassigned", 152: "unassigned",
                    153: "unassigned", 154: "unassigned", 155: "unassigned", 156: "unassigned", 157: "unassigned",
                    158: "unassigned", 159: "unassigned", 160: "unassigned", 161: "unassigned", 162: "unassigned",
                    163: "unassigned", 164: "unassigned", 165: "unassigned", 166: "unassigned", 167: "unassigned",
                    168: "unassigned", 169: "unassigned", 170: "unassigned", 171: "unassigned", 172: "unassigned",
                    173: "unassigned", 174: "unassigned", 175: "unassigned", 176: "unassigned", 177: "unassigned",
                    178: "unassigned", 179: "unassigned", 180: "unassigned", 181: "unassigned", 182: "unassigned",
                    183: "unassigned", 184: "unassigned", 185: "unassigned", 186: "unassigned", 187: "unassigned",
                    188: "unassigned", 189: "unassigned", 190: "unassigned", 191: "unassigned", 192: "unassigned",
                    193: "unassigned", 194: "unassigned", 195: "unassigned", 196: "unassigned", 197: "unassigned",
                    198: "unassigned", 199: "unassigned", 200: "unassigned", 201: "unassigned", 202: "unassigned",
                    203: "unassigned", 204: "unassigned", 205: "unassigned", 206: "unassigned", 207: "unassigned",
                    208: "unassigned", 209: "unassigned", 210: "unassigned", 211: "unassigned", 212: "unassigned",
                    213: "unassigned", 214: "unassigned", 215: "unassigned", 216: "unassigned", 217: "unassigned",
                    218: "unassigned", 219: "unassigned", 220: "unassigned", 221: "unassigned", 222: "unassigned",
                    223: "unassigned", 224: "unassigned", 225: "unassigned", 226: "unassigned", 227: "unassigned",
                    228: "unassigned", 229: "unassigned", 230: "unassigned", 231: "unassigned", 232: "unassigned",
                    233: "unassigned", 234: "unassigned", 235: "unassigned", 236: "unassigned", 237: "unassigned",
                    238: "unassigned", 239: "unassigned", 240: "unassigned", 241: "unassigned", 242: "unassigned",
                    243: "unassigned", 244: "unassigned", 245: "unassigned", 246: "unassigned", 247: "unassigned",
                    248: "unassigned", 249: "unassigned", 250: "unassigned", 251: "unassigned", 252: "unassigned",
                    253: "unassigned", 254: "unassigned", 255: "RAW"
                }
                proto_name = proto_names.get(protocol, f"Proto{protocol}")

                is_localhost = target in ["127.0.0.1", "::1", "localhost"]

                if version == 6:
                    packet = IPv6(dst=target, nh=protocol, hlim=HLIM, fl=0)
                else:
                    if id:
                        ID = id
                    else:
                        ID = mirage.ipv4_id()
                    if flags:
                        FLAGS = flags
                    else:
                        FLAGS = mirage.ipv4_flags()
                    packet = scapy.IP(dst=target, proto=protocol, ttl=TTL,
                                      id=ID, flags=FLAGS)

                if protocol == 1 and version != 6:
                    packet = packet / scapy.ICMP(type=8, code=0) / scapy.Raw(load=random.choice(payloads))
                elif protocol == 58 and version == 6:
                    packet = packet / ICMPv6EchoRequest(data=b"ping") / scapy.Raw(load=random.choice(payloads))
                elif protocol == 6:
                    packet = packet / scapy.TCP(
                        sport=SPORT,
                        dport=random.randint(1, 65535),
                        flags="S",
                        seq=random.randint(1, 4294967295)
                    ) / scapy.Raw(load=random.choice(payloads))

                elif protocol == 17:
                    packet = packet / scapy.UDP(
                        sport=SPORT,
                        dport=random.randint(1, 65535)) / scapy.Raw(load=random.choice(payloads))

                elif protocol == 132:
                    try:
                        from scapy.layers.sctp import SCTP, SCTPChunkInit
                        packet = packet / SCTP(
                            sport=SPORT,
                            dport=80
                        ) / SCTPChunkInit() / scapy.Raw(load=random.choice(payloads))
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

                if fragmente:
                    if recursively:
                        if version == 6:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose, v6=True)
                        else:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print("\n[+] Fragmentation enabled for IP Protocol scan\n")
                    else:
                        if verbose:
                            print(f"\n{yellow}[+] Fragmentation not supported for IP Protocol scan (use -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                if response and response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code == 2:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_protocols'].append(protocol)
                            target_results[target]['closed_protocols_names'].append(proto_name)
                        break
                    elif icmp_type == 0:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['open_protocols'].append(protocol)
                            target_results[target]['open_protocols_names'].append(proto_name)
                        break
                    elif icmp_type == 3 and icmp_code in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_protocols'].append(protocol)
                            target_results[target]['filtered_protocols_names'].append(proto_name)
                        break

                elif response and response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    if code == 4:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_protocols'].append(protocol)
                            target_results[target]['closed_protocols_names'].append(proto_name)
                        break
                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_protocols'].append(protocol)
                            target_results[target]['filtered_protocols_names'].append(proto_name)
                        break

                if response and response.haslayer(scapy.TCP):
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['open_protocols'].append(protocol)
                    if banner_option:
                        banner = Banner.grab(
                            target, 80, protocol="tcp",
                            timeout=3, verbose=verbose, version=version
                        )
                        if banner:
                            with lock:
                                target_results[target]['banners'].append(banner['banner'])
                                target_results[target]['banners_ports'].append(protocol)
                                target_results[target]['open_protocols_names'].append(banner['service'])
                        else:
                            target_results[target]['open_protocols_names'].append(proto_name)
                    break

                if response and response.haslayer(scapy.UDP):
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['open_protocols'].append(protocol)
                        target_results[target]['open_protocols_names'].append(proto_name)
                    break

                if response and response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    if icmp_type in [0, 14, 18]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['open_protocols'].append(protocol)
                            target_results[target]['open_protocols_names'].append(proto_name)
                        break

                if response and (
                        (version == 6 and response.nh == protocol) or (version != 6 and response.proto == protocol)):
                    if is_localhost:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_protocols'].append(protocol)
                            target_results[target]['closed_protocols_names'].append(proto_name)
                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['open_filtered_protocols'].append(protocol)
                            target_results[target]['open_filtered_protocols_names'].append(proto_name)
                    break

                if response is None:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['open_filtered_protocols'].append(protocol)
                        target_results[target]['open_filtered_protocols_names'].append(proto_name)
                    break

                with lock:
                    if target not in target_results:
                        initialize_target_results(target)
                    target_results[target]['closed_protocols'].append(protocol)
                    target_results[target]['closed_protocols_names'].append(proto_name)
                break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning protocol {protocol}: {e}{reset}")
                if attempt == max_retries - 1:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_protocols'].append(protocol)
                        target_results[target]['filtered_protocols_names'].append(proto_name)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_ip_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout,
                         target_results, banner_option, max_threads, targetss, protocols_to_scan,
                         initialize_target_results, service_detection, version, ttl, hlim, sport, payload, id,
                         flags):

        if max_threads == 1:
            for target in targetss:
                for protocol in protocols_to_scan:
                    Payloads.IP_Scan(
                        target, protocol, max_retries, fragmente, recursively,
                        verbose, socket_timeout, lock, target_results,
                        banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport, payload,
                        id, flags
                    )
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for protocol in protocols_to_scan:
                        future = executor.submit(
                            Payloads.IP_Scan,
                            target, protocol, max_retries, fragmente, recursively,
                            verbose, socket_timeout, lock, target_results,
                            banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport,
                            payload,
                            id, flags
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] IP Protocol scan error: {e}{reset}")

    @staticmethod
    def IP_Ping(target, protocol, verbose, socket_timeout, target_results, ttl, hlim, id, flags, v6=False):
        count = 0
        for i in range(2):
            try:
                if ttl:
                    TTL = ttl
                else:
                    TTL = mirage.ipv4_ttl()

                if hlim:
                    HLIM = hlim
                else:
                    HLIM = mirage.ipv6_hlim()
                if v6:
                    packet = IPv6(dst=target, nh=protocol, hlim=HLIM, fl=0)
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    if id:
                        ID = id
                    else:
                        ID = mirage.ipv4_id()
                    if flags:
                        FLAGS = flags
                    else:
                        FLAGS = mirage.ipv4_flags()
                    packet = scapy.IP(dst=target, proto=protocol, ttl=TTL, id=ID, flags=FLAGS)
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                if response:
                    if v6:
                        if response.haslayer(ICMPv6DestUnreach):
                            icmpv6 = response.getlayer(ICMPv6DestUnreach)
                            code = icmpv6.code
                            if code in [1, 3, 4]:
                                target_results[target]['up'] += 1
                            else:
                                target_results[target]['filtered'] += 1
                        elif response.haslayer(ICMPv6EchoReply):
                            target_results[target]['up'] += 1
                        elif response.haslayer(ICMPv6TimeExceeded):
                            target_results[target]['filtered'] += 1
                        elif response.haslayer(ICMPv6ParamProblem):
                            target_results[target]['filtered'] += 1
                        elif response.haslayer(scapy.TCP):
                            flags = response.getlayer(scapy.TCP).flags
                            if flags in [0x12, 0x14, 0x04]:
                                target_results[target]['up'] += 1
                            else:
                                target_results[target]['up'] += 1
                        elif response.haslayer(scapy.UDP):
                            target_results[target]['up'] += 1
                        elif response.nh == protocol:
                            target_results[target]['up'] += 1
                        else:
                            target_results[target]['up'] += 1
                    else:
                        if response.haslayer(scapy.ICMP):
                            icmp = response.getlayer(scapy.ICMP)
                            if icmp.type == 3:
                                if icmp.code in [13, 1, 2, 9, 10]:
                                    target_results[target]['filtered'] += 1
                                elif icmp.code == 3:
                                    target_results[target]['up'] += 1
                                else:
                                    target_results[target]['down'] += 1
                            elif icmp.type in [0, 14, 18]:
                                target_results[target]['up'] += 1
                            elif icmp.type == 11:
                                target_results[target]['filtered'] += 1
                            else:
                                target_results[target]['up'] += 1
                        elif response.haslayer(scapy.TCP):
                            flags = response.getlayer(scapy.TCP).flags
                            if flags in [0x12, 0x14, 0x04]:
                                target_results[target]['up'] += 1
                            else:
                                target_results[target]['up'] += 1
                        elif response.haslayer(scapy.UDP):
                            target_results[target]['up'] += 1
                        elif response.proto == protocol:
                            target_results[target]['up'] += 1
                        else:
                            target_results[target]['up'] += 1
                else:
                    target_results[target]['down'] += 1

            except Exception as e:
                if verbose:
                    print(f"{red}[!] IP Ping Error (IPv6={v6}, protocol={protocol}): {e}{reset}")
                target_results[target]['filtered'] += 1

            count += 1

    @staticmethod
    def threaded_ip_ping(max_threads, verbose, socket_timeout, targets,
                         Target, protocols, target_results, ttl, hlim, id, flags, v6):
        for target in targets:
            target_results[target] = {'up': 0, 'down': 0, 'filtered': 0}

        if max_threads == 1:
            for target in targets:
                for protocol in protocols:
                    Payloads.IP_Ping(target, protocol, verbose,
                                     socket_timeout, target_results, ttl, hlim, id, flags, v6)
        else:
            futures = []
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                for target in targets:
                    for protocol in protocols:
                        future = executor.submit(
                            Payloads.IP_Ping,
                            target, protocol, verbose,
                            socket_timeout, target_results, ttl, hlim, id, flags, v6
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Error: {e}{reset}")

        for target in targets:
            if len(targets) == 1:
                up = target_results[target]['up']
                down = target_results[target]['down']
                filtered = target_results[target]['filtered']

                if up > down and up > filtered:
                    print(f"[IP] Host {target} is up! ({up} up, {down} down)")
                    if target not in Target:
                        Target.append(target)
                elif up < down and down > filtered:
                    print(f"[IP] Host {target} appears down ({up} up, {down} down)")
                    if target not in Target:
                        Target.append(target)
                elif filtered > up and filtered > down:
                    print(
                        f"[IP] Host {target} appears to be not responding ({up} up, {down} down, {filtered} filtered)")
                    if target not in Target:
                        Target.append(target)
                else:
                    print(f"[IP] Host {target}: Inconclusive ({up} up, {down} down, {filtered} filtered)")
                    if target not in Target:
                        Target.append(target)
            else:
                up = target_results[target]['up']
                down = target_results[target]['down']
                filtered = target_results[target]['filtered']

                if up > down and up > filtered:
                    print(f"[IP] Host {target} is up! ({up} up, {down} down)")
                    if target not in Target:
                        Target.append(target)
                elif up < down and down > filtered:
                    print(f"[IP] Host {target} appears down ({up} up, {down} down)")
                elif filtered > up and filtered > down:
                    print(
                        f"[IP] Host {target} appears to be not responding ({up} up, {down} down, {filtered} filtered)")
                else:
                    print(f"[IP] Host {target}: Inconclusive ({up} up, {down} down, {filtered} filtered)")
                    if target not in Target:
                        Target.append(target)

    @staticmethod
    def Window_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,
                    banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport, payload, id,
                    flags):
        for attempt in range(max_retries):
            try:
                Services = []
                Proto = "tcp"
                scan_type = "window"
                if payload == None:
                    payloads = mirage.random_payloads()
                else:
                    payloads = [payload]
                if ttl:
                    TTL = ttl
                else:
                    TTL = mirage.ipv4_ttl()

                if hlim:
                    HLIM = hlim
                else:
                    HLIM = mirage.ipv6_hlim()

                if sport:
                    SPORT = sport
                else:
                    SPORT = mirage.tcp_sport()
                if version == 6:
                    packet = IPv6(dst=target, nh=6, hlim=HLIM) / scapy.TCP(dport=port, sport=SPORT,
                                                                           seq=mirage.tcp_seq(),
                                                                           window=mirage.tcp_window(),
                                                                           options=mirage.Stealth_tcp_options(),
                                                                           flags="A") / scapy.Raw(
                        load=random.choice(payloads))
                else:
                    if id:
                        ID = id
                    else:
                        ID = mirage.ipv4_id()
                    if flags:
                        FLAGS = flags
                    else:
                        FLAGS = mirage.ipv4_flags()
                    packet = scapy.IP(dst=target, id=ID, ttl=TTL,
                                      flags=FLAGS) / scapy.TCP(dport=port, sport=SPORT,
                                                               seq=mirage.tcp_seq(),
                                                               window=mirage.tcp_window(),
                                                               options=mirage.Stealth_tcp_options(),
                                                               flags="A") / scapy.Raw(load=random.choice(payloads))
                if fragmente:
                    if recursively:
                        if version == 6:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose, v6=True)
                        else:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(
                                f"\n{yellow}[+] Fragmentation is Forbiden with WINDOW packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)

                    if banner_option:
                        banner = Banner.grab(
                            target,
                            port,
                            protocol="tcp",
                            timeout=3,
                            verbose=verbose,
                            version=version
                        )

                        if banner:
                            with lock:
                                target_results[target]['banners'].append(banner['banner'])
                                target_results[target]['banners_ports'].append(port)
                                target_results[target]['filtered_ports_services'].append(banner['service'])
                        else:
                            target_results[target]['filtered_ports_services'].append(service)

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x14 or flags == 0x04:
                        window = response.getlayer(scapy.TCP).window
                        if window == 0:
                            with lock:
                                if target not in target_results:
                                    initialize_target_results(target)
                                target_results[target]['closed_ports'].append(port)
                                target_results[target]['closed_ports_services'].append(service)
                        else:
                            with lock:
                                if target not in target_results:
                                    initialize_target_results(target)
                                target_results[target]['open_ports'].append(port)
                                target_results[target]['opened_ports_services'].append(service)

                    else:
                        print(flags)
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    if code == 4:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)
                        break
                    elif code == 1:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break
                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_window_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout, target_results,
                             banner_option, max_threads, targetss, ports_to_scan, i, s, version, ttl, hlim, sport,
                             payload, id, flags):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Window_Scan(target, port, max_retries, fragmente, recursively,
                                         verbose, socket_timeout, lock, target_results,
                                         banner_option, i, s, version, ttl, hlim, sport, payload,
                                         id, flags)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Window_Scan,
                            target, port, max_retries, fragmente, recursively,
                            verbose, socket_timeout, lock, target_results,
                            banner_option, i, s, version, ttl, hlim, sport, payload, id, flags
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Window scan error: {e}{reset}")

    @staticmethod
    def Ack_ping(target, port, socket_timeout, targets_num, target_results, targetss, ttl, hlim, sport, id, flags,
                 version):
        Proto = "tcp"
        if ttl:
            TTL = ttl
        else:
            TTL = mirage.ipv4_ttl()

        if hlim:
            HLIM = hlim
        else:
            HLIM = mirage.ipv6_hlim()

        if sport:
            SPORT = sport
        else:
            SPORT = mirage.tcp_sport()
        if version == 6:
            from scapy.layers.inet6 import IPv6
            packet = IPv6(
                dst=target,
                hlim=HLIM,
                nh=6
            ) / scapy.TCP(
                dport=port,
                sport=SPORT,
                seq=mirage.tcp_seq(),
                window=mirage.tcp_window(),
                options=mirage.Stealth_tcp_options(),
                flags="A"
            )
        else:
            if id:
                ID = id
            else:
                ID = mirage.ipv4_id()
            if flags:
                FLAGS = flags
            else:
                FLAGS = mirage.ipv4_flags()
            packet = scapy.IP(
                dst=target,
                id=ID,
                ttl=TTL,
                flags=FLAGS
            ) / scapy.TCP(
                dport=port,
                sport=SPORT,
                seq=mirage.tcp_seq(),
                window=mirage.tcp_window(),
                options=mirage.Stealth_tcp_options(),
                flags="A"
            )

        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

        if len(targets_num) == 1:
            if response:
                if version == 6 and response.haslayer(ICMPv6DestUnreach):
                    print(f"[ACK] Host {target}:{port} is up! (ICMPv6)")
                    if target not in targetss:
                        targetss.append(target)
                    target_results[target]['up'] += 1
                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags
                    if flags == 0x04 or flags == 0x14:
                        print(f"[ACK] Host {target}:{port} is up! (RST response)")
                        if target not in targetss:
                            targetss.append(target)
                        target_results[target]['up'] += 1
                    else:
                        print(f"[ACK] Host {target}:{port} is up! (Unexpected flags: {flags})")
                        if target not in targetss:
                            targetss.append(target)
                        target_results[target]['up'] += 1
                elif response.haslayer(scapy.ICMP):
                    print(f"[ACK] Host {target}:{port} is up! (ICMP response)")
                    if target not in targetss:
                        targetss.append(target)
                    target_results[target]['up'] += 1
                else:
                    print(f"[ACK] Host {target}:{port} is up! (Unknown response)")
                    if target not in targetss:
                        targetss.append(target)
                    target_results[target]['up'] += 1
            else:
                if target not in targetss:
                    targetss.append(target)

        else:
            if response:
                if version == 6 and response.haslayer(ICMPv6DestUnreach):
                    if target not in targetss:
                        targetss.append(target)
                    target_results[target]['up'] += 1
                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags
                    if flags == 0x04 or flags == 0x14:
                        if target not in targetss:
                            targetss.append(target)
                        target_results[target]['up'] += 1
                    else:
                        if target not in targetss:
                            targetss.append(target)
                        target_results[target]['up'] += 1
                elif response.haslayer(scapy.ICMP):
                    if target not in targetss:
                        targetss.append(target)
                    target_results[target]['up'] += 1
                else:
                    if target not in targetss:
                        targetss.append(target)
                    target_results[target]['up'] += 1

    @staticmethod
    def threaded_ack_ping(max_threads, targets, ping_port, pp, target_results, socket_timeout, targetss, verbose, num,
                          version, ttl, hlim, sport, id, flags):
        if max_threads == 1:
            for Target in targets:
                if ping_port:
                    for port in pp:
                        Payloads.Ack_ping(Target, port, socket_timeout, num, target_results, targetss, ttl, hlim, sport,
                                          id, flags, version)
                else:
                    for port in top_20_tcp_ports:
                        Payloads.Ack_ping(Target, port, socket_timeout, targets, target_results, targetss, ttl, hlim,
                                          sport, id, flags, version)

            for target in targets:
                if target_results[target]['up'] >= 1:
                    pass
                else:
                    print(f"[ACK] Host {target} is shown to be down or not responding")

        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for Target in targets:
                    if ping_port:
                        for port in pp:
                            future = executor.submit(
                                Payloads.Ack_ping, Target, port, socket_timeout, targets, target_results, targetss, ttl,
                                hlim, sport, id, flags, version
                            )
                            time.sleep(0.02)
                            futures.append(future)
                    else:
                        for port in top_20_tcp_ports:
                            future = executor.submit(
                                Payloads.Ack_ping, Target, port, socket_timeout, targets, target_results, targetss, ttl,
                                hlim, sport, id, flags, version
                            )
                            time.sleep(0.02)
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
    def Maimon_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,
                    banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport, payload, id,
                    flags):
        for attempt in range(max_retries):
            try:

                Proto = "tcp"
                scan_type = "maimon"
                if payload == None:
                    payloads = mirage.random_payloads()
                else:
                    payloads = [payload]
                if ttl:
                    TTL = ttl
                else:
                    TTL = mirage.ipv4_ttl()

                if hlim:
                    HLIM = hlim
                else:
                    HLIM = mirage.ipv6_hlim()

                if sport:
                    SPORT = sport
                else:
                    SPORT = mirage.tcp_sport()
                if version == 6:
                    packet = IPv6(dst=target, nh=6, hlim=HLIM) / scapy.TCP(dport=port, sport=SPORT,
                                                                           seq=mirage.tcp_seq(),
                                                                           window=mirage.tcp_window(),
                                                                           options=mirage.Stealth_tcp_options(),
                                                                           flags="FA") / scapy.Raw(
                        load=random.choice(payloads))
                else:
                    if id:
                        ID = id
                    else:
                        ID = mirage.ipv4_id()
                    if flags:
                        FLAGS = flags
                    else:
                        FLAGS = mirage.ipv4_flags()
                    packet = scapy.IP(dst=target, id=ID, ttl=TTL,
                                      flags=FLAGS) / scapy.TCP(dport=port, sport=SPORT,
                                                               seq=mirage.tcp_seq(),
                                                               window=mirage.tcp_window(),
                                                               options=mirage.Stealth_tcp_options(),
                                                               flags="FA") / scapy.Raw(load=random.choice(payloads))
                if fragmente:
                    if recursively:
                        if version == 6:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose, v6=True)
                        else:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(
                                f"\n{yellow}[+] Fragmentation is Forbiden with MAIMON packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['open_filtered_ports'].append(port)

                    if banner_option:
                        banner = Banner.grab(
                            target,
                            port,
                            protocol="tcp",
                            timeout=3,
                            verbose=verbose,
                            version=version
                        )

                        if banner:
                            with lock:
                                target_results[target]['banners'].append(banner['banner'])
                                target_results[target]['banners_ports'].append(port)
                                target_results[target]['open_filtered_ports_services'].append(banner['service'])
                        else:
                            target_results[target]['open_filtered_ports_services'].append(service)

                elif response.haslayer(scapy.TCP):
                    flags = response.getlayer(scapy.TCP).flags

                    if flags == 0x14 or flags == 0x04:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    if code == 4:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)
                        break
                    elif code == 1:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break
                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_maimon_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout, target_results,
                             banner_option, max_threads, targetss, ports_to_scan, i, s, version, ttl, hlim, sport,
                             payload, id, flags):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Maimon_Scan(target, port, max_retries, fragmente, recursively,
                                         verbose, socket_timeout, lock, target_results,
                                         banner_option, i, s, version, ttl, hlim, sport, payload,
                                         id, flags)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Maimon_Scan,
                            target, port, max_retries, fragmente, recursively,
                            verbose, socket_timeout, lock, target_results,
                            banner_option, i, s, version, ttl, hlim, sport, payload,
                            id, flags
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Maimon scan error: {e}{reset}")

    @staticmethod
    def Fdd_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,
                 banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport, payload, id,
                 flags):
        for attempt in range(max_retries):
            try:

                Proto = "tcp"
                scan_type = "fdd"
                if payload == None:
                    payloads = mirage.random_payloads()
                else:
                    payloads = [payload]
                if ttl:
                    TTL = ttl
                else:
                    TTL = mirage.ipv4_ttl()

                if hlim:
                    HLIM = hlim
                else:
                    HLIM = mirage.ipv6_hlim()

                if sport:
                    SPORT = sport
                else:
                    SPORT = mirage.tcp_sport()
                if version == 6:
                    packet = IPv6(dst=target, nh=6, hlim=HLIM) / scapy.TCP(dport=port, sport=SPORT,
                                                                           seq=mirage.tcp_seq(),
                                                                           window=mirage.tcp_window(),
                                                                           options=mirage.Stealth_tcp_options(),
                                                                           flags="U") / scapy.Raw(
                        load=random.choice(payloads))
                else:
                    if id:
                        ID = id
                    else:
                        ID = mirage.ipv4_id()
                    if flags:
                        FLAGS = flags
                    else:
                        FLAGS = mirage.ipv4_flags()
                    packet = scapy.IP(dst=target, id=ID, ttl=TTL,
                                      flags=FLAGS) / scapy.TCP(dport=port, sport=SPORT,
                                                               seq=mirage.tcp_seq(),
                                                               window=mirage.tcp_window(),
                                                               options=mirage.Stealth_tcp_options(),
                                                               flags="U") / scapy.Raw(load=random.choice(payloads))
                if fragmente:
                    if recursively:
                        if version == 6:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose, v6=True)
                        else:
                            response = Payloads.fragementation(packet, Proto, scan_type, verbose)
                        if verbose:
                            print(
                                "\n[+] Demo Fragementation (if you find an error while using it leave it in our github for future updates)\n")
                    else:
                        if verbose:
                            print(
                                f"\n{yellow}[+] Fragmentation is Forbiden with FDD packets (if you want use flag -Rc){reset}\n")
                        response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)
                else:
                    response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['defended_ports'].append(port)

                    if banner_option:
                        banner = Banner.grab(
                            target,
                            port,
                            protocol="tcp",
                            timeout=3,
                            verbose=verbose,
                            version=version
                        )

                        if banner:
                            with lock:
                                target_results[target]['banners'].append(banner['banner'])
                                target_results[target]['banners_ports'].append(port)
                                target_results[target]['defended_ports_services'].append(banner['service'])
                        else:
                            target_results[target]['defended_ports_services'].append(service)

                elif response.haslayer(scapy.TCP):
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['undefended_ports'].append(port)
                        target_results[target]['undefended_ports_services'].append(service)

                elif response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    if code == 4:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['defended_ports'].append(port)
                            target_results[target]['defended_ports_services'].append(service)
                        break
                    elif code == 1:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['defended_ports'].append(port)
                            target_results[target]['defended_ports_services'].append(service)
                        break
                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['defended_ports'].append(port)
                            target_results[target]['defended_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['defended_ports'].append(port)
                            target_results[target]['defended_ports_services'].append(service)
                        break

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['defended_ports'].append(port)
                            target_results[target]['defended_ports_services'].append(service)
                        break

                else:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['defended_ports'].append(port)
                        target_results[target]['defended_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['defended_ports'].append(port)
                        target_results[target]['defended_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_fdd_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout, target_results,
                          banner_option, max_threads, targetss, ports_to_scan, i, s, version, ttl, hlim, sport, payload,
                          id, flags):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Fdd_Scan(target, port, max_retries, fragmente, recursively,
                                      verbose, socket_timeout, lock, target_results,
                                      banner_option, i, s, version, ttl, hlim, sport, payload,
                                      id, flags)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Fdd_Scan,
                            target, port, max_retries, fragmente, recursively,
                            verbose, socket_timeout, lock, target_results,
                            banner_option, i, s, version, ttl, hlim, sport, payload,
                            id, flags
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Fdd scan error: {e}{reset}")

    @staticmethod
    def FTPBounceScan(target, ftpserver, ftp_port, port_range, max_retries=2, fragment=False, recursively=False,
                      verbose=False, socket_timeout=5, lock=None, target_results=None, banner_option=False,
                      initialize_target_results=None, service_detection=None, version=4):

        import socket
        import time
        import ipaddress

        def encode_ip(ip, ver=4):
            if ver == 6:
                return f"|2|{ip}|"
            else:
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
            try:
                listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listen_sock.settimeout(socket_timeout)
                listen_sock.bind(('', 0))
                listen_sock.listen(1)
                local_port = listen_sock.getsockname()[1]

                if ver == 6:
                    if not send_eprt(ftp_control, target_ip, local_port, ver=6):
                        listen_sock.close()
                        return None
                else:
                    if not send_eprt(ftp_control, target_ip, local_port, ver=4):
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
                    data = data_sock.recv(1024)
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
                else:
                    return ("filtered", target_port)

            except Exception as e:
                try:
                    listen_sock.close()
                except:
                    pass
                return None

        if isinstance(port_range, tuple):
            ports = list(range(port_range[0], port_range[1] + 1))
        elif isinstance(port_range, list):
            ports = port_range
        else:
            ports = [port_range]

        results = []

        if version == 6:
            try:
                ipaddress.IPv6Address(target)
            except:
                if verbose:
                    print(f"{red}[!] Invalid IPv6 address: {target}{reset}")
                return False

        if verbose:
            print(f"\n{cyan}[+] FTP Bounce Scan: {ftpserver}:{ftp_port} -> {target} (IPv{version}){reset}")
            print(f"{cyan}[+] Testing {len(ports)} ports{reset}")

        ftp_control = None
        for attempt in range(max_retries):
            try:
                if version == 6:
                    ftp_control = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    ftp_control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                ftp_control.settimeout(socket_timeout)
                ftp_control.connect((ftpserver, ftp_port))

                banner = read_until_response(ftp_control, socket_timeout)
                if verbose and attempt == 0:
                    print(f"{green}[+] FTP Banner: {banner.splitlines()[0] if banner else 'None'}{reset}")

                ftp_control.send(b"USER anonymous\r\n")
                resp = read_until_response(ftp_control, socket_timeout)
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
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)

                        if status == "open":
                            target_results[target]['open_ports'].append(port_num)
                            target_results[target]['open_ports_services'].append(service)
                        elif status == "closed":
                            target_results[target]['closed_ports'].append(port_num)
                            target_results[target]['closed_ports_services'].append(service)
                        else:
                            target_results[target]['filtered_ports'].append(port_num)
                            target_results[target]['filtered_ports_services'].append(service)

                results.append({"port": port_num, "status": status, "service": service})

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error testing port {port}: {e}{reset}")
                results.append({"port": port, "status": "error", "service": "unknown"})

        try:
            ftp_control.send(b"QUIT\r\n")
            read_until_response(ftp_control, socket_timeout)
            ftp_control.close()
        except:
            pass

        return True

    @staticmethod
    def Idle_Scan(target, port, zombie_ip, max_retries, verbose, socket_timeout,
                  lock, target_results, banner_option, initialize_target_results,
                  service_detection, version, ttl, sport, payload, id, flags):

        for attempt in range(max_retries):
            try:
                if payload == None:
                    pass
                else:
                    P = [payload]
                if ttl:
                    TTL = ttl
                else:
                    TTL = mirage.ipv4_ttl()

                if sport:
                    SPORT = sport
                else:
                    SPORT = mirage.tcp_sport()

                if payload != None:
                    probe_pkt = scapy.IP(dst=zombie_ip) / scapy.TCP(dport=445, flags="SA") / scapy.Raw(load=P)
                else:
                    probe_pkt = scapy.IP(dst=zombie_ip) / scapy.TCP(dport=445, flags="SA")
                reply1 = scapy.sr1(probe_pkt, timeout=socket_timeout, verbose=0)
                service = service_detection(port)

                if not reply1 or not reply1.haslayer(scapy.IP):
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    return

                if version == 6:
                    with lock:
                        print(f"\n{yellow}[!] Idle Scan doesn't work with IPv6 {reset}\n")
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    return

                id1 = reply1[scapy.IP].id

                if id:
                    ID = id
                else:
                    ID = mirage.ipv4_id()

                if flags:
                    FLAGS = flags
                else:
                    FLAGS = mirage.ipv4_flags()

                spoofed_pkt = (scapy.IP(src=zombie_ip, dst=target, id=ID, ttl=TTL, flags=FLAGS) /
                               scapy.TCP(dport=port, sport=SPORT,
                                         seq=mirage.tcp_seq(),
                                         flags="S",
                                         window=mirage.tcp_window(),
                                         options=mirage.Stealth_tcp_options()))

                scapy.send(spoofed_pkt, verbose=0)
                time.sleep(0.5)

                reply2 = scapy.sr1(probe_pkt, timeout=socket_timeout, verbose=0)

                if not reply2 or not reply2.haslayer(scapy.IP):
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append("zombie_unreachable_after")
                    return

                id2 = reply2[scapy.IP].id

                diff = (id2 - id1) % 65536
                service = service_detection(port)

                if diff == 1:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['closed_filtered_ports'].append(port)
                        target_results[target]['closed_filtered_ports_services'].append(service)

                elif diff == 2:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['open_ports'].append(port)

                    if banner_option:
                        banner = Banner.grab(
                            target,
                            port,
                            protocol="tcp",
                            timeout=3,
                            verbose=verbose,
                            version=version
                        )
                        if banner:
                            with lock:
                                target_results[target]['banners'].append(banner['banner'])
                                target_results[target]['banners_ports'].append(port)
                                target_results[target]['opened_ports_services'].append(banner['service'])
                        else:
                            target_results[target]['opened_ports_services'].append(service)
                else:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)

                break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Idle scan error on port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        if port in target_results[target]['open_ports']:
                            pass
                        else:
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.2)
                    continue

    @staticmethod
    def threaded_idle_scan(max_retries, lock, verbose, socket_timeout, target_results,
                           banner_option, max_threads, targetss, ports_to_scan,
                           initialize_target_results, service_detection, version,
                           zombie_ips, ttl, sport, payload, id, flags):

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
                                           payload, id, flags)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for zombie, ports in zombie_ports.items():
                        for port in ports:
                            future = executor.submit(
                                Payloads.Idle_Scan,
                                target, port, zombie, max_retries, verbose,
                                socket_timeout, lock, target_results,
                                banner_option, initialize_target_results,
                                service_detection, version, ttl, sport,
                                payload, id, flags
                            )
                            futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] Idle scan thread error: {e}{reset}")

    @staticmethod
    def Sctp_init_Scan(target, port, max_retries, fragmente, recursively, verbose, socket_timeout, lock, target_results,
                       banner_option, initialize_target_results, service_detection, version, ttl, hlim, sport, payload,
                       id, flags):
        for attempt in range(max_retries):
            try:

                Proto = "sctp"
                scan_type = "init"
                if payload == None:
                    pass
                else:
                    payloads = [payload]
                if ttl:
                    TTL = ttl
                else:
                    TTL = mirage.ipv4_ttl()

                if hlim:
                    HLIM = hlim
                else:
                    HLIM = mirage.ipv6_hlim()

                if sport:
                    SPORT = sport
                else:
                    SPORT = mirage.sctp_sport()
                if version == 6:
                    if payload:
                        packet = IPv6(dst=target, nh=6, hlim=HLIM) / scapy.SCTP(sport=SPORT,dport=port, tag=0) / scapy.SCTPChunkInit(a_rwnd=65535,init_tag=12345678,n_out_streams=10,n_in_streams=10,init_tsn=1000) / scapy.Raw(
                            load=random.choice(payloads))
                    else:
                        packet = IPv6(dst=target, nh=6, hlim=HLIM) / scapy.SCTP(sport=SPORT,dport=port, tag=0) / scapy.SCTPChunkInit(a_rwnd=65535,init_tag=12345678,n_out_streams=10,n_in_streams=10,init_tsn=1000)
                else:
                    if id:
                        ID = id
                    else:
                        ID = mirage.ipv4_id()
                    if flags:
                        FLAGS = flags
                    else:
                        FLAGS = mirage.ipv4_flags()

                    if payload:
                        packet = scapy.IP(dst=target, id=ID, ttl=TTL,
                                          flags=FLAGS) / scapy.SCTP(sport=SPORT,dport=port, tag=0) / scapy.SCTPChunkInit(a_rwnd=65535,init_tag=12345678,n_out_streams=10,n_in_streams=10,init_tsn=1000) / scapy.Raw(
                            load=random.choice(payloads))
                    else:
                        packet = scapy.IP(dst=target, id=ID, ttl=TTL,
                                          flags=FLAGS) / scapy.SCTP(sport=SPORT,dport=port, tag=0) / scapy.SCTPChunkInit(a_rwnd=65535,init_tag=12345678,n_out_streams=10,n_in_streams=10,init_tsn=1000)

                response = scapy.sr1(packet, timeout=socket_timeout, verbose=0)

                service = service_detection(port)

                if response is None:

                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)

                elif response.haslayer(scapy.SCTPChuckInitAck):
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['open_ports'].append(port)

                        if banner_option:
                            banner = Banner.grab(
                                target,
                                port,
                                protocol="sctp",
                                timeout=3,
                                verbose=verbose,
                                version=version
                            )

                            if banner:
                                with lock:
                                    target_results[target]['banners'].append(banner['banner'])
                                    target_results[target]['banners_ports'].append(port)
                                    target_results[target]['opened_ports_services'].append(banner['service'])
                            else:
                                target_results[target]['opened_ports_services'].append(service)

                elif response.haslayer(ICMPv6DestUnreach):
                    code = response.getlayer(ICMPv6DestUnreach).code
                    if code == 4:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['closed_ports'].append(port)
                            target_results[target]['closed_ports_services'].append(service)
                        break
                    elif code == 1:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break
                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                elif response.haslayer(scapy.ICMP):
                    icmp_type = response.getlayer(scapy.ICMP).type
                    icmp_code = response.getlayer(scapy.ICMP).code

                    if icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                    else:
                        with lock:
                            if target not in target_results:
                                initialize_target_results(target)
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                        break

                else:
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)
                        target_results[target]['filtered_ports'].append(port)
                        target_results[target]['filtered_ports_services'].append(service)
                    break

            except Exception as e:
                if verbose:
                    print(f"{red}[!] Error scanning port {port}: {e}{reset}")
                if attempt == max_retries - 1:
                    service = service_detection(port)
                    with lock:
                        if target not in target_results:
                            initialize_target_results(target)

                        if port in target_results[target]['open_ports']:
                            pass
                        else:
                            target_results[target]['filtered_ports'].append(port)
                            target_results[target]['filtered_ports_services'].append(service)
                else:
                    time.sleep(0.1)
                    continue

    @staticmethod
    def threaded_sctp_init_scan(max_retries, lock, verbose, fragmente, recursively, socket_timeout, target_results,
                                banner_option, max_threads, targetss, ports_to_scan, i, s, version, ttl, hlim, sport,
                                payload, id, flags):

        if max_threads == 1:
            for target in targetss:
                for port in ports_to_scan:
                    Payloads.Sctp_init_Scan(target, port, max_retries, fragmente, recursively,
                                            verbose, socket_timeout, lock, target_results,
                                            banner_option, i, s, version, ttl, hlim, sport, payload,
                                            id, flags)
        else:
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for target in targetss:
                    for port in ports_to_scan:
                        future = executor.submit(
                            Payloads.Sctp_init_Scan,
                            target, port, max_retries, fragmente, recursively,
                            verbose, socket_timeout, lock, target_results,
                            banner_option, i, s, version, ttl, hlim, sport, payload,
                            id, flags
                        )
                        futures.append(future)

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        if verbose:
                            print(f"{red}[!] SCTP INIT scan error: {e}{reset}")
