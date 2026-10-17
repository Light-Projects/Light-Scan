# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from LightPacket.utils.CIDR import parse_targets
from LightPacket import L2Socket
from LightPacket.Arp import ARP
from LightPacket.EthernetII import Ethernet
from LightPacket.Consts import BROADCAST_MAC
from LightPacket.Detect_layer import DetectLayer
from concurrent.futures import ThreadPoolExecutor, as_completed

def arp_ping(target,verbose) -> ARP | None:
    packet = Ethernet(dst=BROADCAST_MAC) / ARP(ipdst=target,macdst=BROADCAST_MAC)
    response = L2Socket().srp1(packet,timeout=2,filter_str=f'arp src host {target} and arp[7] == 2')
    if response:
        res = DetectLayer().start(response)
        if verbose:
            print(f"[ARP] Host {target} is up (MAC: {res[ARP].macsrc}) ")
        return res
    return None

def arp_scan(target_input='10.148.175.0/24', max_workers=200,verbose=False):
    targets = parse_targets(target_input)
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(arp_ping, target,verbose=verbose): target for target in targets}

        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    return results



