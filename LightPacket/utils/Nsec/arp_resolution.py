from LightPacket.utils.CIDR import parse_targets
from LightPacket import ARP, Ethernet, L2Socket
from LightPacket.Arp import ArpLayer
from LightPacket.Consts import BROADCAST_MAC
from LightPacket.Detect_layer import DetectLayer
from concurrent.futures import ThreadPoolExecutor, as_completed

def arp_ping(target,verbose) -> ArpLayer | None:
    packet = Ethernet(dst=BROADCAST_MAC) / ARP(ipdst=target,macdst=BROADCAST_MAC)
    response = L2Socket().srp1(packet,timeout=1.0,filter_str=f'arp src host {target} and arp[7] == 2')
    if response:
        res = DetectLayer().start(response)
        if verbose:
            print(f"[ARP] Host {target} is up (MAC: {res[ArpLayer].macsrc}) ")
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



