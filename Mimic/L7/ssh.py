import scapy.all as scapy
import random
from scapy.layers.inet6 import IPv6
from ..Transport import Stealth_tcp_options

def ssh_payload_tcp(target, version):
    ssh_clients = [
        "SSH-2.0-OpenSSH_8.9p1",
        "SSH-2.0-OpenSSH_7.4",
        "SSH-2.0-OpenSSH_7.9",
        "SSH-2.0-libssh2_1.10.0",
        "SSH-2.0-PuTTY_Release_0.78",
        "SSH-2.0-LightScan_1.1.8"
    ]
    ssh_banner = random.choice(ssh_clients) + "\r\n"

    if version == 4:
        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32, 255), flags="DF") /
                  scapy.TCP(dport=22, sport=random.randint(60000, 65535),
                            seq=random.randint(1000000000, 4294967295),
                            window=random.choice([5840, 64240, 65535, 29200, 8760]),
                            options=Stealth_tcp_options(), flags="S") /
                  scapy.Raw(load=ssh_banner))
    else:
        packet = (IPv6(dst=target, nh=6, hlim=random.randint(32, 255)) /
                  scapy.TCP(dport=22, sport=random.randint(60000, 65535),
                            seq=random.randint(1000000000, 4294967295),
                            window=random.choice([5840, 64240, 65535, 29200, 8760]),
                            options=Stealth_tcp_options(), flags="S") /
                  scapy.Raw(load=ssh_banner))

    return packet


def ssh_payload_udp(target, version):
    ssh_clients = [
        "SSH-2.0-OpenSSH_8.9p1",
        "SSH-2.0-OpenSSH_7.4",
        "SSH-2.0-OpenSSH_7.9",
        "SSH-2.0-libssh2_1.10.0",
        "SSH-2.0-PuTTY_Release_0.78",
        "SSH-2.0-LightScan_1.1.8"
    ]
    ssh_banner = random.choice(ssh_clients) + "\r\n"

    if version == 4:
        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32, 255), flags="DF") /
                  scapy.UDP(dport=22, sport=random.randint(60000, 65535)) /
                  scapy.Raw(load=ssh_banner))
    else:
        packet = (IPv6(dst=target, nh=17, hlim=random.randint(32, 255)) /
                  scapy.UDP(dport=22, sport=random.randint(60000, 65535)) /
                  scapy.Raw(load=ssh_banner))

    return packet