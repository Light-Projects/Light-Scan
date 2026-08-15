import scapy.all as scapy
import random
from scapy.layers.inet6 import IPv6
from ..Transport import Stealth_tcp_options

def ftp_payload_tcp(target, version):
    ftp_clients = [
        "220 FTP Server Ready",
        "220 ProFTPD Server",
        "220 Microsoft FTP Service",
        "220 vsFTPd Server",
        "220 FileZilla Server",
        "220 Pure-FTPd Server",
        "220 Welcome to FTP Service",
        "220 Welcome to LightScan FTP Server",
    ]
    ftp_banner = random.choice(ftp_clients) + "\r\n"

    if version == 4:
        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32, 255), flags="DF") /
                  scapy.TCP(dport=21, sport=random.randint(60000, 65535),
                            seq=random.randint(1000000000, 4294967295),
                            window=random.choice([5840, 64240, 65535, 29200, 8760]),
                            options=Stealth_tcp_options(), flags="S") /
                  scapy.Raw(load=ftp_banner))
    else:
        packet = (IPv6(dst=target, nh=6, hlim=random.randint(32, 255)) /
                  scapy.TCP(dport=21, sport=random.randint(60000, 65535),
                            seq=random.randint(1000000000, 4294967295),
                            window=random.choice([5840, 64240, 65535, 29200, 8760]),
                            options=Stealth_tcp_options(), flags="S") /
                  scapy.Raw(load=ftp_banner))

    return packet


def ftp_payload_udp(target, version):
    ftp_clients = [
        "220 FTP Server Ready",
        "220 ProFTPD Server",
        "220 Microsoft FTP Service",
        "220 vsFTPd Server",
        "220 FileZilla Server",
        "220 Pure-FTPd Server",
        "220 Welcome to FTP Service",
        "220 Welcome to LightScan FTP Server",
    ]
    ftp_banner = random.choice(ftp_clients) + "\r\n"

    if version == 4:
        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32, 255), flags="DF") /
                  scapy.UDP(dport=21, sport=random.randint(60000, 65535)) /
                  scapy.Raw(load=ftp_banner))
    else:
        packet = (IPv6(dst=target, nh=17, hlim=random.randint(32, 255)) /
                  scapy.UDP(dport=21, sport=random.randint(60000, 65535)) /
                  scapy.Raw(load=ftp_banner))

    return packet