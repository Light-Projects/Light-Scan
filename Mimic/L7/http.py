import scapy.all as scapy
import random
from scapy.layers.inet6 import IPv6
from ..Transport import Stealth_tcp_options

def http_payload_tcp(target, version,port):
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "curl/7.88.1",
        "PostmanRuntime/7.26.0",
        "python-requests/2.25.1"
    ]

    methods = ["GET", "POST", "HEAD", "OPTIONS"]
    method = random.choice(methods)

    if method == "POST":
        payload = (f"POST / HTTP/1.1\r\n"
                   f"Host: {target}\r\n"
                   f"User-Agent: {random.choice(user_agents)}\r\n"
                   f"Accept: */*\r\n"
                   f"Content-Type: application/x-www-form-urlencoded\r\n"
                   f"Content-Length: 7\r\n"
                   f"Connection: close\r\n\r\n"
                   f"test=123").encode()
    else:
        payload = (f"{method} / HTTP/1.1\r\n"
                   f"Host: {target}\r\n"
                   f"User-Agent: {random.choice(user_agents)}\r\n"
                   f"Accept: */*\r\n"
                   f"Connection: close\r\n\r\n").encode()

    if version == 4:
        packet = (scapy.IP(dst=target, id=random.randint(1, 65535), ttl=random.randint(32, 255), flags="DF") /
                  scapy.TCP(dport=port, sport=random.randint(60000, 65535),
                            seq=random.randint(1000000000, 4294967295),
                            window=random.choice([5840, 64240, 65535, 29200, 8760]),
                            options=Stealth_tcp_options(), flags="S") /
                  scapy.Raw(load=payload))
    else:
        packet = (IPv6(dst=target, nh=6, hlim=random.randint(32, 255)) /
                  scapy.TCP(dport=port, sport=random.randint(60000, 65535),
                            seq=random.randint(1000000000, 4294967295),
                            window=random.choice([5840, 64240, 65535, 29200, 8760]),
                            options=Stealth_tcp_options(), flags="S") /
                  scapy.Raw(load=payload))

    return packet