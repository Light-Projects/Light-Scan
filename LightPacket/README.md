# LightPacket - A Comprehensive Packet Manipulation Library

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Version 0.0.4](https://img.shields.io/badge/version-0.0.4-orange.svg)](https://github.com/adamboulaaz92-jpg/LightPacket)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS%20%7C%20BSD-lightgrey.svg)](https://github.com/adamboulaaz92-jpg/LightPacket)

![](images/LightPacket-Logo.png)

## Overview

**LightPacket** is a high-performance, cross-platform packet manipulation, sniffing, and crafting library written in Python and C. It provides a complete toolkit for building, dissecting, inspecting, filtering, and transmitting network packets across Layers 2, 3, and 4.

Designed for network engineers, security researchers, and systems developers, LightPacket seamlessly bridges native low-level socket performance (via Linux `AF_PACKET`, Npcap, and libpcap) with an expressive, pythonic API.

---

### Key Features

- **Multi-Layer Protocol Construction**: Craft and stack Ethernet, Dot3, VLAN (802.1Q & 802.1ad QinQ), ARP, LLC, SNAP, STP, PPP, PPPoE, EAPOL, SLLv1/SLLv2, IPv4, IPv6, TCP, UDP, Raw, and IEEE 802.11 Wi-Fi frames.
- **Pythonic Packet Stacking**: Chain protocols intuitively using the division `/` operator (`Ethernet() / IPv4() / TCP()`).
- **Automatic Protocol Dissection**: Instant parsing of raw wire bytes into structured, typed layer objects with `DetectLayer`.
- **Pure-Python cBPF Engine (`LightBPF`)**: Complete built-in Berkeley Packet Filter compiler, lexer, parser, disassembler, and virtual machine emulator—zero external C dependencies required.
- **Native High-Speed Sockets**: Choose between cross-platform `L2Socket` (libpcap/Npcap) and Linux-optimized `L2Packet` (zero-copy native `AF_PACKET`).
- **Live Packet Sniffer (`Sniffer`)**: Thread-safe capture loop with Python iterator streaming (`s.stream()`), callbacks, packet limits, timeouts, and BPF filtering.
- **Next-Gen Capture Formats**: Full C-accelerated reading and writing for classic **PCAP**, modern **PCAPNG**, and ultra-fast **LBN** (LightBinary) files.
- **Packet Replay Engine (`replay`)**: Replay capture files across network interfaces with configurable pacing, loop counts, jitter, and interruption controls.
- **Interface & Route Discovery**: Auto-detect default interfaces, MAC addresses, gateways, and subnet topologies across Linux, Windows, macOS, and BSD.
- **Interactive Layer Inspection (`ls`)**: Inspect protocol fields, defaults, and data types dynamically in the terminal.

---

## What's New in Version 0.0.4

- **Pure-Python BPF Engine (`LightBPF`)**:
  - Full lexer, recursive-descent parser, and optimizing bytecode compiler for classic BPF (cBPF / pcap-filter).
  - Built-in `BpfEmulator` virtual machine for running filters against raw bytes offline without root.
  - Generates Linux kernel `SO_ATTACH_FILTER` structures (`struct sock_fprog`) and disassembled instruction traces (`disassemble`).
  - Supports protocol checks, CIDR subnets, IPv6 128-bit addresses, VLAN ID isolation, port ranges, packet length checks, and scratch memory register spilling (`M[0..15]`).
- **Full Layer 3 & Layer 4 Suite (`l3.py`)**:
  - `IPv4`: Configurable headers, automatic checksum calculation, and IP Options parsing (`IPOptions`).
  - `IPv6`: 128-bit addressing and chained extension headers (`IPv6ExtHeader`: Hop-by-Hop, Routing, Fragment, ESP, AH, Destination Options, Mobility).
  - `TCP`: Port multiplexing, flags, window sizing, sequence/acknowledgment tracking, options, and checksum calculation with pseudo-header.
  - `UDP`: Lightweight datagrams with automatic payload length and pseudo-header checksum offload.
- **PCAPNG Capture Support (`Saving/pcapng.py`)**:
  - C-accelerated reading and writing of PCAP Next Generation (`.pcapng`) files via `libpcapng.so`.
  - Interface Description Blocks, Enhanced Packet Blocks, and microsecond/nanosecond timestamp fidelity.
- **LBN (LightBinary) Capture Format (`Saving/lbn.py`)**:
  - High-throughput, low-overhead binary capture format with optional zlib compression via `liblbn.so`.
- **Unified Packet Replay (`utils/replay.py`)**:
  - Automated packet replayer supporting `.pcap`, `.pcapng`, and `.lbn` files with rate limiting, delay, random jitter, loop iterations, and callbacks.
- **High-Level Live Sniffer (`Sniffer.py`)**:
  - Modern capture manager wrapping raw sockets with context management (`with Sniffer(...) as s:`), streaming generator (`stream()`), and asynchronous termination.
- **IEEE 802.11 Wireless / Wi-Fi (`Wireless/wlan.py`)**:
  - Full support for 802.11 Management frames (Beacon, Probe Request, Probe Response) and Information Elements (`Element` for SSID, Rates, DSSS, RSN/WPA2, Vendor Specific).
- **Linux SLL (Cooked Capture) Support (`platforms/linux/sll.py`)**:
  - Dissection and construction of Linux `any` cooked capture interfaces (`SLLv1` and `SLLv2`).
- **Enhanced Layer Inspection (`helper/ls.py`)**:
  - Dynamic `ls(Layer)` command inspecting all fields, types, and defaults defined in the protocol catalog.

---

## Architecture Overview (0.0.4)

```
LightPacket/
├── __init__.py                   # Package entry point (platform dispatcher)
├── BaseLayer.py                  # Abstract base layer class & operator overloading
├── l2.py                         # Layer 2 protocol exports
├── l3.py                         # Layer 3 & 4 protocol exports
├── Detect_layer.py               # Dynamic protocol detector & auto-dissector
├── Sniffer.py                    # Live packet sniffer and streaming loop
├── Consts.py                     # Protocol constants, EtherTypes, and SAP values
├── Version.py                    # Version metadata (0.0.4)
├── Hex.py                        # Hexdump formatting utility
│
├── EthernetII.py                 # Ethernet II & Loopback frames
├── Dot3.py                       # IEEE 802.3 Dot3 frames
├── LLC.py                        # Logical Link Control (802.2)
├── Snap.py                       # Subnetwork Access Protocol (SNAP)
├── Vlan.py                       # 802.1Q & 802.1ad (QinQ) tagged frames
├── Arp.py                        # Address Resolution Protocol (ARP)
├── Stp.py                        # Spanning Tree Protocol (STP / RSTP)
├── ppp.py                        # Point-to-Point Protocol (PPP, PPP2b, PPPoE)
├── eapol.py                      # 802.1X EAPOL & EAP authentication methods
├── ipv4.py                       # IPv4 header, IP options, & checksums
├── ipv6.py                       # IPv6 header & extension header parser
├── tcp.py                        # TCP header, flags, options, & checksums
├── udp.py                        # UDP header & checksum calculation
├── Raw.py                        # Raw binary payload wrapper
├── bpf.py                        # libpcap C BPF compilation wrapper
│
├── LightBPF/                     # Pure-Python cBPF Engine (New in 0.0.4)
│   ├── Lexer.py                  # Tokenizer with operator normalization
│   ├── Parser.py                 # Recursive-descent AST parser
│   ├── Compiler.py               # cBPF bytecode compiler, backpatcher & emulator
│   └── README.md                 # Complete LightBPF architectural documentation
│
├── platforms/                    # OS-specific low-level implementations
│   └── linux/
│       ├── L2Packet.py           # Native zero-copy Linux AF_PACKET socket
│       └── sll.py                # Linux Cooked Capture (SLLv1 & SLLv2)
│
├── Wireless/                     # Wireless protocols
│   └── wlan.py                   # IEEE 802.11 Wi-Fi frames & Information Elements
│
├── Saving/                       # Multi-format packet capture I/O
│   ├── pcapreader.py             # C-optimized classic PCAP reader
│   ├── pcapwriter.py             # C-optimized classic PCAP writer
│   ├── pcapng.py                 # PCAP Next Generation (PCAPNG) reader & writer
│   └── lbn.py                    # LightBinary (LBN) high-speed format
│
├── utils/                        # Network & protocol utilities
│   ├── replay.py                 # Capture replay engine (pcap, pcapng, lbn)
│   ├── CIDR.py                   # IP & network address range validator
│   ├── Checksum.py               # One's complement internet checksum
│   ├── FCS.py                    # Frame Check Sequence & CRC32
│   ├── VlanUtils.py              # VLAN stack depth & stripping utilities
│   └── Nsec/
│       └── arp_resolution.py     # High-speed parallel ARP scanner
│
├── lib/                          # Compiled native C shared libraries & sources
│   ├── pcap_reader.c / .h        # Native PCAP reader C extension
│   ├── pcap_writer.c / .h        # Native PCAP writer C extension
│   ├── pcapng.c / .h             # Native PCAPNG C extension
│   └── lbn.c / .h                # Native LightBinary C extension
│
├── helper/                       # Protocol helpers & metadata catalog
│   ├── ls.py                     # Layer introspection & terminal inspector
│   ├── network.py                # Network resolution utilities
│   ├── ipv4/                     # IPv4 options & address converters
│   ├── ipv6/                     # IPv6 extension header definitions
│   └── protos/*.json             # JSON schema definitions for each layer
│
├── Interfaces/                   # Network interface enumeration
│   ├── LinuxInterfaces.py        # Linux sysfs/netlink interface discovery
│   ├── WinInterfaces.py          # Windows Npcap / adapter discovery
│   └── UnixInterfaces.py         # macOS / BSD libpcap interface discovery
│
└── Logger/                       # Unified logging & exception subsystem
    ├── LightLogger.py            # ANSI-color terminal logger
    └── Errors.py                 # Standardized LightPacket exception hierarchy
```

---

## Installation

### Prerequisites

#### Linux (Debian / Ubuntu / Kali)
```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev
```

#### macOS
```bash
brew install libpcap
```

#### Windows
- Install [Npcap](https://npcap.com/) (select **"Install Npcap in WinPcap API-compatible Mode"**).
- Ensure Python 3.8+ is installed.

---

### Install from PyPI

```bash
pip install lightpacket
```

### Install from Source

```bash
git clone https://github.com/adamboulaaz92-jpg/LightPacket.git
cd LightPacket

# Compile C acceleration libraries (Linux / macOS):
gcc ./lib/pcap_reader.c -o ./lib/libpcap_reader.so -Wall -O2 -shared -fPIC
gcc ./lib/pcap_writer.c -o ./lib/libpcap_writer.so -Wall -O2 -shared -fPIC
gcc ./lib/pcapng.c      -o ./lib/libpcapng.so      -Wall -O2 -shared -fPIC
gcc ./lib/lbn.c         -o ./lib/liblbn.so         -Wall -O2 -shared -fPIC

# Install package
python setup.py install
```

---

## Core Protocol Layers

All protocol layers inherit from `BaseLayer` and support chaining via the division `/` operator:

```python
from LightPacket.l2 import Ethernet, ARP
from LightPacket.l3 import IPv4, TCP
from LightPacket.Raw import Raw

# Craft an Ethernet / IPv4 / TCP packet with payload:
packet = Ethernet(dst="aa:bb:cc:dd:ee:ff") / IPv4(dst="192.168.1.1") / TCP(dport=80, flags="S") / Raw(b"GET / HTTP/1.1\r\n\r\n")

# Serialize to raw wire bytes:
wire_bytes = packet.build()
print(f"Total frame length: {len(wire_bytes)} bytes")
```

---

### Layer 2 Protocols (`LightPacket.l2`)

#### Ethernet II (`EthernetII.py`)
```python
from LightPacket.EthernetII import Ethernet

eth = Ethernet(
    src="00:11:22:33:44:55",   # Defaults to local default interface MAC
    dst="ff:ff:ff:ff:ff:ff",   # Defaults to broadcast
    ethertype=0x0800           # Auto-inferred from next layer (e.g. 0x0800 for IPv4)
)
```

#### 802.1Q & 802.1ad QinQ VLAN (`Vlan.py`)
```python
from LightPacket.Vlan import VLAN
from LightPacket.EthernetII import Ethernet
from LightPacket.ipv4 import IPv4

# Single 802.1Q Tag:
vlan_pkt = Ethernet() / VLAN(vlan_id=100, priority=3) / IPv4(dst="10.0.0.1")

# QinQ (Stacked VLANs):
qinq_pkt = Ethernet() / VLAN(vlan_id=10, ethertype=0x88A8) / VLAN(vlan_id=20) / IPv4()
```

#### Address Resolution Protocol (`Arp.py`)
```python
from LightPacket.Arp import ARP

# ARP Who-has Request:
arp_req = ARP(opcode=1, ipsrc="192.168.1.10", ipdst="192.168.1.1")

# ARP Is-at Reply:
arp_rep = ARP(opcode=2, macsrc="00:11:22:33:44:55", ipsrc="192.168.1.1", macdst="aa:bb:cc:dd:ee:ff", ipdst="192.168.1.10")
```

#### Spanning Tree Protocol (`Stp.py`)
```python
from LightPacket.Stp import STP
from LightPacket.LLC import LLC

# Configuration BPDU:
stp_pkt = LLC(dsap=0x42, ssap=0x42) / STP(root_priority=0x8000, root_mac="00:11:22:33:44:55")
```

#### EAPOL & 802.1X Authentication (`eapol.py`)
```python
from LightPacket.eapol import EAPOL, EAP_IDENTITY, EAP_MD5, EAP_TLS

# EAPOL Start:
eapol_start = EAPOL(packet_type=1)

# EAP Identity Response:
eap_id = EAPOL(packet_type=0) / EAP_IDENTITY(eap_id=1, identity="alice@corp.net")
```

#### Linux Cooked Capture (`platforms.linux.sll`)
```python
from LightPacket.platforms.linux.sll import SLLv1, SLLv2

# Parse or build SLL frames captured on 'any' interface
sll = SLLv1(arphrd_type=1, proto=0x0800)
```

---

### Layer 3 & Layer 4 Protocols (`LightPacket.l3`)

#### Internet Protocol Version 4 (`ipv4.py`)
```python
from LightPacket.ipv4 import IPv4

ip = IPv4(
    src="192.168.1.10",
    dst="1.1.1.1",
    ttl=64,
    tos=0x10,
    proto=6     # Auto-inferred if stacked with TCP (6) or UDP (17)
)
```

#### Internet Protocol Version 6 (`ipv6.py`)
```python
from LightPacket.ipv6 import IPv6
from LightPacket.helper.ipv6.IPv6ExtHeader import IPv6ExtHeader

# Base IPv6:
ip6 = IPv6(src="2001:db8::1", dst="2001:db8::2", hop_limit=64)

# Chained Extension Headers:
ip6_ext = IPv6(dst="2001:db8::2") / IPv6ExtHeader(next_header=6, ext_type=44) / TCP(dport=80)
```

#### Transmission Control Protocol (`tcp.py`)
```python
from LightPacket.tcp import TCP

# TCP SYN packet:
tcp_syn = TCP(sport=43210, dport=443, flags="S", seq=1000, window=65535)

# TCP ACK packet:
tcp_ack = TCP(sport=43210, dport=443, flags="A", seq=1001, ack=5001)
```

#### User Datagram Protocol (`udp.py`)
```python
from LightPacket.udp import UDP
from LightPacket.Raw import Raw

# DNS query over UDP:
udp_pkt = UDP(sport=5353, dport=53) / Raw(b"\x12\x34\x01\x00\x00\x01...")
```

---

### IEEE 802.11 Wireless (`Wireless/wlan.py`)

Craft and parse 802.11 Wi-Fi frames directly:

```python
from LightPacket.Wireless.wlan import WiFi, Beacon, Element

# Wi-Fi Beacon Frame:
beacon = (
    WiFi(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55") /
    Beacon(interval=100, capabilities=0x0411) /
    Element(id=0, info=b"Corporate-WiFi") /
    Element(id=1, info=b"\x82\x84\x8b\x96") /
    Element(id=3, info=b"\x06")   # Channel 6
)
```

---

## Automatic Dissection & Introspection

### Dissecting Raw Bytes (`DetectLayer`)

`DetectLayer` automatically inspects wire bytes, decodes each layer header, calculates offsets, and reconstructs the packet tree:

```python
from LightPacket import DetectLayer

raw_bytes = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00\x45\x00..."
parsed_pkt = DetectLayer().start(raw_bytes)

# Display colored visual representation:
parsed_pkt.show()

# Access layers directly:
if parsed_pkt.haslayer("IPv4"):
    print("Destination IP:", parsed_pkt["IPv4"].dst)
```

### Protocol Introspection (`ls`)

Inspect any protocol's fields, types, and descriptions in the terminal:

```python
from LightPacket import ls
from LightPacket.tcp import TCP

# Inspect TCP layer definition:
ls(TCP)

# Or inspect by name:
ls("IPv4")

# List all supported protocols in LightPacket:
ls()
```

---

## Pure-Python cBPF Engine (`LightBPF`)

LightPacket 0.0.4 includes a built-in, pure-Python Berkeley Packet Filter engine that compiles pcap-filter expressions into classic BPF machine code with **zero dependencies**.

```python
from LightPacket.LightBPF.Compiler import BpfCompiler, BpfEmulator, disassemble

# 1. Compile filter string into cBPF instructions
insns = BpfCompiler.compile_str("tcp port 80 and src host 192.168.1.10")

# 2. Print readable assembly (similar to 'tcpdump -d')
print(disassemble(insns))

# 3. Test filter on raw packets offline (without root / libpcap)
matched = BpfEmulator.execute(insns, raw_frame_bytes)
if matched > 0:
    print("Filter matched!")
```

### Attaching to Sockets via Kernel `SO_ATTACH_FILTER`

```python
import socket
from LightPacket.LightBPF.Compiler import BpfCompiler

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind(("eth0", 0))

# Compile and export to ctypes sock_fprog
fprog = BpfCompiler.to_fprog(BpfCompiler.compile_str("tcp and not dst port 22"))

# Attach directly to the Linux kernel socket filter
SO_ATTACH_FILTER = 26
sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
```

For complete technical documentation on the Lexer, Parser, Compiler, and Virtual Machine, refer to the [LightBPF Guide](LightBPF/README.md).

---

## Live Packet Sniffing

### High-Level Sniffer (`Sniffer.py`)

Capture live network traffic using streaming iterators or callbacks:

```python
from LightPacket import Sniffer, DetectLayer

# 1. Stream packets with a filter:
with Sniffer(iface="eth0", filter="tcp or udp", timeout=10.0) as s:
    for raw in s.stream():
        packet = DetectLayer().start(raw)
        print(f"Captured: {packet.summary()}")

# 2. Callback mode:
def on_packet(raw):
    print(f"Received {len(raw)} bytes")

Sniffer(iface="eth0", count=50).start(callback=on_packet)
```

---

## Native Network Sockets

### Cross-Platform `L2Socket` (libpcap / Npcap)

Works identically across Linux, Windows, macOS, and BSD:

```python
from LightPacket import L2Socket
from LightPacket.l2 import Ethernet, ARP

sock = L2Socket(iface="eth0", promisc=True)

# Send Layer 2 frame:
sock.sendl2(Ethernet() / ARP())

# Send and wait for single reply:
reply = sock.srp1(Ethernet() / ARP(ipdst="192.168.1.1"), timeout=2.0)
if reply:
    print("Host MAC:", reply.macsrc)

sock.close()
```

### Linux Zero-Copy `L2Packet` (`AF_PACKET`)

Low-overhead, ultra-fast raw socket for Linux bypassing libpcap:

```python
from LightPacket.platforms.linux.L2Packet import L2Packet

sock = L2Packet(iface="eth0")
sock.sendl2(packet)

# Receive up to 10 packets within 2.5 seconds:
packets = sock.recvl2(count=10, timeout=2.5)
sock.close()
```

---

## Packet Capture I/O & Replay

### PCAP Files (`Saving.pcapwriter`, `Saving.pcapreader`)

```python
from LightPacket import PcapWrite, PcapRead

# Write captured frames:
PcapWrite([pkt1.build(), pkt2.build()], "capture.pcap")

# Read frames:
packets = PcapRead("capture.pcap")
for p in packets:
    print(p["ts_sec"], len(p["data"]))
```

### PCAPNG Files (`Saving.pcapng`)

C-accelerated reading and writing of modern `.pcapng` capture files:

```python
from LightPacket.Saving.pcapng import PcapngWriter, PcapngReader

# Write to PCAPNG:
with PcapngWriter("session.pcapng") as writer:
    iface_id = writer.add_interface(name="eth0", link_type=1)
    writer.write(packet_bytes, interface_id=iface_id)

# Read from PCAPNG:
with PcapngReader("session.pcapng") as reader:
    for pkt in reader:
        print(f"Timestamp: {pkt.timestamp_ns}ns, Len: {pkt.captured_len}")
```

### LBN High-Speed Format (`Saving.lbn`)

```python
from LightPacket.Saving.lbn import LbnWrite, LbnRead

# High-speed compressed storage:
LbnWrite("traffic.lbn", packet_list, compress=1)

# Read back:
loaded_packets = LbnRead("traffic.lbn")
```

### Packet Replay Engine (`utils.replay`)

Replay capture files (`.pcap`, `.pcapng`, or `.lbn`) through any socket interface:

```python
from LightPacket import L2Socket
from LightPacket.utils.replay import replay

sock = L2Socket(iface="eth0")

# Replay capture with 50ms delay, 10% jitter, looping 3 times:
sent = replay(
    file_path="capture.pcapng",
    socket=sock,
    delay=0.05,
    loop=3,
    jitter=0.10,
    on_packet=lambda idx, data: print(f"Sent packet #{idx}")
)

print(f"Replay finished. Total packets sent: {sent}")
sock.close()
```

---

## Network Interfaces & Utilities

### Interface Enumeration

```python
from LightPacket import NetworkInterfaces

ifaces = NetworkInterfaces()

# Show formatted table:
ifaces.show()

# Get default gateway and interface:
default_iface = ifaces.default_interface()
print(f"Default: {default_iface['name']} ({default_iface['mac']})")
```

### MAC & IP Helpers

```python
from LightPacket import MacAddress, inet_aton, inet_ntoa, hexdump

# MAC formatting:
mac = MacAddress("001122334455")
print(mac.colon())  # "00:11:22:33:44:55"

# Binary Hex Dump:
print(hexdump(b"\x00\x01\x02\x03\x04\x05\x06\x07"))
```

---

## Comprehensive Real-World Examples

### 1. High-Speed ARP Network Scanner

```python
import time
from LightPacket import L2Socket, DetectLayer
from LightPacket.l2 import Ethernet, ARP

def scan_network(subnet_ips, interface="eth0"):
    sock = L2Socket(iface=interface)
    sock.set_filter("arp and arp[6:2] == 2")  # ARP Replies only

    print(f"Scanning {len(subnet_ips)} hosts on {interface}...")
    for ip in subnet_ips:
        sock.sendl2(Ethernet(dst="ff:ff:ff:ff:ff:ff") / ARP(opcode=1, ipdst=ip))
        time.sleep(0.01)

    # Collect replies
    replies = sock.recvl2(count=len(subnet_ips), timeout=2.0)
    for raw in replies:
        pkt = DetectLayer().start(raw)
        if pkt and ARP in pkt:
            print(f"Host online: {pkt[ARP].ipsrc} -> {pkt[ARP].macsrc}")

    sock.close()
```

### 2. TCP SYN Port Scanner

```python
from LightPacket import L2Socket, DetectLayer
from LightPacket.l2 import Ethernet
from LightPacket.l3 import IPv4, TCP

def syn_scan(target_ip, ports, interface="eth0"):
    sock = L2Socket(iface=interface)
    sock.set_filter(f"tcp and src host {target_ip}")

    for port in ports:
        syn = Ethernet() / IPv4(dst=target_ip) / TCP(dport=port, flags="S", seq=1000)
        sock.sendl2(syn)

        resp = sock.srp1(syn, timeout=1.0)
        if resp and resp.haslayer("TCP"):
            flags = resp["TCP"].flags
            if "S" in flags and "A" in flags:
                print(f"Port {port}: OPEN (SYN-ACK)")
            elif "R" in flags:
                print(f"Port {port}: CLOSED (RST)")

    sock.close()
```

---

## Version Information

```python
import LightPacket

print(f"LightPacket Version: {LightPacket.__version__}")  # '0.0.4'
```

---

## License

LightPacket is released under the **Mozilla Public License 2.0 (MPL-2.0)**. See the [LICENSE](LICENSE) file for full details.

---

## Author & Community

- **Author**: Adam Boulaaz ([@adamboulaaz92-jpg](https://github.com/adamboulaaz92-jpg))
- **Repository**: [https://github.com/adamboulaaz92-jpg/LightPacket](https://github.com/adamboulaaz92-jpg/LightPacket)
- **Issues & Contributions**: Please submit bug reports and feature requests to the [GitHub Issue Tracker](https://github.com/adamboulaaz92-jpg/LightPacket/issues).
