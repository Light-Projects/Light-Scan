![Python](https://img.shields.io/badge/python-3.13-blue?logo=python&logoColor=white)
![OS](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20macOS%20|%20BSD-2d2d2d?style=for-the-badge&logo=linux&logoColor=white)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Open Source](https://img.shields.io/badge/Open%20Source-❤️-green)](https://opensource.org/)
[![OSI Approved](https://img.shields.io/badge/OSI-Approved-3c9f3c?logo=opensourceinitiative)](https://opensource.org/licenses/gpl-2.0.php)

![](image/Light-Scan-Logo.png)

# Light-Scan — Advanced Network Toolkit & Mini-Framework

**Light-Scan** is not just a port scanner — it is a complete **Network Toolkit and Mini-Framework** designed for security professionals, network administrators, and penetration testers. Built with Python and Scapy, it combines speed, accuracy, and enterprise-grade features in a single cohesive tool.

Unlike traditional scanners that sacrifice one for the other, Light-Scan delivers fast results without compromising depth.



# Light-Scan Version 1.1.8 (Current Version)

# Features

## High-Performance Scanning

Multi-threaded architecture for fast scans
Multiple scan types: TCP Connect, SYN Stealth, UDP, NULL, FIN, ACK, WINDOW, MAIMON, FDD, XMAS, FTP-BOUNCE,IPPROTO,PING,IDLE

Configurable speed presets from Paranoid to Light-mode (500 threads) and manual thread and timeout modification

Smart host discovery with threaded ICMP/ICMPv6/TCP/IP/ARP/NDP detection

## Network Range Support

CIDR notation (/8, /16, /24, etc.) for subnet scanning

Multiple target support via comma-separated lists

Octet ranges (192.168.1.0-100,192.168.1-10.1-244,192.168.1.0;1)

Intelligent host filtering - skips non-responsive hosts in network scans

Safety warnings for large network ranges

## Multiple Saving options

you can save Lightscan results with LightSave that supports 7 differents saving formats from TXT to PDF and YAML

for other tools like LightSniff and LightLab that enteracts with binary packeys they support lbn,pcap and pcang saving

## Advanced Detection

Service detection with custom and system service databases

Firewall detection with detailed analysis

Port state classification: Open, Closed, Filtered, Unfiltered, Open|Filtered, Defended, Undefended

Retry mechanism for unreliable networks

## Professional Features

Flexible port specification: ranges, lists, and top ports

Verbose output for debugging and analysis

Customizable timeouts and thread counts

Custom scan profiles

Clean, organized output with per-target results
    
# Installation

      git clone https://github.com/adamboulaaz92-jpg/Light-Scan.git
      
# Importante

## For Windows
before running Light-Scan you need to install Npcap from https://npcap.com/#download (it's required for Light-Scan to run)

## Windows Setup

    cd Light-Scan
    
    python -m venv venv

    .\venv\Scripts\activate

    pip install -r requirements.txt
    
## For Linux
before running Light-Scan you need to install Npcap from https://npcap.com/#download (it's required for Light-Scan to run) or you can just install libpcap by the command :

### For Debian Based Linux :
        sudo apt install libpcap-dev
### For Arch Based Linux :
        sudo pacman -S libpcap
### For RHEL/CentOS/Fedora :
        sudo yum install libpcap-devel
        # or for newer Fedora:
        sudo dnf install libpcap-devel
### For SUSE :
        sudo zypper install libpcap-devel
### For Alpine Linux :
        sudo apk add libpcap-dev

## Linux Setup

### For Debian Based Linux :

    sudo apt install python3-venv

    python3 -m venv venv

    source venv/bin/activate

    pip install -r requirements.txt
    
### For Arch Based Linux :

    python -m venv venv

    source venv/bin/activate

    pip install -r requirements.txt

### For RHEL/CentOS/Fedora :

    sudo yum install python3-venv
    # or for newer Fedora:
    sudo dnf install python3-venv

    python3 -m venv venv

    source venv/bin/activate

    pip install -r requirements.txt

### For SUSE :

    sudo zypper install python3-venv

    python3 -m venv venv

    source venv/bin/activate

    pip install -r requirements.txt

### For Alpine Linux :

    sudo apk add python3 py3-pip

    python3 -m venv venv

    source venv/bin/activate

    pip install -r requirements.txt

## For macOS

Before running Light-Scan, you need to install libpcap:

### Using Homebrew (Recommended):

    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    brew install libpcap

### Using MacPorts:

    sudo port install libpcap

## macOS Setup

    python3 -m venv venv

    source venv/bin/activate

    pip install -r requirements.txt

## For FreeBSD / OpenBSD / NetBSD

Before running Light-Scan, install libpcap:

### FreeBSD:

    sudo pkg install libpcap python3

### OpenBSD:

    sudo pkg_add libpcap python3

### NetBSD:

    sudo pkgin install libpcap python3

## BSD Setup

    python3 -m venv venv

    source venv/bin/activate

    pip install -r requirements.txt

## For Solaris / Illumos

### Solaris 11:

    pkg install libpcap

### Illumos (OpenIndiana, etc.):

    sudo pkg install libpcap

## Solaris Setup

    python3 -m venv venv

    source venv/bin/activate

    pip install -r requirements.txt

## Guided Auto Setup

    python setup.py
  
# User Guide : 

## Basic Scanning
  
  ### Single Target TCP Scan
  
      python Lightscan.py -T 192.168.1.1
  
  ### SYN Stealth Scan
  
      python Lightscan.py -T 192.168.1.1 -st SYN
  
  ### UDP Scan on Specific Port
  
      python Lightscan.py -T 192.168.1.1 -st UDP -p 53

## Basic Sniffing

### Sniffing With Infinite Packet Count

    python LightSniff.py -c 0 -i Wi-Fi

### Sniffing With Built-in Filters

    python LightSniff.py -c 10 -i wlan0 --tcp --icmp

### Sniffing With binary saving option

    python LightSniff.py -c 100 -i eth0 --bin-save result.lbn

## Basic Saving

### Saving Result in XML

    python LightSave.py -C "python Lightscan.py -T 192.168.1.1" -S xml

### Saving Result in YAML

    python LightSave.py -C "python Lightscan.py -T 192.168.1.1 -st SYN" -S yaml

### Saving Result in HTML

    python LightSave.py -C "python Lightscan.py -T 192.168.1.1 -st UDP -p 53" -S html

## Network Scanning
  
  ### Scan Entire Subnet
  
      python Lightscan.py -T 192.168.1.0/24 -F
  
  ### Multiple Targets
  
      python Lightscan.py -T 192.168.1.1,192.168.1.50,10.0.0.0/24
  
  ### Fast Network Scan with Top Ports
  
      python Lightscan.py -T 10.0.0.0/16 -F -s fast
  
## Advanced Usage
  
  ### Custom Port Range with Retries
  
      python Lightscan.py -T target.com -p 1-1000 --max-retries 3
  
  ### High-Speed Scan with Custom Threads
  
      python Lightscan.py -T 192.168.1.1 -t 200 -tm 0.5
  
  ### Verbose Output for Debugging
  
      python Lightscan.py -T 192.168.1.1 -v -st SYN

## Lightscan 1.1.8

## Command Line Options
  
    usage: Lightscan.py [-h] [-T TARGET] [--rff RFF] [-V6] [-p PORT] [-pp PING_PORT]
                    [-s {paranoid,slow,normal,fast,insane,Light-mode}] [-v] [-n] [-V] [-st SCAN_TYPE]
                    [--zombie ZOMBIE] [-sn] [--ftp-bounce FTP_SERVER] [-F] [-mx MAX_RETRIES] [-t THREADS] [-lst]
                    [--lsse-lst] [--profiles-lst] [-tm TIMEOUT] [-Rc] [-f] [-Pn] [-b] [-O] [-mac]
                    [--load-profile LOAD_PROFILE] [--save-profile SAVE_PROFILE] [-ttl TTL] [-hlim HLIM] [-sport SPORT]
                    [-payload PAYLOAD] [-id ID] [-ip-flags IP_FLAGS] [-Pan] [-Pi] [-Pip PIP] [-A] [-Pt] [-Ps] [-Pk]
                    [-Pu] [-PIt] [-PA] [-Pin] [-Pas] [-q] [--script SCRIPT] [--domain DOMAIN]
                    [--dns-server DNS_SERVER] [-W WORDLIST] [--extensions EXTENSIONS] [--status-codes STATUS_CODES]
                    [--redirect] [--url URL] [--mxp MXP] [--mxd MXD] [-sp SP] [--lsse]
    
    Light-Scan Port Scanner
    
    options:
      -h, --help            show this help message and exit
      -T, --target TARGET   Target IP or Hostname
      --rff RFF             Read Target/s from a file
      -V6                   used when the target is an IPv6
      -p, --port PORT       Port/s to scan
      -pp, --ping-port PING_PORT
                            Port/s to Ping on it
      -s, --speed {paranoid,slow,normal,fast,insane,Light-mode}
                            Scan speed preset
      -v, --verbose         Show verbose output
      -n                    Disable reverse dns
      -V, --version         show Light-Scan version with all additionnal tools
      -st, --scan-type SCAN_TYPE
                            Scan types {TCP,SYN,UDP,NULL,FIN,ACK,XMAS,WINDOW,MAIMON,FDD,FTP-BOUNCE,IPPROTO,PING,IDLE}
      --zombie ZOMBIE       Zombie IP for idle scan (required for --st IDLE)
      -sn                   do only a host discovery without port scaning
      --ftp-bounce FTP_SERVER
                            FTP server for bounce scan (required for --st FTP-BOUNCE)
      -F                    Scan The Top 100 ports for fast scanning
      -mx, --max-retries MAX_RETRIES
                            Max number of retries if port show a no response
      -t, --threads THREADS
                            Number of threads to use
      -lst                  List all targets
      --lsse-lst            List all LSSE Scripts
      --profiles-lst        List all scan profiles from Profiles directory
      -tm, --timeout TIMEOUT
                            Timeout with second
      -Rc, --recursively    recursively scan host that shown to be down or not responding and disable flags like
                            -v,-Pn,etc ...
      -f, --fragmente       fragment the sending packet for more stealth
      -Pn, --no-ping        Do not ping the target/s
      -b, --banner          Banner Grabing
      -O, --os              OS Fingerprint
      -mac                  Light-Scan will skip getting the target mac on Local Networks
      --load-profile LOAD_PROFILE
                            Load the scan profile from Profiles/ directory
      --save-profile SAVE_PROFILE
                            Save the scan profile to Profiles/ directory
      -ttl TTL              Time To Live for IPv4 packets
      -hlim HLIM            Hop Limit for IPv6 packets
      -sport SPORT          Source Port
      -payload PAYLOAD      Add a raw custum Payload
      -id ID                ID Field for IPv4 packets
      -ip-flags IP_FLAGS    IP Flags Field for IPv4 packets (DF=2,MF=1,None=0)
      -Pan, --local-ping    Performe an ARP Ping on Local Networks by default or NDP Ping on Local Networks for IPv6 mode
      -Pi, --ip-ping        IP Protocol Ping
      -Pip PIP              For Specefiy The IP Protocols that -Pi is going to use rather then default
      -A, --agressive       Agressive scan activate all of OS Fingerprints, Banner Grabing, Insane Speed , SYN Scan and
                            Scan Top 100 Ports
      -Pt, --tcp-ping       Do a TCP Ping
      -Ps, --syn-ping       Do a Syn Ping
      -Pk, --ack-ping       DO a ACK Ping
      -Pu, --udp-ping       Do a UDP Ping
      -PIt, --icmp-timestamp-ping
                            Do scan a ICMP Timestamp Ping
      -PA, --icmp-address-ping
                            Do scan a ICMP Address Ping
      -Pin, --icmp-information-ping
                            Do scan a ICMP Information Ping
      -Pas, --icmp-solicitation-ping
                            Do scan a ICMP Solicitation Ping
      -q, --quiet           Quiet mode {does't print the Tool Banner}
      --script SCRIPT       LSSE Script ,Ex: --script http-cert
      --domain DOMAIN       Domain for http/https and Dns based scripts
      --dns-server DNS_SERVER
                            dns server that Light-Scan is going to use (Is Set by Default
      -W, --wordlist WORDLIST
                            Wordlist for scripts
      --extensions EXTENSIONS
                            Extensions for web based scripts
      --status-codes STATUS_CODES
                            Status Codes for web based scripts
      --redirect            Redirect http/https requests for http scripts
      --url URL             Victime URL
      --mxp MXP             max pages to get
      --mxd MXD             max depth to crawl
      -sp SP                Port/s that are going to use by scripts
      --lsse                Use that flag when you want just to performe a script
  
##  Speed Presets

LightScan offers **six speed presets** to balance performance against network conditions and stealth requirements. Each preset controls two key parameters:

- **Threads** — Number of concurrent scan threads (higher = faster)
- **Timeout** — Seconds to wait for a response (higher = more reliable)

| Preset | Threads | Timeout | Best For |
|--------|---------|---------|----------|
|  **paranoid** | 2 | 4.0s | Stealth scans, IDS/IPS evasion, unstable networks |
|  **slow** | 30 | 3.0s | Noisy environments, careful reconnaissance |
|  **normal** | 60 | 2.5s | **Default** — balanced for most scenarios |
|  **fast** | 120 | 2.5s | Internal networks, trusted environments |
|  **insane** | 240 | 1.25s | High-speed LAN scans, aggressive timing |
|  **Light-mode** | 500 | 1.25s | Maximum speed — use on reliable, low-latency networks |



  
## Port Specification Examples
  
  ### Single Port
  
      -p 80
  
  ### Port Range
      
      -p 1-1000
  
  ### Multiple Ports
  
      -p 22,80,443,8080
  
  ### Mixed Ranges and Single Ports
  
      -p 20-25,80,443,8000-9000

## Target Specification Examples
  
  ### Single Target
  
      -T scanme.nmap.org
      or
      -T 8.8.8.8
  
  ### Octet Ranges
      
      -T 192.168.1.0-100 
      or
      -T 192.168-170.1.0-140
  
  ### Multiple Targets
  
      -T 1.1.1.1,8.8.8.8,example.com
  
    
## Network Scanning Features
  CIDR Notation Support
  
  Lightscan supports standard CIDR notation for scanning entire networks:
  
  ### Class C subnet (256 hosts)
      python Lightscan.py -T 192.168.1.0/24
  
  ### Class B subnet (65,536 hosts) - with safety warning
      python Lightscan.py -T 10.0.0.0/16
  
  ### Class A subnet (16.7 million hosts) - extreme warning
      python Lightscan.py -T 10.0.0.0/8
  
## Smart Host Discovery
  
  ### When scanning multiple targets:
  
Performs threaded host discovery first
  
Only scans hosts that respond to discovery probes

Saves time by skipping dead hosts
  
  ### Safety Features
  
Warnings for large network scans
  
Confirmation prompts for massive scans
  
Progress indicators for large expansions
  
### Port States

LightScan classifies ports into **seven distinct states** based on response analysis:

| State | Meaning | Common Causes |
|-------|---------|----------------|
| **Open** | Service is actively listening and accessible | Web server, SSH, database, etc. |
| **Closed** | Host is up but no service is listening | Unused port, service not running |
| **Filtered** | Firewall or filter is blocking access | Stateful firewall, ACL, DROP rules |
| **Open\|Filtered** | Unable to determine (no response received) | Common with UDP scans, packet loss |
| **Defended** | Firewall detected (FDD scan result) | Port behind active firewall protection |
| **Undefended** | No firewall detected (FDD scan result) | Direct port access, no filtering |
| **Unfiltered** | Port accessible but not open (ACK scan) | Used in firewall rule mapping |

# Light-Scan Tools — Complete Guide

Light-Scan is not just a port scanner - it is a complete network toolkit with 5 separated tools that work together seamlessly
for multiple jobs (Scanning,Scripting,Saving,Sniffing and Creating) .


## Table of Contents

### 1. LightSniff - Packet Capture Tool
### 2. LightSave - Results Exporter
### 3. LightPanel - Graphical Interface
### 4. LightLab - Packet Crafting Laboratory
### 5. LightBin - Custom Binary Format
### 6. LSSE - Light-Scan Scripting Engine


## LightSniff - Packet Capture Tool v1.0.1

### Overview
LightSniff is a lightweight, feature-rich packet sniffer built for network analysis and troubleshooting. It uses BPF (Berkeley Packet Filter) syntax for precise traffic filtering and supports both live capture and PCAP export.

### Features
- Live packet capture with BPF filtering
- TCP, UDP, ICMP, ARP protocol filtering
- MAC address filtering
- VLAN tag detection (802.1Q)
- TLS protocol detection (1.0, 1.1, 1.2, 1.3, SSLv3)
- HTTP traffic detection and parsing
- DNS query/response detection
- Save to PCAP, PCAPNG, and LightBin (.lbn)
- Read from PCAP, PCAPNG, and LightBin (.lbn)
- Promiscuous mode support
- Verbose output for detailed analysis
- Quiet mode for silent operation
- Ethernet frame info (MAC addresses, frame type)
- Auto-interface detection

### Command-Line Options

    usage: LightSniff.py [-h] [-i INTERFACE] [-f FILTER] [-c COUNT] [-w WRITE] [-r READ] [--bin-save BIN_SAVE]
                         [--bin-load BIN_LOAD] [-C] [-v] [--no-promisc] [-q] [--eth] [--vlan] [--arp] [--tcp] [--udp]
                         [--icmp] [--mac MAC]
    
    LightSniff - Light-Scan Packet Capture Tool
    
    options:
      -h, --help            show this help message and exit
      -i, --interface INTERFACE
                            Network interface (e.g., eth0, Wi-Fi, wlan0)
      -f, --filter FILTER   BPF filter (e.g., 'tcp port 80', 'icmp', 'arp')
      -c, --count COUNT     Number of packets to capture (0 = infinite)
      -w, --write WRITE     Save to PCAP/PCAPNG file
      -r, --read READ       Read packets from PCAP/PCAPNG file (offline mode)
      --bin-save BIN_SAVE   Save to LightBin binary format (.lbn)
      --bin-load BIN_LOAD   Load from LightBin binary format (.lbn)
      -C, --compress        To compress saved output (only for .lbn)
      -v, --verbose         Show detailed packet info
      --no-promisc          Disable promiscuous mode
      -q, --quiet           Quiet mode (no banner)
      --eth                 Show Ethernet frame info (MAC addresses, frame type)
      --vlan                Show VLAN tags (802.1Q)
      --arp                 Show only ARP packets
      --tcp                 Show only TCP packets
      --udp                 Show only UDP packets
      --icmp                Show only ICMP packets
      --mac MAC             Filter by source or destination MAC address (e.g., aa:bb:cc:dd:ee:ff)
    
    Examples: LightSniff -i eth0 LightSniff -i eth0 -f 'tcp port 80' -w http.pcap LightSniff -i Wi-Fi -c 100 -v LightSniff
    -r capture.pcap LightSniff --bin-load capture.lbn


### Usage Examples

#### Basic Capture
    LightSniff -i eth0

#### Capture HTTP Traffic
    LightSniff -i eth0 -f 'tcp port 80' -w http.pcap

#### Capture with Verbose Output
    LightSniff -i Wi-Fi -c 100 -v

#### Capture and Save as LightBin (with Compression)
    LightSniff -i eth0 -c 100 --bin-save capture.lbn -C

#### Load and Display LightBin File
    LightSniff --bin-load capture.lbn -v

#### Filter by Protocol (TCP + UDP + ICMP)
    LightSniff -i eth0 --tcp --udp --icmp


## LightSave - Results Exporter v1.0.1

### Overview
LightSave captures the output of any Lightscan command and saves it in a structured format. It supports 8 export formats and is designed for easy integration with reporting pipelines and SIEM systems.

### Features
- Captures output of any Lightscan command
- 8 export formats: LIGHT, TXT, HTML, XML, CSV, JSON, PDF, YAML
- Automated saving with timestamps
- Machine-readable output for automation
- Clean, well-formatted files
- Integrated with LightPanel GUI
- Cross-platform (Windows, Linux, macOS, BSD)

### Command-Line Options
    
    usage: LightSave.py [-h] -C C [-S {txt,light,html,xml,csv,json,pdf,yaml}]
    
    LightSave : Light-Scan Scans Saving Tool
    
    options:
      -h, --help            show this help message and exit
      -C C                  Lightscan command
      -S {txt,light,html,xml,csv,json,pdf,yaml}
                            Saving Format (txt,light,html,xml,csv,json,pdf,yaml)


### Usage Examples

#### Save UDP Scan Results as XML
    LightSave -C "python Lightscan.py -T 127.0.0.1 -F -st UDP" -S xml

#### Save Network Scan as HTML Report
    LightSave -C "python Lightscan.py -T 192.168.1.0/24 -s fast" -S html

#### Save Scan Results as JSON for Automation
    LightSave -C "python Lightscan.py -T scanme.nmap.org -p 22,80,443" -S json

#### Save OS and Banner Grab Results as PDF
    LightSave -C "python Lightscan.py -T 192.168.1.100 -O -b" -S pdf


## LightPanel - Graphical Interface v1.0.1

### Overview
LightPanel is a basic graphical user interface for Lightscan. It provides a visual alternative to the command-line, making the toolkit accessible to users who prefer a point-and-click experience.

### Features
- basic graphical interface for Lightscan
- Integrated LightSave functionality
- Cross-platform (Windows, Linux, macOS, BSD)
- Dark theme optimized for long sessions
- Intuitive target and port specification
- Real-time scan progress
- Export results with one click
- Built-in help and documentation

### Launch

    python LightPanel.py


## LightLab - Packet Crafting Laboratory v1.0.0

### Overview
LightLab is an interactive packet crafting laboratory that allows users to build custom packets from scratch using a simple command-line interface. It supports all major protocol layers and includes built-in templates.

### Features
- Build packets from scratch using the new command
- Set parameters using set command
- View packet structure with show
- Send packets with send (with count and verbose)
- Save and load PCAP/PCAPNG/LBN files
- Built-in templates for common operations
- Support for: ether, vlan, arp, ip, ipv6, tcp, udp, icmp, ndp, http, dns, raw
- Interactive shell with command history
- Cross-platform (Windows, Linux, macOS, BSD)

### Commands

| Command | Description |
|---------|-------------|
| new <layer> | Add layer (ether, vlan, arp, ip, ipv6, tcp, udp, icmp, ndp, http, dns, raw) |
| delete <layer> | Delete a layer |
| params <layer> | Show available parameters for a layer |
| set <layer>.<param>=<value> | Set parameter value |
| show | Show current packet structure |
| clear | Clear all layers |
| send [count] [-v] | Send packet |
| timeout <seconds> | Set response timeout |
| interval <seconds> | Set interval time between packets |
| templates | Show example configurations |
| save <filename> | Save to PCAP/PCAPNG |
| load <filename> | Load from PCAP/PCAPNG |
| savebin <filename> | Save to LightBin |
| loadbin <filename> | Load from LightBin |
| history | Show command history |
| help | Show this message |
| exit | Quit LightLab |

### Usage Examples

#### TCP SYN Scan Packet

    LightLab> new ip
    LightLab> set ip.dst=192.168.1.1
    LightLab> new tcp
    LightLab> set tcp.dport=80
    LightLab> set tcp.flags=S
    LightLab> send -v

#### UDP DNS Query

    LightLab> new ip
    LightLab> set ip.dst=8.8.8.8
    LightLab> new udp
    LightLab> set udp.dport=53
    LightLab> new dns
    LightLab> set dns.id=1234
    LightLab> set dns.rd=1
    LightLab> set dns.qd=DNSQR(qname="google.com", qtype=1)
    LightLab> send -v

#### HTTP GET Request

    LightLab> new ip
    LightLab> set ip.dst=example.com
    LightLab> new tcp
    LightLab> set tcp.dport=80
    LightLab> new http
    LightLab> set http.Method=GET
    LightLab> set http.Path=/
    LightLab> set http.Host=example.com
    LightLab> send -v

#### ICMP Ping

    LightLab> new ip
    LightLab> set ip.dst=192.168.1.1
    LightLab> new icmp
    LightLab> set icmp.type=8
    LightLab> set icmp.id=1234
    LightLab> set icmp.seq=1
    LightLab> send -v

#### ARP Request

    LightLab> new ether
    LightLab> set ether.dst=ff:ff:ff:ff:ff:ff
    LightLab> new arp
    LightLab> set arp.pdst=192.168.1.1
    LightLab> send -v

#### VLAN Tagged Packet

    LightLab> new vlan
    LightLab> set vlan.vlan=100
    LightLab> set vlan.prio=5
    LightLab> new ip
    LightLab> set ip.dst=192.168.1.1
    LightLab> new icmp
    LightLab> send -v

## LightBin - Custom Binary Format v1.0
![](image/LightBin.ico)

### Overview
LightBin is Light-Scan's native binary packet format (.lbn). It is designed for fast loading and rich metadata storage, making it ideal for large packet captures and automated analysis.

### Features
- 1.2-2x faster loading than PCAP
- Rich metadata (args, stats, tool, packet_types, timestamps)
- zlib compression for packet data and metadata
- CRC32 checksum for header integrity
- Smart packet detection (Ethernet, VLAN, IPv4, IPv6, ARP, raw)
- Cross-platform (Windows, Linux, macOS, BSD)
- Backward-compatible versioning
- Extensible flags system

### File Structure

Header (24 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-3 | 4 | Magic | LBNx00 - Identifies LightBin format |
| 4-7 | 4 | Version | 1 - Current format version |
| 8-11 | 4 | Created | Unix timestamp (creation time) |
| 12-15 | 4 | Packet Count | Number of packets in file |
| 16-19 | 4 | Flags | Bitmask: 0x01 (Compressed), 0x02 (Metadata) |
| 20-23 | 4 | Checksum | CRC32 of version, created, count, and flags |

Packet Header (12 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-7 | 8 | Timestamp | Packet capture time (double precision float) |
| 8-11 | 4 | Size | Packet size in bytes (unsigned integer) |

Packet Data (Size bytes)
Raw packet bytes as captured from the network.

### Comparison with PCAP

| Feature | LightBin | PCAP |
|---------|----------|------|
| Load Speed | Faster (1.2-2x) | Slower |
| Metadata Support | Rich (Args, Stats, Types) | Limited |
| Compression | zlib (Full) | PCAP-NG Only |
| Checksum | CRC32 (Header) | None |
| Packet Detection | Auto-detects | Manual parsing |
| Cross-Platform | Yes | Yes |
| File Size | 1-6% Larger | Smaller |
| Standardization | Light-Scan Native | Industry Standard |
| Tool Support | LightSniff, LightLab | Wireshark, tcpdump |

## LSSE - Light-Scan Scripting Engine v1.0.6

### Overview
LSSE (Light-Scan Scripting Engine) extends the core scanner's capabilities with 13 built-in scripts for web and DNS reconnaissance, security analysis, and information gathering.

### Features
- 13 built-in scripts for web and DNS reconnaissance
- HTTP/HTTPS and DNS support
- Extensible architecture
- Wordlist support
- Custom extensions and status codes
- Redirect handling
- Cross-platform (Windows, Linux, macOS, BSD)

### HTTP/HTTPS Scripts

| Script | Category | Required Args | Description |
|--------|----------|---------------|-------------|
| spider | safe/discovery | --url | Recursively crawls websites for links and forms |
| http-robots | safe/discovery | --domain, -sp | Fetches and parses robots.txt |
| http-cert | safe/analysis | --domain, -sp | Grabs SSL/TLS certificate information |
| script | safe/discovery | --url | Detects Script tags in HTML pages |
| http-title | safe/discovery | --domain, -sp | Extracts webpage titles |
| http-dir | medium/discovery | --url | Brute forces directories and files |
| http-headers | safe/analysis | --domain, -sp | Security headers analysis |
| http-methods | safe/discovery | --domain, -sp | Checks allowed HTTP methods |
| http-cookie | safe/analysis | --domain, -sp | Checks cookies for Secure and HttpOnly flags |

### DNS Scripts

| Script | Category | Required Args | Description |
|--------|----------|---------------|-------------|
| dns-lookup | safe/discovery | --domain | Fast DNS lookup for IPv4, IPv6 |
| dns-ns | safe/discovery | --domain | Get Name-Server (NS) records |
| dns-subdomain-fuzzing | medium/discovery | --domain | Brute forces subdomains |
| dns-zone-transfer | medium/extracting | --domain | Attempts AXFR zone transfer |

### Command-Line Options

    C:\Users\Heretic>Lightscan --lsse-lst
        __    _       __    __
       / /   (_)___ _/ /_  / /_______________ _____
      / /   / / __ `/ __ \/ __/ ___/ ___/ __ `/ __ \
     / /___/ / /_/ / / / / /_(__  ) /__/ /_/ / / / /
    /_____/_/\__, /_/ /_/\__/____/\___/\__,_/_/ /_/
            /____/
    
    Version : 1.1.7
    Platform : Windows
    
    
    [+] LSSE Scripts (LightScan Scripting Engine)
    --------------------------------------------------
    
    [1] spider
        Required:   --url
        Optional:   --mxd, --mxp
        Category:   safe/discovery/http_https
        Description: Recursively crawls websites for links, forms, and resources
    
    [2] http-robots
        Required:   --domain, -sp
        Optional:   None
        Category:   safe/discovery/http_https
        Description: Fetches and parses robots.txt for hidden paths
    
    [3] http-cert
        Required:   --domain, -sp
        Optional:   None
        Category:   safe/analysis/https
        Description: Grabs SSL/TLS certificate information
    
    [4] script
        Required:   --url
        Optional:   None
        Category:   safe/discovery/http_https
        Description: Detects Script tags in HTML pages
    
    [5] http-title
        Required:   --domain, -sp
        Optional:   --redirect
        Category:   safe/discovery/http_https
        Description: Extracts webpage titles
    
    [6] http-dir
        Required:   --url
        Optional:   --wordlist, --status-codes, --extensions
        Category:   medium/discovery/http_https
        Description: Brute forces directories and files
    
    [7] dns-subdomain-fuzzing
        Required:   --domain
        Optional:   --wordlist, --dns-server
        Category:   medium/discovery/dns
        Description: Brute forces subdomains using wordlist
    
    [8] dns-lookup
        Required:   --domain
        Optional:   --dns-server
        Category:   safe/discovery/dns
        Description: Do fast dns-lookup for IPv4 ,IPv6 address
    
    [9] dns-ns
        Required:   --domain
        Optional:   --dns-server
        Category:   safe/discovery/dns
        Description: Get Name-Server (NS) Record of a domain
    
    [10] dns-zone-transfer
        Required:   --domain
        Optional:   --dns-server
        Category:   medium/extracting/dns
        Description: Attempts AXFR zone transfer to enumerate all DNS records
    
    [11] http-headers
        Required:   --domain, -sp
        Optional:   --redirect
        Category:   safe/analysis/http_https
        Description: Fetches HTTP headers and checks for missing security headers
    
    [12] http-methods
        Required:   --domain, -sp
        Optional:   None
        Category:   safe/discovery/http_https
        Description: Checks which HTTP methods are allowed by the server
    
    [13] http-cookie
        Required:   --domain, -sp
        Optional:   --redirect
        Category:   safe/analysis/http_https
        Description: Checks cookies for Secure and HttpOnly flags
    
    --------------------------------------------------
    [+] Usage: Lightscan --lsse --script <name>

## Performance Tips
  
Use -F for large networks: Scan top 100 ports instead of top 1000
  
Adjust timeout: Reduce timeout for internal networks (-tm 1.5)
  
Increase threads: Use more threads for faster scanning (-t 100)
  
Reduce retries: Use --max-retries 1 for reliable networks
  
Choose appropriate scan type: SYN for speed, TCP for reliability
  
# Troubleshooting
  
  ## Scan is too slow
  
Reduce timeout: -tm 1.0
  
Increase threads: -t 150
  
Use faster speed preset: -s fast
  
  ## No results from UDP scan
  
UDP is connectionless - timeouts are normal
  
Increase retries: --max-retries 3
  
Check if service is actually running
  
  ## Host discovery missing hosts
  
Some hosts block ICMP
  
Use TCP-based discovery by using -Pt Flag
  
Check firewall rules on target hosts
  
# Legal Disclaimer
  
  ## This tool is intended for:
  
Security professionals conducting authorized assessments
  
Network administrators monitoring their own networks
  
Educational and research purposes
  
  Always ensure you have proper authorization before scanning any network or system. Unauthorized scanning may be illegal in your jurisdiction.
  Contributing
  
  Contributions are welcome! Please feel free to submit pull requests, report bugs, or suggest new features.


##  FDD Scan — Firewall Detection

**FDD (Firewall Detection Scan)** is a proprietary scanning technique developed exclusively for LightScan. It sends a TCP packet with the **URGENT (URG) flag** to determine whether a firewall is protecting the target port.
The URG flag is rarely used in legitimate traffic, making it an excellent probe for firewall detection. By analyzing the response (or lack thereof), LightScan can determine if a firewall is actively filtering the port.

###  Response Interpretation

| Response Type | Classification | Explanation |
|---------------|----------------|-------------|
| `RST` or `RST-ACK` |  **Undefended Port** | The port responded directly — no firewall interference |
| `No Response` |  **Defended Port** | No response suggests a firewall is blocking the probe |
| `ICMP Type 3, Code 1,2,3,9,10,13` |  **Defended Port** | ICMP error indicates a firewall is actively rejecting the packet |

###  Example Usage

# Run FDD scan on a single port
    python Lightscan.py -T 192.168.1.1 -p 443 -st FDD

# Scan multiple ports with FDD
    python Lightscan.py -T 192.168.1.1 -p 22,80,443,8080 -st FDD

# Combined with verbose output
    python Lightscan.py -T 192.168.1.1 -p 1-1000 -st FDD -v


## 🙏 Acknowledgments

### Light-Scan is built on the shoulders of giants. We thank the open‑source community, especially to:

-  Scapy — The packet manipulation library that powers Light-Scan

-  Python — The language that makes it all possible

-  Nmap — For setting the standard in network scanning

-  The entire cybersecurity community — For pushing the boundaries of what's possible

**📧 Contact:** lightscanframework@gmail.com 
