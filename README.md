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
Multiple scan types: TCP Connect, SYN Stealth, UDP, NULL, FIN, ACK, WINDOW, MAIMON, FDD, XMAS, FTP-BOUNCE,IPPROTO,PING,IDLE,SCTP-INIT

Configurable speed presets from Paranoid to Light-mode (500 threads) and manual thread and timeout modification

Smart host discovery with threaded ICMP/ICMPv6/TCP/IP/ARP/NDP/IGMP detection

## Network Range Support

CIDR notation (/8, /16, /24, etc.) for subnet scanning

Multiple target support via comma-separated lists

Octet ranges (192.168.1.0-100)

Intelligent host filtering - skips non-responsive hosts in network scans

Safety warnings for large network ranges

## Advanced Detection

Service detection with custom and system service databases

Firewall detection with detailed analysis

Port state classification: Open, Closed, Filtered, Unfiltered, Open|Filtered, Defended, Undefended

Retry mechanism for unreliable networks

## Professional Features

Flexible port specification: ranges, lists, and top ports

Verbose output for debugging and analysis

Customizable timeouts and thread counts

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



**📧 Contact:** lightscanframework@gmail.com
