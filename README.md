
# Light-Scan Framework Documentation

![Python](https://img.shields.io/badge/python-3.13-blue?logo=python&logoColor=white)
![OS](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20macOS%20|%20BSD-2d2d2d?style=for-the-badge&logo=linux&logoColor=white)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![Open Source](https://img.shields.io/badge/Open%20Source-❤️-green)](https://opensource.org/)
[![OSI Approved](https://img.shields.io/badge/OSI-Approved-3c9f3c?logo=opensourceinitiative)](https://opensource.org/licenses/gpl-2.0.php)

![](images/Light-Scan-Logo.png)

---

## Table of Contents

1. Overview
2. Installation
3. Lightscan - Network Port Scanner
4. LightSniff - Packet Capture Tool
5. Mint - Attack Utility
6. LightPanel - GUI Interface
7. License

---

## 1. Overview

Light-Scan Framework is a comprehensive network security scanning suite developed by Adam Boulaaz. It provides a complete toolkit for network reconnaissance, packet analysis, and security testing with both CLI and GUI interfaces.

### Framework Components

| Tool | Description | Version |
|------|-------------|---------|
| Lightscan | Advanced network port scanner with 15+ scan types | 1.1.9 |
| LightSniff | Packet capture and analysis tool | 1.0.3 |
| Mint | Network attack utility (SYN flood, MAC flood) | 1.0.1 |
| LightPanel | Cross-platform GUI interface for Lightscan | 1.0.1 (Posix) / 1.0.3 (Windows) |

---

## 2. Installation

### Prerequisites

```bash
# Python 3.8+ required
python3 --version

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Directory Structure

```
Light-Scan/
├── Lightscan.py          # Main scanner (v1.1.9)
├── LightSniff.py         # Packet capture (v1.0.3)
├── Mint.py               # Attack utility (v1.0.0)
├── LightPanel.py         # GUI launcher
├── LightPanelLin.py      # Linux GUI (v1.0.1)
├── LightPanelWin.py      # Windows GUI (v1.0.3)
└── ....
```

---

## 3. Lightscan - Network Port Scanner

**Version: 1.1.9**

### Overview

Lightscan is a comprehensive network scanner supporting multiple scan types, OS fingerprinting, banner grabbing, and extensive output formats. It's designed as a complete alternative to tools like Nmap with additional features.

### Key Features

- 15+ Scan Types (TCP, SYN, UDP, NULL, FIN, ACK, XMAS, WINDOW, MAIMON, FDD, FTP-BOUNCE, IPPROTO, IDLE, SCTP-INIT, PING)
- 10+ Ping Methods (ARP, TCP, SYN, ACK, UDP, ICMP variants, IGMP)
- OS Fingerprinting with configurable confidence scores
- Banner Grabbing for service detection
- Scripting Engine (LSSE) for extensible functionality
- 10 Output Formats (txt, light, html, xml, csv, json, pdf, yaml, toml, hex-str)
- Profile System for saving/loading scan configurations
- IPv6 Support with full feature parity
- Stealth Options (fragmentation, TTL manipulation, source port spoofing)
- Performance Tuning (threads, timeouts, rate limiting)
- Firewall Assessment with optional disable flag
- Daemon Mode for background operation

### Usage

```bash
sudo python Lightscan.py [options]
```

### Basic Examples

```bash
# Basic SYN scan
sudo python Lightscan.py -T 192.168.1.1 -p 1-1000 -st SYN -s normal

# Aggressive full scan
sudo python Lightscan.py -T example.com -A

# OS detection with banner grabbing
sudo python Lightscan.py -T 10.0.0.1 -O -b -s slow

# Scan from file with stealth
sudo python Lightscan.py --rff targets.txt -p 80,443,8080 -s paranoid -f

# IPv6 scan with specific output
sudo python Lightscan.py -T 2001:db8::1 -V6 -p 1-100 -st TCP --save json

# Run LSSE script
sudo python Lightscan.py --lsse --script http-cert --url https://example.com

# Load and save profiles
sudo python Lightscan.py --load-profile my_scan --save-profile my_results

# Daemon mode (background task)
sudo python Lightscan.py -T 192.168.1.1 -p 1-1000 --daemon
```

### Command Reference

#### Target Specification

| Option | Description | Example |
|--------|-------------|---------|
| -T TARGET | Target IP or hostname | -T 192.168.1.1 |
| --rff RFF | Read targets from file | --rff targets.txt |
| -V6 | IPv6 mode | -V6 |
| --daemon | Run as background task | --daemon |

#### Port Specification

| Option | Description | Example |
|--------|-------------|---------|
| -p PORT | Ports to scan | -p 80,443 or -p 1-1000 |
| -F | Scan top 100 ports | -F |
| --shuffle | Randomize port order | --shuffle |
| -pp PING_PORT | Ports for ping | -pp 80,443 |

#### Scan Types

| Option | Description | Use Case |
|--------|-------------|----------|
| TCP | TCP connect scan | Standard scanning |
| SYN | SYN stealth scan | Stealth scanning |
| UDP | UDP scan | UDP services |
| NULL | NULL scan | Firewall evasion |
| FIN | FIN scan | Firewall evasion |
| ACK | ACK scan | Firewall detection |
| XMAS | XMAS scan | Firewall evasion |
| WINDOW | WINDOW scan | Firewall detection |
| MAIMON | MAIMON scan | Firewall evasion |
| FDD | FDD scan | Firewall detection with URG flag |
| FTP-BOUNCE | FTP bounce scan | Proxy scanning |
| IPPROTO | IP protocol scan | Protocol discovery |
| IDLE | Idle/zombie scan | Advanced stealth |
| PING | Ping sweep | Host discovery |
| SCTP-INIT | SCTP scan | SCTP services |

#### Speed Presets

| Preset | Threads | Timeout | Use Case |
|--------|---------|---------|----------|
| paranoid | 2 | 4.5s | Extreme stealth/IDS evasion |
| slow | 30 | 3.3s | Careful scanning |
| normal | 60 | 2.8s | Balanced default |
| fast | 120 | 2.8s | Production scans |
| insane | 240 | 1.5s | Aggressive scanning |
| light-mode | 400 | 1.5s | Maximum speed |

#### Ping Methods

| Option | Description |
|--------|-------------|
| -sn | Host discovery only (no port scan) |
| -Pn | Disable ping |
| -Pan | ARP/NDP ping (local networks) |
| -Pt | TCP ping |
| -Ps | SYN ping |
| -Pk | ACK ping |
| -Pu | UDP ping |
| -Pi | IP protocol ping |
| -Pip | Specify IP protocols for -Pi |
| -PIt | ICMP timestamp ping |
| -PA | ICMP address ping |
| -Pin | ICMP information ping |
| -Pas | ICMP solicitation ping |
| -Pg | IGMP ping |

#### OS and Service Detection

| Option | Description | Example |
|--------|-------------|---------|
| -O | OS fingerprinting | -O |
| --min-score SCORE | Minimum OS fingerprint score | --min-score 85 |
| --min-confi SCORE | Minimum OS confidence score | --min-confi 70 |
| -b | Banner grabbing | -b |
| -A | Aggressive mode (OS + Banner + SYN + Top100 + Insane) | -A |

#### Stealth and Evasion

| Option | Description | Example |
|--------|-------------|---------|
| -f | Fragment packets | -f |
| --zombie ZOMBIE | Zombie IP for idle scan | --zombie 10.0.0.5 |
| --ftp-bounce SERVER | FTP server for bounce scan | --ftp-bounce 10.0.0.5 |
| -ttl TTL | IPv4 Time To Live | -ttl 128 |
| -hlim HLIM | IPv6 Hop Limit | -hlim 64 |
| -sport SPORT | Source port | -sport 31337 |
| -id ID | IPv4 ID field | -id 31337 |
| -ip-flags FLAGS | IPv4 flags (DF=2, MF=1, None=0) | -ip-flags 2 |
| -payload PAYLOAD | Custom payload | -payload "GET / HTTP/1.0" |
| --no-firewall-ase | Disable firewall assessment | --no-firewall-ase |

#### Performance Options

| Option | Description | Example |
|--------|-------------|---------|
| -t THREADS | Number of threads | -t 100 |
| -tm TIMEOUT | Timeout in seconds | -tm 5 |
| -mx RETRIES | Maximum retries | -mx 3 |
| --interval DELAY | Delay between packets (ms) | --interval 100 |
| -Rc | Recursively scan down hosts | -Rc |

#### Output and Logging

| Option | Description | Example |
|--------|-------------|---------|
| --save FORMAT | Save output format | --save json |
| -v | Verbose output | -v |
| -q | Quiet mode (hide banner) | -q |
| -n | Disable reverse DNS | -n |

**Supported Output Formats:**
- txt - Plain text
- light - Lightscan native format
- html - HTML report
- xml - XML data
- csv - Comma-separated values
- json - JSON data
- pdf - PDF report
- yaml - YAML data
- toml - TOML data
- hex-str - Hex string format

#### LSSE Scripting Engine

The LightScan Scripting Engine (LSSE) allows extensible scanning functionality.

| Option | Description | Example |
|--------|-------------|---------|
| --lsse | Run only scripts (no scan) | --lsse |
| --script SCRIPT | Run specific script | --script http-cert |
| --lsse-lst | List available scripts | --lsse-lst |
| --url URL | Target URL | --url https://example.com |
| --domain DOMAIN | Domain for HTTP/DNS scripts | --domain example.com |
| --dns-server SERVER | DNS server | --dns-server 8.8.8.8 |
| -W WORDLIST | Wordlist for scripts | -W wordlist.txt |
| --extensions EXTS | Web script extensions | --extensions php,html,asp |
| --status-codes CODES | Status codes to check | --status-codes 200,301,302 |
| --redirect | Follow HTTP redirects | --redirect |
| --mxp MXP | Max pages to get | --mxp 50 |
| --mxd MXD | Max depth to crawl | --mxd 3 |
| -sp SP | Ports for scripts | -sp 80,443 |
| --starget STARGET | Targets for scripts | --starget example.com |
| --username USERNAME | Single username | --username admin |
| --password PASSWORD | Single password | --password pass123 |
| --userlist USERLIST | Username list file | --userlist users.txt |
| --passwordlist PASSWORDLIST | Password list file | --passwordlist passwords.txt |

#### Utility Options

| Option | Description |
|--------|-------------|
| -h, --help | Show help message |
| -V, --version | Show version with all additional tools |
| -lst | List all targets |
| --port-lst | List all ports to be scanned |
| --profiles-lst | List all scan profiles |
| --load-profile PROFILE | Load scan profile from Profiles/ directory |
| --save-profile PROFILE | Save scan profile to Profiles/ directory |

---

## 4. LightSniff - Packet Capture Tool

**Version: 1.0.3**

### Overview

LightSniff is a powerful packet capture and analysis tool that supports multiple input/output formats and filtering capabilities. It can capture live traffic, read from PCAP files, and process custom binary and hexadecimal formats.

### Usage

```bash
sudo python LightSniff.py [options]
```

### Basic Examples

```bash
# Capture live traffic on interface
sudo python LightSniff.py -i eth0

# Capture with BPF filter
sudo python LightSniff.py -i eth0 -f 'tcp port 80' -w http.pcap

# Limit capture count
sudo python LightSniff.py -i Wi-Fi -c 100 -v

# Read from PCAP file
sudo python LightSniff.py -r capture.pcap

# Read from LightBin format
sudo python LightSniff.py --bin-load capture.lbn

# Show available interfaces
sudo python LightSniff.py -I
```

### Command Reference

#### Interface Options

| Option | Description | Example |
|--------|-------------|---------|
| -i INTERFACE | Network interface | -i eth0 |
| -I | Show available interfaces | -I |
| --no-promisc | Disable promiscuous mode | --no-promisc |

#### Capture Options

| Option | Description | Example |
|--------|-------------|---------|
| -f FILTER | BPF filter | -f 'tcp port 80' |
| -c COUNT | Number of packets to capture | -c 100 |
| --mac MAC | Filter by MAC address | --mac aa:bb:cc:dd:ee:ff |

#### Output Formats

| Option | Description | File Extension |
|--------|-------------|----------------|
| -w WRITE | Save to PCAP/PCAPNG file | .pcap |
| --bin-save SAVE | Save to LightBin binary format | .lbn |
| --hex-save SAVE | Save to hexadecimal format | .lhex |
| -C | Compress saved output (only .lbn) | -C |

#### Input Formats

| Option | Description | File Extension |
|--------|-------------|----------------|
| -r READ | Read from PCAP/PCAPNG file | .pcap |
| --bin-load LOAD | Load from LightBin format | .lbn |
| --hex-load LOAD | Load from hexadecimal format | .lhex |

#### Display Options

| Option | Description |
|--------|-------------|
| -v | Show detailed packet info |
| -q | Quiet mode (no banner) |
| --eth | Show Ethernet frame info (MAC addresses, frame type) |
| --vlan | Show VLAN tags (802.1Q) |
| --arp | Show only ARP packets |
| --tcp | Show only TCP packets |
| --udp | Show only UDP packets |
| --icmp | Show only ICMP packets |
| --igmp | Show only IGMP packets |
| --ipv4 | Show only IPv4 packets |
| --ipv6 | Show only IPv6 packets |
| --sctp | Show only SCTP packets |
| --icmpv6 | Show only ICMPv6 packets |

### Example Scenarios

**Capture HTTP traffic:**
```bash
sudo python LightSniff.py -i eth0 -f 'tcp port 80' -c 50 -v
```

**Save and compress captured traffic:**
```bash
sudo python LightSniff.py -i wlan0 -c 1000 --bin-save capture.lbn -C
```

**Analyze previously captured traffic:**
```bash
python LightSniff.py --bin-load capture.lbn --tcp --verbose
```

**Filter by specific MAC address:**
```bash
sudo python LightSniff.py -i eth0 --mac aa:bb:cc:dd:ee:ff -v
```

---

## 5. Mint - Attack Utility

**Version: 1.0.0**

### Overview

Mint is a lightweight network attack utility designed for security testing and vulnerability assessment. It supports SYN flood and MAC flood attacks for testing network infrastructure resilience.

### Usage

```bash
sudo python Mint.py [options]
```

### Basic Examples

```bash
# SYN flood attack
sudo python Mint.py -T 192.168.1.1 -c 1000 -p 80 --attack-mode syn-flood

# MAC flood attack
sudo python Mint.py -T 192.168.1.1 -c 5000 --attack-mode mac-flood

# SYN flood with source IP hiding
sudo python Mint.py -T 10.0.0.1 -c 10000 -p 80 -hi --attack-mode syn-flood

# Multi-port attack with shuffled order
sudo python Mint.py -T 192.168.1.1 -c 100 -p 80,443,8080 -s --attack-mode syn-flood
```

### Command Reference

| Option | Description | Example |
|--------|-------------|---------|
| -T TARGET | Target IP or hostname | -T 192.168.1.1 |
| -c C | Packet count per port | -c 1000 |
| -p PORT | Ports to attack | -p 80 or -p 80,443,8080 |
| -hi | Hide source IP using random ones | -hi |
| -s | Shuffle ports order | -s |
| --attack-mode MODE | Attack type (syn-flood, mac-flood) | --attack-mode syn-flood |

### Attack Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| syn-flood | SYN flood attack | Test firewall/IDS resilience |
| mac-flood | MAC flood attack | Test switch MAC table security |

### Important Notes

- Both attack modes require root/administrator privileges
- SYN flood attacks send TCP SYN packets to the target
- MAC flood attacks send Ethernet frames with random MAC addresses
- The -hi flag randomizes source IP addresses for SYN floods
- Use responsibly and only on systems you own or have permission to test

---

## 6. LightPanel - GUI Interface

**Version: 1.0.1 (Linux) / 1.0.3 (Windows)**

### Overview

LightPanel provides a graphical user interface for the Light-Scan framework, making it accessible to users who prefer visual tools over command-line interfaces. It supports both Linux and Windows platforms with platform-specific versions.

### Features

- Cross-platform support (Linux and Windows)
- Dark/Light mode switching
- GUI-based command construction
- Real-time output display
- Profile management
- Copy and clear output functions
- Command injection protection

### Usage

**Linux:**
```bash
sudo python LightPanel.py
```

**Windows:**
```bash
python LightPanel.py
```

### Interface Components

#### Command Bar
- **Command Entry**: Manually type or view generated commands
- **Start Scan Button**: Execute the configured scan
- **Copy Output Button**: Copy console output to clipboard
- **Clear Output Button**: Clear the output display

#### Configuration Options
- **Target**: IP or hostname to scan
- **Ports**: Port specification (e.g., 80,443 or 1-1000)
- **Scan Type**: Select from 15 scan types
- **Speed**: Choose from 6 speed presets
- **Profile**: Load or save scan profiles
- **Saving Format**: Select from 10 output formats

#### Toggle Options
- **Top 100 Ports (-F)**: Fast scan mode
- **OS Detect (-O)**: OS fingerprinting
- **Banner Grab (-b)**: Service banner grabbing
- **No Ping (-Pn)**: Skip host discovery
- **IPv6 Target (-V6)**: Enable IPv6 scanning
- **Fragmentation (-f)**: Packet fragmentation
- **Recursively (-Rc)**: Recursive scanning
- **No rDNS (-n)**: Disable reverse DNS
- **Help Menu (-h)**: Show help

#### Output Display
- Console output from Lightscan
- Real-time scan results
- Error messages and warnings
- Copy to clipboard functionality

### Platform-Specific Notes

**Linux:**
- Requires root privileges (sudo)
- Uses venv environment
- Version: 1.0.1

**Windows:**
- No sudo required (administrator may be needed)
- Uses default Python environment
- Version: 1.0.3

### Security Features

The GUI implements command injection protection:
- Blocks shell metacharacters (&, |, :, `, $, >, <)
- Blocks dangerous commands (cd, pwd, netstat, ifconfig, winget, wmic, ls, ping, chdir, mkdir, dir)

---

## 7. License

Light-Scan Framework - Network Security Scanning Framework
Copyright (C) 2026 Adam Boulaaz

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

---

## Additional Resources

- GitHub Repository: [https://github.com/Light-Projects/Light-Scan]
- Issue Tracker: [https://github.com/Light-Projects/Light-Scan/issues]
- Community: [https://discord.gg/AP6HyXmEq]

---

*Light-Scan Framework v1.1.9*
