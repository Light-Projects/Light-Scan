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

"""
LightPanel Quick Help Module
Cross-platform, modular, and descriptive help system
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QWidget, QFrame, QTextEdit, QSplitter, QListWidget, QListWidgetItem
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QShortcut, QKeySequence


class HelpContent:
    BASIC = {
        "title": "Basic Options",
        "icon": "",
        "content": """
Target (-T)
  The target field is where Lightscan expects
  an IP address, hostname, or network chunk to scan.

  Examples: 192.168.1.1, example.com, scanme.nmap.org

Ports (-p)
  The port or ports to scan.
  Single: 80
  List: 80,443,8080
  Range: 1-1000
  Mixed: 80,443-445,8080

Top 100 Ports (-F)
  Scan only the most common 100 ports.
  Faster scan for quick results.

Randomize Ports (--shuffle)
  Scans ports in random order using Fisher Yates shuffle
  algorithm to perform the randomizing process.
  Helps avoid detection by basic firewalls.

Quiet Mode (-q)
  Remove Lightscan banner for more focus
  on the scan result.

IPv6 scan (-V6)
  When this option is entered Lightscan expects
  an IPv6 address as the targeted system.
"""
    }

    SCAN_TYPES = {
        "title": "Scan Types",
        "icon": "",
        "content": """
TCP Connect (-st TCP) :

  TCP 3-way handshake scan is a port scanning technique that 
  completes the entire TCP connection process to determine if a
  host port is open. 
  It works by sending a SYN packet
  to the host port. If the port is open, the host system replies
  with a SYN-ACK then the scanner responds with an ACK packet to
  finalize the connection, then immediately tears it down.

SYN Stealth (-st SYN) :

  SYN scan is a rapid network reconnaissance technique that
  determines if a host port is open without completing 
  the full TCP three-way handshake. The scanner initiates
  the process by sending a SYN packet. If the host port 
  is up, it responds with a SYN-ACK packet, prompting 
  the scanner to immediately abort the connection
  with a RST packet rather than finalizing it with an ACK.

UDP Scan (-st UDP) :

  UDP scan is a connectionless network reconnaissance technique
  used to identify active services running on User Datagram
  Protocol (UDP) ports, which do not utilize a handshake mechanism.
  The scanning system sends a blank or protocol-specific UDP packet
  to a host port. If the port is closed, the host system
  typically replies with an ICMP Destination Unreachable packet,
  whereas no response at all or a UDP reply indicates that the
  port is open or filtered. Highly prone to packet loss,
  making it harder to execute accurately but critical for
  finding hidden services like DNS or DHCP.

NULL Scan (-st NULL) :

  NULL scan is a stateless TCP reconnaissance technique used to
  bypass traditional packet filters by sending a packet with no
  flags set at all inside its header. According to the RFC 793
  standard, if a host port is closed, the operating system
  must respond with a RST packet, whereas if the port is open
  or filtered by a firewall, the system will completely ignore
  the packet and send no response.

FIN Scan (-st FIN) :

  FIN scan is a stealthy TCP reconnaissance technique that
  sends a packet with only the FIN flag turned on to
  determine the status of a host port without initiating
  a proper connection. Based on RFC 793 specifications,
  if the target port is closed, the remote system is
  required to reply with a RST packet, whereas if the port
  is open, the system will completely discard the packet
  and return no response at all.

ACK Scan (-st ACK) :

  ACK scan is a stateless TCP reconnaissance technique
  used exclusively to map out firewall rulesets and
  filtering behaviors rather than determining if a
  port is open or closed. The scanning system sends a
  TCP packet with only the ACK flag set, which looks
  like a response to an established connection that
  never actually existed. Because this packet is out
  of sequence, both open and closed ports will
  respond with a RST packet if they are unprotected,
  indicating to the scanner that the port is unfiltered,
  whereas a lack of response or an ICMP error indicates
  that a firewall or router is actively dropping the
  traffic (filtered).

XMAS Scan (-st XMAS) :

  An Xmas scan (or Christmas tree scan) is a stealthy TCP
  reconnaissance technique that sends a packet with the
  FIN, PSH, and URG flags all turned on simultaneously,
  lighting up the packet header "like a Christmas tree."
  According to RFC 793 standards, this illogical
  combination of flags forces a closed target port to reply
  with a RST packet, whereas an open or filtered port will
  completely ignore the packet and return no response.

WINDOW Scan (-st WINDOW) :

  A Window scan is an advanced TCP reconnaissance technique
  that exploits an implementation quirk in the TCP window
  size reporting of certain operating systems to
  differentiate between open and closed ports, rather than
  just finding filtered ones like an ACK scan. The scanning
  system sends a TCP packet with only the ACK flag set.
  When the target system responds with a mandatory RST
  packet, the scanner analyzes the TCP Window field inside
  that response header. On vulnerable systems, a closed
  port will return a packet with a window size of zero,
  while an open port will return a positive window size.

MAIMON Scan (-st MAIMON) :

  A Maimon scan (named after its discoverer, Uriel Maimon)
  is an advanced stealth TCP reconnaissance technique that
  sends a packet with the FIN and ACK flags set
  simultaneously to probe target ports through a firewall.
  According to the RFC 793 standard, a remote operating
  system should respond to this out-of-sequence packet
  with a RST packet, regardless of whether the port is
  open or closed. However, Uriel Maimon discovered that
  many BSD-derived systems contain an implementation
  quirk where an open port will completely drop the
  packet and return no response, while a closed port will
  reply with a RST.

FDD Scan (-st FDD) :

  FDD (Firewall Detection Scan) is a scanning
  technique developed by Light-Scan. It sends
  a TCP packet with the URGENT flag to determine whether
  a firewall is protecting the target port. The URG flag
  is rarely used in legitimate traffic, making it an
  excellent probe for firewall detection. By analyzing
  the response (or lack thereof), Light-Scan
  can determine if a firewall is actively filtering the port.

FTP Bounce (-st FTP-BOUNCE) :

  FTP bounce scan is a legacy network reconnaissance
  technique that exploits a vulnerability in the File
  Transfer Protocol specifically the PORT command to
  route port scanning traffic through a proxy FTP
  server. The scanner connects to a vulnerable FTP
  server and uses the PORT command to trick it into
  opening a data connection to a completely different
  target machine and port, rather than sending the
  file back to the scanner. If the file transfer
  succeeds, the target port is open; if it fails with
  a connection error, the port is closed.

IPPROTO (-st IPPROTO) :

  IP protocol scan is a network reconnaissance
  technique used to determine which IP protocols
  (such as ICMP, TCP, UDP, or IGMP) are actively
  supported by a target host, rather than scanning
  for specific port numbers. The scanning system
  iterates through the 8-bit IP protocol field
  (values 0–255) in the IP header, sending raw,
  empty IP packets for each protocol directly to
  the target system. If the target responds with
  an ICMP Protocol Unreachable, the protocol is
  confirmed as closed; if it responds with a
  packet using that specific protocol, it is open;
  while a complete lack of response typically
  indicates that the protocol is either open
  or actively blocked by a firewall (filtered).

IDLE (-st IDLE) :

  Idle scan is a highly stealthy, blind TCP port
  scanning technique that allows an attacker to
  scan a target without ever sending a packet
  from their own IP address. The scanner
  exploits a predictable pattern in the IP
  Sequence ID (IPID) numbers generated by an
  innocent third-party machine, known as the
  "zombie." The scanner first checks the
  zombie's current IPID, then sends a forged
  SYN packet to the target host while spoofing
  the zombie's IP address. If the target port is
  open, the target sends a SYN-ACK to the zombie,
  forcing the zombie to reply with a RST and
  increment its IPID; if the port is closed,
  the target sends a RST, causing the zombie to
  ignore it and keep its IPID unchanged.

PING Sweep (-st PING) :

  By definition, Ping Sweep is not actually a
  scanning technique but rather a host discovery
  method to discover live devices inside a
  network using multiple pinging techniques like
  ICMP Echo, TCP Ping, ICMP Timestamp, etc.

SCTP-INIT (-st SCTP-INIT) :

  SCTP INIT scan is a specialized network
  reconnaissance technique used to determine if
  ports running the Stream Control Transmission Protocol
  are open, functioning as the SCTP equivalent of a
  stealthy TCP SYN scan. The scanning system initiates
  the probe by sending an INIT chunk to a target port.
  If the port is open, the target responds with an
  INIT-ACK chunk, prompting the scanner to immediately
  drop the connection by sending an ABORT chunk instead
  of completing the 4-way handshake. If the port is
  closed, the target responds directly with an ABORT
  chunk, whereas a lack of response or an ICMP
  unreachable indicates that the port is being
  filtered by a firewall.
"""
    }

    SPEED = {
        "title": "Speed Presets",
        "icon": "",
        "content": """
Paranoid
  2 threads, 4.5s timeout.
  Maximum stealth.
  Slowest but hardest to detect.

Slow
  30 threads, 3.3s timeout.
  Careful scanning.
  Minimal network disruption.

Normal
  60 threads, 2.8s timeout.
  Balanced default.
  Good for most scans.

Fast
  120 threads, 2.8s timeout.
  Production scanning.
  Good for internal networks.

Insane
  240 threads, 1.5s timeout.
  Aggressive scanning.
  Fastest but more detectable.

Light-mode
  400 threads, 1.5s timeout.
  Maximum speed.
  Least stealthy.
"""
    }

    ADVANCED = {
        "title": "Advanced Options",
        "icon": "",
        "content": """
OS Detection (-O)
  Identifies operating system using
  TCP/IP stack, UDP and ICMP stacks fingerprinting to
  determine the OS running on a specific host. Also uses
  service banners to determine that as well.

Disable Firewall Assessment (--no-firewall-ase)
  Disable firewall assessment when performance and speed
  are more important than analysis.

Banner Grabbing (-b)
  Captures service banners by specific probes for
  every service and extracts the exact version number
  and service name from it. Required for
  accurate OS detection.

Aggressive Mode (-A)
  Enables all at once:
  • OS Detection
  • Banner Grabbing
  • SYN Scan
  • Top 100 Ports
  • Insane Speed

Host Discovery
  Find live hosts before scanning.
  -sn: Discovery only, no scan.
  -Pn: Skip discovery.
"""
    }

    HOSTDISCOVERY = {
        "title": "Host Discovery",
        "icon": "",
        "content": """
IP Protocol Ping (-Pi) :

  IP protocol ping is a network reconnaissance
  technique used to determine which IP protocols
  (such as ICMP, TCP, UDP, or IGMP) are actively
  supported and up by a target host, rather than scanning
  for specific port numbers. The scanning system
  iterates through the 8-bit IP protocol field
  (values 0–255) in the IP header, sending raw,
  empty IP packets for each protocol directly to
  the target system. Any response from the host
  system is considered a sign that the machine is up.

  -> IP Protocols (-Pip) :

    Is a list of numbers of IP protocols that
    Light-Scan is going to perform a host
    discovery phase on using IP protocols Ping.

TCP Ping (-Pt) :

  TCP 3-way handshake ping is a host discovery technique
  that completes the entire TCP connection process to determine if a
  host is up. It works by sending a SYN packet
  to the host ports. If one of the ports is open, the host system replies
  with a SYN-ACK then the scanner responds with an ACK packet to
  finalize the connection, then immediately tears it down.

SYN Ping (-Ps) :

  SYN ping is a rapid network reconnaissance technique that
  determines if a host is up without completing the full TCP
  3-way handshake. The scanner initiates the process by sending
  a SYN packet. If the host port is up, it responds with a SYN-ACK
  packet, prompting the scanner to immediately abort the connection
  with a RST packet rather than finalizing it with an ACK.

ACK Ping (-Pk) :

  ACK ping is a stateless TCP reconnaissance technique
  used to determine if a host is alive by sending an ACK
  packet without a connection actually existing.
  Because this packet is out
  of sequence, both open and closed ports will
  respond with a RST packet if they are unprotected,
  indicating to the scanner that the port is unfiltered,
  whereas a lack of response or an ICMP error indicates
  that a firewall or router is actively dropping the
  traffic.

UDP Ping (-Pu) :

  UDP ping is a connectionless network reconnaissance technique
  used to identify active hosts running on User Datagram
  Protocol (UDP) ports, which do not utilize a handshake mechanism.
  The scanning system sends a blank or protocol-specific UDP packet
  to a host port. If the port is closed, the host system
  typically replies with an ICMP Destination Unreachable packet,
  whereas no response at all or a UDP reply indicates that the
  port is open or filtered.

ICMP Timestamp (-PIt) :

  ICMP Timestamp Ping scan is a network reconnaissance technique
  that utilizes a specialized ICMP query to verify if a target host
  is active while simultaneously gathering system time data.
  Instead of sending a standard ping (ICMP Echo), the scanner
  transmits an ICMP Type 13 (Timestamp) packet, prompting the
  remote host to reply with an ICMP Type 14 (Timestamp Reply)
  packet containing its current local system time.

ICMP Address (-PA) :

  ICMP Address Mask Ping scan is a network reconnaissance technique
  that sends a specialized query to verify if a target host is
  active while attempting to discover its subnet mask. Instead of
  a standard echo request, the scanning system transmits an ICMP
  Type 17 (Address Mask) packet, prompting the remote
  host to reply with an ICMP Type 18 (Address Mask Reply)
  containing its local subnet configuration.

ICMP Information (-Pin) :

  ICMP Information Ping scan is a legacy network reconnaissance
  technique designed to verify if a target host is active while
  attempting to discover its network configuration automatically.
  Instead of a standard echo request, the scanning system
  transmits an ICMP Type 15 (Information) packet,
  prompting a remote host to reply with an ICMP Type 16
  (Information Reply) packet.

ICMP Solicitation (-Pas) :

  ICMP Router Solicitation Ping scan is a network reconnaissance
  technique that utilizes routing protocol discovery messages to
  verify if a target host or router is active while mapping local
  gateway infrastructure. The scanning system transmits an ICMP
  Type 10 (Router Solicitation) packet, prompting any active
  listening routers on the local segment to respond with an
  ICMP Type 9 (Router Advertisement) packet detailing their
  available routing configurations.

IGMP Ping (-Pg) :

  IGMP Ping scan is an advanced network reconnaissance technique
  used to discover active hosts and multicast capable devices
  within a local network segment by exploiting the Internet
  Group Management Protocol. The scanning system transmits an
  IGMP Membership Query packet (Type 0x11 General Query) to
  the local subnet or the multicast group address (224.0.0.1).
  Active hosts that participate in multicast streaming or
  protocol routing are forced to respond with an IGMP Membership
  Report to declare their active group subscriptions, thereby
  confirming their online status to the scanner.
"""
    }

    STEALTH = {
        "title": "Stealth & Evasion",
        "icon": "",
        "content": """
Fragmentation (-f)
  Splits packets into pieces.
  Evades IDS/IPS systems.

TTL/HLIM Manipulation
  -ttl: IPv4 Time To Live.
  -hlim: IPv6 Hop Limit.
  Lower values hide your location.

Source Port (-sport)
  Spoof the source port.
  Can bypass port-based filters.

IP Flags (-ip-flags)
  DF: Don't Fragment (2).
  MF: More Fragments (1).
  None (0).

IP ID (-id)
  Send Custom IP packet with a specific IP ID.

Custom Payload (-payload)
  Send custom data in packets.

Random Payload (-payload-length)
  Send random data in packets based on length.

Zombie Scan
  --zombie IP required.
  Uses idle host as proxy.
  Completely stealthy.

FTP Bounce
  --ftp-bounce SERVER.
  Uses FTP server as proxy.
  Hides your true source.
"""
    }

    PERFORMANCE = {
        "title": "Performance",
        "icon": "",
        "content": """
Threads (-t)
  Number of parallel scans.
  More = faster, more detectable.
  Default depends on speed preset.

Timeout (-tm)
  Wait time for responses.
  Higher = more reliable.
  Lower = faster.

Max Retries (-mx)
  Retry on no response.
  Higher = more reliable.
  Lower = faster.

Interval (--interval)
  Delay between packets.
  Helps with rate limiting.
  Avoids overwhelming networks.

Recursive (-Rc)
  Scan hosts that appear down.
  More thorough but slower.
"""
    }

    SCRIPTING = {
        "title": "Scripting (LSSE)",
        "icon": "",
        "content": """
What is LSSE?
  Light-Scan Scripting Engine.
  Extends scanning capabilities.
  Python-based scripts.

Script-Only Mode (--lsse)
  Run scripts without scanning.
  Save time and resources.

Available Scripts
  DNS Lookup: Resolve domains.
  DNS Zone Transfer: Find records.
  HTTP Headers: Security check.
  HTTP Methods: Safe/dangerous.
  HTTP Cookies: Security flags.
  HTTP Cert: SSL/TLS check.
  Etc.

Web Options
  --url: Target website.
  --domain: Domain for DNS.
  --wordlist: Dictionary file.
  --extensions: File types.
  --redirect: Follow redirects.

Authentication
  --username: Single user.
  --password: Single password.
  --userlist: Users file.
  --passwordlist: Passwords file.
"""
    }

    OUTPUT = {
        "title": "Output Formats",
        "icon": "",
        "content": """
TXT
  Plain text format.
  Human readable.
  Best for quick viewing.

HTML
  Web page format.
  Browser viewable.
  Best for sharing.

JSON
  Machine readable.
  API compatible.
  Best for automation.

CSV
  Spreadsheet format.
  Excel compatible.
  Best for analysis.

XML
  Machine readable.
  Good for automation.

PDF
  Print ready format.
  Best for documentation.

YAML
  Configuration friendly.
  Easy to read.

TOML
  Modern config format.

HEX
  Debugging format.
  Shows raw data.

LIGHT
  Light-Scan native format.
  Compact and efficient.
"""
    }

    PROFILES = {
        "title": "Profiles",
        "icon": "",
        "content": """
What are Profiles?
  Save scan configurations.
  Reuse settings.
  Share with team.
  Quick scan switching.

How to Use
  Load: --load-profile NAME
  Save: --save-profile NAME
  List: --profiles-lst

Profile Format (JSON)
{
  "name": "my_profile",
  "description": "Info",
  "settings": {
    "target": "192.168.1.1",
    "ports": "1-1000",
    "scan_type": "SYN",
    "speed": "fast",
    "banner": true,
    "os": true
  }
}

Profile Location
  ./Profiles/ directory.
  Created automatically.
"""
    }

    EXAMPLES = {
        "title": "Quick Examples",
        "icon": "",
        "content": """
Basic Scan
  sudo Lightscan.py -T 192.168.1.1 -p 80,443

Full Scan
  sudo Lightscan.py -T example.com -A

OS Detection
  sudo Lightscan.py -T 10.0.0.1 -O -b

Fast Scan
  sudo Lightscan.py -T example.com -F -s fast

Stealth Scan
  sudo Lightscan.py -T 10.0.0.1 -st FIN -f -s paranoid

UDP Scan
  sudo Lightscan.py -T 10.0.0.1 -p 53,161 -st UDP

Host Discovery
  sudo Lightscan.py -T 192.168.1.0/24 -Pan -sn

Save Results
  sudo Lightscan.py -T example.com -A --save json

Run Script
  sudo Lightscan.py --lsse --script http-headers --url https://example.com

Load Profile
  sudo Lightscan.py --load-profile my_scan

Multiple Targets
  sudo Lightscan.py -T 192.168.1.1,192.168.1.2,192.168.1.3 -p 80

Range Targets
  sudo Lightscan.py -T 192.168.1.1-100 -p 443

From File
  sudo Lightscan.py --rff targets.txt -p 1-1000
"""
    }

"""[
            ("Basic", "🧩", HelpContent.BASIC),
            ("Scan Types", "🎯", HelpContent.SCAN_TYPES),
            ("Host Discovery", "🛰️", HelpContent.HOSTDISCOVERY),
            ("Speed", "⚡", HelpContent.SPEED),
            ("Advanced", "🧠", HelpContent.ADVANCED),
            ("Stealth", "🥷", HelpContent.STEALTH),
            ("Performance", "📈", HelpContent.PERFORMANCE),
            ("Scripting", "📜", HelpContent.SCRIPTING),
            ("Output", "💾", HelpContent.OUTPUT),
            ("Profiles", "🗂️", HelpContent.PROFILES),
            ("Examples", "✨", HelpContent.EXAMPLES)
        ]
        "Quick Help - Lightscan Guide"
        "⚡ Quick Help"
        "Lightscan Scanner Guide"
        "Lightscan v1.1.9"
        """

class QuickHelp(QDialog):
    def __init__(self, parent=None,sections=None,title=None,stitle=None,
                 subtitle=None,version=None):
        super().__init__(parent)
        self.parent = parent
        self.current_section = None

        self.sections = sections
        self.title = stitle
        self.subtitle = subtitle
        self.version = version

        self.setWindowTitle(title)
        self.setGeometry(0, 0, 900, 660)
        self.setMinimumSize(760, 520)

        self.setWindowFlags(self.windowFlags() | Qt.WindowType.WindowStaysOnTopHint)

        self.setup_ui()
        self.center_window()
        self.apply_styles()

        self.sidebar.setCurrentRow(0)

        self.shortcut_close_1 = None
        self.shortcut_close_2 = None
        self.bind_shortcuts()

    def bind_shortcuts(self):
        self.shortcut_close_1 = QShortcut(QKeySequence("Escape"), self)
        self.shortcut_close_1.activated.connect(self.close)
        self.shortcut_close_2 = QShortcut(QKeySequence("F1"), self)
        self.shortcut_close_2.activated.connect(self.close)

    def setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(12)

        header = self.create_header()
        main_layout.addWidget(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(10)

        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(190)
        self.sidebar.setFrameShape(QFrame.Shape.NoFrame)
        self.sidebar.setSpacing(3)
        self.sidebar.setUniformItemSizes(True)
        self.sidebar.setVerticalScrollMode(QListWidget.ScrollMode.ScrollPerPixel)

        for section_name, emoji, section_data in self.sections:
            item = QListWidgetItem(f"{emoji}  {section_name}")
            item.setSizeHint(item.sizeHint().expandedTo(item.sizeHint()))
            self.sidebar.addItem(item)

        self.sidebar.setStyleSheet("QListWidget::item { height: 36px; }")
        self.sidebar.currentRowChanged.connect(self.on_row_changed)
        splitter.addWidget(self.sidebar)

        self.content_text = QTextEdit()
        self.content_text.setReadOnly(True)
        self.content_text.setFont(QFont("Consolas", 10))
        splitter.addWidget(self.content_text)

        splitter.setSizes([210, 690])
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        main_layout.addWidget(splitter, 1)

        footer = self.create_footer()
        main_layout.addWidget(footer)

    def create_header(self):
        header = QWidget()
        layout = QHBoxLayout(header)
        layout.setContentsMargins(4, 0, 4, 0)
        layout.setSpacing(10)

        title = QLabel(self.title)
        title_font = QFont("Segoe UI", 16, QFont.Weight.DemiBold)
        title.setFont(title_font)
        layout.addWidget(title, 0)

        subtitle = QLabel(self.subtitle)
        subtitle.setObjectName("subtitle")
        subtitle_font = QFont("Segoe UI", 11)
        subtitle.setFont(subtitle_font)
        layout.addWidget(subtitle)

        layout.addStretch()

        hint = QLabel("Select a section to view details")
        hint.setObjectName("hint")
        hint_font = QFont("Segoe UI", 10)
        hint.setFont(hint_font)
        layout.addWidget(hint)

        return header

    def create_footer(self):
        footer = QWidget()
        layout = QHBoxLayout(footer)
        layout.setContentsMargins(4, 8, 4, 0)

        info = QLabel("Esc / F1 to close")
        info.setObjectName("footerLabel")
        layout.addWidget(info)

        layout.addStretch()

        version = QLabel(self.version)
        version.setObjectName("footerLabel")
        layout.addWidget(version)

        return footer

    def center_window(self):
        screen = self.screen().size()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)

    def on_row_changed(self, row):
        if row < 0 or row >= len(self.sections):
            return
        section_name, emoji, section_data = self.sections[row]
        content = section_data.get("content", "")
        self.content_text.setPlainText(content.strip())
        self.current_section = section_name

    def show_section(self, section_name):
        for i, (name, emoji, _) in enumerate(self.sections):
            if name == section_name:
                self.sidebar.setCurrentRow(i)
                return

    def apply_styles(self):
        is_light = hasattr(self.parent, 'dark_mode') and not self.parent.dark_mode

        if not is_light:
            accent = "#1e6fe0"
            self.setStyleSheet(f"""
                QDialog {{
                    background-color: #f7f5f0;
                }}
                QLabel {{
                    color: {accent};
                }}
                QLabel#subtitle {{
                    color: {accent};
                }}
                QLabel#hint {{
                    color: {accent};
                }}
                QLabel#footerLabel {{
                    color: {accent};
                }}
                QListWidget {{
                    background-color: #ffffff;
                    border: 1px solid #dde2e9;
                    border-radius: 16px;
                    padding: 8px;
                    outline: none;
                    font-size: 13px;
                }}
                QListWidget::item {{
                    color: {accent};
                    background-color: #f7f9fb;
                    border-radius: 12px;
                    padding-left: 8px;
                    margin: 2px 0px;
                }}
                QListWidget::item:hover {{
                    background-color: #e7edf6;
                }}
                QListWidget::item:selected {{
                    background-color: {accent};
                    color: #ffffff;
                }}
                QTextEdit {{
                    background-color: #ffffff;
                    color: {accent};
                    border: 1px solid #dde2e9;
                    border-radius: 16px;
                    padding: 18px;
                    font-family: 'Consolas', monospace;
                    font-size: 13px;
                    selection-background-color: {accent};
                    selection-color: #ffffff;
                }}
                QSplitter::handle {{
                    background-color: transparent;
                }}
                QScrollBar:vertical {{
                    background: transparent;
                    width: 10px;
                    margin: 4px 0;
                }}
                QScrollBar::handle:vertical {{
                    background: #ccd3dc;
                    border-radius: 5px;
                    min-height: 24px;
                }}
                QScrollBar::handle:vertical:hover {{
                    background: {accent};
                }}
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                    height: 0px;
                }}
            """)
        else:
            accent = "#00ffb2"
            self.setStyleSheet(f"""
                QDialog {{
                    background-color: #1a1a1a;
                }}
                QLabel {{
                    color: {accent};
                }}
                QLabel#subtitle {{
                    color: {accent};
                }}
                QLabel#hint {{
                    color: {accent};
                }}
                QLabel#footerLabel {{
                    color: {accent};
                }}
                QListWidget {{
                    background-color: #0a0a0a;
                    border-radius: 16px;
                    padding: 8px;
                    outline: none;
                    font-size: 13px;
                }}
                QListWidget::item {{
                    color: {accent};
                    background-color: #000000;
                    border-radius: 12px;
                    padding-left: 8px;
                    margin: 2px 0px;
                }}
                QListWidget::item:hover {{
                    background-color: #d9ffef ;
                    color: #000000;
                }}
                QListWidget::item:selected {{
                    background-color: {accent};
                    color: #000000;
                }}
                QTextEdit {{
                    background-color: #0a0a0a;
                    color: {accent};
                    border-radius: 16px;
                    padding: 18px;
                    font-family: 'Consolas', monospace;
                    font-size: 13px;
                    selection-background-color: #0a0a0a;
                    selection-color: {accent};
                }}
                QSplitter::handle {{
                    background-color: transparent;
                }}
                QScrollBar:vertical {{
                    background: transparent;
                    width: 10px;
                    margin: 4px 0;
                }}
                QScrollBar::handle:vertical {{
                    background: #0a0a0a;
                    border-radius: 5px;
                    min-height: 24px;
                }}
                QScrollBar::handle:vertical:hover {{
                    background: #0a0a0a;
                }}
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                    height: 0px;
                }}
            """)


def show_quick_help(parent):
    dialog = QuickHelp(
        parent=parent,
        sections=[
            ("Basic", "🧩", HelpContent.BASIC),
            ("Scan Types", "🎯", HelpContent.SCAN_TYPES),
            ("Host Discovery", "🛰️", HelpContent.HOSTDISCOVERY),
            ("Speed", "⚡", HelpContent.SPEED),
            ("Advanced", "🧠", HelpContent.ADVANCED),
            ("Stealth", "🥷", HelpContent.STEALTH),
            ("Performance", "📈", HelpContent.PERFORMANCE),
            ("Scripting", "📜", HelpContent.SCRIPTING),
            ("Output", "💾", HelpContent.OUTPUT),
            ("Profiles", "🗂️", HelpContent.PROFILES),
            ("Examples", "✨", HelpContent.EXAMPLES)
        ],
        title="Quick Help - Lightscan Guide",
        stitle="⚡ Quick Help",
        subtitle="Lightscan Scanner Guide",
        version="Lightscan v1.1.9"
    )
    dialog.exec()


