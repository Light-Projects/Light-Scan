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

import customtkinter

class HelpContent:
    BASIC = {
        "title": "Basic Options",
        "icon": "",
        "content": """
Target (-T)
  The target field is where Lightscan expecte 
  an IP address ,hostname or Network chunk to scan.
  
  Examples: 192.168.1.1, example.com,scanme.nmap.org

Ports (-p)
  The port or ports to scan.
  Single: 80
  List: 80,443,8080
  Range: 1-1000
  Mixed: 80,443-445,8080

Top 100 Ports (-F)
  Scan only the most common 100 ports.
  Faster scan for quick results.

Randomize Ports (--shufle)
  Scans ports in random order using Fisher Yates shuffle
  Algorith to performe the randomizing process.
  Helps avoid detection by basic firewalls.

Quiet Mode (-q)
  Remove Lightscan banner for more focuss
  on the scan result .

IPv6 scan (-V6)
  when this option is entered Lightscan expected
  an IPv6 address as the targeted system .
"""
    }

    SCAN_TYPES = {
        "title": "Scan Types",
        "icon": "",
        "content": """
        
TCP Connect (-st TCP) :

  TCP 3 way handshake scan is a port scanning technique 
  that completes the entire TCP connection process to determine if a
  host port is open. It works by sending a SYN packet
  to the host port. If the port is open, the host system replies 
  with a SYN-ACK thenThe scanner responds with an ACK packet to 
  finalize the connection, then immediately tears it down.
  
SYN Stealth (-st SYN) :

  SYN scan is a rapid network reconnaissance technique that 
  determines if a host port is open without completing the full TCP
  three-way handshake. the scanner initiates the process by sending
  a SYN packet if the host port is up, it responds with a SYN-ACK
  packet, prompting the scanner to immediately abort the connection
  with a RST packet rather than finalizing it with an ACK. 

UDP Scan (-st UDP) :

  UDP scan is a connectionless network reconnaissance technique
  used to identify active services running on User Datagram 
  Protocol (UDP) ports, which do not utilize a handshake mechanism.
  The scanning system sends a blank or protocol-specific UDP packet
  to a host port, if the port is closed, the host system
  typically replies with an ICMP Destination Unreachable packet, 
  whereas no response at all or a UDP reply indicates that the
  port is open or filtered. highly prone to packet loss, 
  making it harder to execute accurately but critical for 
  finding hidden services like DNS or DHCP.
  
NULL Scan (-st NULL) :
  
  NULL scan is a stateless TCP reconnaissance technique used to
  bypass traditional packet filters by sending a packet with no 
  flags set at all inside its header. According to the RFC 793 
  standard, if a host port is closed, the operating system 
  must respond with a RST packet, whereas if the port is open 
  or filtered by a firewall, the system will completely ignore
  the packet and send no response .

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
  system sends a TCP packet with only the ACK flag set, 
  when the target system responds with a mandatory RST 
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
  server. The scanner connects to an vulnerable FTP 
  server and uses the PORT command to trick it into 
  opening a data connection to a completely different 
  target machine and port, rather than sending the 
  file back to the scanner. If the file transfer 
  succeeds, the target port is open, if it fails with 
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
  confirmed as closed, if it responds with a 
  packet using that specific protocol, it is open, 
  while a complete lack of response typically 
  indicates that the protocol is either open 
  or actively blocked by a firewall (filtered) .

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
  increment its IPID, if the port is closed, 
  the target sends a RST, causing the zombie to 
  ignore it and keep its IPID unchanged. 
  
PING Sweep (-st PING) :
  
  by definition Ping Sweeep is not actually a
  scaning technique but rather as a host discovery
  method to discovere live devices inside a 
  network using multiple pinging techniques like
  ICMP Echo, TCP Ping ,ICMP Timestamp , etc ...

SCTP-INIT (-st SCTP-INIT) :

  SCTP INIT scan is a specialized network 
  reconnaissance technique used to determine if 
  ports running the Stream Control Transmission Protocol 
  are open, functioning as the SCTP equivalent of a 
  stealthy TCP SYN scan. The scanning system initiates 
  the probe by sending an INIT chunk to a target port, 
  if the port is open, the target responds with an 
  INIT-ACK chunk, prompting the scanner to immediately 
  drop the connection by sending an ABORT chunk instead 
  of completing the 4 way handshake. If the port is 
  closed, the target responds directly with an ABORT 
  chunk, whereas a lack of response or an ICMP 
  unreachable indicates that the port is being 
  filtered by a firewall .
  
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
  Identifies operating system Using.
  TCP/IP stack, UDP and ICMP stacks fingerprinting to
  determine the os runnig on a specifique host also it uses
  service banners to determine that as well.

Disable Firewall Asessment (--no-firewall-ase)
  disable firewall asessement when performance and speed
  is more important then analysis 

Banner Grabbing (-b)
  Captures service banners by specifique probes for
  every service and extract the exact version number
  and service name from it and it's Required for 
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
  the target system. any response from the host 
  system is considered as sign that machine is up .
  
  -> IP Protocols (-Pip) :
  
    is a list of numbers of IP protocols that
    Light-Scan is going to performe a host 
    discovery phase on using IP protocols Ping.

TCP Ping (-Pt) :
  
  TCP 3 way handshake ping is a host discovery technique 
  that completes the entire TCP connection process to determine if a
  host is up. It works by sending a SYN packet
  to the host ports. If one of the ports is open, the host system replies 
  with a SYN-ACK then The scanner responds with an ACK packet to 
  finalize the connection, then immediately tears it down.
  
SYN Ping (-Ps) :

  SYN ping is a rapid network reconnaissance technique that 
  determines if a host is up without completing the full TCP
  3 way handshake. the scanner initiates the process by sending
  a SYN packet if the host port is up, it responds with a SYN-ACK
  packet, prompting the scanner to immediately abort the connection
  with a RST packet rather than finalizing it with an ACK. 

ACK Ping (-Pk) :

  ACK ping is a stateless TCP reconnaissance technique 
  used to determine if a host is alive by sending a ACK
  packet without a connection actually existed. 
  Because this packet is out 
  of sequence, both open and closed ports will 
  respond with a RST packet if they are unprotected, 
  indicating to the scanner that the port is unfiltered, 
  whereas a lack of response or an ICMP error indicates
  that a firewall or router is actively dropping the
  traffic .

UDP Ping (-Pu) :

  UDP ping is a connectionless network reconnaissance technique
  used to identify active hosts running on User Datagram 
  Protocol (UDP) ports, which do not utilize a handshake mechanism.
  The scanning system sends a blank or protocol-specific UDP packet
  to a host port, if the port is closed, the host system
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
  host to reply with an ICMP Type 18 (Address Mask) 
  containing its local subnet configuration. 

ICMP Information (-Pin) :

  ICMP Information Ping scan is a legacy network reconnaissance 
  technique designed to verify if a target host is active while 
  attempting to discover its network configuration automatically. 
  Instead of a standard echo request, the scanning system 
  transmits an ICMP Type 15 (Information) packet, 
  prompting a remote host to reply with an ICMP Type 16 
  (Information) packet. 

ICMP Solicitation (-Pas) :

  ICMP Router Solicitation Ping scan is a network reconnaissance t
  echnique that utilizes routing protocol discovery messages to 
  verify if a target host or router is active while mapping local 
  gateway infrastructure. The scanning system transmits an ICMP 
  Type 10 (Router Solicitation) packet, prompting any active, 
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
  Send Custom IP packet with a specifique IP ID

Custom Payload (-payload)
  Send custom data in packets.

Random Payload (-payload-lenght)
  Send random data in packets based on lenght. 

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
  Etc ...

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

class QuickHelp:

    def __init__(self, parent):
        self.parent = parent
        self.window = None
        self.current_section = None
        self.section_buttons = []

        self.sections = [
            ("Basic", HelpContent.BASIC),
            ("Scan Types", HelpContent.SCAN_TYPES),
            ("Host Discovery", HelpContent.HOSTDISCOVERY),
            ("Speed", HelpContent.SPEED),
            ("Advanced", HelpContent.ADVANCED),
            ("Stealth", HelpContent.STEALTH),
            ("Performance", HelpContent.PERFORMANCE),
            ("Scripting", HelpContent.SCRIPTING),
            ("Output", HelpContent.OUTPUT),
            ("Profiles", HelpContent.PROFILES),
            ("Examples", HelpContent.EXAMPLES)
        ]

    def show(self):
        self.window = customtkinter.CTkToplevel(self.parent)
        self.window.title("Quick Help - Lightscan Guide")
        self.window.geometry("750x650")
        self.window.resizable(True, True)
        self.window.transient(self.parent)
        self.window.grab_set()

        self.sync_theme()

        self.center_window()

        self.build_ui()

        self.show_section("Basic")

    def sync_theme(self):
        customtkinter.set_appearance_mode(customtkinter.get_appearance_mode())

    def center_window(self):
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f'{width}x{height}+{x}+{y}')

    def build_ui(self):
        main_frame = customtkinter.CTkFrame(self.window)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.build_header(main_frame)

        content_frame = customtkinter.CTkFrame(main_frame)
        content_frame.pack(fill="both", expand=True, pady=(10, 0))

        sidebar = customtkinter.CTkFrame(content_frame, width=180)
        sidebar.pack(side="left", fill="y", padx=(0, 10))
        sidebar.pack_propagate(False)

        self.build_sidebar(sidebar)

        self.content_frame = customtkinter.CTkFrame(content_frame)
        self.content_frame.pack(side="left", fill="both", expand=True)

        self.content_text = customtkinter.CTkTextbox(
            self.content_frame,
            font=("Consolas", 12),
            wrap="word",
            border_width=1,
            border_color=("#dbdbdb", "#121211")
        )
        self.content_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.content_text.configure(state="disabled")

        self.build_footer(main_frame)

        self.window.bind('<Escape>', lambda e: self.window.destroy())
        self.window.bind('<F1>', lambda e: self.window.destroy())

    def build_header(self, parent):
        header = customtkinter.CTkFrame(parent)
        header.pack(fill="x")

        title = customtkinter.CTkLabel(
            header,
            text="⚡ Quick Help",
            font=("Arial", 22, "bold"),
            text_color=("black", "white")
        )
        title.pack(side="left", padx=5)

        subtitle = customtkinter.CTkLabel(
            header,
            text="Lightscan Scanner Guide",
            font=("Arial", 12),
            text_color=("gray", "gray")
        )
        subtitle.pack(side="left", padx=(10, 0))

        hint = customtkinter.CTkLabel(
            header,
            text="Click section → view details  ",
            font=("Arial", 11),
            text_color=("gray", "gray")
        )
        hint.pack(side="right", padx=5)

    def build_sidebar(self, parent):
        scroll_frame = customtkinter.CTkScrollableFrame(
            parent,
            height=500,
            border_width=0
        )
        scroll_frame.pack(fill="both", expand=True)

        for section_name, section_data in self.sections:
            icon = section_data.get("icon", "•")
            btn = customtkinter.CTkButton(
                scroll_frame,
                text=f"{icon} {section_name}",
                command=lambda n=section_name: self.show_section(n),
                font=("Arial", 12),
                height=35,
                corner_radius=8,
                fg_color="transparent",
                hover_color=("#e0e0e0", "#333333"),
                text_color=("black", "white"),
                anchor="w"
            )
            btn.pack(fill="x", pady=2, padx=5)
            self.section_buttons.append((section_name, btn))

        spacer = customtkinter.CTkLabel(scroll_frame, text="")
        spacer.pack(fill="x", pady=10)

    def build_footer(self, parent):
        footer = customtkinter.CTkFrame(parent)
        footer.pack(fill="x", pady=(10, 0))

        info = customtkinter.CTkLabel(
            footer,
            text="  Esc/F1 to close • F1 for help • Theme sync enabled",
            font=("Arial", 10),
            text_color=("gray", "gray")
        )
        info.pack(side="left")

        version = customtkinter.CTkLabel(
            footer,
            text="Lightscan v1.1.9 ",
            font=("Arial", 10),
            text_color=("gray", "gray")
        )
        version.pack(side="right")

    def show_section(self, section_name):
        for name, btn in self.section_buttons:
            if name == section_name:
                btn.configure(fg_color=("#d4e6f1", "#2c3e50"))
            else:
                btn.configure(fg_color="transparent")

        section_data = None
        for name, data in self.sections:
            if name == section_name:
                section_data = data
                break

        if not section_data:
            return

        self.content_text.configure(state="normal")
        self.content_text.delete("1.0", "end")

        content = self.format_content(section_data)
        self.content_text.insert("1.0", content)
        self.content_text.configure(state="disabled")
        self.content_text.see("1.0")

        self.current_section = section_name

    def format_content(self, section_data):
        content = section_data.get("content", "")

        lines = content.split("\n")
        formatted = []

        for line in lines:
            if line.strip() and not line.startswith(" "):
                if ":" in line and not line.startswith("  "):
                    formatted.append(f"\n{line.strip()}")
                else:
                    formatted.append(f"  {line.strip()}")
            elif line.strip().startswith("  "):
                formatted.append(f"  {line.strip()}")
            elif not line.strip():
                formatted.append("")
            else:
                formatted.append(f"    {line.strip()}")

        return "\n".join(formatted)


def show_quick_help(parent):
    QuickHelp(parent).show()


def create_help_button(parent):
    button = customtkinter.CTkButton(
        parent,
        text="? Help",
        command=lambda: show_quick_help(parent),
        width=70,
        height=28,
        font=("Arial", 13),
        corner_radius=10,
        fg_color=("#f7f5f0", "#1a1a1a"),
        bg_color="transparent",
        text_color=("black", "white"),
        hover_color="grey",
        border_color=("#dbdbdb", "#121211"),
        border_width=2
    )
    return button
