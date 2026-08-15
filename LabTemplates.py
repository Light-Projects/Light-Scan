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

from Decoration.Colors import *

def Templates():
    print(f"""
{BOLD}{CYAN}===== LightLab Templates ====={RESET}

{BOLD}1. TCP SYN Scan:{RESET}
new ip
set ip.dst=192.168.1.1
new tcp
set tcp.dport=80
set tcp.flags=S
send -v

{BOLD}2. HTTP GET Request:{RESET}
new ip
set ip.dst=example.com
new tcp
set tcp.dport=80
new http
set http.Method=GET
set http.Path=/
set http.Host=example.com
send -v

{BOLD}3. HTTP POST Request:{RESET}
new ip
set ip.dst=example.com
new tcp
set tcp.dport=80
new http
set http.Method=POST
set http.Path=/login
set http.Host=example.com
set http.Content_Type=application/x-www-form-urlencoded
new raw
set raw.load=username=admin&password=test
send -v

{BOLD}4. UDP DNS Query:{RESET}
new ip
set ip.dst=8.8.8.8
new udp
set udp.dport=53
new dns
set dns.id=1234
set dns.rd=1
set dns.qd=DNSQR(qname="google.com", qtype=1)
send -v

{BOLD}5. ICMP Ping:{RESET}
new ip
set ip.dst=192.168.1.1
new icmp
set icmp.type=8
set icmp.id=1234
set icmp.seq=1
send -v

{BOLD}6. ARP Request:{RESET}
new ether
set ether.dst=ff:ff:ff:ff:ff:ff
new arp
set arp.pdst=192.168.1.1
send -v

{BOLD}7. VLAN Tagged Packet:{RESET}
new vlan
set vlan.vlan=100
set vlan.prio=5
new ip
set ip.dst=192.168.1.1
new icmp
send -v

{BOLD}8. Custom TCP with Options:{RESET}
new ip
set ip.dst=192.168.1.1
new tcp
set tcp.dport=443
set tcp.flags=S
set tcp.window=65535
set tcp.options=[('MSS', 1460), ('SAckOK', ''), ('WScale', 7)]
send -v

{BOLD}9. IPv6 ICMPv6 Echo:{RESET}
new ipv6
set ipv6.dst=::1
new icmpv6_echo
send -v

{BOLD}10. IPv6 Neighbor Solicitation:{RESET}
new ipv6
set ipv6.dst=ff02::1:ff00:1234
new ndp_ns
set ndp_ns.tgt=fe80::1234
send -v

{BOLD}11. DNS ANY Query (Amplification Test):{RESET}
new ip
set ip.src=192.168.1.100
set ip.dst=8.8.8.8
new udp
set udp.dport=53
new dns
set dns.id=5678
set dns.rd=1
set dns.qd=DNSQR(qname="isc.org", qtype=255,unicastresponse=0,qclass=1)
send -v

{BOLD}12. VLAN (Dot1Q):{RESET}
new vlan
set vlan.vlan=1
new vlan
set vlan.vlan=100
new ip
set ip.dst=192.168.100.1
new icmp
send -v

{BOLD}13. SCTP INIT (Association Setup):{RESET}
new ip
set ip.dst=192.168.1.1
new sctp
set sctp.sport=1234
set sctp.dport=132
new sctp_init
set sctp_init.init_tag=12345
set sctp_init.a_rwnd=106496
set sctp_init.n_out_streams=10
set sctp_init.n_in_streams=65535
set sctp_init.init_tsn=1
send -v

{BOLD}14. SCTP INIT ACK:{RESET}
new ip
set ip.dst=192.168.1.1
new sctp
set sctp.sport=132
set sctp.dport=1234
new sctp_init_ack
set sctp_init_ack.init_tag=54321
set sctp_init_ack.a_rwnd=106496
set sctp_init_ack.n_out_streams=10
set sctp_init_ack.n_in_streams=65535
set sctp_init_ack.init_tsn=1
send -v

{BOLD}15. SCTP COOKIE ECHO:{RESET}
new ip
set ip.dst=192.168.1.1
new sctp
set sctp.sport=1234
set sctp.dport=132
new sctp_cookie_echo
set sctp_cookie_echo.cookie=deadbeef
send -v

{BOLD}16. SCTP COOKIE ACK:{RESET}
new ip
set ip.dst=192.168.1.1
new sctp
set sctp.sport=132
set sctp.dport=1234
new sctp_cookie_ack
send -v

{BOLD}17. SCTP DATA Chunk:{RESET}
new ip
set ip.dst=192.168.1.1
new sctp
set sctp.sport=1234
set sctp.dport=132
new sctp_data
set sctp_data.tsn=1
set sctp_data.stream_id=0
set sctp_data.stream_seq=1
set sctp_data.proto_id=0
set sctp_data.data=Hello SCTP
send -v

{BOLD}18. SCTP SACK (Selective Ack):{RESET}
new ip
set ip.dst=192.168.1.1
new sctp
set sctp.sport=132
set sctp.dport=1234
new sctp_sack
set sctp_sack.cum_tsn_ack=1
set sctp_sack.a_rwnd=106496
send -v

{BOLD}19. SCTP Heartbeat / Heartbeat Ack:{RESET}
new ip
set ip.dst=192.168.1.1
new sctp
set sctp.sport=1234
set sctp.dport=132
new sctp_heartbeat
send -v

new sctp_heartbeat_ack
send -v

{BOLD}20. SCTP Abort:{RESET}
new ip
set ip.dst=192.168.1.1
new sctp
set sctp.sport=1234
set sctp.dport=132
new sctp_abort
send -v

{BOLD}21. SCTP Shutdown / Shutdown Ack / Shutdown Complete:{RESET}
new ip
set ip.dst=192.168.1.1
new sctp
set sctp.sport=1234
set sctp.dport=132
new sctp_shutdown
set sctp_shutdown.cumul_tsn_ack=1
send -v

new sctp_shutdown_ack
send -v

new sctp_shutdown_complete
send -v

{BOLD}22. SCTP Error:{RESET}
new ip
set ip.dst=192.168.1.1
new sctp
set sctp.sport=1234
set sctp.dport=132
new sctp_error
send -v

{BOLD}23. IGMPv2 Membership Report (classic):{RESET}
new ip
set ip.dst=239.1.1.1
new igmp
set igmp.type=0x16
set igmp.gaddr=239.1.1.1
send -v

{BOLD}24. IGMPv2 Leave Group:{RESET}
new ip
set ip.dst=224.0.0.2
new igmp
set igmp.type=0x17
set igmp.gaddr=239.1.1.1
send -v

{BOLD}25. IGMPv3 General/Group-Specific Membership Query:{RESET}
new ip
set ip.dst=224.0.0.1
new igmpv3
set igmpv3.type=0x11
new igmpv3mq
set igmpv3mq.gaddr=239.1.1.1
set igmpv3mq.qrv=2
set igmpv3mq.qqic=125
send -v

{BOLD}26. IGMPv3 Group-and-Source-Specific Query:{RESET}
new ip
set ip.dst=224.0.0.1
new igmpv3
set igmpv3.type=0x11
new igmpv3mq
set igmpv3mq.gaddr=239.1.1.1
set igmpv3mq.srcaddrs=['10.0.0.5','10.0.0.6']
send -v

{BOLD}27. IGMPv3 Membership Report (with Group Records):{RESET}
new ip
set ip.dst=224.0.0.22
new igmpv3
set igmpv3.type=0x22
new igmpv3mr
set igmpv3mr.records=[{{'rtype':1,'maddr':'239.1.1.1'}}, {{'rtype':2,'maddr':'239.2.2.2','srcaddrs':['10.0.0.5','10.0.0.6']}}]
send -v
""")

def LabHelp(version):
        print(f"""
    {BOLD}{CYAN}LightLab v{version} Commands{RESET}

    {BOLD}Layer Management:{RESET}
      {GREEN}new <layer>{RESET}        - Add layer (ether,vlan,arp,ip,ipv6,tcp,udp,icmp,ndp_rs,ndp_ra,ndp_na,ndp_ns,icmpv6,icmpv6_echo,http,dns,ssh,raw,
                                                    igmp,igmpv3,igmpv3mr,igmpv3mq,sctp,sctp_init,sctp_init_ack,sctp_cookie_echo,sctp_cookie_ack
                                                    ,sctp_abort,sctp_data,sctp_error,sctp_shutdown,sctp_shutdown_ack,sctp_shutdown_complete,sctp_heartbeat
                                                    ,sctp_heartbeat_ack,sctp_sack)

      {GREEN}delete <layer>{RESET}        - Delete layer
      {GREEN}params <layer>{RESET}        - Show available parameters for a layer
      {GREEN}set <layer>.<param>=<value>{RESET} - Set parameter value
      {GREEN}show{RESET}                 - Show current packet structure
      {GREEN}clear{RESET}               - Clear all layers

    {BOLD}Packet Operations:{RESET}
      {GREEN}send [count] [-v]{RESET}    - Send packet (count=number, -v=verbose)
      {GREEN}timeout <seconds>{RESET}    - Set response timeout
      {GREEN}interval <seconds>{RESET}    - Set interval time between packets

    {BOLD}Help:{RESET}
      {GREEN}templates{RESET}            - Show example configurations
      {GREEN}history{RESET}             - Show command history
      {GREEN}help{RESET}                - Show this message
      {GREEN}exit{RESET}                - Quit LightLab

    {BOLD}File Operations:{RESET}
      {GREEN}save <filename.pcap/.pcapng>{RESET}     - Save current packet to PCAP/PCAPNG
      {GREEN}load <filename.pcap/.pcapng>{RESET}     - Load packet from PCAP/PCAPNG
      {GREEN}savebin <filename.lbn>{RESET}  - Save current packet to LightBin
      {GREEN}loadbin <filename.lbn>{RESET}  - Load packet from LightBin

    {BOLD}Example Workflow:{RESET}
      LightLab> {CYAN}new ip{RESET}
      LightLab> {CYAN}params tcp{RESET}
      LightLab> {CYAN}set ip.dst=192.168.1.1{RESET}
      LightLab> {CYAN}new tcp{RESET}
      LightLab> {CYAN}set tcp.dport=80{RESET}
      LightLab> {CYAN}set tcp.flags=S{RESET}
      LightLab> {CYAN}send -v{RESET}

    {BOLD}DNS Example:{RESET}
      LightLab> {CYAN}new ip{RESET}
      LightLab> {CYAN}set ip.dst=8.8.8.8{RESET}
      LightLab> {CYAN}new udp{RESET}
      LightLab> {CYAN}set udp.dport=53{RESET}
      LightLab> {CYAN}new dns{RESET}
      LightLab> {CYAN}set dns.id=1234{RESET}
      LightLab> {CYAN}set dns.rd=1{RESET}
      LightLab> {CYAN}set dns.qd=DNSQR(qname="google.com", qtype=1,unicastresponse=0,qclass=1){RESET}
      LightLab> {CYAN}send -v{RESET}

    {BOLD}VLAN Example:{RESET}
      LightLab> {CYAN}new vlan{RESET}
      LightLab> {CYAN}set vlan.vlan=100{RESET}
      LightLab> {CYAN}new ip{RESET}
      LightLab> {CYAN}set ip.dst=192.168.1.1{RESET}
      LightLab> {CYAN}new icmp{RESET}
      LightLab> {CYAN}send -v{RESET}
    """)