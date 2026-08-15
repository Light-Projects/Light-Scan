# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

ETHERTYPE = {
    0x0600: "(XNS)",
    0x0800: "(IPv4)",
    0x0801: "(X.75)",
    0x0802: "(NBS)",
    0x0803: "(ECMA)",
    0x0804: "(Chaosnet)",
    0x0805: "(X.25)",
    0x0806: "(ARP)",
    0x0807: "(XNS)",
    0x0808: "(FRARP)",
    0x0900: "(Ungermann-Bass)",
    0x0A00: "(PUP)",
    0x0A01: "(PUP-AT)",
    0x0BAD: "(VINES)",
    0x0BAE: "(VINES-Loop)",
    0x0BAF: "(VINES-Echo)",
    0x1000: "(Berkeley-Trailer)",
    0x1600: "(Valid-Systems)",
    0x22F3: "(TRILL)",
    0x22F4: "(L2-IS-IS)",
    0x4242: "(PCS-BBP)",
    0x6000: "(DEC)",
    0x6001: "(DEC-MOP)",
    0x6002: "(DEC-MOP-RC)",
    0x6003: "(DEC-DECnet)",
    0x6004: "(DEC-LAT)",
    0x6005: "(DEC-Diag)",
    0x6006: "(DEC-Customer)",
    0x6007: "(DEC-LAVC)",
    0x6558: "(Transparent-Bridging)",
    0x6559: "(Raw-FR)",
    0x8003: "(Cronus-VLN)",
    0x8004: "(Cronus-Direct)",
    0x8005: "(HP-Probe)",
    0x8006: "(Nestar)",
    0x8008: "(AT&T)",
    0x8010: "(Excelan)",
    0x8013: "(SGI-Diag)",
    0x8014: "(SGI-Games)",
    0x8015: "(SGI-Reserved)",
    0x8016: "(SGI-Bounce)",
    0x8019: "(Apollo-Domain)",
    0x802E: "(Tymshare)",
    0x802F: "(Tigan)",
    0x8035: "(RARP)",
    0x8036: "(Aeonic)",
    0x8038: "(DEC-LANBridge)",
    0x803D: "(DEC-Encrypt)",
    0x803F: "(DEC-LTM)",
    0x8044: "(PRC)",
    0x8046: "(AT&T)",
    0x8047: "(AT&T)",
    0x8049: "(ExperData)",
    0x805B: "(Stanford-V)",
    0x805C: "(Stanford-V)",
    0x805D: "(E&S)",
    0x8060: "(Little-Machines)",
    0x8062: "(Counterpoint)",
    0x8065: "(UMass)",
    0x8066: "(UMass)",
    0x8067: "(Veeco)",
    0x8068: "(GD)",
    0x8069: "(AT&T)",
    0x806A: "(Autophon)",
    0x806C: "(ComDesign)",
    0x806D: "(Computgraphic)",
    0x807A: "(Matra)",
    0x807B: "(DDE)",
    0x807C: "(Merit)",
    0x8080: "(Vitalink)",
    0x809B: "(Appletalk)",
    0x809F: "(Spider)",
    0x80A3: "(Nixdorf)",
    0x80C4: "(Banyan)",
    0x80C5: "(Banyan)",
    0x80C6: "(Pacer)",
    0x80C7: "(Applitek)",
    0x80D5: "(IBM-SNA)",
    0x80DD: "(Varian)",
    0x80F2: "(Retix)",
    0x80F3: "(AARP)",
    0x80F7: "(Apollo)",
    0x80FF: "(Wellfleet)",
    0x8100: "(VLAN)",
    0x8130: "(Hayes)",
    0x8131: "(VG-Labs)",
    0x8137: "(Novell)",
    0x8138: "(Novell)",
    0x8148: "(Logicraft)",
    0x8149: "(NCD)",
    0x814A: "(Alpha-Micro)",
    0x814C: "(SNMP)",
    0x814D: "(BIIN)",
    0x814E: "(BIIN)",
    0x814F: "(TEC)",
    0x8150: "(Rational)",
    0x817D: "(XTP)",
    0x817E: "(SGI-TimeWarner)",
    0x8180: "(HIPPI-FP)",
    0x8181: "(HIPPI-ST)",
    0x8182: "(HIPPI-6400)",
    0x8183: "(HIPPI-6400)",
    0x818D: "(Motorola)",
    0x81A4: "(ARAI)",
    0x86DB: "(SECTRA)",
    0x86DD: "(IPv6)",
    0x86DE: "(Delta)",
    0x86DF: "(ATOMIC)",
    0x876B: "(TCP-Comp)",
    0x876C: "(IP-AS)",
    0x876D: "(Secure-Data)",
    0x8808: "(EPON)",
    0x8809: "(Slow-Protocols)",
    0x880B: "(PPP)",
    0x880C: "(GSMP)",
    0x8822: "(NIC-Test)",
    0x8847: "(MPLS)",
    0x8848: "(MPLS-UAL)",
    0x8861: "(MCAP)",
    0x8863: "(PPPoE-Discovery)",
    0x8864: "(PPPoE-Session)",
    0x888E: "(EAPOL)",
    0x88A8: "(Q-in-Q)",
    0x88B5: "(802-Experimental)",
    0x88B6: "(802-Experimental)",
    0x88B7: "(802-OUI-Ext)",
    0x88C7: "(802.11-PreAuth)",
    0x88CC: "(LLDP)",
    0x88E5: "(MACsec)",
    0x88E7: "(PBB)",
    0x88F5: "(MVRP)",
    0x88F6: "(MMRP)",
    0x88F7: "(PTP)",
    0x890D: "(802.11r)",
    0x8917: "(802.21-MIH)",
    0x8929: "(802.1Qbe)",
    0x893B: "(TRILL-FGL)",
    0x8940: "(802.1Qbg-ECP)",
    0x8946: "(TRILL-Channel)",
    0x8947: "(GeoNetworking)",
    0x894F: "(NSH)",
    0x9000: "(Loopback)",
    0x9001: "(3Com-XNS)",
    0x9002: "(3Com-TCP-IP)",
    0x9003: "(3Com-Loop)",
    0x9A22: "(Multi-Topology)",
    0xA0ED: "(LoWPAN)",
    0xB7EA: "(GRE-Channel)",
    0xFFFF: "(Reserved)",
}

HWTYPES = {
    1: "(Ethernet 10MB)",
    2: "(Ethernet 3MB)",
    3: "(AX.25)",
    4: "(Proteon ProNET Token Ring)",
    5: "(Chaos)",
    6: "(IEEE 802 Networks)",
    7: "(ARCNET)",
    8: "(Hyperchannel)",
    9: "(Lanstar)",
    10: "(Autonet Short Address)",
    11: "(LocalTalk)",
    12: "(LocalNet)",
    13: "(Ultra link)",
    14: "(SMDS)",
    15: "(Frame Relay)",
    16: "(ATM)",
    17: "(HDLC)",
    18: "(Fibre Channel)",
    19: "(ATM)",
    20: "(Serial Line)",
    21: "(ATM)",
    22: "(MIL-STD-188-220)",
    23: "(Metricom)",
    24: "(IEEE 1394.1995)",
    25: "(MAPOS)",
    26: "(Twinaxial)",
    27: "(EUI-64)",
    28: "(HIPARP)",
    29: "(IP and ARP)",
    30: "(ARPSec)",
    31: "(IP over IPsec tunnel)",
    32: "(InfiniBand)",
    33: "(TIA-102 Project 25 Common Air Interface)",
    34: "(WiMAX)",
    35: "(IEEE 802.22 )",
    36: "(Ethernet over IEEE 802.11)",
    37: "(IEEE 802.16 WirelessMAN)",
    38: "(IEEE 802.20 WirelessMAN)",
    39: "(IEEE 802.22 Wireless Regional Area Networks)",
    40: "(Ethernet over IEEE 802.11)",
    41: "(IEEE 802.16 WirelessMAN)",
}

SAP_VALUES = {
    0x00: "Null LSAP (No protocol)",
    0x02: "Individual LLC Sublayer Management",
    0x04: "Group LLC Sublayer Management",
    0x06: "IP (Internet Protocol)",
    0x08: "SNA (Systems Network Architecture)",
    0x0A: "SNA (Systems Network Architecture)",
    0x0C: "SNA (Systems Network Architecture)",
    0x0E: "SNA (Systems Network Architecture)",
    0x12: "SNA (Systems Network Architecture)",
    0x14: "SNA (Systems Network Architecture)",
    0x16: "SNA (Systems Network Architecture)",
    0x18: "SNA (Systems Network Architecture)",
    0x1A: "SNA (Systems Network Architecture)",
    0x1C: "SNA (Systems Network Architecture)",
    0x1E: "SNA (Systems Network Architecture)",
    0x20: "SNA (Systems Network Architecture)",
    0x22: "SNA (Systems Network Architecture)",
    0x24: "SNA (Systems Network Architecture)",
    0x26: "SNA (Systems Network Architecture)",
    0x28: "SNA (Systems Network Architecture)",
    0x2A: "SNA (Systems Network Architecture)",
    0x2C: "SNA (Systems Network Architecture)",
    0x2E: "SNA (Systems Network Architecture)",
    0x30: "SNA (Systems Network Architecture)",
    0x32: "SNA (Systems Network Architecture)",
    0x34: "SNA (Systems Network Architecture)",
    0x36: "SNA (Systems Network Architecture)",
    0x38: "SNA (Systems Network Architecture)",
    0x3A: "SNA (Systems Network Architecture)",
    0x3C: "SNA (Systems Network Architecture)",
    0x3E: "SNA (Systems Network Architecture)",
    0x40: "SNA (Systems Network Architecture)",
    0x42: "STP (Spanning Tree Protocol)",
    0x44: "SNA (Systems Network Architecture)",
    0x46: "SNA (Systems Network Architecture)",
    0x48: "SNA (Systems Network Architecture)",
    0x4A: "SNA (Systems Network Architecture)",
    0x4C: "SNA (Systems Network Architecture)",
    0x4E: "SNA (Systems Network Architecture)",
    0x50: "SNA (Systems Network Architecture)",
    0x52: "SNA (Systems Network Architecture)",
    0x54: "SNA (Systems Network Architecture)",
    0x56: "SNA (Systems Network Architecture)",
    0x58: "SNA (Systems Network Architecture)",
    0x5A: "SNA (Systems Network Architecture)",
    0x5C: "SNA (Systems Network Architecture)",
    0x5E: "SNA (Systems Network Architecture)",
    0x60: "SNA (Systems Network Architecture)",
    0x62: "SNA (Systems Network Architecture)",
    0x64: "SNA (Systems Network Architecture)",
    0x66: "SNA (Systems Network Architecture)",
    0x68: "SNA (Systems Network Architecture)",
    0x6A: "SNA (Systems Network Architecture)",
    0x6C: "SNA (Systems Network Architecture)",
    0x6E: "SNA (Systems Network Architecture)",
    0x70: "SNA (Systems Network Architecture)",
    0x72: "SNA (Systems Network Architecture)",
    0x74: "SNA (Systems Network Architecture)",
    0x76: "SNA (Systems Network Architecture)",
    0x78: "SNA (Systems Network Architecture)",
    0x7A: "SNA (Systems Network Architecture)",
    0x7C: "SNA (Systems Network Architecture)",
    0x7E: "SNA (Systems Network Architecture)",
    0x80: "SNA (Path Control)",
    0x82: "SNA (Path Control)",
    0x84: "SNA (Path Control)",
    0x86: "SNA (Path Control)",
    0x88: "SNA (Path Control)",
    0x8A: "SNA (Path Control)",
    0x8C: "SNA (Path Control)",
    0x8E: "SNA (Path Control)",
    0x90: "SNA (Path Control)",
    0x92: "SNA (Path Control)",
    0x94: "SNA (Path Control)",
    0x96: "SNA (Path Control)",
    0x98: "SNA (Path Control)",
    0x9A: "SNA (Path Control)",
    0x9C: "SNA (Path Control)",
    0x9E: "SNA (Path Control)",
    0xA0: "SNA (Path Control)",
    0xA2: "SNA (Path Control)",
    0xA4: "SNA (Path Control)",
    0xA6: "SNA (Path Control)",
    0xA8: "SNA (Path Control)",
    0xAA: "SNAP (Subnetwork Access Protocol)",
    0xAC: "SNA (Path Control)",
    0xAE: "SNA (Path Control)",
    0xB0: "SNA (Path Control)",
    0xB2: "SNA (Path Control)",
    0xB4: "SNA (Path Control)",
    0xB6: "SNA (Path Control)",
    0xB8: "SNA (Path Control)",
    0xBA: "SNA (Path Control)",
    0xBC: "SNA (Path Control)",
    0xBE: "SNA (Path Control)",
    0xC0: "SNA (Path Control)",
    0xC2: "SNA (Path Control)",
    0xC4: "SNA (Path Control)",
    0xC6: "SNA (Path Control)",
    0xC8: "SNA (Path Control)",
    0xCA: "SNA (Path Control)",
    0xCC: "SNA (Path Control)",
    0xCE: "SNA (Path Control)",
    0xD0: "SNA (Path Control)",
    0xD2: "SNA (Path Control)",
    0xD4: "SNA (Path Control)",
    0xD6: "SNA (Path Control)",
    0xD8: "SNA (Path Control)",
    0xDA: "SNA (Path Control)",
    0xDC: "SNA (Path Control)",
    0xDE: "SNA (Path Control)",
    0xE0: "IPX/SPX (Novell NetWare)",
    0xE2: "IPX/SPX (Novell NetWare)",
    0xE4: "IPX/SPX (Novell NetWare)",
    0xE6: "IPX/SPX (Novell NetWare)",
    0xE8: "IPX/SPX (Novell NetWare)",
    0xEA: "IPX/SPX (Novell NetWare)",
    0xEC: "IPX/SPX (Novell NetWare)",
    0xEE: "IPX/SPX (Novell NetWare)",
    0xF0: "NetBIOS (IBM)",
    0xF2: "NetBIOS (IBM)",
    0xF4: "NetBIOS (IBM)",
    0xF6: "NetBIOS (IBM)",
    0xF8: "NetBIOS (IBM)",
    0xFA: "NetBIOS (IBM)",
    0xFC: "NetBIOS (IBM)",
    0xFE: "NetBIOS (IBM)",
}

BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
NULL_MAC = '00:00:00:00:00:00'
BROADCAST_MAC_RAW = 'ffffffffffff'
NULL_MAC_RAW = '000000000000'

Layers_names = ["Ethernet" , "Arp", "Dot3", "SNAP", "LLC", "STP", "PPP"]

SAP_NULL = 0x00
SAP_IP = 0x06
SAP_SNA = 0x08
SAP_SNAP = 0xAA
SAP_IPX = 0xE0
SAP_NETBIOS = 0xF0
SAP_LLC_NULL = 0x00
SAP_LLC_IP = 0x06
SAP_LLC_SNAP = 0xAA
SAP_LLC_IPX = 0xE0
SAP_LLC_NETBIOS = 0xF0
LLC_UI = 0x03
LLC_I = 0x00
LLC_S = 0x01
LLC_UA = 0x63
LLC_DISC = 0x43
LLC_SABM = 0x2F
LLC_FRMR = 0x87

IPv4 = 0x0800
ARP_var = 0x0806
RARP = 0x8035
IPv6 = 0x86DD
MPLS = 0x8847
MPLS_UPLABEL = 0x8848
PPPoE_DISCOVERY = 0x8863
PPPoE_SESSION = 0x8864
EAPOL = 0x888E
LLDP = 0x88CC
Q_IN_Q = 0x88A8
MACsec = 0x88E5
PTP = 0x88F7
FCoE = 0x8906
Loopback = 0x9000
XNS = 0x0600
X75 = 0x0801
NBS = 0x0802
ECMA = 0x0803
CHAOSNET = 0x0804
X25 = 0x0805
XNS_COMPAT = 0x0807
FRARP = 0x0808
UNGERMANN_BASS = 0x0900
PUP = 0x0A00
PUP_AT = 0x0A01
VINES = 0x0BAD
VINES_LOOP = 0x0BAE
VINES_ECHO = 0x0BAF
BERKELEY_TRAILER = 0x1000
VALID_SYSTEMS = 0x1600
TRILL = 0x22F3
L2_ISIS = 0x22F4
PCS_BBP = 0x4242
DEC = 0x6000
DEC_MOP = 0x6001
DEC_MOP_RC = 0x6002
DEC_DECNET = 0x6003
DEC_LAT = 0x6004
DEC_DIAG = 0x6005
DEC_CUSTOMER = 0x6006
DEC_LAVC = 0x6007
TRANS_BRIDGING = 0x6558
RAW_FR = 0x6559
CRONUS_VLN = 0x8003
CRONUS_DIRECT = 0x8004
HP_PROBE = 0x8005
NESTAR = 0x8006
ATT = 0x8008
EXCELAN = 0x8010
SGI_DIAG = 0x8013
SGI_GAMES = 0x8014
SGI_RESERVED = 0x8015
SGI_BOUNCE = 0x8016
APOLLO_DOMAIN = 0x8019
TYMSHARE = 0x802E
TIGAN = 0x802F
AEONIC = 0x8036
DEC_LANBRIDGE = 0x8038
DEC_ENCRYPT = 0x803D
DEC_LTM = 0x803F
PRC = 0x8044
EXPERDATA = 0x8049
STANFORD_V = 0x805B
STANFORD_V_PROD = 0x805C
ES = 0x805D
LITTLE_MACHINES = 0x8060
COUNTERPOINT = 0x8062
UMASS = 0x8065
UMASS2 = 0x8066
VEECO = 0x8067
GD = 0x8068
AUTOPHON = 0x806A
COMDESIGN = 0x806C
COMPUTGRAPHIC = 0x806D
MATRA = 0x807A
DDE = 0x807B
MERIT = 0x807C
VITALINK = 0x8080
APPLETALK = 0x809B
SPIDER = 0x809F
NIXDORF = 0x80A3
BANYAN = 0x80C4
BANYAN2 = 0x80C5
PACER = 0x80C6
APPLITEK = 0x80C7
IBM_SNA = 0x80D5
VARIAN = 0x80DD
RETIX = 0x80F2
AARP = 0x80F3
APOLLO = 0x80F7
WELLFLEET = 0x80FF
HAYES = 0x8130
VG_LABS = 0x8131
NOVELL = 0x8137
NOVELL2 = 0x8138
LOGICRAFT = 0x8148
NCD = 0x8149
ALPHA_MICRO = 0x814A
SNMP = 0x814C
BIIN = 0x814D
BIIN2 = 0x814E
TEC = 0x814F
RATIONAL = 0x8150
XTP = 0x817D
SGI_TIMEWARNER = 0x817E
HIPPI_FP = 0x8180
HIPPI_ST = 0x8181
HIPPI_6400 = 0x8182
HIPPI_6400_2 = 0x8183
MOTOROLA = 0x818D
ARAI = 0x81A4
SECTRA = 0x86DB
DELTA = 0x86DE
ATOMIC = 0x86DF
TCP_COMP = 0x876B
IP_AS = 0x876C
SECURE_DATA = 0x876D
EPON = 0x8808
SLOW_PROTOCOLS = 0x8809
PPP = 0x880B
GSMP = 0x880C
NIC_TEST = 0x8822
MCAP = 0x8861
EXPERIMENTAL = 0x88B5
EXPERIMENTAL2 = 0x88B6
OUI_EXT = 0x88B7
PREAUTH = 0x88C7
PBB = 0x88E7
MVRP = 0x88F5
MMRP = 0x88F6
DOT11R = 0x890D
DOT21_MIH = 0x8917
DOT1QBE = 0x8929
TRILL_FGL = 0x893B
DOT1QBG_ECP = 0x8940
TRILL_CHANNEL = 0x8946
GEONETWORKING = 0x8947
NSH = 0x894F
THREECOM_XNS = 0x9001
THREECOM_TCPIP = 0x9002
THREECOM_LOOP = 0x9003
MULTI_TOPOLOGY = 0x9A22
LOWPAN = 0xA0ED
GRE_CHANNEL = 0xB7EA
RESERVED = 0xFFFF
