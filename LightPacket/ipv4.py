# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from LightPacket.helper.ipv4.IPtoa import inet_aton, inet_ntoa
from LightPacket.helper.ipv4.IPOptions import IPOptions, OPT_NAMES
from LightPacket.utils.Checksum import ipv4_header_checksum

LLogger = Logger()


PROTO_ICMP = 1
PROTO_IGMP = 2
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_IPV6 = 41
PROTO_SCTP = 132

IP_PROTOCOLS = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    3: "GGP",
    4: "IPv4",
    5: "ST",
    6: "TCP",
    7: "CBT",
    8: "EGP",
    9: "IGP",
    10: "BBN-RCC-MON",
    11: "NVP-II",
    12: "PUP",
    13: "ARGUS (deprecated)",
    14: "EMCON",
    15: "XNET",
    16: "CHAOS",
    17: "UDP",
    18: "MUX",
    19: "DCN-MEAS",
    20: "HMP",
    21: "PRM",
    22: "XNS-IDP",
    23: "TRUNK-1",
    24: "TRUNK-2",
    25: "LEAF-1",
    26: "LEAF-2",
    27: "RDP",
    28: "IRTP",
    29: "ISO-TP4",
    30: "NETBLT",
    31: "MFE-NSP",
    32: "MERIT-INP",
    33: "DCCP",
    34: "3PC",
    35: "IDPR",
    36: "XTP",
    37: "DDP",
    38: "IDPR-CMTP",
    39: "TP++",
    40: "IL",
    41: "IPv6",
    42: "SDRP",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    45: "IDRP",
    46: "RSVP",
    47: "GRE",
    48: "DSR",
    49: "BNA",
    50: "ESP",
    51: "AH",
    52: "I-NLSP",
    53: "SWIPE (deprecated)",
    54: "NARP",
    55: "Min-IPv4",
    56: "TLSP",
    57: "SKIP",
    58: "IPv6-ICMP",
    59: "IPv6-NoNxt",
    60: "IPv6-Opts",
    61: "any host internal protocol",
    62: "CFTP",
    63: "any local network",
    64: "SAT-EXPAK",
    65: "KRYPTOLAN",
    66: "RVD",
    67: "IPPC",
    68: "any distributed file system",
    69: "SAT-MON",
    70: "VISA",
    71: "IPCV",
    72: "CPNX",
    73: "CPHB",
    74: "WSN",
    75: "PVP",
    76: "BR-SAT-MON",
    77: "SUN-ND",
    78: "WB-MON",
    79: "WB-EXPAK",
    80: "ISO-IP",
    81: "VMTP",
    82: "SECURE-VMTP",
    83: "VINES",
    84: "IPTM",
    85: "NSFNET-IGP",
    86: "DGP",
    87: "TCF",
    88: "EIGRP",
    89: "OSPFIGP",
    90: "Sprite-RPC",
    91: "LARP",
    92: "MTP",
    93: "AX.25",
    94: "IPIP",
    95: "MICP (deprecated)",
    96: "SCC-SP",
    97: "ETHERIP",
    98: "ENCAP",
    99: "any private encryption scheme",
    100: "GMTP",
    101: "IFMP",
    102: "PNNI",
    103: "PIM",
    104: "ARIS",
    105: "SCPS",
    106: "QNX",
    107: "A/N",
    108: "IPComp",
    109: "SNP",
    110: "Compaq-Peer",
    111: "IPX-in-IP",
    112: "VRRP",
    113: "PGM",
    114: "any 0-hop protocol",
    115: "L2TP",
    116: "DDX",
    117: "IATP",
    118: "STP",
    119: "SRP",
    120: "UTI",
    121: "SMP",
    122: "SM (deprecated)",
    123: "PTP",
    124: "ISIS over IPv4",
    125: "FIRE",
    126: "CRTP",
    127: "CRUDP",
    128: "SSCOPMCE",
    129: "IPLT",
    130: "SPS",
    131: "PIPE",
    132: "SCTP",
    133: "FC",
    134: "RSVP-E2E-IGNORE",
    135: "Mobility Header",
    136: "UDPLite",
    137: "MPLS-in-IP",
    138: "manet",
    139: "HIP",
    140: "Shim6",
    141: "WESP",
    142: "ROHC",
    143: "Ethernet",
    144: "AGGFRAG",
    145: "NSH",
    146: "Homa",
    147: "BIT-EMU",
    253: "Use for experimentation and testing",
    254: "Use for experimentation and testing",
    255: "Reserved",
}

IP_PROTOCOLS.update({i: "Unassigned" for i in range(148, 253)})


class IPv4(BaseLayer):
    def __init__(self,
                 dst=None,
                 src=None,
                 proto=None,
                 ttl=64,
                 tos=0,
                 ihl=0,
                 id=0,
                 flags=0,
                 frag_offset=0,
                 version=4,
                 options=None,
                 total_len=None,
                 checksum=None):
        super().__init__()
        self.version = version
        self.tos = tos
        self.total_len = total_len
        self.id = id
        self.flags = flags & 0x07
        self.frag_offset = frag_offset & 0x1FFF
        self.ttl = ttl
        self.proto = proto
        self.checksum = checksum
        self.ihl = ihl
        self.src = str(src) if src is not None else None
        self.dst = str(dst) if dst is not None else None

        if options is None:
            self.options = IPOptions()
        elif isinstance(options, IPOptions):
            self.options = options
        elif isinstance(options, (bytes, bytearray)):
            self.options = IPOptions.parse(bytes(options))
        else:
            self.options = IPOptions(list(options))

    @property
    def _ihl(self) -> int:
        return 5 + (self.options.padded_length // 4)

    def build(self) -> bytes:
        layer = self.payload.__class__.__name__
        if self.proto is None:
            self.proto = {
                'UDP':  PROTO_UDP,
                'TCP':  PROTO_TCP
            }.get(layer, PROTO_TCP)

        options_bytes = self.options.build()
        if self.ihl == 0:
            self.ihl = self._ihl
        else:
            pass

        src = self.src
        if src is None:
            from LightPacket.GetIPv4 import GetIPv4
            src = GetIPv4()
        dst = self.dst if self.dst is not None else "0.0.0.0"

        if layer == 'UDP' and self.payload.checksum is None:
            self.payload.compute_checksum(src=src, dst=dst, is_ipv6=False)
        elif layer == 'TCP' and self.payload.checksum is None:
            self.payload.compute_checksum(src=src, dst=dst, is_ipv6=False)

        payload_bytes = self.get_payload_bytes()

        total_len = self.total_len
        if total_len is None:
            total_len = self.ihl * 4 + len(payload_bytes)

        flags_frag = ((self.flags & 0x07) << 13) | (self.frag_offset & 0x1FFF)

        def _pack(checksum):
            return struct.pack(
                '>BBHHHBBH4s4s',
                (self.version << 4) | (self.ihl & 0x0F),
                self.tos,
                total_len,
                self.id,
                flags_frag,
                self.ttl,
                self.proto,
                checksum,
                inet_aton(src),
                inet_aton(dst),
            ) + options_bytes

        checksum = self.checksum
        if checksum is None:
            checksum = ipv4_header_checksum(_pack(0))

        self.total_len = total_len
        self.src = src
        self.dst = dst
        self.checksum = checksum

        return _pack(checksum) + payload_bytes

    def __len__(self):
        return self.ihl * 4

    def __repr__(self):
        proto_name = IP_PROTOCOLS.get(self.proto, f"proto={self.proto}")
        return (f"<IP src={self.src} dst={self.dst} "
                f"proto={self.proto} ({proto_name}) "
                f"ttl={self.ttl} "
                f"ihl={self.ihl} "
                f"total_len={self.total_len} "
                f"len={self.ihl * 4} (bytes) "
                f"options={len(self.options)} >")

    def copy(self) -> 'IPv4':
        new_layer = IPv4(
            dst=self.dst,
            src=self.src,
            proto=self.proto,
            ttl=self.ttl,
            tos=self.tos,
            id=self.id,
            flags=self.flags,
            frag_offset=self.frag_offset,
            options=self.options.copy(),
            total_len=self.total_len,
            checksum=self.checksum,
            ihl=self.ihl,
            version=self.version
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        proto_name = IP_PROTOCOLS.get(self.proto, str(self.proto))
        fields = [
            f"src={self.src}",
            f"dst={self.dst}",
            f"proto={self.proto} ({proto_name})",
            f"ttl={self.ttl}",
            f"id={self.id}",
            f"ihl={self.ihl}",
            f"total_len={self.total_len}",
            f"checksum=0x{self.checksum:04x}" if self.checksum else "checksum=None",
        ]
        if self.options:
            fields.append(f"options={self.options!r}")
        return fields


class IPv4Parser:

    @staticmethod
    def load_as_ip_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        raw = raw_packet[0]

        if len(raw) < 20:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="IPv4 required header is 20 bytes")
            return None

        (version_ihl, tos, total_len, id_, flags_frag,
         ttl, proto, checksum,
         src_bytes, dst_bytes) = struct.unpack('>BBHHHBBH4s4s', raw[:20])

        version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F

        if version != 4:
            if version == 6:
                from LightPacket.ipv6 import IPv6Parser
                IPv6Parser.load_as_ip_layer(raw_packet, verbose=verbose)
                return
            else:
                LLogger.error(error_code=ErrorCode.INVALID_VESRION,
                              message=f"IPv4 version mismatch (got {version})")
                return None

        if ihl < 5:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message=f"IPv4 IHL too small ({ihl})")
            return None

        header_len = ihl * 4
        if len(raw) < header_len:
            LLogger.error(error_code=ErrorCode.TRUNCATED_DATA,
                          message=f"IPv4 options truncated (need {header_len})")
            return None

        options_bytes = raw[20:header_len] if header_len > 20 else b""
        options = IPOptions.parse(options_bytes)
        payload = raw[header_len:]

        flags = (flags_frag >> 13) & 0x07
        frag_offset = flags_frag & 0x1FFF

        src_str = inet_ntoa(src_bytes)
        dst_str = inet_ntoa(dst_bytes)

        ip = IPv4(
            dst=dst_str,
            src=src_str,
            proto=proto,
            ttl=ttl,
            tos=tos,
            id=id_,
            flags=flags,
            frag_offset=frag_offset,
            options=options,
            total_len=total_len,
            checksum=checksum,
            ihl=ihl,
            version=version
        )

        if verbose:
            proto_name = IP_PROTOCOLS.get(proto, str(proto))
            print(f"\n{BOLD}IPv4 LAYER : {RESET}IHL({PURPLE}{ihl}{RESET}) "f"Total Len({PURPLE}{total_len}{RESET}) >")
            print(f'   {BLUE}SRC:{CYAN} {src_str}')
            print(f'   {BLUE}DST:{CYAN} {dst_str}')
            print(f'   {BLUE}VERSION:{CYAN} {version}')
            print(f'   {BLUE}PROTO:{CYAN} {proto} ({proto_name})')
            print(f'   {BLUE}TLEN:{CYAN} {total_len}')
            print(f'   {BLUE}TTL:{CYAN} {ttl}')
            print(f'   {BLUE}TOS:{CYAN} {tos}')
            print(f'   {BLUE}ID:{CYAN} {id_}')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:02x} | FRAG:{frag_offset}')
            print(f'   {BLUE}FRAG-OFFSET:{CYAN} 0x{frag_offset:02x}')
            print(f'   {BLUE}CHECKSUM:{CYAN} 0x{checksum:02x} {RESET}')

            if options:
                print(f'   {BLUE}OPTIONS:{CYAN} {len(options)} option(s), '
                      f'{options.raw_length} bytes {RESET}')
                for opt in options:
                    name = OPT_NAMES.get(opt.type, str(opt.type))
                    print(f'      {BLUE}- {name}:{CYAN} {opt!r} {RESET}')

        if len(payload) > 0 and payload != b'':
            if proto == 17:
                from LightPacket.udp import UDPParser
                return ip / UDPParser.load_as_udp_layer(payload, verbose=verbose)

            if proto == 6:
                from LightPacket.tcp import TCPParser
                return ip / TCPParser.load_as_tcp_layer(payload, verbose=verbose)

            from LightPacket.Raw import RawParser
            return ip / RawParser.load_as_Raw_layer(payload, verbose=verbose)

        return ip
