# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
import socket
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from LightPacket.helper.tcp.TCPOptions import TCPOptions
from LightPacket.utils.Checksum import transport_checksum

LLogger = Logger()

TCP_HEADER_MIN = 20
TCP_HEADER_MAX = 60

FIN = 0x001
SYN = 0x002
RST = 0x004
PSH = 0x008
ACK = 0x010
URG = 0x020
ECE = 0x040
CWR = 0x080
NS  = 0x100

FLAG_ALIASES = {
    'F': FIN, 'FIN': FIN,
    'S': SYN, 'SYN': SYN,
    'R': RST, 'RST': RST,
    'P': PSH, 'PSH': PSH,
    'A': ACK, 'ACK': ACK,
    'U': URG, 'URG': URG,
    'E': ECE, 'ECE': ECE,
    'C': CWR, 'CWR': CWR,
    'N': NS,  'NS':  NS,
}

FLAG_ORDER = [
    ('F', FIN),
    ('S', SYN),
    ('R', RST),
    ('P', PSH),
    ('A', ACK),
    ('U', URG),
    ('E', ECE),
    ('C', CWR),
    ('N', NS),
]

FLAG_LONG_NAMES = {
    FIN: "FIN", SYN: "SYN", RST: "RST", PSH: "PSH", ACK: "ACK",
    URG: "URG", ECE: "ECE", CWR: "CWR", NS:  "NS",
}


def _ones_complement_checksum(data: bytes) -> int:
    """16-bit one's complement checksum of a byte string."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def flags_to_str(flags: int) -> str:
    """Return canonical short string, e.g. 'SA' for SYN+ACK, 'FPA' for FIN+PSH+ACK."""
    return ''.join(letter for letter, bit in FLAG_ORDER if flags & bit)


def flags_to_list(flags: int) -> list:
    """Return list of long names, e.g. ['SYN', 'ACK']."""
    return [FLAG_LONG_NAMES[bit] for _, bit in FLAG_ORDER if flags & bit]


class TCP(BaseLayer):

    def __init__(self, sport=10000, dport=443, seq=0, ack=0,
                 data_offset=5, flags=0, window=65535,
                 checksum=None, urgent_ptr=0, options=None):
        super().__init__()
        self.sport = sport & 0xFFFF
        self.dport = dport & 0xFFFF
        self.seq = seq & 0xFFFFFFFF
        self.ack = ack & 0xFFFFFFFF
        self.data_offset = data_offset & 0x0F
        self.flags = flags & 0x1FF
        self.window = window & 0xFFFF
        self.checksum = checksum
        self.urgent_ptr = urgent_ptr & 0xFFFF

        if options is None:
            self.options = TCPOptions()
        elif isinstance(options, TCPOptions):
            self.options = options
        elif isinstance(options, (bytes, bytearray)):
            self.options = TCPOptions.parse(bytes(options))
        else:
            self.options = TCPOptions(list(options))

    def has_flag(self, flag) -> bool:
        bits = self._parse_flag_arg(flag)
        if bits is None:
            return False
        return (self.flags & bits) == bits

    def set_flag(self, flag, enabled: bool = True) -> None:
        """Enable or disable flag(s). Accepts the same forms as has_flag."""
        bits = self._parse_flag_arg(flag)
        if bits is None:
            return
        if enabled:
            self.flags |= bits
        else:
            self.flags &= ~bits & 0x1FF

    @staticmethod
    def _parse_flag_arg(flag):
        """Return an int bitmask, or None if unparseable."""
        if isinstance(flag, int):
            return flag & 0x1FF

        if isinstance(flag, (list, tuple)):
            total = 0
            for f in flag:
                sub = TCP._parse_flag_arg(f)
                if sub is None:
                    return None
                total |= sub
            return total

        if isinstance(flag, str):
            s = flag.strip().upper()

            if ',' in s or '-' in s or '+' in s:
                s = s.replace(',', ' ').replace('-', ' ').replace('+', ' ')
                parts = s.split()
                total = 0
                for p in parts:
                    sub = TCP._parse_flag_arg(p)
                    if sub is None:
                        return None
                    total |= sub
                return total

            if s in FLAG_ALIASES:
                return FLAG_ALIASES[s]

            total = 0
            for ch in s:
                if ch not in FLAG_ALIASES:
                    return None
                total |= FLAG_ALIASES[ch]
            return total

        return None

    def is_fin(self): return self.has_flag(FIN)
    def is_syn(self): return self.has_flag(SYN)
    def is_rst(self): return self.has_flag(RST)
    def is_psh(self): return self.has_flag(PSH)
    def is_ack(self): return self.has_flag(ACK)
    def is_urg(self): return self.has_flag(URG)
    def is_ece(self): return self.has_flag(ECE)
    def is_cwr(self): return self.has_flag(CWR)
    def is_ns(self):  return self.has_flag(NS)

    def is_syn_ack(self):  return self.has_flag('SA')
    def is_fin_ack(self):  return self.has_flag('FA')
    def is_psh_ack(self):  return self.has_flag('PA')
    def is_rst_ack(self):  return self.has_flag('RA')

    def flags_str(self) -> str:
        """Canonical short string: 'SA', 'FPA', '' etc."""
        return flags_to_str(self.flags)

    def flags_list(self) -> list:
        """List of long names: ['SYN', 'ACK']."""
        return flags_to_list(self.flags)

    def compute_checksum(self, src: str, dst: str, is_ipv6: bool = False) -> int:
        payload_bytes = self.get_payload_bytes()

        header_len = TCP_HEADER_MIN + self.options.padded_length
        tcp_length = header_len + len(payload_bytes)

        af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        src_bytes = socket.inet_pton(af, src)
        dst_bytes = socket.inet_pton(af, dst)

        offset_reserved_flags = (self.data_offset << 12) | (self.flags & 0x1FF)
        options_bytes = self.options.build()

        header_zero_csum = struct.pack(
            '>HHIIHHHH',
            self.sport, self.dport, self.seq, self.ack,
            offset_reserved_flags, self.window, 0, self.urgent_ptr
        ) + options_bytes

        transport_bytes = header_zero_csum + payload_bytes
        checksum = transport_checksum(src_bytes, dst_bytes, 6, transport_bytes)
        self.checksum = checksum
        return checksum

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        options_bytes = self.options.build()
        self.data_offset = (TCP_HEADER_MIN + len(options_bytes)) // 4

        checksum = self.checksum if self.checksum is not None else 0

        offset_reserved_flags = (self.data_offset << 12) | (self.flags & 0x1FF)

        header = struct.pack(
            '>HHIIHHHH',
            self.sport,
            self.dport,
            self.seq,
            self.ack,
            offset_reserved_flags,
            self.window,
            checksum,
            self.urgent_ptr,
        ) + options_bytes

        return header + payload_bytes

    def __len__(self):
        return TCP_HEADER_MIN + self.options.padded_length

    def __repr__(self):
        csum = f"0x{self.checksum:04x}" if self.checksum is not None else "None"
        return (f"<TCP sport={self.sport} dport={self.dport} "
                f"seq={self.seq} ack={self.ack} "
                f"flags=[{self.flags_str()}] "
                f"win={self.window} "
                f"checksum={csum} "
                f"options={len(self.options)} "
                f"len={len(self)}>")

    def copy(self) -> 'TCP':
        new_layer = TCP(
            sport=self.sport,
            dport=self.dport,
            seq=self.seq,
            ack=self.ack,
            data_offset=self.data_offset,
            flags=self.flags,
            window=self.window,
            checksum=self.checksum,
            urgent_ptr=self.urgent_ptr,
            options=self.options.copy(),
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        csum = f"0x{self.checksum:04x}" if self.checksum is not None else "None"
        fields = [
            f"sport={self.sport}",
            f"dport={self.dport}",
            f"seq={self.seq}",
            f"ack={self.ack}",
            f"data_offset={self.data_offset} ({self.data_offset * 4} bytes)",
            f"flags=0x{self.flags:03x} [{self.flags_str()}] ({', '.join(self.flags_list()) or 'none'})",
            f"window={self.window}",
            f"checksum={csum}",
            f"urgent_ptr={self.urgent_ptr}",
        ]
        if self.options:
            fields.append(f"options={self.options!r}")
        return fields


class TCPParser:

    @staticmethod
    def load_as_tcp_layer(raw_packet, Alr=0, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        raw = raw_packet[0]

        if len(raw) < TCP_HEADER_MIN:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="TCP required header is 20 bytes")
            return None

        (sport, dport, seq, ack, offset_reserved_flags,
         window, checksum, urgent_ptr) = struct.unpack('>HHIIHHHH', raw[:TCP_HEADER_MIN])

        data_offset = (offset_reserved_flags >> 12) & 0x0F
        flags = offset_reserved_flags & 0x1FF

        if data_offset < 5:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message=f"TCP data_offset too small ({data_offset})")
            return None

        header_len = data_offset * 4
        if header_len > TCP_HEADER_MAX:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message=f"TCP header too long ({header_len})")
            return None

        if len(raw) < header_len:
            LLogger.error(error_code=ErrorCode.TRUNCATED_DATA,
                          message=f"TCP options truncated (need {header_len}, have {len(raw)})")
            return None

        options_bytes = raw[TCP_HEADER_MIN:header_len]
        options = TCPOptions.parse(options_bytes)
        payload = raw[header_len:]

        tcp = TCP(
            sport=sport, dport=dport,
            seq=seq, ack=ack,
            data_offset=data_offset, flags=flags,
            window=window, checksum=checksum,
            urgent_ptr=urgent_ptr,
            options=options,
        )

        if verbose:
            print(f"\n{BOLD}TCP LAYER : {RESET}Len({PURPLE}{header_len}{RESET}) "
                  f"Total Len({PURPLE}{len(raw)}{RESET}) >")
            print(f'   {BLUE}SPORT:{CYAN} {sport}')
            print(f'   {BLUE}DPORT:{CYAN} {dport}')
            print(f'   {BLUE}SEQ:{CYAN} {seq}')
            print(f'   {BLUE}ACK:{CYAN} {ack}')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:03x} [{tcp.flags_str()}] 'f'({", ".join(tcp.flags_list()) or "none"})')
            print(f'   {BLUE}WINDOW:{CYAN} {window}')
            print(f'   {BLUE}CHECKSUM:{CYAN} 0x{checksum:04x}')
            print(f'   {BLUE}URGENT PTR:{CYAN} {urgent_ptr} {RESET}')
            if options:
                print(f'   {BLUE}OPTIONS:{CYAN} {len(options)} option(s), '
                      f'{options.raw_length} bytes {RESET}')
                for opt in options:
                    print(f'      {BLUE}- {opt!r} {RESET}')

        if len(payload) > 0 and Alr != 1 and payload != b'':
            from LightPacket.Raw import RawParser
            return tcp / RawParser.load_as_Raw_layer(payload, verbose=verbose)

        return tcp