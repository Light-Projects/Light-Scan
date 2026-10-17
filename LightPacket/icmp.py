# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
import socket
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from LightPacket.helper.ipv4.IPtoa import inet_aton, inet_ntoa
from LightPacket.utils.Checksum import transport_checksum

LLogger = Logger()

ICMP_HEADER_MIN = 8

# ---------------------------------------------------------------------------
# Type / Code constants (RFC 792, RFC 950, RFC 1256, RFC 1812, RFC 4884)
# ---------------------------------------------------------------------------
ICMP_ECHO_REPLY            = 0
ICMP_DEST_UNREACH          = 3
ICMP_SOURCE_QUENCH         = 4
ICMP_REDIRECT              = 5
ICMP_ALTERNATE_HOST        = 6    # deprecated
ICMP_ECHO_REQUEST          = 8
ICMP_ROUTER_ADVERTISEMENT  = 9
ICMP_ROUTER_SOLICITATION   = 10
ICMP_TIME_EXCEEDED         = 11
ICMP_PARAMETER_PROBLEM     = 12
ICMP_TIMESTAMP             = 13
ICMP_TIMESTAMP_REPLY       = 14
ICMP_INFO_REQUEST          = 15   # deprecated
ICMP_INFO_REPLY            = 16   # deprecated
ICMP_ADDRESS_MASK_REQUEST  = 17   # deprecated
ICMP_ADDRESS_MASK_REPLY    = 18   # deprecated
ICMP_TRACEROUTE            = 30
ICMP_DATAGRAM_CONVERSION   = 31   # deprecated
ICMP_MOBILE_HOST_REDIRECT  = 32   # deprecated
ICMP_IPV6_WHERE_ARE_YOU    = 33   # deprecated
ICMP_IPV6_I_AM_HERE        = 34   # deprecated
ICMP_MOBILE_REG_REQUEST    = 35   # deprecated
ICMP_MOBILE_REG_REPLY      = 36   # deprecated
ICMP_DOMAIN_NAME_REQUEST   = 37   # deprecated
ICMP_DOMAIN_NAME_REPLY     = 38   # deprecated
ICMP_SKIP_DISCOVERY        = 39   # deprecated
ICMP_PHOTURIS              = 40   # deprecated
ICMP_EXT_ECHO_REQUEST      = 42   # RFC 8335
ICMP_EXT_ECHO_REPLY        = 43   # RFC 8335

ICMP_TYPES = {
    0:  "echo-reply",
    3:  "dest-unreach",
    4:  "source-quench",
    5:  "redirect",
    6:  "alternate-host",
    8:  "echo-request",
    9:  "router-advertisement",
    10: "router-solicitation",
    11: "time-exceeded",
    12: "parameter-problem",
    13: "timestamp",
    14: "timestamp-reply",
    15: "info-request",
    16: "info-reply",
    17: "address-mask-request",
    18: "address-mask-reply",
    30: "traceroute",
    31: "datagram-conversion-error",
    32: "mobile-host-redirect",
    33: "ipv6-where-are-you",
    34: "ipv6-i-am-here",
    35: "mobile-registration-request",
    36: "mobile-registration-reply",
    37: "domain-name-request",
    38: "domain-name-reply",
    39: "skip-discovery",
    40: "photuris",
    42: "extended-echo-request",
    43: "extended-echo-reply",
}

# Destination Unreachable codes (RFC 792 / 1812 / 1122)
DEST_UNREACH_CODES = {
    0:  "net-unreachable",
    1:  "host-unreachable",
    2:  "protocol-unreachable",
    3:  "port-unreachable",
    4:  "fragmentation-needed",
    5:  "source-route-failed",
    6:  "dest-network-unknown",
    7:  "dest-host-unknown",
    8:  "source-host-isolated",
    9:  "net-admin-prohibited",
    10: "host-admin-prohibited",
    11: "net-unreachable-tos",
    12: "host-unreachable-tos",
    13: "communication-prohibited",
    14: "host-precedence-violation",
    15: "precedence-cutoff",
}

# Redirect codes (RFC 792 / 1812)
REDIRECT_CODES = {
    0: "redirect-net",
    1: "redirect-host",
    2: "redirect-tos-net",
    3: "redirect-tos-host",
}

# Time Exceeded codes
TIME_EXCEEDED_CODES = {
    0: "ttl-exceeded-in-transit",
    1: "fragment-reassembly-timeout",
}

# Parameter Problem codes
PARAM_PROBLEM_CODES = {
    0: "pointer-indicates-error",
    1: "missing-required-option",
    2: "bad-length",
}

# Photuris codes
PHOTURIS_CODES = {
    0: "bad-spi",
    1: "authentication-failed",
    2: "decompression-failed",
    3: "decryption-failed",
    4: "need-authentication",
    5: "need-authorization",
}

# Extended Echo (RFC 8335) codes
EXT_ECHO_CODES = {
    0: "no-error",
    1: "malformed-query",
    2: "no-such-interface",
    3: "no-such-table-entry",
}

# Extended Echo reply Query-Type / reply flags (byte 1)
EXT_ECHO_REPLY_VALUES = {
    0: "no-reply",
    1: "ipv4-reply",
    2: "ipv6-reply",
    3: "ipv4-ipv6-reply",
}

# Types that carry the (id, seq, unused) triple (echo / timestamp / info / mask / router)
_ECHO_LIKE_TYPES = {
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    ICMP_TIMESTAMP,
    ICMP_TIMESTAMP_REPLY,
    ICMP_INFO_REQUEST,
    ICMP_INFO_REPLY,
    ICMP_ADDRESS_MASK_REQUEST,
    ICMP_ADDRESS_MASK_REPLY,
    ICMP_ROUTER_ADVERTISEMENT,
    ICMP_ROUTER_SOLICITATION,
    ICMP_EXT_ECHO_REQUEST,
    ICMP_EXT_ECHO_REPLY,
}

# Types that carry a 4-byte "unused / gateway / pointer" field instead
_UNUSED_TYPES = {
    ICMP_DEST_UNREACH,
    ICMP_SOURCE_QUENCH,
    ICMP_REDIRECT,
    ICMP_TIME_EXCEEDED,
    ICMP_PARAMETER_PROBLEM,
    ICMP_ALTERNATE_HOST,
    ICMP_DATAGRAM_CONVERSION,
    ICMP_MOBILE_HOST_REDIRECT,
    ICMP_IPV6_WHERE_ARE_YOU,
    ICMP_IPV6_I_AM_HERE,
    ICMP_MOBILE_REG_REQUEST,
    ICMP_MOBILE_REG_REPLY,
    ICMP_DOMAIN_NAME_REQUEST,
    ICMP_DOMAIN_NAME_REPLY,
    ICMP_SKIP_DISCOVERY,
    ICMP_PHOTURIS,
}


class ICMP(BaseLayer):

    def __init__(self,
                 type: int = ICMP_ECHO_REQUEST,
                 code: int = 0,
                 checksum: int = None,
                 id: int = 1000,
                 seq: int = 20,
                 unused: int = 0,
                 gateway: str = None,
                 pointer: int = 0,
                 num_addrs: int = 0,
                 addr_entry_size: int = 2,
                 lifetime: int = 0,
                 orig_ts: int = 0,
                 recv_ts: int = 0,
                 trans_ts: int = 0,
                 mask: str = None,
                 reserved: int = 0):

        super().__init__()
        self.type = type & 0xFF
        self.code = code & 0xFF
        self.checksum = checksum
        self.id = id & 0xFFFF
        self.seq = seq & 0xFFFF
        self.unused = unused & 0xFFFFFFFF

        self.gateway = gateway
        self.pointer = pointer & 0xFF

        self.num_addrs = num_addrs & 0xFF
        self.addr_entry_size = addr_entry_size & 0xFF
        self.lifetime = lifetime & 0xFFFF

        self.orig_ts = orig_ts & 0xFFFFFFFF
        self.recv_ts = recv_ts & 0xFFFFFFFF
        self.trans_ts = trans_ts & 0xFFFFFFFF

        self.mask = mask

        self.reserved = reserved & 0xFFFFFFFF

    # ------------------------------------------------------------------ #
    # Accessors
    # ------------------------------------------------------------------ #
    def is_echo_request(self):      return self.type == ICMP_ECHO_REQUEST
    def is_echo_reply(self):        return self.type == ICMP_ECHO_REPLY
    def is_dest_unreachable(self):  return self.type == ICMP_DEST_UNREACH
    def is_time_exceeded(self):     return self.type == ICMP_TIME_EXCEEDED
    def is_redirect(self):          return self.type == ICMP_REDIRECT
    def is_parameter_problem(self): return self.type == ICMP_PARAMETER_PROBLEM
    def is_timestamp(self):         return self.type in (ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY)
    def is_address_mask(self):      return self.type in (ICMP_ADDRESS_MASK_REQUEST, ICMP_ADDRESS_MASK_REPLY)
    def is_router(self):            return self.type in (ICMP_ROUTER_SOLICITATION, ICMP_ROUTER_ADVERTISEMENT)
    def is_extended_echo(self):     return self.type in (ICMP_EXT_ECHO_REQUEST, ICMP_EXT_ECHO_REPLY)

    def type_name(self) -> str:
        return ICMP_TYPES.get(self.type, f"type-{self.type}")

    def code_name(self) -> str:
        if self.type == ICMP_DEST_UNREACH:
            return DEST_UNREACH_CODES.get(self.code, f"code-{self.code}")
        if self.type == ICMP_TIME_EXCEEDED:
            return TIME_EXCEEDED_CODES.get(self.code, f"code-{self.code}")
        if self.type == ICMP_REDIRECT:
            return REDIRECT_CODES.get(self.code, f"code-{self.code}")
        if self.type == ICMP_PARAMETER_PROBLEM:
            return PARAM_PROBLEM_CODES.get(self.code, f"code-{self.code}")
        if self.type == ICMP_PHOTURIS:
            return PHOTURIS_CODES.get(self.code, f"code-{self.code}")
        if self.type in (ICMP_EXT_ECHO_REQUEST, ICMP_EXT_ECHO_REPLY):
            return EXT_ECHO_CODES.get(self.code, f"code-{self.code}")
        return f"code-{self.code}"

    # ------------------------------------------------------------------ #
    # Serialization
    # ------------------------------------------------------------------ #
    def _build_rest_of_header(self) -> bytes:
        """Build the 4-byte field that follows Type/Code/Checksum."""
        t = self.type

        if t in (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST,
                 ICMP_INFO_REQUEST, ICMP_INFO_REPLY,
                 ICMP_EXT_ECHO_REQUEST, ICMP_EXT_ECHO_REPLY):
            return struct.pack('>HH', self.id, self.seq)

        if t in (ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY):
            return struct.pack('>HH', self.id, self.seq)

        if t in (ICMP_ADDRESS_MASK_REQUEST, ICMP_ADDRESS_MASK_REPLY):
            return struct.pack('>HH', self.id, self.seq)

        if t == ICMP_REDIRECT:
            gw = self.gateway if self.gateway is not None else "0.0.0.0"
            return inet_aton(gw)

        if t == ICMP_PARAMETER_PROBLEM:
            return struct.pack('>BBH', self.pointer, 0, 0)

        if t in (ICMP_ROUTER_SOLICITATION, ICMP_ROUTER_ADVERTISEMENT):
            return struct.pack('>BBH', self.num_addrs,
                               self.addr_entry_size, self.lifetime)

        if t in _UNUSED_TYPES:
            return struct.pack('>I', self.unused)

        return struct.pack('>I', self.unused)

    def compute_checksum(self, src: str = None, dst: str = None, is_ipv6: bool = False) -> int:
        rest = self._build_rest_of_header()
        message = struct.pack('>BBH', self.type, self.code, 0) + rest + self.get_payload_bytes()

        if is_ipv6:
            src_bytes = socket.inet_pton(socket.AF_INET6, src) if src else b'\x00' * 16
            dst_bytes = socket.inet_pton(socket.AF_INET6, dst) if dst else b'\x00' * 16
            self.checksum = transport_checksum(src_bytes, dst_bytes, 58, message)
        else:
            if len(message) % 2:
                message += b'\x00'

            total = 0
            for i in range(0, len(message), 2):
                total += (message[i] << 8) | message[i + 1]
                total = (total & 0xFFFF) + (total >> 16)

            self.checksum = (~total) & 0xFFFF

        return self.checksum

    def build(self) -> bytes:

        rest = self._build_rest_of_header()
        payload_bytes = self.get_payload_bytes()
        data = payload_bytes

        checksum = self.checksum if self.checksum is not None else 0
        header = struct.pack('>BBH', self.type, self.code, checksum) + rest
        return header + data

    def __len__(self):
        return ICMP_HEADER_MIN

    def __repr__(self):
        csum = f"0x{self.checksum:04x}" if self.checksum is not None else "None"
        return (f"<ICMP type={self.type} ({self.type_name()}) "
                f"code={self.code} ({self.code_name()}) "
                f"checksum={csum} "
                f"id={self.id} seq={self.seq} >")

    def copy(self) -> 'ICMP':
        new_layer = ICMP(
            type=self.type,
            code=self.code,
            checksum=self.checksum,
            id=self.id,
            seq=self.seq,
            unused=self.unused,
            gateway=self.gateway,
            pointer=self.pointer,
            num_addrs=self.num_addrs,
            addr_entry_size=self.addr_entry_size,
            lifetime=self.lifetime,
            orig_ts=self.orig_ts,
            recv_ts=self.recv_ts,
            trans_ts=self.trans_ts,
            mask=self.mask,
            reserved=self.reserved,
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        csum = f"0x{self.checksum:04x}" if self.checksum is not None else "None"
        fields = [
            f"type={self.type} ({self.type_name()})",
            f"code={self.code} ({self.code_name()})",
            f"checksum={csum}",
        ]

        if self.type in _ECHO_LIKE_TYPES:
            fields.append(f"id={self.id}")
            fields.append(f"seq={self.seq}")
        elif self.type == ICMP_REDIRECT:
            fields.append(f"gateway={self.gateway}")
        elif self.type == ICMP_PARAMETER_PROBLEM:
            fields.append(f"pointer={self.pointer}")
        elif self.type in (ICMP_ROUTER_SOLICITATION, ICMP_ROUTER_ADVERTISEMENT):
            fields.append(f"num_addrs={self.num_addrs}")
            fields.append(f"addr_entry_size={self.addr_entry_size}")
            fields.append(f"lifetime={self.lifetime}")
        elif self.type in (ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY):
            fields.append(f"id={self.id}")
            fields.append(f"seq={self.seq}")
            fields.append(f"orig_ts={self.orig_ts}")
            fields.append(f"recv_ts={self.recv_ts}")
            fields.append(f"trans_ts={self.trans_ts}")
        elif self.type in (ICMP_ADDRESS_MASK_REQUEST, ICMP_ADDRESS_MASK_REPLY):
            fields.append(f"id={self.id}")
            fields.append(f"seq={self.seq}")
            fields.append(f"mask={self.mask}")
        else:
            fields.append(f"unused=0x{self.unused:08x}")

        return fields


class ICMPParser:

    @staticmethod
    def load_as_icmp_layer(raw_packet, Alr=0, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        raw = raw_packet[0]

        if len(raw) < ICMP_HEADER_MIN:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="ICMP required header is 8 bytes")
            return None

        icmp_type, code, checksum = struct.unpack('>BBH', raw[:4])
        rest = raw[4:8]
        payload = raw[8:]

        id_ = 0
        seq = 0
        unused = 0
        gateway = None
        pointer = 0
        num_addrs = 0
        addr_entry_size = 0
        lifetime = 0
        orig_ts = recv_ts = trans_ts = 0
        mask = None

        if icmp_type in (ICMP_ECHO_REPLY, ICMP_ECHO_REQUEST,
                         ICMP_INFO_REQUEST, ICMP_INFO_REPLY,
                         ICMP_EXT_ECHO_REQUEST, ICMP_EXT_ECHO_REPLY):
            id_, seq = struct.unpack('>HH', rest)

        elif icmp_type in (ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY):
            id_, seq = struct.unpack('>HH', rest)
            if len(payload) >= 12:
                orig_ts, recv_ts, trans_ts = struct.unpack('>III', payload[:12])
                payload = payload[12:]

        elif icmp_type in (ICMP_ADDRESS_MASK_REQUEST, ICMP_ADDRESS_MASK_REPLY):
            id_, seq = struct.unpack('>HH', rest)
            if len(payload) >= 4:
                mask = inet_ntoa(payload[:4])
                payload = payload[4:]

        elif icmp_type == ICMP_REDIRECT:
            gateway = inet_ntoa(rest)

        elif icmp_type == ICMP_PARAMETER_PROBLEM:
            pointer = rest[0]

        elif icmp_type in (ICMP_ROUTER_SOLICITATION, ICMP_ROUTER_ADVERTISEMENT):
            num_addrs, addr_entry_size, lifetime = struct.unpack('>BBH', rest)

        elif icmp_type in _UNUSED_TYPES:
            unused, = struct.unpack('>I', rest)

        else:
            unused, = struct.unpack('>I', rest)

        icmp = ICMP(
            type=icmp_type,
            code=code,
            checksum=checksum,
            id=id_,
            seq=seq,
            unused=unused,
            gateway=gateway,
            pointer=pointer,
            num_addrs=num_addrs,
            addr_entry_size=addr_entry_size,
            lifetime=lifetime,
            orig_ts=orig_ts,
            recv_ts=recv_ts,
            trans_ts=trans_ts,
            mask=mask,
        )

        if verbose:
            print(f"\n{BOLD}ICMP LAYER : {RESET}Len({PURPLE}{ICMP_HEADER_MIN}{RESET}) "
                  f"Total Len({PURPLE}{len(raw)}{RESET}) >")
            print(f'   {BLUE}TYPE:{CYAN} {icmp_type} ({icmp.type_name()})')
            print(f'   {BLUE}CODE:{CYAN} {code} ({icmp.code_name()})')
            print(f'   {BLUE}CHECKSUM:{CYAN} 0x{checksum:04x}')

            if icmp_type in _ECHO_LIKE_TYPES:
                print(f'   {BLUE}ID:{CYAN} {id_}')
                print(f'   {BLUE}SEQ:{CYAN} {seq}')
            elif icmp_type == ICMP_REDIRECT:
                print(f'   {BLUE}GATEWAY:{CYAN} {gateway}')
            elif icmp_type == ICMP_PARAMETER_PROBLEM:
                print(f'   {BLUE}POINTER:{CYAN} {pointer}')
            elif icmp_type in (ICMP_ROUTER_SOLICITATION, ICMP_ROUTER_ADVERTISEMENT):
                print(f'   {BLUE}NUM ADDRS:{CYAN} {num_addrs}')
                print(f'   {BLUE}ADDR ENTRY SIZE:{CYAN} {addr_entry_size}')
                print(f'   {BLUE}LIFETIME:{CYAN} {lifetime}')
            elif icmp_type in (ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY):
                print(f'   {BLUE}ID:{CYAN} {id_}')
                print(f'   {BLUE}SEQ:{CYAN} {seq}')
                print(f'   {BLUE}ORIG TS:{CYAN} {orig_ts}')
                print(f'   {BLUE}RECV TS:{CYAN} {recv_ts}')
                print(f'   {BLUE}TRANS TS:{CYAN} {trans_ts}')
            elif icmp_type in (ICMP_ADDRESS_MASK_REQUEST, ICMP_ADDRESS_MASK_REPLY):
                print(f'   {BLUE}ID:{CYAN} {id_}')
                print(f'   {BLUE}SEQ:{CYAN} {seq}')
                print(f'   {BLUE}MASK:{CYAN} {mask}')
            else:
                print(f'   {BLUE}UNUSED:{CYAN} 0x{unused:08x}')
            print(f'{RESET}', end='')

        if len(payload) > 0 and Alr != 1 and payload != b'':
            from LightPacket.Raw import RawParser
            return icmp / RawParser.load_as_Raw_layer(payload, verbose=verbose)

        return icmp