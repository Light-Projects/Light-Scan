# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BLUE,CYAN,RESET

LLogger = Logger()

EXT_HOP_BY_HOP = 0
EXT_ROUTING = 43
EXT_FRAGMENT = 44
EXT_DESTINATION_OPTIONS = 60
EXT_MOBILITY = 135

FIXED_LENGTH_TYPES = (EXT_FRAGMENT,)
FRAGMENT_HEADER_LEN = 8

EXT_HEADER_NAMES = {
    EXT_HOP_BY_HOP: "Hop-by-Hop Options",
    EXT_ROUTING: "Routing",
    EXT_FRAGMENT: "Fragment",
    EXT_DESTINATION_OPTIONS: "Destination Options",
    EXT_MOBILITY: "Mobility",
}

PROTO_NAMES = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}
PROTO_NAMES.update(EXT_HEADER_NAMES)


class IPv6ExtHeader(BaseLayer):
    """
    Generic IPv6 extension header (RFC 8200 s4).

    Covers Hop-by-Hop Options (0), Routing (43), Destination Options (60)
    and Mobility (135) via the standard TLV-chained layout:

        +-------------+-------------+------------------------------+
        | next_header |hdr_ext_len  |   type-specific data ...      |
        +-------------+-------------+------------------------------+
             1 byte       1 byte      (hdr_ext_len + 1) * 8 - 2 bytes

    Fragment (44) is special-cased: it has no hdr_ext_len field and is
    always exactly 8 bytes (next_header, reserved, frag_offset/flags,
    identification) -- pass type=EXT_FRAGMENT and raw `data` of the
    remaining 7 bytes and this class will not pad it to an 8-byte
    multiple the way the generic types are.

    `data` holds the header's payload as raw bytes (e.g. pre-built TLV
    options for Hop-by-Hop/Destination Options, or routing-type-specific
    fields for Routing). This first pass does not decode individual
    options within `data` -- it is treated as an opaque blob, consistent
    with "one class, generic chain" scope.
    """

    def __init__(self, type: int, next_header=None, data: bytes = b""):
        super().__init__()
        self.type = type & 0xFF
        self.next_header = next_header
        self.data = data if data else b""
        self._pseudo_addrs = None  # (src, dst) forwarded by IPv6.build() for UDP auto-checksum

    @property
    def is_fixed_length(self) -> bool:
        return self.type in FIXED_LENGTH_TYPES

    @property
    def hdr_ext_len(self) -> int:
        """
        Value of the on-wire hdr_ext_len field: length of this header in
        8-byte units, minus 1, not counting the first 8 bytes. Not
        meaningful for fixed-length types (Fragment).
        """
        total = 2 + len(self.data)
        padded = (total + 7) & ~0x07
        return (padded // 8) - 1

    @property
    def wire_length(self) -> int:
        """Total on-wire length of this header, in bytes."""
        if self.is_fixed_length:
            return FRAGMENT_HEADER_LEN
        return (self.hdr_ext_len + 1) * 8

    def build(self) -> bytes:
        payload_class = self.payload.__class__.__name__ if self.payload else None
        if self.next_header is None:
            self.next_header = {
                'UDP': 17,
                'TCP': 6,
            }.get(payload_class, 59)  # 59 = No Next Header, RFC 8200 default when unknown

            if isinstance(self.payload, IPv6ExtHeader):
                self.next_header = self.payload.type

        # Same auto-checksum convenience as IPv6.build(): if this
        # extension header is immediately followed by a UDP layer with no
        # checksum set, compute it now. We don't have src/dst here, so we
        # walk up via the caller -- IPv6.build() already resolved and
        # passed them down before calling get_payload_bytes() on the
        # first ext header in the chain; each subsequent ext header
        # forwards them along via _pseudo_addrs.
        if payload_class == 'UDP' and self.payload.checksum is None and self._pseudo_addrs:
            src, dst = self._pseudo_addrs
            self.payload.compute_checksum(src=src, dst=dst, is_ipv6=True)
        elif isinstance(self.payload, IPv6ExtHeader) and self._pseudo_addrs:
            self.payload._pseudo_addrs = self._pseudo_addrs

        if self.is_fixed_length:
            body = self.data[:FRAGMENT_HEADER_LEN - 1].ljust(FRAGMENT_HEADER_LEN - 1, b'\x00')
            header = struct.pack('>B', self.next_header) + body
        else:
            body = self.data
            hdr_ext_len = self.hdr_ext_len
            padded_total = (hdr_ext_len + 1) * 8
            pad_needed = padded_total - 2 - len(body)
            if pad_needed > 0:
                body = body + b'\x00' * pad_needed
            header = struct.pack('>BB', self.next_header, hdr_ext_len) + body

        payload_bytes = self.get_payload_bytes()
        return header + payload_bytes

    def __len__(self):
        return self.wire_length

    def __repr__(self):
        name = EXT_HEADER_NAMES.get(self.type, f"type={self.type}")
        return (f"<IPv6ExtHeader {name} "
                f"next_header={self.next_header} "
                f"len={self.wire_length} (bytes) >")

    def copy(self) -> 'IPv6ExtHeader':
        new_layer = IPv6ExtHeader(
            type=self.type,
            next_header=self.next_header,
            data=self.data,
        )
        new_layer._pseudo_addrs = self._pseudo_addrs
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        name = EXT_HEADER_NAMES.get(self.type, str(self.type))
        next_name = PROTO_NAMES.get(self.next_header, str(self.next_header))
        return [
            f"type={self.type} ({name})",
            f"next_header={self.next_header} ({next_name})",
            f"len={self.wire_length}",
            f"data={self.data.hex()}" if self.data else "data=(empty)",
        ]


class IPv6ExtHeaderParser:

    @staticmethod
    def load_as_ext_header(ext_type: int, raw_packet, verbose=False):
        """
        Parse a single extension header of the given type from the start
        of raw_packet, returning (ext_header_layer, remaining_bytes) so
        the caller (typically IPv6Parser, walking next_header values) can
        keep unwrapping the chain.
        """
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        raw = raw_packet[0]

        if ext_type in FIXED_LENGTH_TYPES:
            if len(raw) < FRAGMENT_HEADER_LEN:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message=f"IPv6 Fragment header requires {FRAGMENT_HEADER_LEN} bytes")
                return None, b""

            next_header = raw[0]
            data = raw[1:FRAGMENT_HEADER_LEN]
            remaining = raw[FRAGMENT_HEADER_LEN:]

            ext = IPv6ExtHeader(type=ext_type, next_header=next_header, data=data)

            if verbose:
                name = EXT_HEADER_NAMES.get(ext_type, str(ext_type))
                print(f"   EXT HEADER ({name}): next_header={next_header} "
                      f"len={FRAGMENT_HEADER_LEN} data={data.hex()}")

            return ext, remaining

        if len(raw) < 2:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message=f"IPv6 extension header type={ext_type} truncated")
            return None, b""

        next_header, hdr_ext_len = struct.unpack('>BB', raw[:2])
        total_len = (hdr_ext_len + 1) * 8

        if len(raw) < total_len:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message=f"IPv6 extension header type={ext_type} "
                                  f"truncated (need {total_len}, have {len(raw)})")
            return None, b""

        data = raw[2:total_len]
        remaining = raw[total_len:]

        ext = IPv6ExtHeader(type=ext_type, next_header=next_header, data=data)

        if verbose:
            name = EXT_HEADER_NAMES.get(ext_type, str(ext_type))
            print(f"   {BLUE}EXT HEADER ({name}):{CYAN} next_header={next_header} "
                  f"len={total_len} data={data.hex()} {RESET}")

        return ext, remaining