# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import socket
import struct
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from LightPacket.helper.ipv6.IPv6ExtHeader import IPv6ExtHeader, IPv6ExtHeaderParser, EXT_HEADER_NAMES
from LightPacket.ipv4 import IP_PROTOCOLS as PROTO_NAMES

LLogger = Logger()


PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

EXT_HEADERS = {
    0:   "Hop-by-Hop Options",
    43:  "Routing",
    44:  "Fragment",
    50:  "ESP",
    51:  "AH",
    60:  "Destination Options",
    135: "Mobility",
}

def inet6_aton(addr: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, addr)

def inet6_ntoa(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, raw)

class IPv6(BaseLayer):
    def __init__(self,
                 dst=None,
                 src=None,
                 next_header=None,
                 hop_limit=64,
                 traffic_class=0,
                 version=6,
                 flow_label=0,
                 payload_len=None):
        super().__init__()
        self.version = version
        self.traffic_class = traffic_class & 0xFF
        self.flow_label = flow_label & 0xFFFFF
        self.payload_len = payload_len
        self.next_header = next_header
        self.hop_limit = hop_limit
        self.src = str(src) if src is not None else None
        self.dst = str(dst) if dst is not None else None

    def build(self) -> bytes:
        layer = self.payload.__class__.__name__
        if self.next_header is None:
            if isinstance(self.payload, IPv6ExtHeader):
                self.next_header = self.payload.type
            else:
                self.next_header = {
                    'UDP':    PROTO_UDP,
                    'TCP':    PROTO_TCP
                }.get(layer, PROTO_TCP)

        src = self.src
        if src is None:
            src = "::"
        dst = self.dst if self.dst is not None else "::"

        if layer == 'UDP' and self.payload.checksum is None:
            self.payload.compute_checksum(src=src, dst=dst, is_ipv6=True)
        elif layer == 'TCP' and self.payload.checksum is None:
            self.payload.compute_checksum(src=src, dst=dst, is_ipv6=True)
        elif isinstance(self.payload, IPv6ExtHeader):
            self.payload._pseudo_addrs = (src, dst)

        payload_bytes = self.get_payload_bytes()

        payload_len = self.payload_len
        if payload_len is None:
            payload_len = len(payload_bytes)

        version_tc_fl = (
            (self.version & 0x0F) << 28
            | (self.traffic_class & 0xFF) << 20
            | (self.flow_label & 0xFFFFF)
        )

        header = struct.pack(
            '>IHBB16s16s',
            version_tc_fl,
            payload_len,
            self.next_header,
            self.hop_limit,
            inet6_aton(src),
            inet6_aton(dst),
        )

        self.payload_len = payload_len
        self.src = src
        self.dst = dst

        return header + payload_bytes

    def __len__(self):
        return 40

    def __repr__(self):
        proto_name = PROTO_NAMES.get(self.next_header, f"next_header={self.next_header}")
        return (f"<IPv6 src={self.src} dst={self.dst} "
                f"next_header={self.next_header} ({proto_name}) "
                f"hop_limit={self.hop_limit} "
                f"payload_len={self.payload_len} "
                f"len=40 (bytes) >")

    def copy(self) -> 'IPv6':
        new_layer = IPv6(
            dst=self.dst,
            src=self.src,
            next_header=self.next_header,
            hop_limit=self.hop_limit,
            traffic_class=self.traffic_class,
            flow_label=self.flow_label,
            payload_len=self.payload_len,
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        proto_name = PROTO_NAMES.get(self.next_header, str(self.next_header))
        return [
            f"src={self.src}",
            f"dst={self.dst}",
            f"next_header={self.next_header} ({proto_name})",
            f"hop_limit={self.hop_limit}",
            f"traffic_class={self.traffic_class}",
            f"flow_label=0x{self.flow_label:05x}",
            f"payload_len={self.payload_len}",
        ]


class IPv6Parser:

    @staticmethod
    def load_as_ip_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        raw = raw_packet[0]

        if len(raw) < 40:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="IPv6 required header is 40 bytes")
            return None

        (version_tc_fl, payload_len, next_header, hop_limit,
         src_bytes, dst_bytes) = struct.unpack('>IHBB16s16s', raw[:40])

        version = (version_tc_fl >> 28) & 0x0F
        traffic_class = (version_tc_fl >> 20) & 0xFF
        flow_label = version_tc_fl & 0xFFFFF

        if version != 6:
            if version == 4:
                from LightPacket.ipv4 import IPv4Parser
                IPv4Parser.load_as_ip_layer(raw_packet, verbose=verbose)
                return
            else:
                LLogger.error(error_code=ErrorCode.INVALID_VESRION,
                              message=f"IPv6 version mismatch (got {version})")
                return None

        if len(raw) < 40 + payload_len:
            LLogger.error(error_code=ErrorCode.TRUNCATED_DATA,
                          message=f"IPv6 payload truncated "
                                  f"(need {payload_len}, have {len(raw) - 40})")
            return None

        payload = raw[40:40 + payload_len]
        current_type = next_header

        src_str = inet6_ntoa(src_bytes)
        dst_str = inet6_ntoa(dst_bytes)

        ip = IPv6(
            dst=dst_str,
            src=src_str,
            next_header=next_header,
            hop_limit=hop_limit,
            traffic_class=traffic_class,
            flow_label=flow_label,
            payload_len=payload_len,
            version=version
        )

        if verbose:
            proto_name = PROTO_NAMES.get(next_header, str(next_header))
            print(f"\n{BOLD}IPv6 LAYER : {RESET}Payload Len({PURPLE}{payload_len}{RESET}) Total Len({PURPLE}{len(raw)}{RESET}) >")
            print(f'   {BLUE}SRC:{CYAN} {src_str}')
            print(f'   {BLUE}DST:{CYAN} {dst_str}')
            print(f'   {BLUE}VERSION:{CYAN} {version}')
            print(f'   {BLUE}NEXT HEADER:{CYAN} {next_header} ({proto_name})')
            print(f'   {BLUE}HOP LIMIT:{CYAN} {hop_limit}')
            print(f'   {BLUE}TRAFFIC CLASS:{CYAN} 0x{traffic_class:02x}')
            print(f'   {BLUE}FLOW LABEL:{CYAN} 0x{flow_label:05x} {RESET}')

        ext_layers = []
        while current_type in EXT_HEADER_NAMES and len(payload) > 0:
            ext, payload = IPv6ExtHeaderParser.load_as_ext_header(
                current_type, payload, verbose=verbose
            )
            if ext is None:
                break
            ext_layers.append(ext)
            current_type = ext.next_header

        result = ip
        for ext in ext_layers:
            result = result / ext

        if len(payload) > 0 and payload != b'':
            if current_type == 17:
                from LightPacket.udp import UDPParser
                return result / UDPParser.load_as_udp_layer(payload, verbose=verbose)

            if current_type == 6:
                from LightPacket.tcp import TCPParser
                return ip / TCPParser.load_as_tcp_layer(payload, verbose=verbose)

            from LightPacket.Raw import RawParser
            return result / RawParser.load_as_Raw_layer(payload, verbose=verbose)

        return result