# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from .Layers.Mac import MacAddress
from .BaseLayer import BaseLayer
from typing import Union
from .Logger.LightLogger import Logger, ErrorCode
from .Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE

LLogger = Logger()

"""
STP Layer Creation (class STPLayer)
"""

class STPLayer(BaseLayer):

    def __init__(self, protocol_id=0x0000, protocol_version=0x00, bpdu_type=0x00, flags=0x00,
                 root_priority=0x8000, root_mac: Union[str,bytes] =b'\x00\x11\x22\x33\x44\x55',
                 root_path_cost=0, bridge_priority=0x8000,
                 bridge_mac : Union[str,bytes] =b'\x00\x11\x22\x33\x44\x55', port_id=0x8001,
                 message_age=0, max_age=5120, hello_time=512,
                 forward_delay=3840):
        super().__init__()
        self.protocol_id = protocol_id
        self.protocol_version = protocol_version
        self.bpdu_type = bpdu_type
        self.flags = flags
        self.root_priority = root_priority
        self.root_mac = MacAddress(root_mac)
        self.root_path_cost = root_path_cost
        self.bridge_priority = bridge_priority
        self.bridge_mac = MacAddress(bridge_mac)
        self.port_id = port_id
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay

    def build(self) -> bytes:
        result = struct.pack(
            '!H B B B H 6s I H 6s H H H H H',
            self.protocol_id,
            self.protocol_version,
            self.bpdu_type,
            self.flags,
            self.root_priority,
            bytes(self.root_mac),
            self.root_path_cost,
            self.bridge_priority,
            bytes(self.bridge_mac),
            self.port_id,
            self.message_age,
            self.max_age,
            self.hello_time,
            self.forward_delay
        )

        if self.payload:
            return result + self.payload.build()
        return result

    def __len__(self):
        return 35 + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        bpdu_type_str = "Config" if self.bpdu_type == 0x00 else "TCN" if self.bpdu_type == 0x80 else "RSTP"
        return (f"<STP protoid=0x{self.protocol_id:02x} version=0x{self.protocol_version:02x} type={bpdu_type_str} "
                f"flags=0x{self.flags:02x} root_prio={self.root_priority} "
                f"root_mac={self.root_mac} cost={self.root_path_cost} "
                f"bridge_prio={self.bridge_priority} bridge_mac={self.bridge_mac} "
                f"port=0x{self.port_id:04x} age={self.message_age} "
                f"max_age={self.max_age} hello={self.hello_time} "
                f"fwd_delay={self.forward_delay} len={len(self)}>")

    def copy(self) -> 'STPLayer':
        new_layer = STPLayer(
            protocol_id=self.protocol_id,
            protocol_version=self.protocol_version,
            bpdu_type=self.bpdu_type,
            flags=self.flags,
            root_priority=self.root_priority,
            root_mac=bytes(self.root_mac),
            root_path_cost=self.root_path_cost,
            bridge_priority=self.bridge_priority,
            bridge_mac=bytes(self.bridge_mac),
            port_id=self.port_id,
            message_age=self.message_age,
            max_age=self.max_age,
            hello_time=self.hello_time,
            forward_delay=self.forward_delay
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        bpdu_type_str = "Config" if self.bpdu_type == 0x00 else "TCN" if self.bpdu_type == 0x80 else "RSTP"
        return [
            f"protoid=0x{self.protocol_id:02x}",
            f"version=0x{self.protocol_version:02x}",
            f"type= {self.bpdu_type} ({bpdu_type_str})",
            f"flags=0x{self.flags:02x}",
            f"root_prio={self.root_priority}",
            f"root_mac={self.root_mac}",
            f"cost={self.root_path_cost}",
            f"bridge_prio={self.bridge_priority}",
            f"bridge_mac={self.bridge_mac}",
            f"port=0x{self.port_id:04x}",
            f"age={self.message_age}",
            f"max_age={self.max_age} ({self.max_age/256:.2f}s)",
            f"hello={self.hello_time} ({self.hello_time/256:.2f}s)",
            f"fwd_delay={self.forward_delay} ({self.forward_delay/256:.2f}s)"
        ]

"""
STP Parser (separate from the builder)
"""

class STPParser:

    @staticmethod
    def load_as_stp_layer(raw_packet, Alr=0, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 35:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                         message="STP required header is 35 bytes")

        stp_header = raw_packet[0][:35]
        length = len(stp_header)

        fields = struct.unpack(
            '!H B B B H 6s I H 6s H H H H H',
            stp_header
        )

        protocol_id = fields[0]
        protocol_version = fields[1]
        bpdu_type = fields[2]
        flags = fields[3]
        root_priority = fields[4]
        root_mac = fields[5]
        root_path_cost = fields[6]
        bridge_priority = fields[7]
        bridge_mac = fields[8]
        port_id = fields[9]
        message_age = fields[10]
        max_age = fields[11]
        hello_time = fields[12]
        forward_delay = fields[13]

        payload = raw_packet[0][35:]
        total = len(payload) + length

        bpdu_type_str = "Configuration" if bpdu_type == 0x00 else "TCN" if bpdu_type == 0x80 else "RSTP"

        if verbose:
            print(f"\n{BOLD}STP LAYER : {RESET}Len({PURPLE}{length}{RESET}) Total Len({PURPLE}{total}{RESET}) >")
            print(f'   {BLUE}Protocol ID:{CYAN} 0x{protocol_id:04x}')
            print(f'   {BLUE}Protocol Version:{CYAN} 0x{protocol_version:02x}')
            print(f'   {BLUE}BPDU Type:{CYAN} 0x{bpdu_type:02x} ({bpdu_type_str})')
            print(f'   {BLUE}Flags:{CYAN} 0x{flags:02x}')
            if flags & 0x01:
                print(f'      {BLUE}- Topology Change (TC){RESET}')
            if flags & 0x02:
                print(f'      {BLUE}- Topology Change Acknowledgment (TCA){RESET}')
            if flags & 0x04:
                print(f'      {BLUE}- Proposal{RESET}')
            if flags & 0x20:
                print(f'      {BLUE}- Learning{RESET}')
            if flags & 0x40:
                print(f'      {BLUE}- Forwarding{RESET}')
            if flags & 0x80:
                print(f'      {BLUE}- Agreement{RESET}')
            root_mac_str = ':'.join(f'{b:02x}' for b in root_mac)
            bridge_mac_str = ':'.join(f'{b:02x}' for b in bridge_mac)
            print(f'   {BLUE}Root Priority:{CYAN} {root_priority}')
            print(f'   {BLUE}Root MAC:{CYAN} {root_mac_str}')
            print(f'   {BLUE}Root Path Cost:{CYAN} {root_path_cost}')
            print(f'   {BLUE}Bridge Priority:{CYAN} {bridge_priority}')
            print(f'   {BLUE}Bridge MAC:{CYAN} {bridge_mac_str}')
            print(f'   {BLUE}Port ID:{CYAN} 0x{port_id:04x}')
            print(f'   {BLUE}Message Age:{CYAN} {message_age} ticks')
            print(f'   {BLUE}Max Age:{CYAN} {max_age} ticks ({max_age/256:.2f}s)')
            print(f'   {BLUE}Hello Time:{CYAN} {hello_time} ticks ({hello_time/256:.2f}s)')
            print(f'   {BLUE}Forward Delay:{CYAN} {forward_delay} ticks ({forward_delay/256:.2f}s){RESET}')

        if len(payload) > 0:
            from .Raw import RawParser
            RawParser.load_as_Raw_layer(payload, verbose=verbose)

        stp = STPLayer(
            protocol_version=protocol_version,
            bpdu_type=bpdu_type,
            flags=flags,
            root_priority=root_priority,
            root_mac=root_mac,
            root_path_cost=root_path_cost,
            bridge_priority=bridge_priority,
            bridge_mac=bridge_mac,
            port_id=port_id,
            message_age=message_age,
            max_age=max_age,
            hello_time=hello_time,
            forward_delay=forward_delay
        )

        return stp