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

from scapy.all import *
from scapy.packet import Packet
from scapy.fields import IntField, ByteField, StrField
import struct


class SSH(Packet):
    name = "SSH"
    fields_desc = [
        IntField("packet_length", 0),
        ByteField("padding_length", 0),
        StrField("data", ""),
        StrField("padding", "")
    ]

    def post_build(self, pkt, pay):
        if self.packet_length == 0:
            data_len = len(self.data) if self.data else 0
            padding_len = len(self.padding) if self.padding else 0
            total_len = data_len + padding_len + 1
            pkt = struct.pack("!I", total_len) + pkt[4:]
        return pkt + pay

    def do_dissect(self, s):
        raw = s
        if len(raw) < 5:
            return raw

        self.packet_length = struct.unpack("!I", raw[:4])[0]
        self.padding_length = raw[4]
        data_len = self.packet_length - self.padding_length - 1

        if len(raw) < 5 + data_len + self.padding_length:
            return raw

        self.data = raw[5:5 + data_len]
        self.padding = raw[5 + data_len:5 + data_len + self.padding_length]

        return raw[5 + data_len + self.padding_length:]

