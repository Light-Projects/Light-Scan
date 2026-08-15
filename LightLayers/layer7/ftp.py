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

import re
from scapy.packet import Packet, bind_layers
from scapy.fields import StrField
from scapy.layers.inet import TCP


class FTPRequest(Packet):
    name = "FTPRequest"
    fields_desc = [
        StrField("comd", ""),
        StrField("arg", ""),
    ]

    def do_dissect(self, s):
        line = s.decode('utf-8', errors='ignore').split('\r\n')[0].split('\n')[0]
        if ' ' in line:
            cmd, arg = line.split(' ', 1)
        else:
            cmd, arg = line, ''
        self.fields['comd'] = cmd
        self.fields['arg'] = arg
        return b""

    def do_build(self):
        cmd = self.comd.decode('utf-8', errors='ignore') if isinstance(self.comd, bytes) else self.comd
        arg = self.arg.decode('utf-8', errors='ignore') if isinstance(self.arg, bytes) else self.arg
        line = cmd + (f" {arg}" if arg else "")
        return (line + "\r\n").encode()

    def extract_padding(self, s):
        return b"", s

    def mysummary(self):
        return self.sprintf("FTP Request %comd% %arg%")


class FTPResponse(Packet):
    name = "FTPResponse"
    fields_desc = [
        StrField("code", "000"),
        StrField("sep", " "),
        StrField("message", ""),
    ]

    def do_dissect(self, s):
        line = s.decode('utf-8', errors='ignore').split('\r\n')[0].split('\n')[0]
        m = re.match(r'^(\d{3})([ \-])(.*)$', line)
        if m:
            self.fields['code'], self.fields['sep'], self.fields['message'] = m.groups()
        else:
            self.fields['code'], self.fields['sep'], self.fields['message'] = '', '', line
        return b""

    def do_build(self):
        return f"{self.code}{self.sep}{self.message}\r\n".encode()

    def extract_padding(self, s):
        return b"", s

    def mysummary(self):
        return self.sprintf("FTP Response %code% %message%")


def parse_pasv(message):
    m = re.search(r'\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)', message)
    if not m:
        return None
    a, b, c, d, p1, p2 = map(int, m.groups())
    return f"{a}.{b}.{c}.{d}", (p1 << 8) + p2


bind_layers(TCP, FTPRequest, dport=21)
bind_layers(TCP, FTPResponse, sport=21)