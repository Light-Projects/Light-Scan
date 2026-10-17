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


def detect_quicc(payload, dport, sport):
    if not payload or len(payload) < 1:
        return False, None, "Empty payload"

    is_long_marker = payload[0] in [0xC0, 0xCD, 0xEA, 0xE2, 0xC6, 0x46]
    if not (is_long_marker or sport == 443 or dport == 443):
        return False, None, "Invalid payload"

    first_byte = payload[0]
    header_form = (first_byte & 0x80) >> 7
    fixed_bit = (first_byte & 0x40) >> 6

    if fixed_bit != 1:
        return False, None, "Invalid Fixed Bit"

    if header_form == 1 and len(payload) < 10:
        return False, None, "Not QUIC: Long header too short"
    elif header_form == 0 and len(payload) < 5:
        return False, None, "Not QUIC: Short header too short"

    if header_form == 1:
        version = int.from_bytes(payload[1:5], 'big')

        version_names = {
            0x00000001: "QUIC v1 (RFC 9000)",
            0x51303439: "QUIC Q043",
            0x51303538: "QUIC Q058",
            0x51303132: "QUIC Q012",
            0x51303333: "QUIC Q033",
            0x51303636: "QUIC Q066",
            0xff00001d: "Draft 29",
            0x709a50c4: "Draft 27",
            0x00000000: "Version Negotiation"
        }

        version_str = version_names.get(version, f"Unknown (0x{version:08x})")
        details = f"Long | Version: {version_str}"

        if len(payload) >= 6:
            dcid_len = payload[5]
            if len(payload) >= 6 + dcid_len:
                dcid = payload[6:6 + dcid_len]
                details += f" | DCID: {dcid.hex()}"

        return True, "Long", details

    pkt_num_len = (first_byte & 0x03) + 1
    spin_bit = (first_byte & 0x20) >> 5
    key_phase = (first_byte & 0x04) >> 2
    details = f"Short | PN Len: {pkt_num_len}"
    details += f" | Spin:{spin_bit} | K:{key_phase}"
    return True, "Short", details