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

"""
Turns raw scapy TCP options into the flat dict the signature scorers use.
"""


def analyze_tcp_options(options, packet_id=0, version=4):
    if not options:
        return {}

    analysis = {
        'order': [opt[0] for opt in options],
        'mss': None,
        'wscale': None,
        'timestamp': None,
        'sack': False,
        'id': packet_id,
        'version': version,
    }

    for opt_name, opt_value in options:
        if opt_name == 'MSS':
            analysis['mss'] = opt_value
        elif opt_name == 'WScale':
            analysis['wscale'] = opt_value
        elif opt_name == 'Timestamp':
            analysis['timestamp'] = opt_value
        elif opt_name == 'SAckOK':
            analysis['sack'] = True

    return analysis