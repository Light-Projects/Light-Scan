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

import random
from Mimic.L4.udp import *
from Mimic.L4.tcp import *
from Mimic.L4.sctp import *

def Stealth_tcp_options():
    options = [
        ('MSS', random.randint(1000, 1440)),
        ('WScale', random.randint(2, 14)),
        ('Timestamp', (random.randint(1, 1000000000), 0)),
        ('SAckOK', ''),
        ('NOP', None),
        ('NOP', None),
        ('EOL', None)
    ]
    random.shuffle(options)
    for i, opt in enumerate(options):
        if opt[0] == 'MSS':
            options.insert(0, options.pop(i))
            break
    return options