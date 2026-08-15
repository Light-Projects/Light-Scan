# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
LightPacket - Cross-platform packet manipulation library
"""

import sys

if sys.platform == "win32":
    from .LightPacketWin import *
elif sys.platform == "linux":
    from .LightPacketLin import *
else:
    from .LightPacketUnix import *

from .Version import __version__
version = __version__
