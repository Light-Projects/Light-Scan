# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

class LightPacketError(Exception):
    pass

class InvalidDataLengthError(LightPacketError):
    pass

class NotFoundError(LightPacketError):
    pass

class InvalidMacAddressError(LightPacketError):
    pass

class InvalidIPAddressError(LightPacketError):
    pass

class InvalidDataTypeError(LightPacketError):
    pass