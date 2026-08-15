# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

def is_llc(payload):
    if len(payload) < 3:
        return False

    dsap = payload[0]
    ssap = payload[1]
    control = payload[2]

    if (dsap % 2 == 0 or dsap == 0xAA) and (ssap % 2 == 0 or ssap == 0xAA):
        return True
    elif dsap == ssap:
        return True

    return False