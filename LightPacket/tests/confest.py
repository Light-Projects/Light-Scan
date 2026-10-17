# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Shared pytest fixtures/config for the LightPacket test suite.

These tests are written against the actual LightPacket source layout
(imports like `from LightPacket.Arp import ARP`). Run them from the
repository root with LightPacket importable on sys.path, e.g.:

    pip install pytest
    pytest tests/

No network access, root privileges, libpcap, or Npcap are required —
socket-level classes (L2Socket / L2Packet) are tested with mocks only.
"""
import pytest


@pytest.fixture
def sample_mac_src():
    return "00:11:22:33:44:55"


@pytest.fixture
def sample_mac_dst():
    return "aa:bb:cc:dd:ee:ff"


@pytest.fixture
def broadcast_mac():
    return "ff:ff:ff:ff:ff:ff"