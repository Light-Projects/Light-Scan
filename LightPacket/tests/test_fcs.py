# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.utils.FCS.FCS

crc32_ieee is cross-checked against Python's stdlib binascii.crc32, and
crc32_ethernet/crc16_ccitt are checked for basic correctness properties
(determinism, 4/2-byte output, verify() round-trips).
"""
import binascii
import pytest

from LightPacket.utils.FCS import FCS


def test_crc32_ieee_matches_binascii():
    data = b"The quick brown fox jumps over the lazy dog"
    expected = (binascii.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big")
    assert FCS.crc32_ieee(data) == expected


def test_crc32_ieee_empty_input():
    assert FCS.crc32_ieee(b"") == (binascii.crc32(b"") & 0xFFFFFFFF).to_bytes(4, "big")


def test_crc32_ethernet_returns_4_bytes():
    result = FCS.crc32_ethernet(b"hello world")
    assert isinstance(result, bytes)
    assert len(result) == 4


def test_crc32_ethernet_is_deterministic():
    data = b"deterministic-check"
    assert FCS.crc32_ethernet(data) == FCS.crc32_ethernet(data)


def test_crc32_ethernet_differs_for_different_input():
    assert FCS.crc32_ethernet(b"AAAA") != FCS.crc32_ethernet(b"BBBB")


def test_crc16_ccitt_returns_2_bytes():
    result = FCS.crc16_ccitt(b"frame relay data")
    assert isinstance(result, bytes)
    assert len(result) == 2


def test_crc16_ccitt_is_deterministic():
    data = b"same-input"
    assert FCS.crc16_ccitt(data) == FCS.crc16_ccitt(data)


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------

def test_verify_ethernet_round_trip():
    payload = b"ethernet frame payload"
    fcs = FCS.crc32_ethernet(payload)
    packet = payload + fcs
    assert FCS.verify(packet, fcs_type="ethernet") is True


def test_verify_ethernet_detects_corruption():
    payload = b"ethernet frame payload"
    fcs = FCS.crc32_ethernet(payload)
    corrupted = (payload[:-1] + b"\x00") + fcs
    assert FCS.verify(corrupted, fcs_type="ethernet") is False


def test_verify_ieee_round_trip():
    payload = b"ieee crc payload"
    fcs = FCS.crc32_ieee(payload)
    packet = payload + fcs
    assert FCS.verify(packet, fcs_type="ieee") is True


def test_verify_too_short_packet_returns_false():
    assert FCS.verify(b"abc", fcs_type="ethernet") is False


def test_verify_unknown_fcs_type_returns_false():
    payload = b"data"
    fcs = FCS.crc32_ethernet(payload)
    assert FCS.verify(payload + fcs, fcs_type="not-a-real-type") is False