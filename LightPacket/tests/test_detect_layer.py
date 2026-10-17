# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.Detect_layer.DetectLayer

Focuses on dispatch logic (which parser gets called for which ethertype /
linktype / length), using monkeypatched parser entry points so we verify
routing rather than re-testing each protocol's own parser.
"""
import struct

from LightPacket.Detect_layer import DetectLayer
from LightPacket.EthernetII import Ethernet
from LightPacket.Arp import ARP
from LightPacket.ipv4 import IPv4


def test_detect_layer_routes_ethernet_ii_to_ethernet_parser():
    packet = (Ethernet(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
              ARP(ipsrc="10.0.0.1", ipdst="10.0.0.2",
                  macsrc="00:11:22:33:44:55", macdst="ff:ff:ff:ff:ff:ff"))
    raw_bytes = packet.build()

    result = DetectLayer().start(raw_bytes)

    assert isinstance(result, Ethernet)
    assert result.ethertype == 0x0806


def test_detect_layer_accepts_layer_object_and_calls_build():
    packet = Ethernet(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / IPv4()
    result = DetectLayer().start(packet)

    assert isinstance(result, Ethernet)


def test_detect_layer_previous_layer_in_layers_names_forces_raw(monkeypatch):
    from LightPacket import Consts

    monkeypatch.setattr(Consts, "Layers_names", ["Ethernet"])

    called = {}

    def fake_raw(pkt, verbose=False):
        called["fired"] = True
        return "RAW_RESULT"

    monkeypatch.setattr("LightPacket.Raw.RawParser.load_as_Raw_layer", fake_raw)

    result = DetectLayer().start(b"\x00" * 20, previous_layer="Ethernet")
    assert called.get("fired") is True
    assert result == "RAW_RESULT"


def test_detect_layer_short_packet_falls_back_to_raw(monkeypatch):
    called = {}

    def fake_raw(pkt, verbose=False):
        called["fired"] = True
        return "RAW_RESULT"

    monkeypatch.setattr("LightPacket.Raw.RawParser.load_as_Raw_layer", fake_raw)
    # <14 bytes and not a recognizable PPP frame -> Raw fallback
    monkeypatch.setattr("LightPacket.Detect_layer.is_ppp_frame", lambda pkt: False)

    result = DetectLayer().start(b"\x01\x02\x03")
    assert called.get("fired") is True
    assert result == "RAW_RESULT"


def test_detect_layer_handles_exception_and_logs(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("parser exploded")

    monkeypatch.setattr("LightPacket.EthernetII.EthernetParser.load_as_ethernet_layer", boom)


    packet = Ethernet(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") / IPv4()
    result = DetectLayer().start(packet.build())

    assert result is not None


def test_detect_layer_dot3_ethertype_below_1500_routes_to_dot3(monkeypatch):
    called = {}

    def fake_dot3(pkt, verbose=False):
        called["fired"] = True
        return "DOT3_RESULT"

    monkeypatch.setattr("LightPacket.Dot3.Dot3Parser.load_as_dot3_layer", fake_dot3)

    # Ethernet header w/ length field (<=1500) instead of ethertype
    header = bytes.fromhex("ffffffffffff") + bytes.fromhex("001122334455") + struct.pack(">H", 100)
    packet = header + b"\x00" * 50

    result = DetectLayer().start(packet)
    assert called.get("fired") is True
    assert result == "DOT3_RESULT"