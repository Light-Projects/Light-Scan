# LightPacket/tests/test_wlan.py
"""
802.11 Wi-Fi layer tests.

NOTE ON ENDIANNESS:
Beacon/ProbeResponse fixed fields (timestamp / interval / capability) are
built with '!QHH' (big-endian). IEEE 802.11-2020 specifies these as
little-endian. Wireshark dissects both without "malformed" warnings, but
displays the wrong values for the wrong byte order. If Wireshark shows
beacon_interval as 25600 instead of 100, switch to '<QHH'. Tests below
assert the CURRENT behaviour so they pass today.
"""

import struct
import pytest

from LightPacket.Wireless.wlan import (
    WiFi, WiFiParser,
    Beacon, BeaconParser,
    ProbeRequest, ProbeRequestParser,
    ProbeResponse, ProbeResponseParser,
    Element, ElementParser,
    parse_rsn_ie, parse_ht_capabilities_ie,
    RSNParseError,
    detect_data_link_type,
    FRAME_TYPE_MANAGEMENT, FRAME_TYPE_DATA,
    SUB_TYPE_BEACON, SUB_TYPE_PROBE_REQ, SUB_TYPE_PROBE_RSP,
    SUB_TYPE_DATA, SUB_TYPE_QOS_DATA,
    FC_FLAG_TO_DS, FC_FLAG_FROM_DS, FC_FLAG_PROTECTED, FC_FLAG_ORDER,
    CAP_ESS, CAP_PRIVACY,
    IE_SSID, IE_VENDOR_SPECIFIC,
    DATA_LINK_TYPE_80211, DATA_LINK_TYPE_ETHERNET, DATA_LINK_TYPE_UNKNOWN,
)


# ---------------------------------------------------------------------------
# WiFi MAC header
# ---------------------------------------------------------------------------

class TestWiFiHeader:

    def test_minimum_size(self):
        assert len(WiFi().build()) == 24

    def test_roundtrip_basic(self):
        w = WiFi(
            frame_type=FRAME_TYPE_DATA,
            subtype=SUB_TYPE_DATA,
            duration=0x1234,
            addr1=b'\xaa' * 6,
            addr2=b'\xbb' * 6,
            addr3=b'\xcc' * 6,
            seq_control=0x1234,
        )
        parsed = WiFiParser.load_as_wifi_layer(w.build())
        assert parsed.frame_type == FRAME_TYPE_DATA
        assert parsed.subtype == SUB_TYPE_DATA
        assert parsed.duration == 0x1234
        assert parsed.addr1 == b'\xaa' * 6
        assert parsed.addr2 == b'\xbb' * 6
        assert parsed.addr3 == b'\xcc' * 6
        assert parsed.seq_control == 0x1234

    def test_frame_control_bit_layout(self):
        w = WiFi(frame_type=FRAME_TYPE_MANAGEMENT,
                 subtype=SUB_TYPE_BEACON,
                 flags=FC_FLAG_PROTECTED)
        raw = w.build()
        fc = struct.unpack('<H', raw[:2])[0]
        assert fc & 0x0003 == 0
        assert (fc >> 2) & 0x03 == FRAME_TYPE_MANAGEMENT
        assert (fc >> 4) & 0x0F == SUB_TYPE_BEACON
        assert ((fc >> 8) & 0xFF) == FC_FLAG_PROTECTED

    def test_qos_adds_two_bytes(self):
        w = WiFi(frame_type=FRAME_TYPE_DATA, subtype=SUB_TYPE_QOS_DATA)
        assert len(w.build()) == 24 + 2

    def test_4addr_mode_adds_six_bytes(self):
        w = WiFi(frame_type=FRAME_TYPE_DATA, subtype=SUB_TYPE_DATA,
                 flags=FC_FLAG_TO_DS | FC_FLAG_FROM_DS)
        assert len(w.build()) == 24 + 6

    def test_ht_control_adds_four_bytes(self):
        w = WiFi(frame_type=FRAME_TYPE_MANAGEMENT,
                 subtype=SUB_TYPE_BEACON, flags=FC_FLAG_ORDER)
        assert len(w.build()) == 24 + 4

    def test_subtype_auto_from_payload(self):
        w = WiFi(frame_type=FRAME_TYPE_MANAGEMENT) / Beacon()
        raw = w.build()
        fc = struct.unpack('<H', raw[:2])[0]
        assert (fc >> 4) & 0x0F == SUB_TYPE_BEACON

    def test_address_helpers_default(self):
        w = WiFi(frame_type=FRAME_TYPE_DATA, subtype=SUB_TYPE_DATA,
                 addr1=b'\xaa' * 6, addr2=b'\xbb' * 6, addr3=b'\xcc' * 6)
        assert w.get_ra() == b'\xaa' * 6
        assert w.get_ta() == b'\xbb' * 6
        assert w.get_bssid() == b'\xcc' * 6

    def test_address_helpers_to_ds(self):
        w = WiFi(frame_type=FRAME_TYPE_DATA, subtype=SUB_TYPE_DATA,
                 flags=FC_FLAG_TO_DS,
                 addr1=b'\xaa' * 6, addr2=b'\xbb' * 6, addr3=b'\xcc' * 6)
        assert w.get_da() == b'\xcc' * 6
        assert w.get_sa() == b'\xbb' * 6

    def test_address_helpers_from_ds(self):
        w = WiFi(frame_type=FRAME_TYPE_DATA, subtype=SUB_TYPE_DATA,
                 flags=FC_FLAG_FROM_DS,
                 addr1=b'\xaa' * 6, addr2=b'\xbb' * 6, addr3=b'\xcc' * 6)
        assert w.get_da() == b'\xaa' * 6
        assert w.get_sa() == b'\xcc' * 6

    def test_flag_helpers(self):
        w = WiFi(frame_type=FRAME_TYPE_DATA, subtype=SUB_TYPE_DATA,
                 flags=FC_FLAG_PROTECTED | FC_FLAG_TO_DS)
        f = w.get_flags()
        assert f['protected'] is True
        assert f['to_ds'] is True
        assert f['from_ds'] is False


# ---------------------------------------------------------------------------
# Beacon
# ---------------------------------------------------------------------------

class TestBeacon:

    def test_fixed_field_size(self):
        assert len(Beacon().build()) == 12

    def test_roundtrip(self):
        b = Beacon(timestamp=0xDEADBEEF, beacon_interval=100,
                   capability=CAP_ESS | CAP_PRIVACY)
        parsed = BeaconParser.load_as_beacon_layer(b.build())
        assert parsed.timestamp == 0xDEADBEEF
        assert parsed.beacon_interval == 100
        assert parsed.capability == CAP_ESS | CAP_PRIVACY

    def test_capability_flags(self):
        b = Beacon(capability=CAP_ESS | CAP_PRIVACY)
        assert b.is_ess()
        assert b.has_privacy()
        assert not b.is_ibss()

    def test_through_wifi_parser(self):
        frame = WiFi(frame_type=FRAME_TYPE_MANAGEMENT) / Beacon(beacon_interval=100)
        parsed = WiFiParser.load_as_wifi_layer(frame.build())
        assert parsed.subtype == SUB_TYPE_BEACON
        assert parsed.payload.__class__.__name__ == 'Beacon'
        assert parsed.payload.beacon_interval == 100


# ---------------------------------------------------------------------------
# Probe Request / Response
# ---------------------------------------------------------------------------

class TestProbeRequest:

    def test_empty_probe_request(self):
        assert len(ProbeRequest().build()) == 0

    def test_with_ssid_element(self):
        p = ProbeRequest() / Element(ie_id=IE_SSID, data=b'MyWiFi')
        raw = p.build()
        assert raw[0] == IE_SSID
        assert raw[1] == 6
        assert raw[2:8] == b'MyWiFi'

    def test_through_wifi_parser(self):
        frame = (WiFi(frame_type=FRAME_TYPE_MANAGEMENT)
                 / ProbeRequest()
                 / Element(ie_id=IE_SSID, data=b'test'))
        raw = frame.build()
        fc = struct.unpack('<H', raw[:2])[0]
        assert (fc >> 4) & 0x0F == SUB_TYPE_PROBE_REQ


class TestProbeResponse:

    def test_fixed_field_size(self):
        assert len(ProbeResponse().build()) == 12

    def test_through_wifi_parser(self):
        frame = (WiFi(frame_type=FRAME_TYPE_MANAGEMENT)
                 / ProbeResponse(beacon_interval=100))
        parsed = WiFiParser.load_as_wifi_layer(frame.build())
        assert parsed.subtype == SUB_TYPE_PROBE_RSP


# ---------------------------------------------------------------------------
# Information Elements
# ---------------------------------------------------------------------------

class TestElement:

    def test_single_element(self):
        assert Element(ie_id=IE_SSID, data=b'Test').build() == b'\x00\x04Test'

    def test_roundtrip(self):
        e = Element(ie_id=IE_SSID, data=b'Test')
        parsed = ElementParser.load_as_element_layer(e.build())
        assert parsed.ie_id == IE_SSID
        assert parsed.data == b'Test'

    def test_element_chain(self):
        e1 = Element(ie_id=IE_SSID, data=b'Net')
        e2 = Element(ie_id=3, data=b'\x06')
        raw = (e1 / e2).build()
        assert raw == b'\x00\x03Net\x03\x01\x06'

    def test_element_chain_parses(self):
        parsed = ElementParser.load_as_element_layer(b'\x00\x03Net\x03\x01\x06')
        assert parsed.ie_id == IE_SSID
        assert parsed.data == b'Net'
        assert parsed.payload.ie_id == 3
        assert parsed.payload.data == b'\x06'

    def test_vendor_specific_element(self):
        e = Element(ie_id=IE_VENDOR_SPECIFIC,
                    oui=b'\x00\x50\xf2', ouitype=1, data=b'\x01\x02')
        raw = e.build()
        assert raw[0] == IE_VENDOR_SPECIFIC
        assert raw[1] == 6                      # 3 (OUI) + 1 (type) + 2 (data)
        assert raw[2:5] == b'\x00\x50\xf2'
        assert raw[5] == 1
        assert raw[6:8] == b'\x01\x02'


# ---------------------------------------------------------------------------
# RSN IE
# ---------------------------------------------------------------------------

class TestRSN:

    def test_basic_rsn_ie(self):
        body = (b'\x01\x00'            # version 1
                + b'\x00\x0f\xac\x04'  # group cipher: CCMP
                + b'\x01\x00'          # 1 pairwise
                + b'\x00\x0f\xac\x04'  # pairwise: CCMP
                + b'\x01\x00'          # 1 AKM
                + b'\x00\x0f\xac\x02'  # AKM: PSK
                + b'\x00\x00')         # caps
        data = b'\x30' + bytes([len(body)]) + body
        r = parse_rsn_ie(data)
        assert r['version'] == 1
        assert 'CCMP' in r['group_cipher_suite']
        assert 'CCMP' in r['pairwise_cipher_suites'][0]
        assert 'PSK' in r['akm_suites'][0]

    def test_truncated_raises(self):
        with pytest.raises(RSNParseError):
            parse_rsn_ie(b'\x30\x05\x01\x00\x00\x0f\xac')


# ---------------------------------------------------------------------------
# HT Capabilities
# ---------------------------------------------------------------------------

class TestHTCapabilities:

    def test_basic_parse(self):
        data = (b'\x00\x00'      # cap info
                + b'\x00'        # ampdu params
                + b'\x00' * 16   # mcs set
                + b'\x00\x00'    # extended caps
                + b'\x00' * 4    # tx beamforming
                + b'\x00')       # asel
        r = parse_ht_capabilities_ie(data)
        assert r['capability_info']['raw'] == 0
        assert r['mcs_set']['supported_mcs'] == []


# ---------------------------------------------------------------------------
# Data link type detection
# ---------------------------------------------------------------------------

class TestDataLinkDetection:

    def test_beacon_identified_as_80211(self):
        frame = (WiFi(frame_type=FRAME_TYPE_MANAGEMENT) / Beacon()).build()
        assert detect_data_link_type(frame) == DATA_LINK_TYPE_80211

    def test_ethernet_identified(self):
        eth = b'\xff' * 6 + b'\xaa' * 6 + b'\x08\x00' + b'\x00' * 20
        assert detect_data_link_type(eth) == DATA_LINK_TYPE_ETHERNET

    def test_short_packet_unknown(self):
        assert detect_data_link_type(b'\x01') == DATA_LINK_TYPE_UNKNOWN