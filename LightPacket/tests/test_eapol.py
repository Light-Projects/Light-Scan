# LightPacket/tests/test_eapol.py
"""
EAPOL / EAP framework tests.

Focused on the parser dispatch logic (EAPOL code 0x00 = EAP-Packet),
EAP length field encoding, and round-trip integrity.
"""

import struct
import pytest

from LightPacket.eapol import (
    EAPOL, EAPOLParser,
    EAPOL_CODE_EAP_PACKET, EAPOL_CODE_START,
    EAPOL_CODE_LOGOFF, EAPOL_CODE_KEY,
    EAP_IDENTITY,
    EAP_Key,
    EAP_NAK,
    EAP_NOTIFICATION,
    EAP_TYPE_IDENTITY, EAP_TYPE_NAK, EAP_TYPE_NOTIFICATION,
)


# ---------------------------------------------------------------------------
# EAPOL header
# ---------------------------------------------------------------------------

class TestEAPOLHeader:

    def test_default_header_is_4_bytes(self):
        raw = EAPOL().build()
        assert len(raw) == 4
        version, code, length = struct.unpack('!BBH', raw)
        assert version == 2
        assert code == 0
        assert length == 0

    def test_length_auto_calculated(self):
        pkt = EAPOL() / EAP_IDENTITY(identity=b'alice')
        raw = pkt.build()
        _, _, length = struct.unpack('!BBH', raw[:4])
        assert length == len(raw) - 4

    def test_code_auto_detected_for_eap_method(self):
        """EAP-Packet code is 0x00, not 0x01. Regression test."""
        pkt = EAPOL() / EAP_IDENTITY(identity=b'user')
        raw = pkt.build()
        _, code, _ = struct.unpack('!BBH', raw[:4])
        assert code == EAPOL_CODE_EAP_PACKET

    def test_code_auto_detected_for_key(self):
        pkt = EAPOL() / EAP_Key()
        raw = pkt.build()
        _, code, _ = struct.unpack('!BBH', raw[:4])
        assert code == EAPOL_CODE_KEY

    def test_explicit_code_not_overridden(self):
        pkt = EAPOL(code=EAPOL_CODE_LOGOFF) / EAP_IDENTITY(identity=b'x')
        raw = pkt.build()
        _, code, _ = struct.unpack('!BBH', raw[:4])
        assert code == EAPOL_CODE_LOGOFF

    def test_start_frame(self):
        pkt = EAPOL(code=EAPOL_CODE_START)
        raw = pkt.build()
        assert raw == b'\x02\x01\x00\x00'


# ---------------------------------------------------------------------------
# EAP-Identity
# ---------------------------------------------------------------------------

class TestEAPIdentity:

    def test_length_field_includes_header(self):
        raw = EAP_IDENTITY(identity=b'bob').build()
        # 5 byte EAP header + 3 byte identity
        assert len(raw) == 8
        _, _, length, eap_type = struct.unpack('!BBHB', raw[:5])
        assert length == 8
        assert eap_type == EAP_TYPE_IDENTITY

    def test_roundtrip_through_eapol(self):
        pkt = EAPOL() / EAP_IDENTITY(identity=b'alice')
        parsed = EAPOLParser.load_as_eapol_layer(pkt.build())
        assert parsed.payload.__class__.__name__ == 'EAP_IDENTITY'
        assert parsed.payload.identity == b'alice'
        assert parsed.payload.code == 1

    def test_response_code(self):
        req = EAP_IDENTITY(code=1, identity=b'')
        resp = EAP_IDENTITY(code=2, identity=b'user')
        assert req.code == 1
        assert resp.code == 2


# ---------------------------------------------------------------------------
# EAP-Key
# ---------------------------------------------------------------------------

class TestEAPKey:

    def test_minimum_wire_size(self):
        raw = EAP_Key().build()

        assert len(raw) == 95

    def test_roundtrip(self):
        key = EAPOL() / EAP_Key(
            key_info=0x0183,  # pairwise + ack + mic + kdv=2
            key_replay_counter=b'\x00\x00\x00\x00\x00\x00\x00\x01',
            key_nonce=b'\xaa' * 32,
        )
        parsed = EAPOLParser.load_as_eapol_layer(key.build())

        assert parsed[EAP_Key].__class__.__name__ == 'EAP_Key'
        assert parsed[EAP_Key].key_info == 0x0183
        assert parsed[EAP_Key].key_nonce == b'\xaa' * 32
        assert parsed[EAP_Key].key_replay_counter == b'\x00\x00\x00\x00\x00\x00\x00\x01'

    def test_key_info_helpers(self):
        key = EAP_Key()
        key.set_key_info(key_type=1, key_ack=True, key_mic=True,
                         descriptor_version=2)
        assert key.is_pairwise()
        assert key.is_key_ack()
        assert key.is_key_mic()
        assert not key.is_install()
        assert not key.is_secure()

    def test_key_data_len_auto(self):
        key = EAPOL() / EAP_Key(key_data=b'\xdd' * 22)
        parsed = EAPOLParser.load_as_eapol_layer(key.build())
        assert parsed[EAP_Key].key_data_len == 22
        assert parsed[EAP_Key].key_data == b'\xdd' * 22


# ---------------------------------------------------------------------------
# EAP-NAK and EAP-Notification
# ---------------------------------------------------------------------------

class TestNAK:

    def test_roundtrip(self):
        pkt = EAPOL() / EAP_NAK(allowed_types=b'\x0d\x15')
        parsed = EAPOLParser.load_as_eapol_layer(pkt.build())
        assert parsed.payload.__class__.__name__ == 'EAP_NAK'
        assert parsed.payload.allowed_types == b'\x0d\x15'


class TestNotification:

    def test_roundtrip(self):
        notif = EAP_NOTIFICATION(message=b'Hello')
        raw = notif.build()
        assert raw[4] == EAP_TYPE_NOTIFICATION
        assert raw[5:] == b'Hello'


def test_mschapv2_response_over_255_bytes():
    from LightPacket.eapol import EAP_MSCHAPv2, EAPOLParser, MSCHAPV2_OPCODE_RESPONSE
    resp = EAP_MSCHAPv2(
        opcode=MSCHAPV2_OPCODE_RESPONSE,
        response=b'\xaa' * 49,
        name=b'long-username-with-many-chars-' * 10,  # pushes over 255
    )
    raw = (EAPOL() / resp).build()
    eap_len = struct.unpack('!H', raw[6:8])[0]   # EAP length after EAPOL 4-byte header
    assert eap_len > 255
    # both bytes of the length must be set — this is the regression
    assert raw[6] != 0

    parsed = EAPOLParser.load_as_eapol_layer(raw)
    assert parsed.payload.length > 255