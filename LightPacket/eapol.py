# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.BaseLayer import BaseLayer
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from LightPacket.Consts import eapol_types, eapol_versions

LLogger = Logger()

# --- EAPOL code values (IEEE 802.1X) ---
EAPOL_CODE_EAP_PACKET = 0x00
EAPOL_CODE_START      = 0x01
EAPOL_CODE_LOGOFF     = 0x02
EAPOL_CODE_KEY        = 0x03
EAPOL_CODE_ASF_ALERT  = 0x04

# --- EAP code values (RFC 3748) ---
EAP_CODE_REQUEST  = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS  = 3
EAP_CODE_FAILURE  = 4

# --- EAP type values ---
EAP_TYPE_IDENTITY     = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_NAK          = 3
EAP_TYPE_MD5          = 4
EAP_TYPE_OTP          = 5
EAP_TYPE_GTC          = 6
EAP_TYPE_TLS          = 13
EAP_TYPE_LEAP         = 17
EAP_TYPE_TTLS         = 21
EAP_TYPE_PEAP         = 25
EAP_TYPE_MSCHAPV2     = 26
EAP_TYPE_FAST         = 43
EAP_TYPE_PWD          = 52

# Names of layer classes that carry an EAP payload inside EAPOL.
_EAP_METHOD_LAYERS = {
    'EAP_STATE', 'EAP_IDENTITY', 'EAP_PEAP', 'EAP_MD5',
    'EAP_TLS', 'EAP_TTLS', 'EAP_FAST', 'EAP_LEAP', 'EAP_MSCHAPv2',
    'EAP_NAK', 'EAP_NOTIFICATION', 'EAP_PWD', 'EAP_GTC', 'EAP_OTP',
}

def _set_u16(buf: bytearray, offset: int, value: int) -> None:
    """Write a big-endian u16 into a bytearray in place."""
    buf[offset]     = (value >> 8) & 0xFF
    buf[offset + 1] = value & 0xFF


# ---------------------------------------------------------------------------
# EAPOL
# ---------------------------------------------------------------------------

class EAPOL(BaseLayer):

    def __init__(self, version: int = 2, code: int = 0, length: int = 0):
        super().__init__()
        self.version = version
        self.code = code
        self.length = length

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        layer = self.payload.__class__.__name__ if self.payload else None

        # Only auto-detect code when the caller hasn't set one.
        if self.code == 0 and layer is not None:
            if layer == 'EAP_Key':
                self.code = EAPOL_CODE_KEY
            elif layer in _EAP_METHOD_LAYERS:
                self.code = EAPOL_CODE_EAP_PACKET
            else:
                self.code = EAPOL_CODE_START

        if self.length == 0:
            self.length = len(payload_bytes)

        return struct.pack('!BBH', self.version, self.code, self.length) + payload_bytes

    def __len__(self):
        return 4 + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return f"<EAPOL version={hex(self.version)}, code={hex(self.code)}, len={hex(self.length)}>"

    def copy(self) -> 'EAPOL':
        new = EAPOL(self.version, self.code, self.length)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        return [
            f"version={self.version}",
            f"code={self.code} {eapol_types.get(self.code, '')}",
            f"len={self.length}",
        ]


class EAPOLParser:

    @staticmethod
    def load_as_eapol_layer(raw_packet, Alr=0, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 4:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAPOL required header is 4 bytes")
            return None

        header = raw_packet[0][:4]
        version, code, length = struct.unpack('!BBH', header)
        payload = raw_packet[0][4:4 + length]

        if verbose:
            print(f"\n{BOLD}EAPOL LAYER : {RESET}Len({PURPLE}{len(header)}{RESET}) "
                  f"Total Len({PURPLE}{4 + len(payload)}{RESET}) >")
            print(f'   {BLUE}VERSION:{CYAN} {hex(version)} {eapol_versions.get(version, "")}')
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {eapol_types.get(code, "")}')
            print(f'   {BLUE}LEN:{CYAN} {hex(length)}{RESET}')

        eapol = EAPOL(version=version, code=code, length=length)

        if not payload:
            return eapol

        prelayer = EAPOLParser._dispatch(code, payload, verbose)
        return eapol / prelayer

    @staticmethod
    def _dispatch(code: int, payload: bytes, verbose: bool):
        from LightPacket.Raw import RawParser

        if code == EAPOL_CODE_KEY:
            return EAPOLKeyParser.load_as_eapolkey_layer(payload, verbose=verbose)

        if code == EAPOL_CODE_EAP_PACKET:
            if payload[:1] in (b'\x03', b'\x04'):
                return EAP_STATE_Parser.load_as_eapol_state_layer(payload, verbose=verbose)

            if len(payload) >= 5:
                eap_type = payload[4]
                parser = _EAP_TYPE_PARSERS.get(eap_type)
                if parser is not None:
                    return parser(payload, verbose=verbose)

            return RawParser.load_as_Raw_layer(payload, verbose=verbose)

        return RawParser.load_as_Raw_layer(payload, verbose=verbose)


# ---------------------------------------------------------------------------
# EAP Success / Failure
# ---------------------------------------------------------------------------

class EAP_STATE(BaseLayer):
    def __init__(self, code: int = 3, id: int = 1, length: int = 0):
        super().__init__()
        self.code = code
        self.id = id
        self.length = length

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        if self.length == 0:
            self.length = 4 + len(payload_bytes)
        return struct.pack('!BBH', self.code, self.id, self.length) + payload_bytes

    def __len__(self):
        return 4 + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        name = "Success" if self.code == EAP_CODE_SUCCESS else \
               "Failure" if self.code == EAP_CODE_FAILURE else "Unknown"
        return f"<EAP_STATE {name} code={hex(self.code)}, id={hex(self.id)}, len={hex(self.length)}>"

    def copy(self) -> 'EAP_STATE':
        new = EAP_STATE(self.code, self.id, self.length)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        return [f"code={self.code}", f"id={self.id}", f"len={self.length}"]


class EAP_STATE_Parser:

    @staticmethod
    def load_as_eapol_state_layer(raw_packet, Alr=0, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 4:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP STATE required header is 4 bytes")
            return None

        code, eap_id, length = struct.unpack('!BBH', raw_packet[0][:4])
        payload = raw_packet[0][4:4 + length]

        if verbose:
            label = "SUCCESS" if code == EAP_CODE_SUCCESS else \
                    "FAILURE" if code == EAP_CODE_FAILURE else "STATE"
            print(f"\n{BOLD}EAP {label} LAYER : {RESET}Len({PURPLE}4{RESET}) "
                  f"Total Len({PURPLE}{4 + len(payload)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(length)}{RESET}')

        eapol = EAP_STATE(code=code, id=eap_id, length=length)

        if payload:
            from .Raw import RawParser
            return eapol / RawParser.load_as_Raw_layer(payload, verbose=verbose)
        return eapol


# ---------------------------------------------------------------------------
# EAP-Identity
# ---------------------------------------------------------------------------

class EAP_IDENTITY(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = EAP_TYPE_IDENTITY, identity: bytes = b''):
        super().__init__()
        self.code = code
        self.id = id
        self.length = length
        self.type = type
        self.identity = identity

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        if self.length == 0:
            self.length = 5 + len(self.identity) + len(payload_bytes)
        return (struct.pack('!BBHB', self.code, self.id, self.length, self.type)
                + self.identity + payload_bytes)

    def __len__(self):
        return 5 + len(self.identity) + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (f"<EAP_IDENTITY code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, identity={self.identity}>")

    def copy(self) -> 'EAP_IDENTITY':
        new = EAP_IDENTITY(self.code, self.id, self.length, self.type, self.identity)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        return [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}",
            f"type={self.type}",
            f"identity={self.identity}",
        ]


class EAP_IDENTITY_Parser:

    @staticmethod
    def load_as_eapol_identity_layer(raw_packet, Alr=0, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 5:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP IDENTITY required header is 5 bytes")
            return None

        code, eap_id, length, eap_type = struct.unpack('!BBHB', raw_packet[0][:5])
        identity = raw_packet[0][5:length]

        if verbose:
            label = "(Request)" if code == EAP_CODE_REQUEST else \
                    "(Response)" if code == EAP_CODE_RESPONSE else ""
            print(f"\n{BOLD}EAP IDENTITY LAYER : {RESET}Len({PURPLE}5{RESET}) "
                  f"Total Len({PURPLE}{length}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(length)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)}{RESET}')
            if identity:
                print(f'   {BLUE}IDENTITY:{CYAN} {identity}{RESET}')

        return EAP_IDENTITY(code=code, id=eap_id, length=length,
                            type=eap_type, identity=identity)


# ---------------------------------------------------------------------------
# EAP-MD5
# ---------------------------------------------------------------------------

class EAP_MD5(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = EAP_TYPE_MD5, value_size: int = 0,
                 value: bytes = b'', name: bytes = b''):
        super().__init__()
        self.code = code
        self.id = id
        self.length = length
        self.type = type
        self.value_size = value_size
        self.value = value
        self.name = name

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        # Only derive value_size from value when the caller hasn't set one.
        if self.value_size == 0:
            self.value_size = len(self.value) if self.value else 16

        if self.length == 0:
            self.length = 6 + len(self.value) + len(self.name) + len(payload_bytes)

        return (struct.pack('!BBHBB', self.code, self.id, self.length,
                            self.type, self.value_size)
                + self.value + self.name + payload_bytes)

    def __len__(self):
        return (6 + len(self.value) + len(self.name)
                + (len(self.payload) if self.payload else 0))

    def __repr__(self):
        return (f"<EAP_MD5 code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"value_size={hex(self.value_size)}, value={self.value}, name={self.name}>")

    def copy(self) -> 'EAP_MD5':
        new = EAP_MD5(self.code, self.id, self.length, self.type,
                      self.value_size, self.value, self.name)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}",
            f"type={self.type}",
            f"value_size={self.value_size}",
            f"value={self.value}",
        ]
        if self.name:
            fields.append(f"name={self.name}")
        return fields


class EAP_MD5_Parser:

    @staticmethod
    def load_as_eapol_md5_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-MD5 requires at least 6 bytes")
            return None

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])
        if eap_type != EAP_TYPE_MD5:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_MD5} (MD5)")

        value_size = data[5]
        value = data[6:6 + value_size]
        name = data[6 + value_size:]

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            value_label = "CHALLENGE" if code == 1 else "MD5_HASH" if code == 2 else "VALUE"
            print(f"\n{BOLD}EAP MD5 LAYER : {RESET}Len({PURPLE}6{RESET}) "
                  f"Total Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (MD5)')
            print(f'   {BLUE}VALUE_SIZE:{CYAN} {hex(value_size)} {RESET}')
            if value:
                print(f'   {BLUE}{value_label}:{CYAN} {value}{RESET}')
            if name:
                print(f'   {BLUE}NAME:{CYAN} {name}{RESET}')

        return EAP_MD5(code=code, id=eap_id, length=total_len, type=EAP_TYPE_MD5,
                       value_size=value_size, value=value, name=name)


# ---------------------------------------------------------------------------
# EAP-TLS  (RFC 5216)
# ---------------------------------------------------------------------------

class EAP_TLS(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = EAP_TYPE_TLS, L: int = 0, M: int = 0, S: int = 0,
                 reserved: int = 0, tls_message_len: int = 0,
                 tls_data: bytes = b''):
        super().__init__()
        self.code = code
        self.id = id
        self.length = length
        self.type = type
        self.L = L
        self.M = M
        self.S = S
        self.reserved = reserved
        self.tls_message_len = tls_message_len
        self.tls_data = tls_data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        flags = (self.L << 7) | (self.M << 6) | (self.S << 5) | (self.reserved & 0x1F)

        body = struct.pack('!BBHBB', self.code, self.id, self.length,
                           self.type, flags)
        if self.L:
            if self.tls_message_len == 0:
                self.tls_message_len = len(self.tls_data)
            body += struct.pack('!I', self.tls_message_len)
        body += self.tls_data + payload_bytes

        if self.length == 0:
            self.length = len(body)
            _set_u16(bytearray(body), 2, self.length) if False else None
            arr = bytearray(body)
            _set_u16(arr, 2, self.length)
            body = bytes(arr)
        return body

    def __len__(self):
        total = 5 + len(self.tls_data)
        if self.L:
            total += 4
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        return (f"<EAP_TLS code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"L={self.L} M={self.M} S={self.S}, "
                f"tls_len={len(self.tls_data)}>")

    def copy(self) -> 'EAP_TLS':
        new = EAP_TLS(self.code, self.id, self.length, self.type,
                      self.L, self.M, self.S, self.reserved,
                      self.tls_message_len, self.tls_data)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}",
            f"type={self.type}",
            f"L={self.L} M={self.M} S={self.S}",
            f"reserved={self.reserved}",
        ]
        if self.L:
            fields.append(f"tls_message_len={self.tls_message_len}")
        if self.tls_data:
            fields.append(f"tls_data={self.tls_data.hex()}")
        return fields


class EAP_TLS_Parser:

    @staticmethod
    def load_as_eap_tls_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-TLS requires at least 6 bytes")
            return None

        code, eap_id, total_len, eap_type, flags = struct.unpack('!BBHBB', data[:6])
        if eap_type != EAP_TYPE_TLS:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_TLS} (TLS)")

        L = (flags >> 7) & 0x01
        M = (flags >> 6) & 0x01
        S = (flags >> 5) & 0x01
        reserved = flags & 0x1F

        offset = 6
        tls_message_len = 0
        if L:
            if len(data) < offset + 4:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message="EAP-TLS: L flag set but tls_message_len missing")
                return None
            tls_message_len = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4

        tls_data = data[offset:]

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            flags_desc = []
            if L: flags_desc.append("Length included")
            if M: flags_desc.append("More fragments")
            if S: flags_desc.append("Start")
            if not flags_desc: flags_desc.append("None")

            print(f"\n{BOLD}EAP TLS LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (TLS)')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:02x} [{", ".join(flags_desc)}]')
            if L:
                print(f'   {BLUE}TLS_MESSAGE_LEN:{CYAN} {hex(tls_message_len)}')
            if tls_data:
                print(f'   {BLUE}TLS Data:{CYAN} {tls_data[:64].hex()}{RESET}')

        return EAP_TLS(code=code, id=eap_id, length=total_len, type=EAP_TYPE_TLS,
                       L=L, M=M, S=S, reserved=reserved,
                       tls_message_len=tls_message_len, tls_data=tls_data)


# ---------------------------------------------------------------------------
# EAPOL-Key (4-way handshake)
# ---------------------------------------------------------------------------

EAPOL_KEY_INFO_KEY_TYPE           = 0x0001
EAPOL_KEY_INFO_KEY_INDEX_MASK     = 0x0006
EAPOL_KEY_INFO_KEY_INDEX_SHIFT    = 1
EAPOL_KEY_INFO_INSTALL            = 0x0040
EAPOL_KEY_INFO_KEY_ACK            = 0x0080
EAPOL_KEY_INFO_KEY_MIC            = 0x0100
EAPOL_KEY_INFO_SECURE             = 0x0200
EAPOL_KEY_INFO_ERROR              = 0x0400
EAPOL_KEY_INFO_REQUEST            = 0x0800
EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA = 0x1000
EAPOL_KEY_INFO_SMK_MESSAGE        = 0x2000
EAPOL_KEY_INFO_KEY_ID_MASK        = 0xC000
EAPOL_KEY_INFO_KEY_ID_SHIFT       = 14

EAPOL_KEY_DESCRIPTOR_VERSION_MASK  = 0x0003
EAPOL_KEY_DESCRIPTOR_VERSION_SHIFT = 0

EAPOL_KEY_DESCRIPTOR_1   = 1
EAPOL_KEY_DESCRIPTOR_2   = 2
EAPOL_KEY_DESCRIPTOR_WPA = 3

EAPOL_KEY_DESCRIPTOR_NAMES = {
    1: "RC4 (WEP/WPA legacy)",
    2: "RSN (802.11i/WPA2 - AES)",
    3: "WPA (legacy)",
}

EAPOL_KEY_MIC_LEN            = 16
EAPOL_KEY_NONCE_LEN          = 32
EAPOL_KEY_IV_LEN             = 16
EAPOL_KEY_RSC_LEN            = 8
EAPOL_KEY_ID_LEN             = 8
EAPOL_KEY_REPLAY_COUNTER_LEN = 8


class EAP_Key(BaseLayer):
    def __init__(self, descriptor: int = EAPOL_KEY_DESCRIPTOR_2, key_info: int = 0,
                 key_len: int = 0,
                 key_replay_counter: bytes = b'\x00' * EAPOL_KEY_REPLAY_COUNTER_LEN,
                 key_nonce: bytes = b'\x00' * EAPOL_KEY_NONCE_LEN,
                 eapol_key_iv: bytes = b'\x00' * EAPOL_KEY_IV_LEN,
                 key_rsc: bytes = b'\x00' * EAPOL_KEY_RSC_LEN,
                 key_id: bytes = b'\x00' * EAPOL_KEY_ID_LEN,
                 key_mic: bytes = b'\x00' * EAPOL_KEY_MIC_LEN,
                 key_data_len: int = 0, key_data: bytes = b''):
        super().__init__()
        self.descriptor = descriptor
        self.key_info = key_info
        self.key_len = key_len
        self.key_replay_counter = key_replay_counter
        self.key_nonce = key_nonce
        self.eapol_key_iv = eapol_key_iv
        self.key_rsc = key_rsc
        self.key_id = key_id
        self.key_mic = key_mic
        self.key_data_len = key_data_len
        self.key_data = key_data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        if self.key_len == 0:
            self.key_len = len(self.key_data)
        if self.key_data_len == 0:
            self.key_data_len = len(self.key_data)

        return (
            struct.pack('!BHH', self.descriptor, self.key_info, self.key_len)
            + self.key_replay_counter
            + self.key_nonce
            + self.eapol_key_iv
            + self.key_rsc
            + self.key_id
            + self.key_mic[:EAPOL_KEY_MIC_LEN]
            + struct.pack('!H', self.key_data_len)
            + self.key_data
            + payload_bytes
        )

    def __len__(self):
        return (1 + 2 + 2 + EAPOL_KEY_REPLAY_COUNTER_LEN + EAPOL_KEY_NONCE_LEN
                + EAPOL_KEY_IV_LEN + EAPOL_KEY_RSC_LEN + EAPOL_KEY_ID_LEN
                + EAPOL_KEY_MIC_LEN + 2 + len(self.key_data)
                + (len(self.payload) if self.payload else 0))

    def __repr__(self):
        return (f"<EAP_Key descriptor={self.descriptor}, "
                f"key_info=0x{self.key_info:04x}, "
                f"key_len={self.key_len}, key_data_len={self.key_data_len}, "
                f"replay={self.key_replay_counter.hex()[:8]}...>")

    def copy(self) -> 'EAP_Key':
        new = EAP_Key(self.descriptor, self.key_info, self.key_len,
                      self.key_replay_counter, self.key_nonce, self.eapol_key_iv,
                      self.key_rsc, self.key_id, self.key_mic,
                      self.key_data_len, self.key_data)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        fields = [
            f"descriptor={self.descriptor}",
            f"key_info=0x{self.key_info:04x}",
            f"key_len={self.key_len}",
            f"replay_counter={self.key_replay_counter.hex()}",
            f"nonce={self.key_nonce.hex()}",
            f"iv={self.eapol_key_iv.hex()}",
            f"rsc={self.key_rsc.hex()}",
            f"key_id={self.key_id.hex()}",
            f"mic={self.key_mic.hex()}",
            f"key_data_len={self.key_data_len}",
        ]
        if self.key_data:
            fields.append(f"key_data={self.key_data[:32].hex()}")
        return fields

    # --- key_info helpers ---
    def get_descriptor_version_from_flags(self) -> int:
        return (self.key_info & EAPOL_KEY_DESCRIPTOR_VERSION_MASK) >> EAPOL_KEY_DESCRIPTOR_VERSION_SHIFT

    def get_descriptor_version_name(self) -> str:
        return EAPOL_KEY_DESCRIPTOR_NAMES.get(self.get_descriptor_version_from_flags(),
                                              "Unknown")

    def is_rsn(self) -> bool:
        return self.get_descriptor_version_from_flags() == EAPOL_KEY_DESCRIPTOR_2

    def get_key_type(self) -> int:
        return self.key_info & EAPOL_KEY_INFO_KEY_TYPE

    def is_pairwise(self) -> bool:
        return self.get_key_type() == 1

    def is_group(self) -> bool:
        return self.get_key_type() == 0

    def get_key_index(self) -> int:
        return (self.key_info & EAPOL_KEY_INFO_KEY_INDEX_MASK) >> EAPOL_KEY_INFO_KEY_INDEX_SHIFT

    def get_key_id(self) -> int:
        return (self.key_info & EAPOL_KEY_INFO_KEY_ID_MASK) >> EAPOL_KEY_INFO_KEY_ID_SHIFT

    def is_install(self) -> bool: return bool(self.key_info & EAPOL_KEY_INFO_INSTALL)
    def is_key_ack(self) -> bool: return bool(self.key_info & EAPOL_KEY_INFO_KEY_ACK)
    def is_key_mic(self) -> bool: return bool(self.key_info & EAPOL_KEY_INFO_KEY_MIC)
    def is_secure(self)  -> bool: return bool(self.key_info & EAPOL_KEY_INFO_SECURE)
    def is_error(self)   -> bool: return bool(self.key_info & EAPOL_KEY_INFO_ERROR)
    def is_request(self) -> bool: return bool(self.key_info & EAPOL_KEY_INFO_REQUEST)
    def is_encrypted_key_data(self) -> bool:
        return bool(self.key_info & EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA)
    def is_smk_message(self) -> bool:
        return bool(self.key_info & EAPOL_KEY_INFO_SMK_MESSAGE)

    def set_key_info(self, key_type: int = 0, key_index: int = 0, key_id: int = 0,
                     install: bool = False, key_ack: bool = False,
                     key_mic: bool = False, secure: bool = False,
                     error: bool = False, request: bool = False,
                     encrypted: bool = False, smk: bool = False,
                     descriptor_version: int = EAPOL_KEY_DESCRIPTOR_2) -> None:
        info = 0
        info |= (descriptor_version & 0x03) << EAPOL_KEY_DESCRIPTOR_VERSION_SHIFT
        info |= (key_type & 0x01)
        info |= (key_index & 0x03) << EAPOL_KEY_INFO_KEY_INDEX_SHIFT
        info |= (key_id & 0x03) << EAPOL_KEY_INFO_KEY_ID_SHIFT
        if install:   info |= EAPOL_KEY_INFO_INSTALL
        if key_ack:   info |= EAPOL_KEY_INFO_KEY_ACK
        if key_mic:   info |= EAPOL_KEY_INFO_KEY_MIC
        if secure:    info |= EAPOL_KEY_INFO_SECURE
        if error:     info |= EAPOL_KEY_INFO_ERROR
        if request:   info |= EAPOL_KEY_INFO_REQUEST
        if encrypted: info |= EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA
        if smk:       info |= EAPOL_KEY_INFO_SMK_MESSAGE
        self.key_info = info


class EAPOLKeyParser:

    @staticmethod
    def load_as_eapolkey_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 95:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP Key requires at least 95 bytes")
            return None

        offset = 0
        descriptor = data[offset]; offset += 1
        key_info = struct.unpack('!H', data[offset:offset + 2])[0]; offset += 2
        key_len = struct.unpack('!H', data[offset:offset + 2])[0]; offset += 2
        key_replay_counter = data[offset:offset + 8]; offset += 8
        key_nonce = data[offset:offset + 32]; offset += 32
        eapol_key_iv = data[offset:offset + 16]; offset += 16
        key_rsc = data[offset:offset + 8]; offset += 8
        key_id = data[offset:offset + 8]; offset += 8
        key_mic = data[offset:offset + 16]; offset += 16
        key_data_len = struct.unpack('!H', data[offset:offset + 2])[0]; offset += 2
        key_data = data[offset:offset + key_data_len]
        offset += key_data_len

        if verbose:
            desc = EAPOL_KEY_DESCRIPTOR_NAMES.get(descriptor, f"Unknown ({descriptor})")
            kdv = (key_info & EAPOL_KEY_DESCRIPTOR_VERSION_MASK) >> EAPOL_KEY_DESCRIPTOR_VERSION_SHIFT
            flags_desc = []
            for mask, name in [(EAPOL_KEY_INFO_INSTALL, "Install"),
                               (EAPOL_KEY_INFO_KEY_ACK, "Key ACK"),
                               (EAPOL_KEY_INFO_KEY_MIC, "Key MIC"),
                               (EAPOL_KEY_INFO_SECURE, "Secure"),
                               (EAPOL_KEY_INFO_ERROR, "Error"),
                               (EAPOL_KEY_INFO_REQUEST, "Request"),
                               (EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA, "Encrypted"),
                               (EAPOL_KEY_INFO_SMK_MESSAGE, "SMK")]:
                if key_info & mask:
                    flags_desc.append(name)

            print(f"\n{BOLD}EAP KEY LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}Descriptor:{CYAN} {descriptor} ({desc})')
            print(f'   {BLUE}Key Info:{CYAN} 0x{key_info:04x} [{", ".join(flags_desc)}]')
            print(f'   {BLUE}  KDV:{CYAN} {kdv}')
            print(f'   {BLUE}Key Length:{CYAN} {key_len}')
            print(f'   {BLUE}Replay Counter:{CYAN} {key_replay_counter.hex()}')
            print(f'   {BLUE}Nonce:{CYAN} {key_nonce.hex()}')
            print(f'   {BLUE}MIC:{CYAN} {key_mic.hex()}')
            print(f'   {BLUE}Key Data Length:{CYAN} {key_data_len} {RESET}')

        eapolkey = EAP_Key(descriptor=descriptor, key_info=key_info, key_len=key_len,
                           key_replay_counter=key_replay_counter, key_nonce=key_nonce,
                           eapol_key_iv=eapol_key_iv, key_rsc=key_rsc, key_id=key_id,
                           key_mic=key_mic, key_data_len=key_data_len, key_data=key_data)

        if len(data) > offset:
            from .Raw import RawParser
            return eapolkey / RawParser.load_as_Raw_layer(data[offset:], verbose=verbose)
        return eapolkey


# ---------------------------------------------------------------------------
# EAP-TTLS (RFC 5281)
# ---------------------------------------------------------------------------

class EAP_TTLS(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = EAP_TYPE_TTLS, L: int = 0, M: int = 0, S: int = 0,
                 reserved: int = 0, version: int = 0,
                 tls_message_len: int = 0, tls_data: bytes = b''):
        super().__init__()
        self.code = code
        self.id = id
        self.length = length
        self.type = type
        self.L = L
        self.M = M
        self.S = S
        self.reserved = reserved
        self.version = version
        self.tls_message_len = tls_message_len
        self.tls_data = tls_data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        flags = ((self.L << 7) | (self.M << 6) | (self.S << 5)
                 | ((self.reserved & 0x03) << 3) | (self.version & 0x07))

        body = struct.pack('!BBHBB', self.code, self.id, self.length,
                           self.type, flags)
        if self.L:
            if self.tls_message_len == 0:
                self.tls_message_len = len(self.tls_data)
            body += struct.pack('!I', self.tls_message_len)
        body += self.tls_data + payload_bytes

        if self.length == 0:
            self.length = len(body)
            arr = bytearray(body)
            _set_u16(arr, 2, self.length)
            body = bytes(arr)
        return body

    def __len__(self):
        total = 5 + len(self.tls_data)
        if self.L:
            total += 4
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        return (f"<EAP_TTLS code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"L={self.L} M={self.M} S={self.S} V={self.version}, "
                f"tls_len={len(self.tls_data)}>")

    def copy(self) -> 'EAP_TTLS':
        new = EAP_TTLS(self.code, self.id, self.length, self.type,
                       self.L, self.M, self.S, self.reserved, self.version,
                       self.tls_message_len, self.tls_data)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}", f"id={self.id}", f"len={self.length}",
            f"type={self.type}", f"L={self.L} M={self.M} S={self.S}",
            f"reserved={self.reserved}", f"version={self.version}",
        ]
        if self.L:
            fields.append(f"tls_message_len={self.tls_message_len}")
        if self.tls_data:
            fields.append(f"tls_data={self.tls_data.hex()}")
        return fields


class EAP_TTLS_Parser:

    @staticmethod
    def load_as_eap_ttls_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-TTLS requires at least 6 bytes")
            return None

        code, eap_id, total_len, eap_type, flags = struct.unpack('!BBHBB', data[:6])
        if eap_type != EAP_TYPE_TTLS:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_TTLS} (TTLS)")

        L = (flags >> 7) & 0x01
        M = (flags >> 6) & 0x01
        S = (flags >> 5) & 0x01
        reserved = (flags >> 3) & 0x03
        version = flags & 0x07

        offset = 6
        tls_message_len = 0
        if L:
            if len(data) < offset + 4:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message="EAP-TTLS: L flag set but Message Length missing")
                return None
            tls_message_len = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4

        tls_data = data[offset:]

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            flags_desc = []
            if L: flags_desc.append("Length included")
            if M: flags_desc.append("More fragments")
            if S: flags_desc.append("Start")
            if not flags_desc: flags_desc.append("None")

            print(f"\n{BOLD}EAP TTLS LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (TTLS)')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:02x} [{", ".join(flags_desc)}]')
            print(f'   {BLUE}VERSION:{CYAN} {version} {RESET}')
            if L:
                print(f'   {BLUE}TLS_MESSAGE_LEN:{CYAN} {hex(tls_message_len)} {RESET}')
            if tls_data:
                print(f'   {BLUE}TLS Data:{CYAN} {tls_data.hex()}{RESET}')

        return EAP_TTLS(code=code, id=eap_id, length=total_len, type=EAP_TYPE_TTLS,
                        L=L, M=M, S=S, reserved=reserved, version=version,
                        tls_message_len=tls_message_len, tls_data=tls_data)


# ---------------------------------------------------------------------------
# EAP-PEAP (RFC 7486)
# ---------------------------------------------------------------------------

class EAP_PEAP(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = EAP_TYPE_PEAP, L: int = 0, M: int = 0, S: int = 0,
                 reserved: int = 0, version: int = 0,
                 tls_message_len: int = 0, tls_data: bytes = b''):
        super().__init__()
        self.code = code
        self.id = id
        self.length = length
        self.type = type
        self.L = L
        self.M = M
        self.S = S
        self.reserved = reserved
        self.version = version
        self.tls_message_len = tls_message_len
        self.tls_data = tls_data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        flags = ((self.L << 7) | (self.M << 6) | (self.S << 5)
                 | ((self.reserved & 0x03) << 3) | (self.version & 0x07))

        body = struct.pack('!BBHBB', self.code, self.id, self.length,
                           self.type, flags)
        if self.L:
            if self.tls_message_len == 0:
                self.tls_message_len = len(self.tls_data)
            body += struct.pack('!I', self.tls_message_len)
        body += self.tls_data + payload_bytes

        if self.length == 0:
            self.length = len(body)
            arr = bytearray(body)
            _set_u16(arr, 2, self.length)
            body = bytes(arr)
        return body

    def __len__(self):
        total = 5 + len(self.tls_data)
        if self.L:
            total += 4
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        return (f"<EAP_PEAP code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"L={self.L} M={self.M} S={self.S} V={self.version}, "
                f"tls_len={len(self.tls_data)}>")

    def copy(self) -> 'EAP_PEAP':
        new = EAP_PEAP(self.code, self.id, self.length, self.type,
                       self.L, self.M, self.S, self.reserved, self.version,
                       self.tls_message_len, self.tls_data)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}", f"id={self.id}", f"len={self.length}",
            f"type={self.type}", f"L={self.L} M={self.M} S={self.S}",
            f"reserved={self.reserved}", f"version={self.version}",
        ]
        if self.L:
            fields.append(f"tls_message_len={self.tls_message_len}")
        if self.tls_data:
            fields.append(f"tls_data={self.tls_data.hex()}")
        return fields


class EAP_PEAP_Parser:

    @staticmethod
    def load_as_eap_peap_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-PEAP requires at least 6 bytes")
            return None

        code, eap_id, total_len, eap_type, flags = struct.unpack('!BBHBB', data[:6])
        if eap_type != EAP_TYPE_PEAP:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_PEAP} (PEAP)")

        L = (flags >> 7) & 0x01
        M = (flags >> 6) & 0x01
        S = (flags >> 5) & 0x01
        reserved = (flags >> 3) & 0x03
        version = flags & 0x07

        offset = 6
        tls_message_len = 0
        if L:
            if len(data) < offset + 4:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message="EAP-PEAP: L flag set but Message Length missing")
                return None
            tls_message_len = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4

        tls_data = data[offset:]

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            flags_desc = []
            if L: flags_desc.append("Length included")
            if M: flags_desc.append("More fragments")
            if S: flags_desc.append("Start")
            if not flags_desc: flags_desc.append("None")

            print(f"\n{BOLD}EAP PEAP LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (PEAP)')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:02x} [{", ".join(flags_desc)}]')
            print(f'   {BLUE}VERSION:{CYAN} {version}')
            if L:
                print(f'   {BLUE}TLS_MESSAGE_LEN:{CYAN} {hex(tls_message_len)}')
            if tls_data:
                print(f'   {BLUE}TLS Data:{CYAN} {tls_data.hex()}{RESET}')

        return EAP_PEAP(code=code, id=eap_id, length=total_len, type=EAP_TYPE_PEAP,
                        L=L, M=M, S=S, reserved=reserved, version=version,
                        tls_message_len=tls_message_len, tls_data=tls_data)


# ---------------------------------------------------------------------------
# EAP-FAST (RFC 4851) — note: no version nibble, reserved is 5 bits
# ---------------------------------------------------------------------------

class EAP_FAST(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = EAP_TYPE_FAST, L: int = 0, M: int = 0, S: int = 0,
                 reserved: int = 0, message_len: int = 0, data: bytes = b''):
        super().__init__()
        self.code = code
        self.id = id
        self.length = length
        self.type = type
        self.L = L
        self.M = M
        self.S = S
        self.reserved = reserved
        self.message_len = message_len
        self.data = data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        flags = (self.L << 7) | (self.M << 6) | (self.S << 5) | (self.reserved & 0x1F)

        body = struct.pack('!BBHBB', self.code, self.id, self.length,
                           self.type, flags)
        if self.L:
            if self.message_len == 0:
                self.message_len = len(self.data)
            body += struct.pack('!I', self.message_len)
        body += self.data + payload_bytes

        if self.length == 0:
            self.length = len(body)
            arr = bytearray(body)
            _set_u16(arr, 2, self.length)
            body = bytes(arr)
        return body

    def __len__(self):
        total = 5 + len(self.data)
        if self.L:
            total += 4
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        return (f"<EAP_FAST code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"L={self.L} M={self.M} S={self.S}, data_len={len(self.data)}>")

    def copy(self) -> 'EAP_FAST':
        new = EAP_FAST(self.code, self.id, self.length, self.type,
                       self.L, self.M, self.S, self.reserved,
                       self.message_len, self.data)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}", f"id={self.id}", f"len={self.length}",
            f"type={self.type}", f"L={self.L} M={self.M} S={self.S}",
            f"reserved={self.reserved}",
        ]
        if self.L:
            fields.append(f"message_len={self.message_len}")
        if self.data:
            fields.append(f"data={self.data.hex()}")
        return fields


class EAP_FAST_Parser:

    @staticmethod
    def load_as_eap_fast_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-FAST requires at least 6 bytes")
            return None

        code, eap_id, total_len, eap_type, flags = struct.unpack('!BBHBB', data[:6])
        if eap_type != EAP_TYPE_FAST:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_FAST} (FAST)")

        L = (flags >> 7) & 0x01
        M = (flags >> 6) & 0x01
        S = (flags >> 5) & 0x01
        reserved = flags & 0x1F

        offset = 6
        message_len = 0
        if L:
            if len(data) < offset + 4:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message="EAP-FAST: L flag set but Message Length missing")
                return None
            message_len = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4

        fast_data = data[offset:]

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            flags_desc = []
            if L: flags_desc.append("Length included")
            if M: flags_desc.append("More fragments")
            if S: flags_desc.append("Start")
            if not flags_desc: flags_desc.append("None")

            print(f"\n{BOLD}EAP FAST LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (FAST)')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:02x} [{", ".join(flags_desc)}]')
            if L:
                print(f'   {BLUE}MESSAGE_LEN:{CYAN} {hex(message_len)}')
            if fast_data:
                print(f'   {BLUE}Data:{CYAN} {fast_data.hex()}{RESET}')

        return EAP_FAST(code=code, id=eap_id, length=total_len, type=EAP_TYPE_FAST,
                        L=L, M=M, S=S, reserved=reserved,
                        message_len=message_len, data=fast_data)


# ---------------------------------------------------------------------------
# EAP-LEAP
# ---------------------------------------------------------------------------

LEAP_VERSION         = 1
LEAP_CHALLENGE_LEN   = 16
LEAP_RESPONSE_LEN    = 24


class EAP_LEAP(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = EAP_TYPE_LEAP, version: int = LEAP_VERSION,
                 unused: int = 0, count: int = 0,
                 challenge_response: bytes = b'', username: bytes = b''):
        super().__init__()
        self.code = code
        self.id = id
        self.length = length
        self.type = type
        self.version = version
        self.unused = unused
        self.count = count
        self.challenge_response = challenge_response
        self.username = username

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        # count is defined by the challenge/response length; don't let them drift.
        self.count = len(self.challenge_response)

        body = struct.pack('!BBHB', self.code, self.id, self.length, self.type)
        body += struct.pack('!BBB', self.version, self.unused, self.count)
        body += self.challenge_response + self.username + payload_bytes

        if self.length == 0:
            self.length = len(body)
            arr = bytearray(body)
            _set_u16(arr, 2, self.length)
            body = bytes(arr)
        return body

    def __len__(self):
        return (8 + len(self.challenge_response) + len(self.username)
                + (len(self.payload) if self.payload else 0))

    def __repr__(self):
        preview = self.challenge_response[:16].hex()
        if len(self.challenge_response) > 16:
            preview += "..."
        return (f"<EAP_LEAP code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"version={self.version}, count={self.count}, "
                f"data_len={len(self.challenge_response)}, "
                f"username={self.username.decode('utf-8', errors='ignore')[:20]}>")

    def copy(self) -> 'EAP_LEAP':
        new = EAP_LEAP(self.code, self.id, self.length, self.type,
                       self.version, self.unused, self.count,
                       self.challenge_response, self.username)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}", f"id={self.id}", f"len={self.length}",
            f"type={self.type} (LEAP)",
            f"version={self.version}", f"unused={self.unused}",
            f"count={self.count}",
        ]
        if self.challenge_response:
            fields.append(f"challenge_response={self.challenge_response.hex()}")
        if self.username:
            fields.append(f"username={self.username.decode('utf-8', errors='ignore')}")
        return fields

    def get_challenge(self) -> bytes:
        return self.challenge_response[:LEAP_CHALLENGE_LEN]

    def get_response(self) -> bytes:
        return self.challenge_response[:LEAP_RESPONSE_LEN]

    def is_challenge(self) -> bool:
        return self.code == 1 and len(self.challenge_response) == LEAP_CHALLENGE_LEN

    def is_response(self) -> bool:
        return self.code == 2 and len(self.challenge_response) == LEAP_RESPONSE_LEN

    def get_username(self) -> str:
        return self.username.decode('utf-8', errors='ignore')


class EAP_LEAP_Parser:

    @staticmethod
    def load_as_eap_leap_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 8:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-LEAP requires at least 8 bytes")
            return None

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])
        if eap_type != EAP_TYPE_LEAP:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_LEAP} (LEAP)")

        version, unused, count = struct.unpack('!BBB', data[5:8])
        offset = 8
        challenge_response = data[offset:offset + count]
        offset += count
        username = data[offset:]

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            print(f"\n{BOLD}EAP LEAP LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (LEAP)')
            print(f'   {BLUE}COUNT:{CYAN} {count} bytes')
            if challenge_response:
                print(f'   {BLUE}CHALLENGE/RESPONSE:{CYAN} {challenge_response.hex()}')
            if username:
                print(f'   {BLUE}USERNAME:{CYAN} {username.decode("utf-8", errors="ignore")}{RESET}')

        return EAP_LEAP(code=code, id=eap_id, length=total_len, type=EAP_TYPE_LEAP,
                        version=version, unused=unused, count=count,
                        challenge_response=challenge_response, username=username)


# ---------------------------------------------------------------------------
# EAP-MSCHAPv2 (RFC 2759)
# ---------------------------------------------------------------------------

MSCHAPV2_OPCODE_CHALLENGE       = 1
MSCHAPV2_OPCODE_RESPONSE        = 2
MSCHAPV2_OPCODE_SUCCESS         = 3
MSCHAPV2_OPCODE_FAILURE         = 4
MSCHAPV2_OPCODE_CHANGE_PASSWORD = 7

MSCHAPV2_CHALLENGE_LEN        = 16
MSCHAPV2_RESPONSE_LEN         = 49
MSCHAPV2_VALUE_SIZE_CHALLENGE = 0x10
MSCHAPV2_VALUE_SIZE_RESPONSE  = 0x31


class EAP_MSCHAPv2(BaseLayer):

    def __init__(self, code: int = 1, identifier: int = 1, length: int = 0,
                 type: int = EAP_TYPE_MSCHAPV2,
                 opcode: int = MSCHAPV2_OPCODE_CHALLENGE,
                 ms_chapv2_id: int = 1, ms_length: int = 0,
                 value_size: int = 0,
                 challenge: bytes = b'\x00' * 16, response: bytes = b'',
                 message: bytes = b'', name: bytes = b''):
        super().__init__()
        self.code = code
        self.identifier = identifier
        self.length = length
        self.type = type
        self.opcode = opcode
        self.ms_chapv2_id = ms_chapv2_id
        self.ms_length = ms_length
        self.value_size = value_size
        self.challenge = challenge
        self.response = response
        self.message = message
        self.name = name

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        if self.value_size == 0:
            if self.opcode == MSCHAPV2_OPCODE_CHALLENGE:
                self.value_size = MSCHAPV2_VALUE_SIZE_CHALLENGE
            elif self.opcode == MSCHAPV2_OPCODE_RESPONSE:
                self.value_size = MSCHAPV2_VALUE_SIZE_RESPONSE

        body = struct.pack('!BBHB', self.code, self.identifier, self.length, self.type)
        body += struct.pack('!BBH', self.opcode, self.ms_chapv2_id, self.ms_length)

        if self.opcode == MSCHAPV2_OPCODE_CHALLENGE:
            body += struct.pack('!B', self.value_size)
            body += self.challenge[:MSCHAPV2_CHALLENGE_LEN]
            body += self.name
        elif self.opcode == MSCHAPV2_OPCODE_RESPONSE:
            body += struct.pack('!B', self.value_size)
            body += self.response[:MSCHAPV2_RESPONSE_LEN]
            body += self.name
        else:
            body += self.message

        body += payload_bytes

        # EAP length field: total EAP payload length (5-byte header + MS body).
        if self.length == 0:
            self.length = len(body)
        if self.ms_length == 0:
            self.ms_length = self.length - 5

        arr = bytearray(body)
        _set_u16(arr, 2, self.length)   # EAP length at offset 2
        _set_u16(arr, 7, self.ms_length)  # MS-Length at offset 7 (after opcode+id)
        return bytes(arr)

    def __len__(self):
        total = 9
        if self.opcode == MSCHAPV2_OPCODE_CHALLENGE:
            total += 1 + len(self.challenge) + len(self.name)
        elif self.opcode == MSCHAPV2_OPCODE_RESPONSE:
            total += 1 + len(self.response) + len(self.name)
        else:
            total += len(self.message)
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        names = {1: "Challenge", 2: "Response", 3: "Success", 4: "Failure", 7: "ChangePassword"}
        return (f"<EAP_MSCHAPv2 code={hex(self.code)}, id={hex(self.identifier)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"opcode={names.get(self.opcode, self.opcode)}, "
                f"ms_id={hex(self.ms_chapv2_id)}, ms_len={hex(self.ms_length)}>")

    def copy(self) -> 'EAP_MSCHAPv2':
        new = EAP_MSCHAPv2(self.code, self.identifier, self.length, self.type,
                           self.opcode, self.ms_chapv2_id, self.ms_length,
                           self.value_size, self.challenge, self.response,
                           self.message, self.name)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        names = {1: "Challenge", 2: "Response", 3: "Success", 4: "Failure", 7: "ChangePassword"}
        fields = [
            f"code={self.code}", f"id={self.identifier}", f"len={self.length}",
            f"type={self.type} (MSCHAPv2)",
            f"opcode={self.opcode} ({names.get(self.opcode, '?')})",
            f"ms_chapv2_id={self.ms_chapv2_id}",
            f"ms_length={self.ms_length}",
            f"value_size={self.value_size}",
        ]
        if self.challenge:
            fields.append(f"challenge={self.challenge.hex()}")
        if self.response:
            fields.append(f"response={self.response.hex()}")
        if self.message:
            fields.append(f"message={self.message}")
        if self.name:
            fields.append(f"name={self.name}")
        return fields


class EAP_MSCHAPv2_Parser:

    @staticmethod
    def load_as_eap_mschapv2_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 9:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-MSCHAPv2 requires at least 9 bytes")
            return None

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])
        if eap_type != EAP_TYPE_MSCHAPV2:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_MSCHAPV2} (MSCHAPv2)")

        opcode, ms_id, ms_length = struct.unpack('!BBH', data[5:9])
        offset = 9
        value_size = 0
        challenge = response = message = name = b''

        if opcode == MSCHAPV2_OPCODE_CHALLENGE and len(data) > offset:
            value_size = data[offset]; offset += 1
            if value_size == MSCHAPV2_VALUE_SIZE_CHALLENGE:
                challenge = data[offset:offset + MSCHAPV2_CHALLENGE_LEN]
                offset += MSCHAPV2_CHALLENGE_LEN
                name = data[offset:]
            else:
                challenge = data[offset:]
        elif opcode == MSCHAPV2_OPCODE_RESPONSE and len(data) > offset:
            value_size = data[offset]; offset += 1
            if value_size == MSCHAPV2_VALUE_SIZE_RESPONSE:
                response = data[offset:offset + MSCHAPV2_RESPONSE_LEN]
                offset += MSCHAPV2_RESPONSE_LEN
                name = data[offset:]
            else:
                response = data[offset:]
        elif opcode in (MSCHAPV2_OPCODE_SUCCESS, MSCHAPV2_OPCODE_FAILURE,
                        MSCHAPV2_OPCODE_CHANGE_PASSWORD):
            message = data[offset:]

        if verbose:
            names = {1: "Challenge", 2: "Response", 3: "Success", 4: "Failure", 7: "ChangePassword"}
            print(f"\n{BOLD}EAP MSCHAPv2 LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(EAP_TYPE_MSCHAPV2)}')
            print(f'   {BLUE}MS ID:{CYAN} {hex(ms_id)}')
            print(f'   {BLUE}MS LENGTH:{CYAN} {hex(ms_length)}')
            print(f'   {BLUE}IDENTIFIER:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}OPCODE:{CYAN} {names.get(opcode, opcode)}')
            print(f'   {BLUE}MS-LENGTH:{CYAN} {ms_length}{RESET}')
            print(f'   {BLUE}VALUE:{CYAN} {value_size}{RESET}')
            print(f'   {BLUE}Challenge:{CYAN} {challenge}{RESET}')
            print(f'   {BLUE}Response:{CYAN} {response}{RESET}')
            print(f'   {BLUE}Message:{CYAN} {message}{RESET}')
            print(f'   {BLUE}Name:{CYAN} {name}{RESET}')

        return EAP_MSCHAPv2(code=code, identifier=eap_id, length=total_len,
                            type=EAP_TYPE_MSCHAPV2, opcode=opcode,
                            ms_chapv2_id=ms_id, ms_length=ms_length,
                            value_size=value_size, challenge=challenge,
                            response=response, message=message, name=name)


# ---------------------------------------------------------------------------
# EAP-NAK
# ---------------------------------------------------------------------------

class EAP_NAK(BaseLayer):
    def __init__(self, code: int = 2, identifier: int = 1, length: int = 0,
                 type: int = EAP_TYPE_NAK, allowed_types: bytes = b'\x00'):
        super().__init__()
        self.code = code
        self.identifier = identifier
        self.length = length
        self.type = type
        self.allowed_types = allowed_types

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        body = struct.pack('!BBHB', self.code, self.identifier, self.length, self.type)
        body += self.allowed_types + payload_bytes
        if self.length == 0:
            self.length = len(body)
            arr = bytearray(body)
            _set_u16(arr, 2, self.length)
            body = bytes(arr)
        return body

    def __len__(self):
        return 5 + len(self.allowed_types) + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (f"<EAP_NAK code={hex(self.code)}, id={hex(self.identifier)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"allowed_types={self.allowed_types.hex()}>")

    def copy(self) -> 'EAP_NAK':
        new = EAP_NAK(self.code, self.identifier, self.length, self.type,
                      self.allowed_types)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        fields = [f"code={self.code}", f"id={self.identifier}",
                  f"len={self.length}", f"type={self.type} (Legacy Nak)"]
        if self.allowed_types:
            fields.append(f"allowed_types={[hex(t) for t in self.allowed_types]}")
        return fields

    def get_allowed_types(self) -> list:
        return list(self.allowed_types)


class EAP_NAK_Parser:

    @staticmethod
    def load_as_eap_nak_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-NAK requires at least 6 bytes")
            return None

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])
        if eap_type != EAP_TYPE_NAK:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_NAK} (NAK)")
        allowed_types = data[5:]

        if verbose:
            print(f"\n{BOLD}EAP LEGACY NAK LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}ALLOWED TYPES:{CYAN} {[hex(t) for t in allowed_types]}{RESET}')

        return EAP_NAK(code=code, identifier=eap_id, length=total_len,
                       type=eap_type, allowed_types=allowed_types)


# ---------------------------------------------------------------------------
# EAP-Notification
# ---------------------------------------------------------------------------

class EAP_NOTIFICATION(BaseLayer):
    def __init__(self, code: int = 1, identifier: int = 1, length: int = 0,
                 type: int = EAP_TYPE_NOTIFICATION, message: bytes = b''):
        super().__init__()
        self.code = code
        self.identifier = identifier
        self.length = length
        self.type = type
        self.message = message

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        body = struct.pack('!BBHB', self.code, self.identifier, self.length, self.type)
        body += self.message + payload_bytes
        if self.length == 0:
            self.length = len(body)
            arr = bytearray(body)
            _set_u16(arr, 2, self.length)
            body = bytes(arr)
        return body

    def __len__(self):
        return 5 + len(self.message) + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (f"<EAP_NOTIFICATION code={hex(self.code)}, id={hex(self.identifier)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"message={self.message[:30]}>")

    def copy(self) -> 'EAP_NOTIFICATION':
        new = EAP_NOTIFICATION(self.code, self.identifier, self.length,
                               self.type, self.message)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        fields = [f"code={self.code}", f"id={self.identifier}",
                  f"len={self.length}", f"type={self.type} (Notification)"]
        if self.message:
            fields.append(f"message={self.message}")
        return fields


class EAP_NOTIFICATION_Parser:

    @staticmethod
    def load_as_eap_notification_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 5:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-Notification requires at least 5 bytes")
            return None

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])
        if eap_type != EAP_TYPE_NOTIFICATION:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_NOTIFICATION} (Notification)")
        message = data[5:]

        if verbose:
            print(f"\n{BOLD}EAP NOTIFICATION LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}MESSAGE:{CYAN} {message}{RESET}')

        return EAP_NOTIFICATION(code=code, identifier=eap_id, length=total_len,
                                type=eap_type, message=message)


# ---------------------------------------------------------------------------
# EAP-pwd (RFC 5931)
# ---------------------------------------------------------------------------

PWD_EXCHANGE_ID       = 0
PWD_EXCHANGE_COMMIT   = 1
PWD_EXCHANGE_CONFIRM  = 2

PWD_EXCHANGE_NAMES = {0: "Identity", 1: "Commit", 2: "Confirm", 3: "Crypto Binding"}
PWD_FAILURE_NAMES = {
    0: "Unknown", 1: "Authentication Failure", 2: "Invalid Group",
    3: "No Retry", 4: "Abort", 5: "Timeout",
}


class EAP_PWD(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = EAP_TYPE_PWD, L: int = 0, M: int = 0,
                 pwd_exchange: int = PWD_EXCHANGE_ID, total_length: int = 0,
                 data: bytes = b''):
        super().__init__()
        self.code = code
        self.id = id
        self.length = length
        self.type = type
        self.L = L
        self.M = M
        self.pwd_exchange = pwd_exchange & 0x3F
        self.total_length = total_length
        self.data = data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        flags = (self.L << 7) | (self.M << 6) | (self.pwd_exchange & 0x3F)

        body = struct.pack('!BBHBB', self.code, self.id, self.length,
                           self.type, flags)
        if self.L:
            if self.total_length == 0:
                self.total_length = len(self.data)
            body += struct.pack('!H', self.total_length)
        body += self.data + payload_bytes

        if self.length == 0:
            self.length = len(body)
            arr = bytearray(body)
            _set_u16(arr, 2, self.length)
            body = bytes(arr)
        return body

    def __len__(self):
        total = 6
        if self.L:
            total += 2
        total += len(self.data)
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        return (f"<EAP_PWD code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"exchange={PWD_EXCHANGE_NAMES.get(self.pwd_exchange, self.pwd_exchange)}, "
                f"L={self.L} M={self.M}>")

    def copy(self) -> 'EAP_PWD':
        new = EAP_PWD(self.code, self.id, self.length, self.type,
                      self.L, self.M, self.pwd_exchange,
                      self.total_length, self.data)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}", f"id={self.id}", f"len={self.length}",
            f"type={self.type} (EAP-pwd)",
            f"L={self.L} M={self.M}",
            f"pwd_exchange={self.pwd_exchange} "
            f"({PWD_EXCHANGE_NAMES.get(self.pwd_exchange, '?')})",
        ]
        if self.L:
            fields.append(f"total_length={self.total_length}")
        if self.data:
            fields.append(f"data={self.data.hex()}")
        return fields

    def get_failure_code(self) -> int:
        return self.data[0] if self.data else -1

    def get_failure_code_name(self) -> str:
        code = self.get_failure_code()
        return PWD_FAILURE_NAMES.get(code, f"Unknown({code})") if code >= 0 else "No failure"


class EAP_PWD_Parser:

    @staticmethod
    def load_as_eap_pwd_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-pwd requires at least 6 bytes")
            return None

        code, eap_id, total_len, eap_type, flags = struct.unpack('!BBHBB', data[:6])
        if eap_type != EAP_TYPE_PWD:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_PWD} (EAP-pwd)")

        L = (flags >> 7) & 0x01
        M = (flags >> 6) & 0x01
        pwd_exchange = flags & 0x3F

        offset = 6
        total_length = 0
        if L:
            if len(data) < offset + 2:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message="EAP-pwd: L flag set but Total-Length missing")
                return None
            total_length = struct.unpack('!H', data[offset:offset + 2])[0]
            offset += 2

        pwd_data = data[offset:]

        if verbose:
            print(f"\n{BOLD}EAP PWD LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}PWD-Exch:{CYAN} {PWD_EXCHANGE_NAMES.get(pwd_exchange, pwd_exchange)}')
            if L:
                print(f'   {BLUE}TOTAL-LENGTH:{CYAN} {total_length}')
            if pwd_data:
                print(f'   {BLUE}DATA:{CYAN} {pwd_data.hex()}{RESET}')

        return EAP_PWD(code=code, id=eap_id, length=total_len, type=EAP_TYPE_PWD,
                       L=L, M=M, pwd_exchange=pwd_exchange,
                       total_length=total_length, data=pwd_data)


# ---------------------------------------------------------------------------
# EAP-GTC / EAP-OTP
# ---------------------------------------------------------------------------

class EAP_GTC(BaseLayer):
    def __init__(self, code: int = 1, identifier: int = 1, length: int = 0,
                 type: int = EAP_TYPE_GTC, data: bytes = b''):
        super().__init__()
        self.code = code
        self.identifier = identifier
        self.length = length
        self.type = type
        self.data = data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        body = struct.pack('!BBHB', self.code, self.identifier, self.length, self.type)
        body += self.data + payload_bytes
        if self.length == 0:
            self.length = len(body)
            arr = bytearray(body)
            _set_u16(arr, 2, self.length)
            body = bytes(arr)
        return body

    def __len__(self):
        return 5 + len(self.data) + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (f"<EAP_GTC code={hex(self.code)}, id={hex(self.identifier)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, data={self.data}>")

    def copy(self) -> 'EAP_GTC':
        new = EAP_GTC(self.code, self.identifier, self.length, self.type, self.data)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        return [f"code={self.code}", f"id={self.identifier}",
                f"len={self.length}", f"type={self.type} (GTC)",
                f"data={self.data}"]


class EAP_GTC_Parser:

    @staticmethod
    def load_as_eap_gtc_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 5:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-GTC requires at least 5 bytes")
            return None

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])
        if eap_type != EAP_TYPE_GTC:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_GTC} (GTC)")

        if verbose:
            print(f"\n{BOLD}EAP GTC LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {code}')
            print(f'   {BLUE}ID:{CYAN} {eap_id}')
            print(f'   {BLUE}TYPE:{CYAN} {eap_type}')
            print(f'   {BLUE}TOTAL-LENGTH:{CYAN} {total_len} {RESET}')
            if len(data[5:]) > 0:
                print(f'   {BLUE}DATA:{CYAN} {data[5:]}{RESET}')

        return EAP_GTC(code=code, identifier=eap_id, length=total_len,
                       type=eap_type, data=data[5:])


class EAP_OTP(BaseLayer):
    def __init__(self, code: int = 1, identifier: int = 1, length: int = 0,
                 type: int = EAP_TYPE_OTP, data: bytes = b''):
        super().__init__()
        self.code = code
        self.identifier = identifier
        self.length = length
        self.type = type
        self.data = data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        body = struct.pack('!BBHB', self.code, self.identifier, self.length, self.type)
        body += self.data + payload_bytes
        if self.length == 0:
            self.length = len(body)
            arr = bytearray(body)
            _set_u16(arr, 2, self.length)
            body = bytes(arr)
        return body

    def __len__(self):
        return 5 + len(self.data) + (len(self.payload) if self.payload else 0)

    def __repr__(self):
        return (f"<EAP_OTP code={hex(self.code)}, id={hex(self.identifier)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, data={self.data}>")

    def copy(self) -> 'EAP_OTP':
        new = EAP_OTP(self.code, self.identifier, self.length, self.type, self.data)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new

    def _show_fields(self) -> list:
        return [f"code={self.code}", f"id={self.identifier}",
                f"len={self.length}", f"type={self.type} (OTP)",
                f"data={self.data}"]


class EAP_OTP_Parser:

    @staticmethod
    def load_as_eap_otp_layer(raw_packet, verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 5:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-OTP requires at least 5 bytes")
            return None

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])
        if eap_type != EAP_TYPE_OTP:
            LLogger.warning(f"EAP Type is {eap_type}, expected {EAP_TYPE_OTP} (OTP)")

        if verbose:
            print(f"\n{BOLD}EAP OTP LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {code}')
            print(f'   {BLUE}ID:{CYAN} {eap_id}')
            print(f'   {BLUE}TYPE:{CYAN} {eap_type}')
            print(f'   {BLUE}TOTAL-LENGTH:{CYAN} {total_len} {RESET}')
            if len(data[5:]) > 0:
                print(f'   {BLUE}DATA:{CYAN} {data[5:]}{RESET}')

        return EAP_OTP(code=code, identifier=eap_id, length=total_len,
                       type=eap_type, data=data[5:])


# ---------------------------------------------------------------------------
# EAP type -> parser dispatch table (defined after all classes)
# ---------------------------------------------------------------------------

_EAP_TYPE_PARSERS = {
    EAP_TYPE_IDENTITY:     lambda p, verbose=False: EAP_IDENTITY_Parser.load_as_eapol_identity_layer(p, verbose=verbose),
    EAP_TYPE_NOTIFICATION: lambda p, verbose=False: EAP_NOTIFICATION_Parser.load_as_eap_notification_layer(p, verbose=verbose),
    EAP_TYPE_NAK:          lambda p, verbose=False: EAP_NAK_Parser.load_as_eap_nak_layer(p, verbose=verbose),
    EAP_TYPE_MD5:          lambda p, verbose=False: EAP_MD5_Parser.load_as_eapol_md5_layer(p, verbose=verbose),
    EAP_TYPE_OTP:          lambda p, verbose=False: EAP_OTP_Parser.load_as_eap_otp_layer(p, verbose=verbose),
    EAP_TYPE_GTC:          lambda p, verbose=False: EAP_GTC_Parser.load_as_eap_gtc_layer(p, verbose=verbose),
    EAP_TYPE_TLS:          lambda p, verbose=False: EAP_TLS_Parser.load_as_eap_tls_layer(p, verbose=verbose),
    EAP_TYPE_LEAP:         lambda p, verbose=False: EAP_LEAP_Parser.load_as_eap_leap_layer(p, verbose=verbose),
    EAP_TYPE_TTLS:         lambda p, verbose=False: EAP_TTLS_Parser.load_as_eap_ttls_layer(p, verbose=verbose),
    EAP_TYPE_PEAP:         lambda p, verbose=False: EAP_PEAP_Parser.load_as_eap_peap_layer(p, verbose=verbose),
    EAP_TYPE_MSCHAPV2:     lambda p, verbose=False: EAP_MSCHAPv2_Parser.load_as_eap_mschapv2_layer(p, verbose=verbose),
    EAP_TYPE_FAST:         lambda p, verbose=False: EAP_FAST_Parser.load_as_eap_fast_layer(p, verbose=verbose),
    EAP_TYPE_PWD:          lambda p, verbose=False: EAP_PWD_Parser.load_as_eap_pwd_layer(p, verbose=verbose),
}

def dispatch_eap_payload(payload: bytes, verbose: bool = False):
    """
    Dispatch a raw EAP payload (Code | ID | Length | Type | Type-Data)
    to the correct EAP method layer.

    Shared by:
      * EAPOL-Packet   (EAPOL code = 0x00, from Ethernet/Dot3/WiFi/SLL)
      * EAP over PPP   (PPP proto   = 0xC227, from PPP/PPP2b)
    """
    from LightPacket.Raw import RawParser

    if len(payload) < 4:
        return RawParser.load_as_Raw_layer(payload, verbose=verbose)

    code = payload[0]

    if code in (EAP_CODE_SUCCESS, EAP_CODE_FAILURE):
        return EAP_STATE_Parser.load_as_eapol_state_layer(payload, verbose=verbose)

    if code in (EAP_CODE_REQUEST, EAP_CODE_RESPONSE) and len(payload) >= 5:
        eap_type = payload[4]
        parser = _EAP_TYPE_PARSERS.get(eap_type)
        if parser is not None:
            return parser(payload, verbose=verbose)

    print("DDDDDDDDDDDDDDDDDDDDDDDDDd")
    return RawParser.load_as_Raw_layer(payload, verbose=verbose)