# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from .BaseLayer import BaseLayer
from .Logger.LightLogger import Logger, ErrorCode
from .Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from .Consts import eapol_types, eapol_versions

LLogger = Logger()


"""
EAPOL Layer Creation (class EAPOL)
"""

class EAPOL(BaseLayer):

    def __init__(self, version: int = 2, code: int = 0, length: int = 0):
        super().__init__()
        self.version = version
        self.code = code
        self.length = length

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()
        layer = self.payload.__class__.__name__
        if layer and self.code == 0:
            if layer in ['EAP_STATE','EAP_IDENTITY','EAP_PEAP','EAP_MD5',
                         'EAP_TLS','EAP_TTLS','EAP_FAST','EAP_LEAP','EAP_MSCHAPv2',
                         'EAP_NAK','EAP_NOTIFICATION','EAP_PWD','EAP_GTC','EAP_OTP']:
                self.code = 0
            elif layer in ['EAP_Key']:
                self.code = 3
            else:
                self.code = 1

        if self.length == 0:
            self.length = len(payload_bytes)
        result = struct.pack('!BBH', self.version, self.code, self.length)

        if payload_bytes:
            return result + payload_bytes
        return result

    def __len__(self):
        return 4 + (len(self.payload) if self.payload else 0)


    def __repr__(self):
        return (
            f"<EAPOL version={hex(self.version)}, code={hex(self.code)}, len={hex(self.length)}>")

    def copy(self) -> 'EAPOL':
        new_layer = EAPOL(
            version=self.version,
            code=self.code,
            length=self.length
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"version={self.version}",
            f"code={self.code}",
            f"len={self.length}"
        ]


"""
EAPOL Parser (separate from the builder)
"""

class EAPOLParser:

    @staticmethod
    def load_as_eapol_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 4:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="EAPOL required header is 4 bytes")


        EAPOLH = raw_packet[0][:4]

        version, code, lenght = struct.unpack('!BBH', EAPOLH)

        payload = raw_packet[0][4:]
        Lenght = len(EAPOLH)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}EAPOL LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}VERSION:{CYAN} {hex(version)} {eapol_versions.get(version, '')}')
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {eapol_types.get(code,'')}')
            print(f'   {BLUE}LEN:{CYAN} {hex(lenght)}{RESET}')

        eapol = EAPOL(
            version=version,
            code=code,
            length=lenght
        )
        if len(payload) > 0:
            if code != 0x1:
                if code == 0x3:
                    prelayer = EAPOLKeyParser.load_as_eapolkey_layer(payload,verbose=verbose)
                elif payload[:1] in [b'\x03',b'\x04']:
                    prelayer = EAP_STATE_Parser.load_as_eapol_state_layer(payload,verbose=verbose)
                elif len(payload) >= 5 :
                    if payload[4:5] == b'\x01':
                        prelayer = EAP_IDENTITY_Parser.load_as_eapol_identity_layer(payload,verbose=verbose)
                    elif payload[4:5] == b'\x03':
                        prelayer = EAP_NAK_Parser.load_as_eap_nak_layer(payload, verbose=verbose)
                    elif payload[4:5] == b'\x06':
                        prelayer = EAP_GTC_Parser.load_as_eap_gtc_layer(payload,verbose=verbose)
                    elif payload[4:5] == b'\x05':
                        prelayer = EAP_OTP_Parser.load_as_eap_otp_layer(payload,verbose=verbose)
                    elif payload[4:5] == b'\x02':
                        prelayer = EAP_NOTIFICATION_Parser.load_as_eap_notification_layer(payload, verbose=verbose)
                    elif payload[4:5] == b'\x04':
                        prelayer = EAP_MD5_Parser.load_as_eapol_md5_layer(payload,verbose=verbose)
                    elif payload[4:5] in [b'\x0d', b'\r']:
                        prelayer = EAP_TLS_Parser.load_as_eap_tls_layer(payload, verbose=verbose)
                    elif payload[4:5] == b'\x11':
                        prelayer = EAP_LEAP_Parser.load_as_eap_leap_layer(payload,verbose=verbose)
                    elif payload[4:5] in [b'\x15']:
                        prelayer = EAP_TTLS_Parser.load_as_eap_ttls_layer(payload, verbose=verbose)
                    elif payload[4:5] in [b'\x19']:
                        prelayer = EAP_PEAP_Parser.load_as_eap_peap_layer(payload, verbose=verbose)
                    elif payload[4:5] == b'\x1a':
                        prelayer = EAP_MSCHAPv2_Parser.load_as_eap_mschapv2_layer(payload, verbose=verbose)
                    elif payload[4:5] in [b'\x2b']:
                        prelayer = EAP_FAST_Parser.load_as_eap_fast_layer(payload, verbose=verbose)
                    elif payload[4:5] in [b'\x34']:
                        prelayer = EAP_PWD_Parser.load_as_eap_pwd_layer(payload, verbose=verbose)
                    else:
                        from .Raw import RawParser
                        prelayer = RawParser.load_as_Raw_layer(payload, verbose=verbose)
                else:
                    from .Raw import RawParser
                    prelayer = RawParser.load_as_Raw_layer(payload,verbose=verbose)
            else:
                from .Raw import RawParser
                prelayer = RawParser.load_as_Raw_layer(payload, verbose=verbose)

            return eapol / prelayer
        return eapol

"""
EAP STATE Layer Creation (class EAP_STATE))
"""

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
        result = struct.pack('!BBH', self.code, self.id, self.length)

        if payload_bytes:
            return result + payload_bytes
        return result

    def __len__(self):
        return 4 + (len(self.payload) if self.payload else 0)


    def __repr__(self):
        return (
            f"<EAP_STATE code={hex(self.code)}, id={hex(self.id)}, len={hex(self.length)}>")

    def copy(self) -> 'EAP_STATE':
        new_layer = EAP_STATE(
            code=self.code,
            id=self.id,
            length=self.length
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}"
        ]

"""
EAP STATE Parser (separate from the builder)
"""

class EAP_STATE_Parser:

    @staticmethod
    def load_as_eapol_state_layer(raw_packet,Alr=0,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 4:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="EAP STATE required header is 4 bytes")


        EAPOLH = raw_packet[0][:4]

        code, id, lenght = struct.unpack('!BBH', EAPOLH)

        payload = raw_packet[0][4:]
        Lenght = len(EAPOLH)
        Total = len(payload) + Lenght

        if verbose:
            if code == 3:
                print(f"\n{BOLD}EAP SUCCESS LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
                print(f'   {BLUE}CODE:{CYAN} {hex(code)} ')
                print(f'   {BLUE}ID:{CYAN} {hex(id)} ')
                print(f'   {BLUE}LEN:{CYAN} {hex(lenght)}{RESET}')
            else:
                print(f"\n{BOLD}EAP FAILURE LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
                print(f'   {BLUE}CODE:{CYAN} {hex(code)} ')
                print(f'   {BLUE}ID:{CYAN} {hex(id)} ')
                print(f'   {BLUE}LEN:{CYAN} {hex(lenght)}{RESET}')

        eapol = EAP_STATE(
            code=code,
            id=id,
            length=lenght
        )

        if len(payload) > 0:
            from .Raw import RawParser
            prelayer = RawParser.load_as_Raw_layer(payload,verbose=verbose)

            return eapol / prelayer
        return eapol

"""
EAP IDENTITY Layer Creation (class EAP_IDENTITY))
"""

class EAP_IDENTITY(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,type: int = 1,identity: bytes = b''):
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
        result = struct.pack('!BBHB', self.code, self.id, self.length,self.type) + self.identity

        if payload_bytes:
            return result + payload_bytes
        return result

    def __len__(self):
        return 5 + len(self.identity) + (len(self.payload) if self.payload else 0)


    def __repr__(self):
        return (
            f"<EAP_IDENTITY code={hex(self.code)}, id={hex(self.id)}, len={hex(self.length)}, type={hex(self.type)}>, identity={self.identity}"
        )

    def copy(self) -> 'EAP_IDENTITY':
        new_layer = EAP_IDENTITY(
            code=self.code,
            id=self.id,
            length=self.length,
            type=self.type,
            identity=self.identity
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        return [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}",
            f"type={self.type}",
            f"identity={self.identity}",
        ]

"""
EAP IDENTITY Parser (separate from the builder)
"""

class EAP_IDENTITY_Parser:

    @staticmethod
    def load_as_eapol_identity_layer(raw_packet,Alr=0,verbose=False):
        from builtins import type
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        if len(raw_packet[0]) < 5:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,message="EAP STATE required header is 5 bytes")


        EAPOLH = raw_packet[0][:5]

        code, id, lenght,type = struct.unpack('!BBHB', EAPOLH)

        payload = raw_packet[0][5:]
        Lenght = len(EAPOLH)
        Total = len(payload) + Lenght

        if verbose:
            print(f"\n{BOLD}EAP IDENTITY LAYER : {RESET}Len({PURPLE}{Lenght}{RESET}) Total Len({PURPLE}{Total}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {"(Request)" if code == 1 else "(Response)" if code == 2 else ""}')
            print(f'   {BLUE}ID:{CYAN} {hex(id)} ')
            print(f'   {BLUE}LEN:{CYAN} {hex(lenght)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(type)} {'(Identity)' if type == 1 else ''}{RESET}')
            if payload != b'' and code == 2:
                print(f'   {BLUE}IDENTITY:{CYAN} {payload} {RESET}')

        eapol = EAP_IDENTITY(
            code=code,
            id=id,
            length=lenght,
            type=type,
            identity=payload
        )

        if code != 2 and payload:
            from .Raw import RawParser
            prelayer = RawParser.load_as_Raw_layer(payload,verbose=verbose)
            return  eapol / prelayer
        return eapol

"""
EAP MD5 Layer Creation (class EAP_MD5)
"""

class EAP_MD5(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = 4, value_size: int = 16, value: bytes = b'',
                 name: bytes = b''):
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

        if self.length == 0:
            self.length = 6 + len(self.value) + len(self.name) + len(payload_bytes)

        self.value_size = len(self.value)

        result = struct.pack('!BBHBB', self.code, self.id, self.length, self.type, self.value_size)
        result += self.value
        if self.name:
            result += self.name

        if payload_bytes:
            result += payload_bytes
        return result

    def __len__(self):
        return (6 + len(self.value) + len(self.name) +
                (len(self.payload) if self.payload else 0))

    def __repr__(self):
        return (f"<EAP_MD5 code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"value_size={hex(self.value_size)}, value={self.value}, name={self.name}>")

    def copy(self) -> 'EAP_MD5':
        new_layer = EAP_MD5(
            code=self.code,
            id=self.id,
            length=self.length,
            type=self.type,
            value_size=self.value_size,
            value=self.value,
            name=self.name
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

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


"""
EAP MD5 Parser (separate from the builder)
"""

class EAP_MD5_Parser:
    @staticmethod
    def load_as_eapol_md5_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]
        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-MD5 requires at least 6 bytes (5‑byte header + Value‑Size)")

        header = data[:5]
        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', header)
        if eap_type != 4:
            LLogger.warning(f"EAP Type is {eap_type}, expected 4 (MD5)")

        value_size = data[5]
        value_start = 6
        value = data[value_start:value_start + value_size] if value_size else b''

        name_start = value_start + value_size
        name = data[name_start:] if len(data) > name_start else b''

        header_len = 6
        total_len_calc = len(data)

        eap_md5 = EAP_MD5(
            code=code,
            id=eap_id,
            length=total_len,
            type=4,
            value_size=value_size,
            value=value,
            name=name
        )


        if len(data) > name_start + len(name):
            extra = data[name_start + len(name):]
            if extra:
                from .Raw import RawParser
                raw_layer = RawParser.load_as_Raw_layer(extra, verbose=verbose)
                eap_md5 /= raw_layer

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            value_label = "CHALLENGE" if code == 1 else "MD5_HASH" if code == 2 else "VALUE"
            print(f"\n{BOLD}EAP MD5 LAYER : {RESET}Len({PURPLE}{header_len}{RESET}) "
                  f"Total Len({PURPLE}{total_len_calc}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (MD5)')
            print(f'   {BLUE}VALUE_SIZE:{CYAN} {hex(value_size)} {RESET}')
            if value:
                print(f'   {BLUE}{value_label}:{CYAN} {value}{RESET}')
            if name:
                print(f'   {BLUE}NAME:{CYAN} {name}{RESET}')

        return eap_md5

"""
EAP TLS Layer Creation (class EAP_TLS)
- RFC 5216: EAP-TLS Authentication Protocol
"""

class EAP_TLS(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = 13, L: int = 0, M: int = 0, S: int = 0,
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

        expdata = b''
        if self.L:
            if self.tls_message_len == 0:
                self.tls_message_len = len(self.tls_data)
            expdata = struct.pack('!I', self.tls_message_len)

        result = struct.pack('!BBHBB', self.code, self.id, self.length, self.type, flags) + expdata
        result += self.tls_data


        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            arr = bytearray(result)
            arr[3] = len(result)
            result = bytes(arr)
        return result

    def __len__(self):
        total = 5 + len(self.tls_data)
        if self.L:
            total += 4
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        flags_str = f"L={self.L}, M={self.M}, S={self.S}"
        tls_preview = self.tls_data[:16].hex() if self.tls_data else ""
        if len(self.tls_data) > 16:
            tls_preview += "..."
        return (f"<EAP_TLS code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"flags=[{flags_str}], tls_len={len(self.tls_data)}, "
                f"tls={tls_preview}>")

    def copy(self) -> 'EAP_TLS':
        new_layer = EAP_TLS(
            code=self.code,
            id=self.id,
            length=self.length,
            type=self.type,
            L=self.L,
            M=self.M,
            S=self.S,
            reserved=self.reserved,
            tls_message_len=self.tls_message_len,
            tls_data=self.tls_data
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}",
            f"type={self.type}",
            f"L={self.L}",
            f"M={self.M}",
            f"S={self.S}",
            f"reserved={self.reserved}",
        ]
        if self.L:
            fields.append(f"tls_message_len={self.tls_message_len}")
        if self.tls_data:
            preview = self.tls_data.hex()
            fields.append(f"tls_data={preview}")
        return fields


"""
EAP TLS Parser (separate from the builder)
"""

class EAP_TLS_Parser:
    @staticmethod
    def load_as_eap_tls_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-TLS requires at least 6 bytes (header + type + flags)")

        code, eap_id, total_len, eap_type, flags = struct.unpack('!BBHBB', data[:6])

        if eap_type != 13:
            LLogger.warning(f"EAP Type is {eap_type}, expected 13 (TLS)")

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
            tls_message_len = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4

        tls_data = data[offset:] if len(data) > offset else b''

        eap_tls = EAP_TLS(
            code=code,
            id=eap_id,
            length=total_len,
            type=13,
            L=L,
            M=M,
            S=S,
            reserved=reserved,
            tls_message_len=tls_message_len,
            tls_data=tls_data
        )

        if len(data) > offset + len(tls_data):
            extra = data[offset + len(tls_data):]
            if extra:
                from .Raw import RawParser
                raw_layer = RawParser.load_as_Raw_layer(extra, verbose=verbose)
                eap_tls /= raw_layer

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            flags_desc = []
            if L:
                flags_desc.append("Length included")
            if M:
                flags_desc.append("More fragments")
            if S:
                flags_desc.append("Start")
            if not flags_desc:
                flags_desc.append("None")

            print(f"\n{BOLD}EAP TLS LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (TLS)')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:02x} [{", ".join(flags_desc)}]')
            print(f'   {BLUE}RESERVED:{CYAN} {hex(reserved)} {RESET}')
            if L:
                print(f'   {BLUE}TLS_MESSAGE_LEN:{CYAN} {hex(tls_message_len)} ({tls_message_len} bytes)')

            if tls_data:
                preview = tls_data[:64].hex() if len(tls_data) > 0 else ""
                if len(tls_data) > 64:
                    preview += "..."
                print(f'   {BLUE}TLS Data:{CYAN} {preview}{RESET}')

        return eap_tls


EAPOL_KEY_INFO_KEY_TYPE = 0x0001
EAPOL_KEY_INFO_KEY_INDEX_MASK = 0x0006
EAPOL_KEY_INFO_KEY_INDEX_SHIFT = 1
EAPOL_KEY_INFO_INSTALL = 0x0040
EAPOL_KEY_INFO_KEY_ACK = 0x0080
EAPOL_KEY_INFO_KEY_MIC = 0x0100
EAPOL_KEY_INFO_SECURE = 0x0200
EAPOL_KEY_INFO_ERROR = 0x0400
EAPOL_KEY_INFO_REQUEST = 0x0800
EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA = 0x1000
EAPOL_KEY_INFO_SMK_MESSAGE = 0x2000
EAPOL_KEY_INFO_KEY_ID_MASK = 0xC000
EAPOL_KEY_INFO_KEY_ID_SHIFT = 14

EAPOL_KEY_DESCRIPTOR_VERSION_MASK = 0x0003
EAPOL_KEY_DESCRIPTOR_VERSION_SHIFT = 0

EAPOL_KEY_DESCRIPTOR_1 = 1
EAPOL_KEY_DESCRIPTOR_2 = 2
EAPOL_KEY_DESCRIPTOR_WPA = 3

EAPOL_KEY_DESCRIPTOR_NAMES = {
    1: "RC4 (WEP/WPA legacy)",
    2: "RSN (802.11i/WPA2 - AES)",
    3: "WPA (legacy)"
}

EAPOL_KEY_PAIRWISE = 0x01
EAPOL_KEY_GROUP = 0x00

EAPOL_KEY_MIC_LEN = 16
EAPOL_KEY_NONCE_LEN = 32
EAPOL_KEY_IV_LEN = 16
EAPOL_KEY_RSC_LEN = 8
EAPOL_KEY_ID_LEN = 8
EAPOL_KEY_REPLAY_COUNTER_LEN = 8

EAPOL_KEY_TYPE = 3

KEY_DATA_DESCRIPTOR_GTK = 1
KEY_DATA_DESCRIPTOR_IGTK = 2
KEY_DATA_DESCRIPTOR_BIGTK = 3


"""
EAPOL-Key Layer Creation (class EAP_Key)
IEEE 802.11-2016: EAPOL-Key frame used in 4-Way Handshake and Group Key Handshake
"""

class EAP_Key(BaseLayer):
    def __init__(self, descriptor: int = EAPOL_KEY_DESCRIPTOR_2, key_info: int = 0, key_len: int = 0,
                 key_replay_counter: bytes = b'\x00' * EAPOL_KEY_REPLAY_COUNTER_LEN,
                 key_nonce: bytes = b'\x00' * EAPOL_KEY_NONCE_LEN,
                 eapol_key_iv: bytes = b'\x00' * EAPOL_KEY_IV_LEN,
                 key_rsc: bytes = b'\x00' * EAPOL_KEY_RSC_LEN,
                 key_id: bytes = b'\x00' * EAPOL_KEY_ID_LEN,
                 key_mic: bytes = b'\x00' * EAPOL_KEY_MIC_LEN,
                 key_data_len: int = 0,
                 key_data: bytes = b''):
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

        result = struct.pack('!BHH', self.descriptor, self.key_info, self.key_len)
        result += self.key_replay_counter
        result += self.key_nonce
        result += self.eapol_key_iv
        result += self.key_rsc
        result += self.key_id

        result += self.key_mic[:EAPOL_KEY_MIC_LEN]

        if self.key_data_len == 0:
            self.key_data_len = len(self.key_data)
        result += struct.pack('!H', self.key_data_len)

        result += self.key_data

        if payload_bytes:
            result += payload_bytes
        return result

    def __len__(self):
        total = 1 + 2 + 2 + EAPOL_KEY_REPLAY_COUNTER_LEN + EAPOL_KEY_NONCE_LEN + \
                EAPOL_KEY_IV_LEN + EAPOL_KEY_RSC_LEN + EAPOL_KEY_ID_LEN + EAPOL_KEY_MIC_LEN + 2
        total += len(self.key_data)
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        return (f"<EAP_Key descriptor={self.descriptor}, "
                f"key_info=0x{self.key_info:04x}, "
                f"key_len={self.key_len}, "
                f"key_data_len={self.key_data_len}, "
                f"replay_counter={self.key_replay_counter.hex()[:8]}...>")

    def copy(self) -> 'EAP_Key':
        new_layer = EAP_Key(
            descriptor=self.descriptor,
            key_info=self.key_info,
            key_len=self.key_len,
            key_replay_counter=self.key_replay_counter,
            key_nonce=self.key_nonce,
            eapol_key_iv=self.eapol_key_iv,
            key_rsc=self.key_rsc,
            key_id=self.key_id,
            key_mic=self.key_mic,
            key_data_len=self.key_data_len,
            key_data=self.key_data
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

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
            preview = self.key_data[:32].hex()
            if len(self.key_data) > 32:
                preview += "..."
            fields.append(f"key_data={preview}")
        return fields


    def get_descriptor_version_from_flags(self) -> int:
        """Get Key Descriptor Version from bits 0-1 of key_info."""
        return (self.key_info & EAPOL_KEY_DESCRIPTOR_VERSION_MASK) >> EAPOL_KEY_DESCRIPTOR_VERSION_SHIFT

    def get_descriptor_version_name(self) -> str:
        version = self.get_descriptor_version_from_flags()
        return EAPOL_KEY_DESCRIPTOR_NAMES.get(version, f"Unknown ({version})")

    def is_rsn(self) -> bool:
        return self.get_descriptor_version_from_flags() == EAPOL_KEY_DESCRIPTOR_2

    def is_wpa_legacy(self) -> bool:
        return self.get_descriptor_version_from_flags() == EAPOL_KEY_DESCRIPTOR_1

    def get_key_type(self) -> int:
        return (self.key_info & EAPOL_KEY_INFO_KEY_TYPE) >> 0

    def is_pairwise(self) -> bool:
        return self.get_key_type() == 1

    def is_group(self) -> bool:
        return self.get_key_type() == 0

    def get_key_index(self) -> int:
        return (self.key_info & EAPOL_KEY_INFO_KEY_INDEX_MASK) >> EAPOL_KEY_INFO_KEY_INDEX_SHIFT

    def get_key_id(self) -> int:
        return (self.key_info & EAPOL_KEY_INFO_KEY_ID_MASK) >> EAPOL_KEY_INFO_KEY_ID_SHIFT

    def is_install(self) -> bool:
        return bool(self.key_info & EAPOL_KEY_INFO_INSTALL)

    def is_key_ack(self) -> bool:
        return bool(self.key_info & EAPOL_KEY_INFO_KEY_ACK)

    def is_key_mic(self) -> bool:
        return bool(self.key_info & EAPOL_KEY_INFO_KEY_MIC)

    def is_secure(self) -> bool:
        return bool(self.key_info & EAPOL_KEY_INFO_SECURE)

    def is_error(self) -> bool:
        return bool(self.key_info & EAPOL_KEY_INFO_ERROR)

    def is_request(self) -> bool:
        return bool(self.key_info & EAPOL_KEY_INFO_REQUEST)

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
        info |= (key_type & 0x01) << 0
        info |= (key_index & 0x03) << EAPOL_KEY_INFO_KEY_INDEX_SHIFT
        info |= (key_id & 0x03) << EAPOL_KEY_INFO_KEY_ID_SHIFT
        if install:
            info |= EAPOL_KEY_INFO_INSTALL
        if key_ack:
            info |= EAPOL_KEY_INFO_KEY_ACK
        if key_mic:
            info |= EAPOL_KEY_INFO_KEY_MIC
        if secure:
            info |= EAPOL_KEY_INFO_SECURE
        if error:
            info |= EAPOL_KEY_INFO_ERROR
        if request:
            info |= EAPOL_KEY_INFO_REQUEST
        if encrypted:
            info |= EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA
        if smk:
            info |= EAPOL_KEY_INFO_SMK_MESSAGE
        self.key_info = info

    def set_descriptor(self, descriptor: int) -> None:
        self.descriptor = descriptor


"""
EAP Key Parser (separate from the builder)
"""

class EAPOLKeyParser:
    @staticmethod
    def load_as_eapolkey_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 95:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP Key requires at least 95 bytes")

        offset = 0
        descriptor = data[offset]
        offset += 1

        key_info = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2

        key_len = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2

        key_replay_counter = data[offset:offset + EAPOL_KEY_REPLAY_COUNTER_LEN]
        offset += EAPOL_KEY_REPLAY_COUNTER_LEN

        key_nonce = data[offset:offset + EAPOL_KEY_NONCE_LEN]
        offset += EAPOL_KEY_NONCE_LEN

        eapol_key_iv = data[offset:offset + EAPOL_KEY_IV_LEN]
        offset += EAPOL_KEY_IV_LEN

        key_rsc = data[offset:offset + EAPOL_KEY_RSC_LEN]
        offset += EAPOL_KEY_RSC_LEN

        key_id = data[offset:offset + EAPOL_KEY_ID_LEN]
        offset += EAPOL_KEY_ID_LEN

        key_mic = data[offset:offset + EAPOL_KEY_MIC_LEN]
        offset += EAPOL_KEY_MIC_LEN

        key_data_len = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2

        key_data = data[offset:offset + key_data_len] if key_data_len > 0 else b''
        offset += key_data_len

        eapolkey = EAP_Key(
            descriptor=descriptor,
            key_info=key_info,
            key_len=key_len,
            key_replay_counter=key_replay_counter,
            key_nonce=key_nonce,
            eapol_key_iv=eapol_key_iv,
            key_rsc=key_rsc,
            key_id=key_id,
            key_mic=key_mic,
            key_data_len=key_data_len,
            key_data=key_data
        )

        if len(data) > offset:
            extra = data[offset:]
            if extra:
                from .Raw import RawParser
                raw_layer = RawParser.load_as_Raw_layer(extra, verbose=verbose)
                eapolkey /= raw_layer

        if verbose:
            descriptor_name = EAPOL_KEY_DESCRIPTOR_NAMES.get(descriptor, f"Unknown ({descriptor})")
            key_desc_version = (key_info & EAPOL_KEY_DESCRIPTOR_VERSION_MASK) >> EAPOL_KEY_DESCRIPTOR_VERSION_SHIFT
            version_name = EAPOL_KEY_DESCRIPTOR_NAMES.get(key_desc_version, f"Unknown ({key_desc_version})")

            key_type = "Pairwise" if (key_info & EAPOL_KEY_INFO_KEY_TYPE) else "Group"
            key_index = (key_info & EAPOL_KEY_INFO_KEY_INDEX_MASK) >> EAPOL_KEY_INFO_KEY_INDEX_SHIFT
            key_id_val = (key_info & EAPOL_KEY_INFO_KEY_ID_MASK) >> EAPOL_KEY_INFO_KEY_ID_SHIFT

            flags_desc = []
            if key_info & EAPOL_KEY_INFO_INSTALL:
                flags_desc.append("Install")
            if key_info & EAPOL_KEY_INFO_KEY_ACK:
                flags_desc.append("Key ACK")
            if key_info & EAPOL_KEY_INFO_KEY_MIC:
                flags_desc.append("Key MIC")
            if key_info & EAPOL_KEY_INFO_SECURE:
                flags_desc.append("Secure")
            if key_info & EAPOL_KEY_INFO_ERROR:
                flags_desc.append("Error")
            if key_info & EAPOL_KEY_INFO_REQUEST:
                flags_desc.append("Request")
            if key_info & EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA:
                flags_desc.append("Encrypted")
            if key_info & EAPOL_KEY_INFO_SMK_MESSAGE:
                flags_desc.append("SMK")

            print(f"\n{BOLD}EAP KEY LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}Descriptor:{CYAN} {descriptor} ({descriptor_name})')
            print(f'   {BLUE}Key Info:{CYAN} 0x{key_info:04x} [{", ".join(flags_desc)}]')
            print(f'   {BLUE}  - Key Descriptor Version:{CYAN} {key_desc_version} ({version_name})')
            print(f'   {BLUE}  - Key Type:{CYAN} {key_type}')
            print(f'   {BLUE}  - Key Index:{CYAN} {key_index}')
            print(f'   {BLUE}  - Key ID:{CYAN} {key_id_val}')
            print(f'   {BLUE}Key Length:{CYAN} {key_len}')
            print(f'   {BLUE}Replay Counter:{CYAN} {key_replay_counter.hex()}')
            print(f'   {BLUE}Nonce:{CYAN} {key_nonce.hex()}')
            print(f'   {BLUE}IV:{CYAN} {eapol_key_iv.hex()}')
            print(f'   {BLUE}RSC:{CYAN} {key_rsc.hex()}')
            print(f'   {BLUE}Key ID:{CYAN} {key_id.hex()}')
            print(f'   {BLUE}MIC:{CYAN} {key_mic.hex()}')
            print(f'   {BLUE}Key Data Length:{CYAN} {key_data_len} {RESET}')
            if key_data:
                preview = key_data.hex()

                print(f'   {BLUE}Key Data:{CYAN} {preview}{RESET}')

        return eapolkey

"""
EAP TTLS Layer Creation (class EAP_TTLS)
- RFC 5281: Extensible Authentication Protocol - Tunneled Transport Layer Security
"""

class EAP_TTLS(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = 21, L: int = 0, M: int = 0, S: int = 0,
                 reserved: int = 0, version: int = 0,
                 tls_message_len: int = 0,
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
        self.version = version
        self.tls_message_len = tls_message_len
        self.tls_data = tls_data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        flags = (self.L << 7) | (self.M << 6) | (self.S << 5) | ((self.reserved & 0x03) << 3) | (self.version & 0x07)

        result = struct.pack('!BBHBB', self.code, self.id, self.length, self.type, flags)

        if self.L:
            if self.tls_message_len == 0:
                self.tls_message_len = len(self.tls_data)
            result += struct.pack('!I', self.tls_message_len)

        result += self.tls_data

        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            arr = bytearray(result)
            arr[2] = (len(result) >> 8) & 0xFF
            arr[3] = len(result) & 0xFF
            result = bytes(arr)
        return result

    def __len__(self):
        total = 5 + len(self.tls_data)
        if self.L:
            total += 4
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        flags_str = f"L={self.L}, M={self.M}, S={self.S}, V={self.version}"
        tls_preview = self.tls_data.hex()

        return (f"<EAP_TTLS code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"flags=[{flags_str}], tls_len={len(self.tls_data)}, "
                f"tls={tls_preview}>")

    def copy(self) -> 'EAP_TTLS':
        new_layer = EAP_TTLS(
            code=self.code,
            id=self.id,
            length=self.length,
            type=self.type,
            L=self.L,
            M=self.M,
            S=self.S,
            reserved=self.reserved,
            version=self.version,
            tls_message_len=self.tls_message_len,
            tls_data=self.tls_data
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}",
            f"type={self.type}",
            f"L={self.L}",
            f"M={self.M}",
            f"S={self.S}",
            f"reserved={self.reserved}",
            f"version={self.version}",
        ]
        if self.L:
            fields.append(f"tls_message_len={self.tls_message_len}")
        if self.tls_data:
            preview = self.tls_data.hex()
            fields.append(f"tls_data={preview}")
        return fields

    def get_version(self) -> int:
        """Get EAP-TTLS version (0 = v0)."""
        return self.version

    def get_version_name(self) -> str:
        """Get version name."""
        return f"EAP-TTLSv{self.version}"

    def is_start(self) -> bool:
        """Check if this is a Start packet."""
        return bool(self.S)

    def is_fragmented(self) -> bool:
        """Check if this packet is fragmented."""
        return bool(self.M)

    def has_length(self) -> bool:
        """Check if Message Length field is present."""
        return bool(self.L)

    def get_total_message_length(self) -> int:
        """Get total TLS message length."""
        return self.tls_message_len


"""
EAP TTLS Parser (separate from the builder)
"""

class EAP_TTLS_Parser:
    @staticmethod
    def load_as_eap_ttls_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-TTLS requires at least 6 bytes (EAP header + Type + Flags)")

        code, eap_id, total_len, eap_type, flags = struct.unpack('!BBHBB', data[:6])

        if eap_type != 21:
            LLogger.warning(f"EAP Type is {eap_type}, expected 21 (TTLS)")

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
            tls_message_len = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4

        tls_data = data[offset:] if len(data) > offset else b''

        eap_ttls = EAP_TTLS(
            code=code,
            id=eap_id,
            length=total_len,
            type=21,
            L=L,
            M=M,
            S=S,
            reserved=reserved,
            version=version,
            tls_message_len=tls_message_len,
            tls_data=tls_data
        )

        if len(data) > offset + len(tls_data):
            extra = data[offset + len(tls_data):]
            if extra:
                from .Raw import RawParser
                raw_layer = RawParser.load_as_Raw_layer(extra, verbose=verbose)
                eap_ttls /= raw_layer

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            flags_desc = []
            if L:
                flags_desc.append("Length included")
            if M:
                flags_desc.append("More fragments")
            if S:
                flags_desc.append("Start")
            if not flags_desc:
                flags_desc.append("None")

            print(f"\n{BOLD}EAP TTLS LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (TTLS)')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:02x} [{", ".join(flags_desc)}]')
            print(f'   {BLUE}RESERVED:{CYAN} {hex(reserved)}')
            print(f'   {BLUE}VERSION:{CYAN} {hex(version)} (EAP-TTLSv{version})')
            if L:
                print(f'   {BLUE}TLS_MESSAGE_LEN:{CYAN} {hex(tls_message_len)} ({tls_message_len} bytes)')
            if tls_data:
                preview = tls_data.hex()
                print(f'   {BLUE}TLS Data:{CYAN} {preview}{RESET}')

        return eap_ttls

"""
EAP PEAP Layer Creation (class EAP_PEAP)
- RFC 7486: Extensible Authentication Protocol - Protected EAP (PEAP)v2
"""

class EAP_PEAP(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = 25, L: int = 0, M: int = 0, S: int = 0,
                 reserved: int = 0, version: int = 0,
                 tls_message_len: int = 0,
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
        self.version = version
        self.tls_message_len = tls_message_len
        self.tls_data = tls_data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        flags = (self.L << 7) | (self.M << 6) | (self.S << 5) | ((self.reserved & 0x03) << 3) | (self.version & 0x07)

        result = struct.pack('!BBHBB', self.code, self.id, self.length, self.type, flags)

        if self.L:
            if self.tls_message_len == 0:
                self.tls_message_len = len(self.tls_data)
            result += struct.pack('!I', self.tls_message_len)

        result += self.tls_data

        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            arr = bytearray(result)
            arr[2] = (len(result) >> 8) & 0xFF
            arr[3] = len(result) & 0xFF
            result = bytes(arr)
        return result

    def __len__(self):
        total = 5 + len(self.tls_data)
        if self.L:
            total += 4
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        flags_str = f"L={self.L}, M={self.M}, S={self.S}, V={self.version}"
        tls_preview = self.tls_data[:16].hex() if self.tls_data else ""
        if len(self.tls_data) > 16:
            tls_preview += "..."
        return (f"<EAP_PEAP code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"flags=[{flags_str}], tls_len={len(self.tls_data)}, "
                f"tls={tls_preview}>")

    def copy(self) -> 'EAP_PEAP':
        new_layer = EAP_PEAP(
            code=self.code,
            id=self.id,
            length=self.length,
            type=self.type,
            L=self.L,
            M=self.M,
            S=self.S,
            reserved=self.reserved,
            version=self.version,
            tls_message_len=self.tls_message_len,
            tls_data=self.tls_data
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}",
            f"type={self.type}",
            f"L={self.L}",
            f"M={self.M}",
            f"S={self.S}",
            f"reserved={self.reserved}",
            f"version={self.version}",
        ]
        if self.L:
            fields.append(f"tls_message_len={self.tls_message_len}")
        if self.tls_data:
            preview = self.tls_data.hex()
            fields.append(f"tls_data={preview}")
        return fields

    def get_version(self) -> int:
        return self.version

    def get_version_name(self) -> str:
        return f"PEAPv{self.version}"

    def is_start(self) -> bool:
        return bool(self.S)

    def is_fragmented(self) -> bool:
        return bool(self.M)

    def has_length(self) -> bool:
        return bool(self.L)


"""
EAP PEAP Parser
"""

class EAP_PEAP_Parser:
    @staticmethod
    def load_as_eap_peap_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-PEAP requires at least 6 bytes")

        code, eap_id, total_len, eap_type, flags = struct.unpack('!BBHBB', data[:6])

        if eap_type != 25:
            LLogger.warning(f"EAP Type is {eap_type}, expected 25 (PEAP)")

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
            tls_message_len = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4

        tls_data = data[offset:] if len(data) > offset else b''

        eap_peap = EAP_PEAP(
            code=code,
            id=eap_id,
            length=total_len,
            type=25,
            L=L,
            M=M,
            S=S,
            reserved=reserved,
            version=version,
            tls_message_len=tls_message_len,
            tls_data=tls_data
        )

        if len(data) > offset + len(tls_data):
            extra = data[offset + len(tls_data):]
            if extra:
                from .Raw import RawParser
                raw_layer = RawParser.load_as_Raw_layer(extra, verbose=verbose)
                eap_peap /= raw_layer

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            flags_desc = []
            if L:
                flags_desc.append("Length included")
            if M:
                flags_desc.append("More fragments")
            if S:
                flags_desc.append("Start")
            if not flags_desc:
                flags_desc.append("None")

            print(f"\n{BOLD}EAP PEAP LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (PEAP)')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:02x} [{", ".join(flags_desc)}]')
            print(f'   {BLUE}RESERVED:{CYAN} {hex(reserved)}')
            print(f'   {BLUE}VERSION:{CYAN} {hex(version)} (PEAPv{version})')
            if L:
                print(f'   {BLUE}TLS_MESSAGE_LEN:{CYAN} {hex(tls_message_len)} ({tls_message_len} bytes)')
            if tls_data:
                preview = tls_data.hex()
                print(f'   {BLUE}TLS Data:{CYAN} {preview}{RESET}')

        return eap_peap

"""
EAP FAST Layer Creation (class EAP_FAST)
- RFC 4851: Extensible Authentication Protocol - Flexible Authentication via Secure Tunneling (EAP-FAST)
"""

class EAP_FAST(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = 43, L: int = 0, M: int = 0, S: int = 0,
                 reserved: int = 0, message_len: int = 0,
                 data: bytes = b''):
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

        result = struct.pack('!BBHBB', self.code, self.id, self.length, self.type, flags)

        if self.L:
            if self.message_len == 0:
                self.message_len = len(self.data)
            result += struct.pack('!I', self.message_len)

        result += self.data

        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            arr = bytearray(result)
            arr[2] = (len(result) >> 8) & 0xFF
            arr[3] = len(result) & 0xFF
            result = bytes(arr)
        return result

    def __len__(self):
        total = 5 + len(self.data)
        if self.L:
            total += 4
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        flags_str = f"L={self.L}, M={self.M}, S={self.S}"
        preview = self.data.hex()
        return (f"<EAP_FAST code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"flags=[{flags_str}], tls_len={len(self.data)}, "
                f"data={preview}>")

    def copy(self) -> 'EAP_FAST':
        new_layer = EAP_FAST(
            code=self.code,
            id=self.id,
            length=self.length,
            type=self.type,
            L=self.L,
            M=self.M,
            S=self.S,
            reserved=self.reserved,
            message_len=self.message_len,
            data=self.data
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}",
            f"type={self.type}",
            f"L={self.L}",
            f"M={self.M}",
            f"S={self.S}",
            f"reserved={self.reserved}",
        ]
        if self.L:
            fields.append(f"tls_message_len={self.tls_message_len}")
        if self.tls_data:
            preview = self.tls_data.hex()
            fields.append(f"tls_data={preview}")
        return fields

    def is_start(self) -> bool:
        return bool(self.S)

    def is_fragmented(self) -> bool:
        return bool(self.M)

    def has_length(self) -> bool:
        return bool(self.L)

"""
EAP FAST Parser
"""

class EAP_FAST_Parser:
    @staticmethod
    def load_as_eap_fast_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-FAST requires at least 6 bytes")

        code, eap_id, total_len, eap_type, flags = struct.unpack('!BBHBB', data[:6])

        if eap_type != 43:
            LLogger.warning(f"EAP Type is {eap_type}, expected 43 (FAST)")

        L = (flags >> 7) & 0x01
        M = (flags >> 6) & 0x01
        S = (flags >> 5) & 0x01
        reserved = flags & 0x1F

        offset = 6
        tls_message_len = 0

        if L:
            if len(data) < offset + 4:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message="EAP-FAST: L flag set but Message Length missing")
            tls_message_len = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4

        tls_data = data[offset:] if len(data) > offset else b''

        eap_fast = EAP_FAST(
            code=code,
            id=eap_id,
            length=total_len,
            type=43,
            L=L,
            M=M,
            S=S,
            reserved=reserved,
            tls_message_len=tls_message_len,
            tls_data=tls_data
        )

        if len(data) > offset + len(tls_data):
            extra = data[offset + len(tls_data):]
            if extra:
                from .Raw import RawParser
                raw_layer = RawParser.load_as_Raw_layer(extra, verbose=verbose)
                eap_fast /= raw_layer

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            flags_desc = []
            if L:
                flags_desc.append("Length included")
            if M:
                flags_desc.append("More fragments")
            if S:
                flags_desc.append("Start")
            if not flags_desc:
                flags_desc.append("None")

            print(f"\n{BOLD}EAP FAST LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (FAST)')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:02x} [{", ".join(flags_desc)}]')
            print(f'   {BLUE}RESERVED:{CYAN} {hex(reserved)}')
            if L:
                print(f'   {BLUE}MESSAGE_LEN:{CYAN} {hex(tls_message_len)} ({tls_message_len} bytes)')
            if tls_data:
                preview = tls_data.hex() if len(tls_data) > 0 else ""

                print(f'   {BLUE}Data:{CYAN} {preview}{RESET}')

        return eap_fast


EAP_TYPE_LEAP = 17

LEAP_VERSION = 1

LEAP_CHALLENGE_LEN = 16

LEAP_RESPONSE_LEN = 24

"""
EAP LEAP Layer Creation (class EAP_LEAP)
"""


class EAP_LEAP(BaseLayer):
    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = EAP_TYPE_LEAP, version: int = LEAP_VERSION,
                 unused: int = 0, count: int = 0,
                 challenge_response: bytes = b'',
                 username: bytes = b''):
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

        result = struct.pack('!BBHB', self.code, self.id, self.length, self.type)
        if self.count == 0:
            self.count = len(self.challenge_response)

        result += struct.pack('!BBB', self.version, self.unused, self.count)

        result += self.challenge_response

        result += self.username

        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            self.length = len(result)
            arr = bytearray(result)
            arr[2] = (self.length >> 8) & 0xFF
            arr[3] = self.length & 0xFF
            result = bytes(arr)

        return result

    def __len__(self):
        total = 5 + 3 + len(self.challenge_response) + len(self.username)
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        data_preview = self.challenge_response[:16].hex() if self.challenge_response else ""
        if len(self.challenge_response) > 16:
            data_preview += "..."
        return (f"<EAP_LEAP code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"version={self.version}, count={self.count}, "
                f"resp_len={len(self.challenge_response)}, "
                f"username={self.username.decode('utf-8', errors='ignore')[:20]}>")

    def copy(self) -> 'EAP_LEAP':
        new_layer = EAP_LEAP(
            code=self.code,
            id=self.id,
            length=self.length,
            type=self.type,
            version=self.version,
            unused=self.unused,
            count=self.count,
            challenge_response=self.challenge_response,
            username=self.username
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}",
            f"type={self.type} (LEAP)",
            f"version={self.version}",
            f"unused={self.unused}",
            f"count={self.count}",
        ]
        if self.challenge_response:
            preview = self.challenge_response.hex()
            fields.append(f"challenge_response={preview}")
        if self.username:
            fields.append(f"username={self.username.decode('utf-8', errors='ignore')}")
        return fields

    def get_challenge(self) -> bytes:
        """Return the challenge (first 16 bytes of challenge_response)."""
        return self.challenge_response[:LEAP_CHALLENGE_LEN] if len(
            self.challenge_response) >= LEAP_CHALLENGE_LEN else b''

    def get_response(self) -> bytes:
        """Return the response (24 bytes)."""
        return self.challenge_response[:LEAP_RESPONSE_LEN] if len(self.challenge_response) >= LEAP_RESPONSE_LEN else b''

    def is_challenge(self) -> bool:
        """Check if this is a LEAP Challenge (Request with 16-byte challenge)."""
        return self.code == 1 and len(self.challenge_response) == LEAP_CHALLENGE_LEN

    def is_response(self) -> bool:
        """Check if this is a LEAP Response (Response with 24-byte response)."""
        return self.code == 2 and len(self.challenge_response) == LEAP_RESPONSE_LEN

    def get_username(self) -> str:
        """Return the username as a string."""
        return self.username.decode('utf-8', errors='ignore')


"""
EAP LEAP Parser
"""

class EAP_LEAP_Parser:
    @staticmethod
    def load_as_eap_leap_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 8:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-LEAP requires at least 8 bytes")

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])

        if eap_type != EAP_TYPE_LEAP:
            LLogger.warning(f"EAP Type is {eap_type}, expected 17 (LEAP)")

        version, unused, count = struct.unpack('!BBB', data[5:8])

        offset = 8

        challenge_response = data[offset:offset + count]
        offset += count

        username = data[offset:]

        eap_leap = EAP_LEAP(
            code=code,
            id=eap_id,
            length=total_len,
            type=EAP_TYPE_LEAP,
            version=version,
            unused=unused,
            count=count,
            challenge_response=challenge_response,
            username=username
        )

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            data_label = "Challenge" if code == 1 and count == LEAP_CHALLENGE_LEN else \
                        "Response" if code == 2 and count == LEAP_RESPONSE_LEN else \
                        f"Data ({count} bytes)"

            print(f"\n{BOLD}EAP LEAP LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (LEAP)')
            print(f'   {BLUE}VERSION:{CYAN} {hex(version)}')
            print(f'   {BLUE}UNUSED:{CYAN} {hex(unused)}')
            print(f'   {BLUE}COUNT:{CYAN} {hex(count)} ({count} bytes)')
            print(f'   {BLUE}CHALLENGE/RESPONSE:{CYAN} {data_label}')
            if challenge_response:
                preview = challenge_response.hex()
                print(f'     {BLUE} -> {CYAN}{preview}{RESET}')
            if username:
                print(f'   {BLUE}USERNAME:{CYAN} {username.decode("utf-8", errors="ignore")}{RESET}')

        return eap_leap


EAP_TYPE_MSCHAPV2 = 26

MSCHAPV2_OPCODE_CHALLENGE = 1
MSCHAPV2_OPCODE_RESPONSE = 2
MSCHAPV2_OPCODE_SUCCESS = 3
MSCHAPV2_OPCODE_FAILURE = 4
MSCHAPV2_OPCODE_CHANGE_PASSWORD = 7

MSCHAPV2_CHALLENGE_LEN = 16
MSCHAPV2_RESPONSE_LEN = 49
MSCHAPV2_VALUE_SIZE_CHALLENGE = 0x10
MSCHAPV2_VALUE_SIZE_RESPONSE = 0x31

"""
EAP MSCHAPv2 Layer Creation (class EAP_MSCHAPv2)
"""

class EAP_MSCHAPv2(BaseLayer):

    def __init__(self, code: int = 1, identifier: int = 1, length: int = 0,
                 type: int = EAP_TYPE_MSCHAPV2,
                 opcode: int = MSCHAPV2_OPCODE_CHALLENGE,
                 ms_chapv2_id: int = 1,
                 ms_length: int = 0,
                 value_size: int = 0,
                 challenge: bytes = b'',
                 response: bytes = b'',
                 message: bytes = b'',
                 name: bytes = b''):
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

        result = struct.pack('!BBHB', self.code, self.identifier, self.length, self.type)

        result += struct.pack('!BBH', self.opcode, self.ms_chapv2_id, self.ms_length)

        if self.opcode == MSCHAPV2_OPCODE_CHALLENGE:
            result += struct.pack('!B', self.value_size)  # 0x10
            result += self.challenge[:MSCHAPV2_CHALLENGE_LEN]
            if self.name:
                result += self.name

        elif self.opcode == MSCHAPV2_OPCODE_RESPONSE:
            result += struct.pack('!B', self.value_size)
            result += self.response[:MSCHAPV2_RESPONSE_LEN]
            if self.name:
                result += self.name

        elif self.opcode == MSCHAPV2_OPCODE_SUCCESS:
            if self.message:
                result += self.message

        elif self.opcode == MSCHAPV2_OPCODE_FAILURE:
            if self.message:
                result += self.message

        elif self.opcode == MSCHAPV2_OPCODE_CHANGE_PASSWORD:
            if self.message:
                result += self.message

        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            self.length = len(result)
            self.ms_length = self.length - 5
            arr = bytearray(result)
            arr[3] = self.length
            arr[8] = self.ms_length
            result = bytes(arr)

        return result

    def __len__(self):
        total = 5 + 4
        if self.opcode == MSCHAPV2_OPCODE_CHALLENGE:
            total += 1 + len(self.challenge) + len(self.name)
        elif self.opcode == MSCHAPV2_OPCODE_RESPONSE:
            total += 1 + len(self.response) + len(self.name)
        elif self.opcode in (MSCHAPV2_OPCODE_SUCCESS, MSCHAPV2_OPCODE_FAILURE, MSCHAPV2_OPCODE_CHANGE_PASSWORD):
            total += len(self.message)
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        opcode_names = {
            1: "Challenge",
            2: "Response",
            3: "Success",
            4: "Failure",
            7: "ChangePassword"
        }
        op_name = opcode_names.get(self.opcode, f"Unknown({self.opcode})")
        return (f"<EAP_MSCHAPv2 code={hex(self.code)}, id={hex(self.identifier)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"opcode={op_name}, ms_id={hex(self.ms_chapv2_id)}, "
                f"ms_len={hex(self.ms_length)}>")

    def copy(self) -> 'EAP_MSCHAPv2':
        new_layer = EAP_MSCHAPv2(
            code=self.code,
            identifier=self.identifier,
            length=self.length,
            type=self.type,
            opcode=self.opcode,
            ms_chapv2_id=self.ms_chapv2_id,
            ms_length=self.ms_length,
            value_size=self.value_size,
            challenge=self.challenge,
            response=self.response,
            message=self.message,
            name=self.name
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        opcode_names = {
            1: "Challenge",
            2: "Response",
            3: "Success",
            4: "Failure",
            7: "ChangePassword"
        }
        op_name = opcode_names.get(self.opcode, f"Unknown({self.opcode})")

        fields = [
            f"code={self.code}",
            f"id={self.identifier}",
            f"len={self.length}",
            f"type={self.type} (MSCHAPv2)",
            f"opcode={self.opcode} ({op_name})",
            f"ms_chapv2_id={self.ms_chapv2_id}",
            f"ms_length={self.ms_length}",
            f"value_size={self.value_size}",
        ]
        if self.opcode == MSCHAPV2_OPCODE_CHALLENGE:
            if self.challenge:
                fields.append(f"challenge={self.challenge.hex()}")
        elif self.opcode == MSCHAPV2_OPCODE_RESPONSE:
            if self.response:
                fields.append(f"response={self.response.hex()}")
        if self.message:
            try:
                fields.append(f"message={self.message.decode('utf-8', errors='ignore')}")
            except:
                fields.append(f"message={self.message.hex()}")
        if self.name:
            try:
                fields.append(f"name={self.name.decode('utf-8', errors='ignore')}")
            except:
                fields.append(f"name={self.name.hex()}")
        return fields


"""
EAP MSCHAPv2 Parser
"""


class EAP_MSCHAPv2_Parser:
    @staticmethod
    def load_as_eap_mschapv2_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 9:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-MSCHAPv2 requires at least 9 bytes")

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])

        if eap_type != EAP_TYPE_MSCHAPV2:
            LLogger.warning(f"EAP Type is {eap_type}, expected 26 (MSCHAPv2)")

        opcode, ms_id, ms_length = struct.unpack('!BBH', data[5:9])

        offset = 9
        value_size = 0
        challenge = b''
        response = b''
        message = b''
        name = b''

        if opcode == MSCHAPV2_OPCODE_CHALLENGE:
            if len(data) >= offset + 1:
                value_size = data[offset]
                offset += 1
                if value_size == MSCHAPV2_VALUE_SIZE_CHALLENGE:
                    if len(data) >= offset + MSCHAPV2_CHALLENGE_LEN:
                        challenge = data[offset:offset + MSCHAPV2_CHALLENGE_LEN]
                        offset += MSCHAPV2_CHALLENGE_LEN
                        name = data[offset:] if len(data) > offset else b''
                else:
                    challenge = data[offset:] if len(data) > offset else b''

        elif opcode == MSCHAPV2_OPCODE_RESPONSE:
            if len(data) >= offset + 1:
                value_size = data[offset]
                offset += 1
                if value_size == MSCHAPV2_VALUE_SIZE_RESPONSE:
                    if len(data) >= offset + MSCHAPV2_RESPONSE_LEN:
                        response = data[offset:offset + MSCHAPV2_RESPONSE_LEN]
                        offset += MSCHAPV2_RESPONSE_LEN
                        name = data[offset:] if len(data) > offset else b''
                else:
                    response = data[offset:] if len(data) > offset else b''

        elif opcode == MSCHAPV2_OPCODE_SUCCESS:
            if len(data) > offset:
                message = data[offset:]

        elif opcode == MSCHAPV2_OPCODE_FAILURE:
            if len(data) > offset:
                message = data[offset:]

        elif opcode == MSCHAPV2_OPCODE_CHANGE_PASSWORD:
            if len(data) > offset:
                message = data[offset:]

        eap_mschapv2 = EAP_MSCHAPv2(
            code=code,
            identifier=eap_id,
            length=total_len,
            type=EAP_TYPE_MSCHAPV2,
            opcode=opcode,
            ms_chapv2_id=ms_id,
            ms_length=ms_length,
            value_size=value_size,
            challenge=challenge,
            response=response,
            message=message,
            name=name
        )


        if verbose:
            opcode_names = {
                1: "Challenge",
                2: "Response",
                3: "Success",
                4: "Failure",
                7: "ChangePassword"
            }
            op_name = opcode_names.get(opcode, f"Unknown({opcode})")
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""

            print(f"\n{BOLD}EAP MSCHAPv2 LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}IDENTIFIER:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (MSCHAPv2)')
            print(f'   {BLUE}OPCODE:{CYAN} {hex(opcode)} ({op_name})')
            print(f'   {BLUE}MS-CHAPv2-ID:{CYAN} {hex(ms_id)}')
            print(f'   {BLUE}MS-LENGTH:{CYAN} {hex(ms_length)} {RESET}')
            if value_size:
                print(f'   {BLUE}VALUE-SIZE:{CYAN} {hex(value_size)} {RESET}')

            if opcode == MSCHAPV2_OPCODE_CHALLENGE:
                if challenge:
                    print(f'   {BLUE}CHALLENGE:{CYAN} {challenge.hex()} {RESET}')
                if name:
                    try:
                        print(f'   {BLUE}NAME:{CYAN} {name.decode("utf-8", errors="ignore")} {RESET}')
                    except:
                        print(f'   {BLUE}NAME:{CYAN} {name.hex()} {RESET}')

            elif opcode == MSCHAPV2_OPCODE_RESPONSE:
                if response:
                    if len(response) >= 24:
                        nt_response = response[:24]
                        flags = response[24] if len(response) > 24 else 0
                        peer_challenge = response[25:41] if len(response) >= 41 else b''
                        reserved = response[41:49] if len(response) >= 49 else b''
                        print(f'   {BLUE}NT-RESPONSE:{CYAN} {nt_response.hex()}')
                        print(f'   {BLUE}FLAGS:{CYAN} {hex(flags)}')
                        if peer_challenge:
                            print(f'   {BLUE}PEER-CHALLENGE:{CYAN} {peer_challenge.hex()}')
                        if reserved:
                            print(f'   {BLUE}RESERVED:{CYAN} {reserved.hex()}')
                if name:
                    try:
                        print(f'   {BLUE}NAME:{CYAN} {name.decode("utf-8", errors="ignore")}')
                    except:
                        print(f'   {BLUE}NAME:{CYAN} {name.hex()}')

            elif opcode == MSCHAPV2_OPCODE_SUCCESS:
                if message:
                    try:
                        msg_str = message.decode('ascii', errors='ignore')
                        print(f'   {BLUE}MESSAGE:{CYAN} {msg_str}')
                    except:
                        print(f'   {BLUE}MESSAGE:{CYAN} {message.hex()}')

            elif opcode == MSCHAPV2_OPCODE_FAILURE:
                if message:
                    try:
                        msg_str = message.decode('utf-8', errors='ignore')
                        print(f'   {BLUE}ERROR:{CYAN} {msg_str}')
                    except:
                        print(f'   {BLUE}ERROR:{CYAN} {message.hex()}')

        print(RESET)

        return eap_mschapv2


"""
EAP Legacy Nak Layer Creation (class EAP_NAK)
- RFC 3748: Extensible Authentication Protocol
"""

EAP_TYPE_NAK = 3

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

        result = struct.pack('!BBHB', self.code, self.identifier, self.length, self.type)
        result += self.allowed_types

        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            self.length = len(result)
            arr = bytearray(result)
            arr[2] = (self.length >> 8) & 0xFF
            arr[3] = self.length & 0xFF
            result = bytes(arr)
        return result

    def __len__(self):
        total = 5 + len(self.allowed_types)
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        return (f"<EAP_NAK code={hex(self.code)}, id={hex(self.identifier)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"allowed_types={self.allowed_types.hex()}>")

    def copy(self) -> 'EAP_NAK':
        new_layer = EAP_NAK(
            code=self.code,
            identifier=self.identifier,
            length=self.length,
            type=self.type,
            allowed_types=self.allowed_types
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.identifier}",
            f"len={self.length}",
            f"type={self.type} (Legacy Nak)",
        ]
        if self.allowed_types:
            types_list = []
            for t in self.allowed_types:
                types_list.append(f"{hex(t)}")
            fields.append(f"allowed_types={', '.join(types_list)}")
        return fields

    def get_allowed_types(self) -> list:
        """Return list of allowed EAP types as integers."""
        return list(self.allowed_types)


class EAP_NAK_Parser:
    @staticmethod
    def load_as_eap_nak_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-NAK requires at least 6 bytes")

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])

        if eap_type != EAP_TYPE_NAK:
            LLogger.warning(f"EAP Type is {eap_type}, expected 3 (Legacy Nak)")

        allowed_types = data[5:] if len(data) > 5 else b''

        eap_nak = EAP_NAK(
            code=code,
            identifier=eap_id,
            length=total_len,
            type=eap_type,
            allowed_types=allowed_types
        )

        if verbose:
            code_label = "(Response)" if code == 2 else "(Unknown)"
            allowed_list = []
            for t in allowed_types:
                allowed_list.append(f"{hex(t)}")

            print(f"\n{BOLD}EAP LEGACY NAK LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (Legacy Nak)')
            if allowed_types:
                print(f'   {BLUE}ALLOWED TYPES:{CYAN} {", ".join(allowed_list)}{RESET}')
            else:
                print(f'   {BLUE}ALLOWED TYPES:{CYAN} (none){RESET}')

        return eap_nak


"""
EAP Notification Layer Creation (class EAP_NOTIFICATION)
- RFC 3748: Extensible Authentication Protocol
"""

EAP_TYPE_NOTIFICATION = 2

class EAP_NOTIFICATION(BaseLayer):

    def __init__(self, code: int = 1, identifier: int = 1, length: int = 0,
                 type: int = EAP_TYPE_NOTIFICATION, message: bytes = b'\x00'):
        super().__init__()
        self.code = code
        self.identifier = identifier
        self.length = length
        self.type = type
        self.message = message

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        result = struct.pack('!BBHB', self.code, self.identifier, self.length, self.type)
        result += self.message

        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            self.length = len(result)
            arr = bytearray(result)
            arr[2] = (self.length >> 8) & 0xFF
            arr[3] = self.length & 0xFF
            result = bytes(arr)
        return result

    def __len__(self):
        total = 5 + len(self.message)
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        try:
            msg_preview = self.message.decode('utf-8', errors='ignore')
            if len(msg_preview) > 30:
                msg_preview = msg_preview[:30] + "..."
        except:
            msg_preview = self.message.hex()[:30]
        return (f"<EAP_NOTIFICATION code={hex(self.code)}, id={hex(self.identifier)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"message={msg_preview}>")

    def copy(self) -> 'EAP_NOTIFICATION':
        new_layer = EAP_NOTIFICATION(
            code=self.code,
            identifier=self.identifier,
            length=self.length,
            type=self.type,
            message=self.message
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.identifier}",
            f"len={self.length}",
            f"type={self.type} (Notification)",
        ]
        if self.message:
            try:
                msg = self.message.decode('utf-8', errors='ignore')
                fields.append(f"message={msg}")
            except:
                fields.append(f"message={self.message.hex()}")
        return fields


class EAP_NOTIFICATION_Parser:
    @staticmethod
    def load_as_eap_notification_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-Notification requires at least 6 bytes")

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])

        if eap_type != EAP_TYPE_NOTIFICATION:
            LLogger.warning(f"EAP Type is {eap_type}, expected 2 (Notification)")

        message = data[5:] if len(data) > 5 else b''

        eap_notification = EAP_NOTIFICATION(
            code=code,
            identifier=eap_id,
            length=total_len,
            type=eap_type,
            message=message
        )

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""
            print(f"\n{BOLD}EAP NOTIFICATION LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (Notification)')
            if message:
                try:
                    msg = message.decode('utf-8', errors='ignore')
                    print(f'   {BLUE}MESSAGE:{CYAN} {msg}{RESET}')
                except:
                    print(f'   {BLUE}MESSAGE:{CYAN} {message.hex()}{RESET}')
            else:
                print(f'   {BLUE}MESSAGE:{CYAN} (empty){RESET}')

        return eap_notification


"""
EAP-pwd Layer Creation (class EAP_PWD)
- RFC 5931: Extensible Authentication Protocol - Password Authenticated Exchange
"""

EAP_TYPE_PWD = 52

PWD_EXCHANGE_ID = 0
PWD_EXCHANGE_COMMIT = 1
PWD_EXCHANGE_CONFIRM = 2
PWD_EXCHANGE_CRYPTO_BINDING = 3

PWD_EXCHANGE_NAMES = {
    0: "Identity",
    1: "Commit",
    2: "Confirm",
    3: "Crypto Binding"
}

PWD_FAILURE_UNKNOWN = 0
PWD_FAILURE_AUTH_FAIL = 1
PWD_FAILURE_INVALID_GROUP = 2
PWD_FAILURE_NO_RETRY = 3
PWD_FAILURE_ABORT = 4
PWD_FAILURE_TIMEOUT = 5

PWD_FAILURE_NAMES = {
    0: "Unknown",
    1: "Authentication Failure",
    2: "Invalid Group",
    3: "No Retry",
    4: "Abort",
    5: "Timeout"
}


class EAP_PWD(BaseLayer):

    def __init__(self, code: int = 1, id: int = 1, length: int = 0,
                 type: int = EAP_TYPE_PWD,
                 L: int = 0, M: int = 0,
                 pwd_exchange: int = PWD_EXCHANGE_ID,
                 total_length: int = 0,
                 data: bytes = b'\x00'):
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

        result = struct.pack('!BBHBB', self.code, self.id, self.length, self.type, flags)

        if self.L:
            result += struct.pack('!H', self.total_length)

        result += self.data

        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            self.length = len(result)
            arr = bytearray(result)
            arr[2] = (self.length >> 8) & 0xFF
            arr[3] = self.length & 0xFF
            result = bytes(arr)
        return result

    def __len__(self):
        total = 6
        if self.L:
            total += 2
        total += len(self.data)
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        ex_name = PWD_EXCHANGE_NAMES.get(self.pwd_exchange, f"Unknown({self.pwd_exchange})")
        return (f"<EAP_PWD code={hex(self.code)}, id={hex(self.id)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"exchange={ex_name}, L={self.L}, M={self.M}>")

    def copy(self) -> 'EAP_PWD':
        new_layer = EAP_PWD(
            code=self.code,
            id=self.id,
            length=self.length,
            type=self.type,
            L=self.L,
            M=self.M,
            pwd_exchange=self.pwd_exchange,
            total_length=self.total_length,
            data=self.data
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        ex_name = PWD_EXCHANGE_NAMES.get(self.pwd_exchange, f"Unknown({self.pwd_exchange})")
        fields = [
            f"code={self.code}",
            f"id={self.id}",
            f"len={self.length}",
            f"type={self.type} (EAP-pwd)",
            f"L={self.L}",
            f"M={self.M}",
            f"pwd_exchange={self.pwd_exchange} ({ex_name})",
        ]
        if self.L:
            fields.append(f"total_length={self.total_length}")
        if self.data:
            if self.pwd_exchange in (PWD_EXCHANGE_ID, PWD_EXCHANGE_COMMIT, PWD_EXCHANGE_CONFIRM):

                preview = self.data.hex()
                fields.append(f"data={preview}")
            else:
                preview = self.data.hex()
                fields.append(f"data={preview}")
        return fields


    def get_exchange_name(self) -> str:
        return PWD_EXCHANGE_NAMES.get(self.pwd_exchange, f"Unknown({self.pwd_exchange})")

    def is_identity(self) -> bool:
        return self.pwd_exchange == PWD_EXCHANGE_ID

    def is_commit(self) -> bool:
        return self.pwd_exchange == PWD_EXCHANGE_COMMIT

    def is_confirm(self) -> bool:
        return self.pwd_exchange == PWD_EXCHANGE_CONFIRM

    def has_more(self) -> bool:
        return bool(self.M)

    def has_length(self) -> bool:
        return bool(self.L)

    def get_failure_code(self) -> int:
        """If this is a failure packet, return the failure code (first byte of data)."""
        if self.data and len(self.data) >= 1:
            return self.data[0]
        return -1

    def get_failure_message(self) -> bytes:
        """If this is a failure packet, return the message (after failure code)."""
        if len(self.data) >= 2:
            return self.data[1:]
        return b''

    def get_failure_code_name(self) -> str:
        code = self.get_failure_code()
        return PWD_FAILURE_NAMES.get(code, f"Unknown({code})") if code >= 0 else "No failure"


class EAP_PWD_Parser:
    @staticmethod
    def load_as_eap_pwd_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-pwd requires at least 6 bytes")

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])
        eap_type = data[4] if len(data) > 4 else 0

        if eap_type != EAP_TYPE_PWD:
            LLogger.warning(f"EAP Type is {eap_type}, expected 52 (EAP-pwd)")

        flags = data[5] if len(data) > 5 else 0
        L = (flags >> 7) & 0x01
        M = (flags >> 6) & 0x01
        pwd_exchange = flags & 0x3F

        offset = 6
        total_length = 0

        if L:
            if len(data) >= offset + 2:
                total_length = struct.unpack('!H', data[offset:offset + 2])[0]
                offset += 2
            else:
                LLogger.warning("EAP-pwd: L flag set but Total-Length missing")

        pwd_data = data[offset:] if len(data) > offset else b''

        eap_pwd = EAP_PWD(
            code=code,
            id=eap_id,
            length=total_len,
            type=eap_type,
            L=L,
            M=M,
            pwd_exchange=pwd_exchange,
            total_length=total_length,
            data=pwd_data
        )

        if verbose:
            ex_name = PWD_EXCHANGE_NAMES.get(pwd_exchange, f"Unknown({pwd_exchange})")
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""

            print(f"\n{BOLD}EAP PWD LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (EAP-pwd)')
            print(f'   {BLUE}FLAGS:{CYAN} 0x{flags:02x}')
            print(f'   {BLUE}  L:{CYAN} {L}')
            print(f'   {BLUE}  M:{CYAN} {M}')
            print(f'   {BLUE}  PWD-Exch:{CYAN} {hex(pwd_exchange)} ({ex_name})')
            if L:
                print(f'   {BLUE}TOTAL-LENGTH:{CYAN} {hex(total_length)}')
            if pwd_data:
                preview = pwd_data.hex()
                print(f'   {BLUE}DATA:{CYAN} {preview}{RESET}')

        return eap_pwd


"""
EAP-GTC Layer Creation (class EAP_GTC)
- RFC 3748: Extensible Authentication Protocol
"""

EAP_TYPE_GTC = 6

class EAP_GTC(BaseLayer):

    def __init__(self, code: int = 1, identifier: int = 1, length: int = 0,
                 type: int = EAP_TYPE_GTC, data: bytes = b'\x00'):
        super().__init__()
        self.code = code
        self.identifier = identifier
        self.length = length
        self.type = type
        self.data = data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        result = struct.pack('!BBHB', self.code, self.identifier, self.length, self.type)
        result += self.data

        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            self.length = len(result)
            arr = bytearray(result)
            arr[2] = (self.length >> 8) & 0xFF
            arr[3] = self.length & 0xFF
            result = bytes(arr)
        return result

    def __len__(self):
        total = 5 + len(self.data)
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        try:
            preview = self.data.decode('utf-8', errors='ignore')
        except:
            preview = self.data.hex()[:30]
        return (f"<EAP_GTC code={hex(self.code)}, id={hex(self.identifier)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"data={preview}>")

    def copy(self) -> 'EAP_GTC':
        new_layer = EAP_GTC(
            code=self.code,
            identifier=self.identifier,
            length=self.length,
            type=self.type,
            data=self.data
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.identifier}",
            f"len={self.length}",
            f"type={self.type} (GTC)",
        ]
        if self.data:
            try:
                msg = self.data.decode('utf-8', errors='ignore')
                fields.append(f"data={msg}")
            except:
                fields.append(f"data={self.data.hex()}")
        return fields

    def get_challenge(self) -> str:
        """Get the challenge as a string (Request)."""
        return self.data.decode('utf-8', errors='ignore')

    def get_response(self) -> str:
        """Get the response as a string (Response)."""
        return self.data.decode('utf-8', errors='ignore')

    def is_challenge(self) -> bool:
        return self.code == 1

    def is_response(self) -> bool:
        return self.code == 2


class EAP_GTC_Parser:
    @staticmethod
    def load_as_eap_gtc_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-GTC requires at least 6 bytes")

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])

        if eap_type != EAP_TYPE_GTC:
            LLogger.warning(f"EAP Type is {eap_type}, expected 6 (GTC)")

        gtc_data = data[5:] if len(data) > 5 else b''

        eap_gtc = EAP_GTC(
            code=code,
            identifier=eap_id,
            length=total_len,
            type=eap_type,
            data=gtc_data
        )

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""

            print(f"\n{BOLD}EAP GTC LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (GTC) {RESET}')
            if gtc_data:
                try:
                    msg = gtc_data.decode('utf-8', errors='ignore')
                    print(f'   {BLUE}DATA:{CYAN} {msg}{RESET}')
                except:
                    print(f'   {BLUE}DATA:{CYAN} {gtc_data.hex()}{RESET}')
            else:
                print(f'   {BLUE}DATA:{CYAN} (empty){RESET}')

        return eap_gtc


"""
EAP-OTP Layer Creation (class EAP_OTP)
- RFC 3748: Extensible Authentication Protocol
"""

EAP_TYPE_OTP = 5

class EAP_OTP(BaseLayer):

    def __init__(self, code: int = 1, identifier: int = 1, length: int = 0,
                 type: int = EAP_TYPE_OTP, data: bytes = b'\x00'):
        super().__init__()
        self.code = code
        self.identifier = identifier
        self.length = length
        self.type = type
        self.data = data

    def build(self) -> bytes:
        payload_bytes = self.get_payload_bytes()

        result = struct.pack('!BBHB', self.code, self.identifier, self.length, self.type)
        result += self.data

        if payload_bytes:
            result += payload_bytes

        if self.length == 0:
            self.length = len(result)
            arr = bytearray(result)
            arr[2] = (self.length >> 8) & 0xFF
            arr[3] = self.length & 0xFF
            result = bytes(arr)
        return result

    def __len__(self):
        total = 5 + len(self.data)
        if self.payload:
            total += len(self.payload)
        return total

    def __repr__(self):
        try:
            preview = self.data.decode('utf-8', errors='ignore')
            if len(preview) > 30:
                preview = preview[:30] + "..."
        except:
            preview = self.data.hex()[:30]
        return (f"<EAP_OTP code={hex(self.code)}, id={hex(self.identifier)}, "
                f"len={hex(self.length)}, type={hex(self.type)}, "
                f"data={preview}>")

    def copy(self) -> 'EAP_OTP':
        new_layer = EAP_OTP(
            code=self.code,
            identifier=self.identifier,
            length=self.length,
            type=self.type,
            data=self.data
        )
        if self.payload:
            new_layer.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        if self._raw_payload:
            new_layer._raw_payload = self._raw_payload
        return new_layer

    def _show_fields(self) -> list:
        fields = [
            f"code={self.code}",
            f"id={self.identifier}",
            f"len={self.length}",
            f"type={self.type} (OTP)",
        ]
        if self.data:
            try:
                msg = self.data.decode('utf-8', errors='ignore')
                fields.append(f"data={msg}")
            except:
                fields.append(f"data={self.data.hex()}")
        return fields

    def get_challenge(self) -> str:
        """Get the challenge as a string (Request)."""
        return self.data.decode('utf-8', errors='ignore')

    def get_response(self) -> str:
        """Get the OTP response as a string (Response)."""
        return self.data.decode('utf-8', errors='ignore')

    def is_challenge(self) -> bool:
        return self.code == 1

    def is_response(self) -> bool:
        return self.code == 2


class EAP_OTP_Parser:
    @staticmethod
    def load_as_eap_otp_layer(raw_packet, verbose=False):
        from builtins import type

        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        data = raw_packet[0]

        if len(data) < 6:
            LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                          message="EAP-OTP requires at least 6 bytes")

        code, eap_id, total_len, eap_type = struct.unpack('!BBHB', data[:5])

        if eap_type != EAP_TYPE_OTP:
            LLogger.warning(f"EAP Type is {eap_type}, expected 5 (OTP)")

        otp_data = data[5:] if len(data) > 5 else b''

        eap_otp = EAP_OTP(
            code=code,
            identifier=eap_id,
            length=total_len,
            type=eap_type,
            data=otp_data
        )

        if verbose:
            code_label = "(Request)" if code == 1 else "(Response)" if code == 2 else ""

            print(f"\n{BOLD}EAP OTP LAYER : {RESET}Len({PURPLE}{len(data)}{RESET}) >")
            print(f'   {BLUE}CODE:{CYAN} {hex(code)} {code_label}')
            print(f'   {BLUE}ID:{CYAN} {hex(eap_id)}')
            print(f'   {BLUE}LEN:{CYAN} {hex(total_len)}')
            print(f'   {BLUE}TYPE:{CYAN} {hex(eap_type)} (OTP) {RESET}')
            if otp_data:
                try:
                    msg = otp_data.decode('utf-8', errors='ignore')
                    print(f'   {BLUE}DATA:{CYAN} {msg}{RESET}')
                except:
                    print(f'   {BLUE}DATA:{CYAN} {otp_data.hex()}{RESET}')
            else:
                print(f'   {BLUE}DATA:{CYAN} (empty){RESET}')

        return eap_otp