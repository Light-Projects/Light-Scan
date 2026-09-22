# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.Logger.LightLogger import Logger, ErrorCode

LLogger = Logger()

OPT_EOL       = 0
OPT_NOP       = 1
OPT_MSS       = 2
OPT_WS        = 3   # Window Scale
OPT_SACK_PERM = 4
OPT_SACK      = 5
OPT_TS        = 8   # Timestamps

_NO_LEN_DATA = (OPT_EOL, OPT_NOP)

OPT_NAMES = {
    0: "EOL",
    1: "NOP",
    2: "MSS",
    3: "WindowScale",
    4: "SACK-Permitted",
    5: "SACK",
    8: "Timestamps",
}


class TCPOption:

    def __init__(self, kind: int, data: bytes = b""):
        self.kind = kind & 0xFF
        self.data = data if data else b""

    @property
    def is_single_byte(self) -> bool:
        return self.kind in _NO_LEN_DATA

    @property
    def length(self) -> int:
        if self.is_single_byte:
            return 1
        return 2 + len(self.data)

    def build(self) -> bytes:
        if self.is_single_byte:
            return struct.pack('>B', self.kind)
        return struct.pack('>BB', self.kind, self.length) + self.data

    def copy(self) -> 'TCPOption':
        return TCPOption(self.kind, self.data)

    def __len__(self):
        return self.length

    def __repr__(self):
        name = OPT_NAMES.get(self.kind, f"kind={self.kind}")
        if self.is_single_byte:
            return f"<TCPOption {name}>"
        if self.kind == OPT_MSS and len(self.data) == 2:
            return f"<TCPOption MSS value={struct.unpack('>H', self.data)[0]}>"
        if self.kind == OPT_WS and len(self.data) == 1:
            return f"<TCPOption WindowScale shift={self.data[0]}>"
        if self.kind == OPT_TS and len(self.data) == 8:
            tsval, tsecr = struct.unpack('>II', self.data)
            return f"<TCPOption Timestamps tsval={tsval} tsecr={tsecr}>"
        return f"<TCPOption {name} len={self.length} data={self.data.hex()}>"


class TCPOptions:

    def __init__(self, options=None):
        self.options = list(options) if options else []

    def append(self, option: 'TCPOption') -> None:
        self.options.append(option)

    def __iter__(self):
        return iter(self.options)

    def __len__(self):
        return len(self.options)

    def __getitem__(self, idx):
        return self.options[idx]

    def get(self, kind: int):
        for opt in self.options:
            if opt.kind == kind:
                return opt
        return None

    def has(self, kind: int) -> bool:
        return self.get(kind) is not None

    @property
    def raw_length(self) -> int:
        return sum(opt.length for opt in self.options)

    @property
    def padded_length(self) -> int:
        raw = self.raw_length
        return (raw + 3) & ~0x03

    def build(self) -> bytes:
        blob = b"".join(opt.build() for opt in self.options)
        pad = self.padded_length - len(blob)
        if pad > 0:
            blob += b"\x00" * pad
        return blob

    def copy(self) -> 'TCPOptions':
        return TCPOptions([opt.copy() for opt in self.options])

    def __bool__(self):
        return len(self.options) > 0

    def __repr__(self):
        return f"<TCPOptions [{', '.join(repr(o) for o in self.options)}]>"

    @staticmethod
    def mss(value: int) -> 'TCPOption':
        return TCPOption(OPT_MSS, struct.pack('>H', value & 0xFFFF))

    @staticmethod
    def window_scale(shift: int) -> 'TCPOption':
        return TCPOption(OPT_WS, struct.pack('>B', shift & 0xFF))

    @staticmethod
    def sack_permitted() -> 'TCPOption':
        return TCPOption(OPT_SACK_PERM)

    @staticmethod
    def timestamps(tsval: int, tsecr: int) -> 'TCPOption':
        return TCPOption(OPT_TS, struct.pack('>II', tsval & 0xFFFFFFFF, tsecr & 0xFFFFFFFF))

    @staticmethod
    def nop() -> 'TCPOption':
        return TCPOption(OPT_NOP)

    @staticmethod
    def eol() -> 'TCPOption':
        return TCPOption(OPT_EOL)

    @staticmethod
    def parse(raw: bytes) -> 'TCPOptions':
        opts = TCPOptions()
        i = 0
        n = len(raw)

        while i < n:
            kind = raw[i]

            if kind in _NO_LEN_DATA:
                opts.append(TCPOption(kind))
                i += 1
                if kind == OPT_EOL:
                    break
                continue

            if i + 1 >= n:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message=f"TCP option kind={kind} missing length byte")
                break

            opt_len = raw[i + 1]
            if opt_len < 2:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message=f"TCP option kind={kind} invalid length={opt_len}")
                break

            data_end = i + opt_len
            if data_end > n:
                LLogger.error(error_code=ErrorCode.TRUNCATED_DATA,
                              message=f"TCP option kind={kind} truncated "
                                      f"(need {opt_len}, have {n - i})")
                break

            data = raw[i + 2:data_end]
            opts.append(TCPOption(kind, data))
            i = data_end

        return opts