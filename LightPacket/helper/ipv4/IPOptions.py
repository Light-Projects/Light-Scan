# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import struct
from LightPacket.Logger.LightLogger import Logger, ErrorCode

LLogger = Logger()

OPT_EOL = 0
OPT_NOP = 1

_NO_LEN_DATA = (OPT_EOL, OPT_NOP)

OPT_NAMES = {
    0:   "EOL",
    1:   "NOP",
    7:   "RR",     
    68:  "TS",
    131: "LSRR",
    137: "SSRR",
    148: "RTRALT",
}

class IPOption:

    def __init__(self, type: int, data: bytes = b""):
        self.type = type & 0xFF
        self.data = data if data else b""

    @property
    def is_single_byte(self) -> bool:
        return self.type in _NO_LEN_DATA

    @property
    def length(self) -> int:
        if self.is_single_byte:
            return 1
        return 2 + len(self.data)

    def build(self) -> bytes:
        if self.is_single_byte:
            return struct.pack('>B', self.type)
        return struct.pack('>BB', self.type, self.length) + self.data

    def copy(self) -> 'IPOption':
        return IPOption(self.type, self.data)

    def __len__(self):
        return self.length

    def __repr__(self):
        name = OPT_NAMES.get(self.type, f"type={self.type}")
        if self.is_single_byte:
            return f"<IPOption {name}>"
        return f"<IPOption {name} len={self.length} data={self.data.hex()}>"


class IPOptions:

    def __init__(self, options=None):
        self.options = list(options) if options else []

    def append(self, option: 'IPOption') -> None:
        self.options.append(option)

    def __iter__(self):
        return iter(self.options)

    def __len__(self):
        return len(self.options)

    def __getitem__(self, idx):
        return self.options[idx]

    def get(self, type: int):
        for opt in self.options:
            if opt.type == type:
                return opt
        return None

    def has(self, type: int) -> bool:
        return self.get(type) is not None

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

    def copy(self) -> 'IPOptions':
        return IPOptions([opt.copy() for opt in self.options])

    def __bool__(self):
        return len(self.options) > 0

    def __repr__(self):
        return f"<IPOptions [{', '.join(repr(o) for o in self.options)}]>"

    @staticmethod
    def parse(raw: bytes) -> 'IPOptions':
        opts = IPOptions()
        i = 0
        n = len(raw)

        while i < n:
            opt_type = raw[i]

            if opt_type in _NO_LEN_DATA:
                opts.append(IPOption(opt_type))
                i += 1
                if opt_type == OPT_EOL:
                    break
                continue

            if i + 1 >= n:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message=f"IPv4 option type={opt_type} missing length byte")
                break

            opt_len = raw[i + 1]
            if opt_len < 2:
                LLogger.error(error_code=ErrorCode.INVALID_DATA_LENGTH,
                              message=f"IPv4 option type={opt_type} invalid length={opt_len}")
                break

            data_end = i + opt_len
            if data_end > n:
                LLogger.error(error_code=ErrorCode.TRUNCATED_DATA,
                              message=f"IPv4 option type={opt_type} truncated "
                                      f"(need {opt_len}, have {n - i})")
                break

            data = raw[i + 2:data_end]
            opts.append(IPOption(opt_type, data))
            i = data_end

        return opts