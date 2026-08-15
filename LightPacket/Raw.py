# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

from .Decoration.Colors import BOLD, RESET, CYAN, BLUE, PURPLE
from .Logger.LightLogger import Logger
from .BaseLayer import BaseLayer
from typing import Optional


LLogger = Logger()

"""
Raw Layer Creation (class RawLayer)
"""

class RawLayer(BaseLayer):
    def __init__(self, payload: Optional[bytes] = None):
        super().__init__()
        self._raw_payload = payload or b''

    def build(self) -> bytes:
        result = self._raw_payload or b''

        if self.payload is not None:
            if hasattr(self.payload, 'build'):
                result += self.payload.build()
            else:
                result += bytes(self.payload)

        return result

    def __len__(self):
        base_len = len(self._raw_payload or b'')
        if self.payload:
            if hasattr(self.payload, '__len__'):
                base_len += len(self.payload)
        return base_len

    def __repr__(self):
        payload = self._raw_payload or b''
        if len(payload) > 32:
            return f"<Raw payload={payload[:32]}... len={len(payload)}>"
        return f"<Raw payload={payload} len={len(payload)}>"

    def copy(self) -> 'RawLayer':
        new = RawLayer(payload=self._raw_payload)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, 'copy') else self.payload
        return new

    def _show_fields(self) -> list[str]:
        payload = self._raw_payload or b''
        fields = []
        fields.append(f"payload={payload}")
        fields.append(f"len={len(payload)}")
        return fields


"""
Raw Parser (separate from the builder)
"""

class RawParser:

    @staticmethod
    def load_as_Raw_layer(raw_packet,verbose=False):
        if type(raw_packet) is not list:
            raw_packet = [raw_packet]
            if hasattr(raw_packet[0], 'build') and type(raw_packet[0]) is not bytes:
                raw_packet[0] = raw_packet[0].build()

        Raw = raw_packet[0]
        lenght = len(Raw)

        if verbose:
            print(f"\n{BOLD}RAW LAYER : Len({PURPLE}{lenght}{RESET}) >")
            print(f'   {BLUE}PAYLOAD:{CYAN} {Raw} {RESET}')

        raw = RawLayer(
            payload=Raw,
        )

        return raw

