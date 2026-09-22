# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
LightPacket live packet sniffer.

Wraps L2Socket with a capture loop: count, timeout, callback, stop.

Usage:
    from LightPacket import Sniffer

    with Sniffer(iface="eth0", filter="tcp port 80", count=10) as s:
        for pkt in s.stream():
            print(len(pkt), pkt[:20].hex())

    # Or callback mode:
    def on_pkt(raw):
        print(len(raw))

    packets = Sniffer(iface="eth0", count=100).start(callback=on_pkt)
"""

import time
import threading
from typing import Callable, Iterator, Optional, List


class Sniffer:
    def __init__(self, iface: Optional[str] = None,
                 filter: Optional[str] = None,
                 count: int = 0,
                 timeout: Optional[float] = None,
                 promisc: bool = True,
                 snaplen: int = 65535,
                 monitor: bool = False,
                 socket_factory=None):

        self.iface = iface
        self.filter = filter
        self.count = count
        self.timeout = timeout
        self.promisc = promisc
        self.snaplen = snaplen
        self.monitor = monitor
        self._socket_factory = socket_factory
        self.link = 1

        self._sock = None
        self._stop_event = threading.Event()
        self._packets_captured = 0

    def start(self, callback: Optional[Callable[[bytes], None]] = None
              ) -> List[bytes]:
        packets = []
        for pkt in self.stream():
            packets.append(pkt)
            if callback is not None:
                callback(pkt)
        return packets

    def stream(self) -> Iterator[bytes]:
        self._open()
        start_time = time.monotonic()
        try:
            while not self._stop_event.is_set():
                if self.count and self._packets_captured >= self.count:
                    return

                if self.timeout is not None:
                    elapsed = time.monotonic() - start_time
                    if elapsed >= self.timeout:
                        return
                    per_recv_timeout = min(0.25, self.timeout - elapsed)
                else:
                    per_recv_timeout = 0.25

                try:
                    pkt = self._sock.recv_one(timeout=per_recv_timeout)
                except KeyboardInterrupt:
                    self._stop_event.set()
                    return
                if pkt is None:
                    continue

                self._packets_captured += 1
                yield pkt
        finally:
            self._close()

    def stop(self):
        self._stop_event.set()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._close()
        return False

    def __link__(self):
        return self.link

    @property
    def packets_captured(self) -> int:
        return self._packets_captured

    def __repr__(self):
        state = "open" if self._sock else "closed"
        return (f"<Sniffer iface={self.iface!r} "
                f"filter={self.filter!r} "
                f"captured={self._packets_captured} {state}>")

    def _open(self):
        if self._sock is not None:
            return

        if self._socket_factory is None:
            from LightPacket import L2Socket
            self.factory = L2Socket
        else:
            self.factory = self._socket_factory

        self._sock = self.factory(
            iface=self.iface,
            promisc=self.promisc,
            snaplen=self.snaplen,
            monitor=self.monitor,
        )
        self.link = self.factory(self.iface).datalink()
        if self.filter:
            self._sock.set_filter(self.filter)

    def _close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None