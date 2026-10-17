# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import random
import time
from typing import Callable, Iterator, Optional

from LightPacket.Saving.pcapreader import PcapReadStream
from LightPacket.Saving.lbn import LbnReadStream
from LightPacket.Saving.pcapng import PcapngReader
from LightPacket.file.dtype import detect_file_type
from LightPacket.Logger.LightLogger import Logger, WarningCode

LLogger = Logger()


def replay(
    file_path: str,
    socket,
    delay: float = 0.2,
    count: int = 0,
    loop: int = 1,
    jitter: float = 0.0,
    on_packet: Optional[Callable[[int, bytes], None]] = None,
    stop_event=None,
) -> int:

    """
    Replay packets from a capture file through `socket`.

    Args:
        file_path: path to a .pcap, .pcapng, or .lbn capture.
        socket: any object with a .sendl2(bytes) method (L2Socket, L2SocketL, L2Packet).
        delay: base seconds to sleep between packets.
        count: number of packets to send per pass, 0 = all packets in the file.
        loop: number of passes over the (selected) packets, 0 = loop forever
              until stop_event is set or the file is exhausted (files are
              re-opened on every pass, so this replays the same packets again).
        jitter: adds a uniform random +/- jitter fraction to `delay`
                (e.g. jitter=0.1 -> delay varies +/-10%). 0 disables jitter.
        on_packet: optional callback(index, packet_bytes) invoked right
                   before each packet is sent, useful for progress/logging.
        stop_event: optional threading.Event-like object; replay stops as
                    soon as stop_event.is_set() returns True.

    Returns:
        Total number of packets actually sent across all passes.
    """

    file_type = detect_file_type(file_path)

    sent = 0
    pass_num = 0
    while loop == 0 or pass_num < loop:
        pass_num += 1
        for i, packet in enumerate(_iter_packets(file_type, file_path)):
            if stop_event is not None and stop_event.is_set():
                return sent
            if count and i >= count:
                break

            if on_packet is not None:
                on_packet(i, packet)

            socket.sendl2(packet)
            sent += 1

            sleep_for = _with_jitter(delay, jitter)
            if sleep_for > 0:
                time.sleep(sleep_for)

        if loop == 0 and stop_event is None:
            continue

    return sent


def _with_jitter(delay: float, jitter: float) -> float:
    if jitter <= 0:
        return delay
    spread = delay * jitter
    return max(0.0, delay + random.uniform(-spread, spread))


def _iter_packets(type_: str, file_path: str) -> Iterator[bytes]:
    if type_ == 'pcap':
        with PcapReadStream(file_path) as stream:
            for pkt in stream.packets:
                yield pkt['data']

    elif type_ == 'lightbin':
        with LbnReadStream(file_path) as stream:
            for pkt in stream:
                yield pkt

    elif type_ == 'pcapng':
        with PcapngReader(file_path) as reader:
            for pkt in reader:
                yield pkt.data

    else:
        LLogger.warning(
            message=f"Unknown capture file format for '{file_path}', trying as PCAP"
        )
        try:
            with PcapReadStream(file_path) as stream:
                for pkt in stream.packets:
                    yield pkt['data']
        except Exception as e:
            LLogger.warning(message=f"Failed to read '{file_path}' as PCAP fallback: {e}",
                            warning_code=WarningCode.UNKNOWN_FILE_FORMAT)
            return