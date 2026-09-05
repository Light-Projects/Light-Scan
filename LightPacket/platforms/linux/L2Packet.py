# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Standalone LightPacket L2Packet (AF_PACKET) for Linux (Only) layer 2 packets socket.
"""
import ctypes
import time
import socket
import select
from LightPacket.bpf import get_bpf_bytes,free_filter
from typing import List
from LightPacket.Logger.LightLogger import Logger, ErrorCode
from LightPacket.Interfaces.LibpcapInterfacesLin import get_default_interface_name_linux

defaultiface = None

Logger = Logger()
if defaultiface == None:
    defaultiface = get_default_interface_name_linux()

try:
    pcap_lib = ctypes.CDLL("libpcap.so.1")
except OSError:
    try:
        pcap_lib = ctypes.CDLL("libpcap.so")
    except OSError:
        pass

class L2Packet:
    def __init__(self, iface=None, nonstop=True,snaplen=65535):
        if iface is None:
            iface = defaultiface
            if iface is None:
                raise RuntimeError("No network interface found")

        self.iface = iface
        self.sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(socket.ETH_P_ALL)
        )
        #
        self.sock.bind((iface, socket.ETH_P_ALL))
        self.sock.setblocking(nonstop)
        self.snaplen = snaplen
        self._filter = None
        self.closed = False

    def sendl2(self, packet):
        """Send a Layer 2 packet."""
        if self.closed or not self.sock:
            raise RuntimeError("Socket closed")

        if hasattr(packet, 'build') and callable(packet.build):
            packet = packet.build()

        self.sock.send(packet)

    def set_filter(self, filter_str: str) -> bool:
        if not self.sock:
            return False

        try:
            filter_bytes,bp = get_bpf_bytes(filter_str, self.iface)
        except Exception:
            Logger.error(error_code=ErrorCode.CANNOT_COMPILE_BPF,message="Cannot compile filter filter, make sure libpcap is installed")

        self._filter = filter_str
        self.sock.setsockopt(socket.SOL_SOCKET, 26, filter_bytes)
        free_filter(bp)
        return True

    def recvl2(self, count: int = 1, timeout: float = 1.0) -> List[bytes]:
        """Receive Layer 2 packets."""
        if self.closed or not self.sock:
            raise RuntimeError("Socket closed")

        packets = []
        deadline = time.time() + timeout
        received = 0

        target_count = count if count > 0 else float('inf')

        was_blocking = self.sock.getblocking()
        self.sock.setblocking(False)

        try:
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break

                if count > 0 and received >= target_count:
                    break

                ready, _, _ = select.select([self.sock], [], [], remaining)

                if ready:
                    try:
                        data, addr = self.sock.recvfrom(self.snaplen)
                        if data:
                            packets.append(data)
                            received += 1
                    except socket.error as e:
                        if e.errno == socket.EAGAIN or e.errno == socket.EWOULDBLOCK:
                            continue
                        raise
                else:
                    break

        finally:
            self.sock.setblocking(was_blocking)

        return packets

    def close(self):
        """Close the socket."""
        if self.sock:
            self.sock.close()
            self.closed = True

    def __del__(self):
        self.close()