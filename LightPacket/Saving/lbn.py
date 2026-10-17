# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import ctypes
import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__)).replace("Saving","lib")

if sys.platform == "win32":
    lib = ctypes.CDLL(f"{current_dir}/liblbn.dll")
elif sys.platform == "linux":
    lib = ctypes.CDLL(f"{current_dir}/liblbn.so")
elif sys.platform == "darwin":
    lib = ctypes.CDLL(f"{current_dir}/liblbn.dylib")
else:
    lib = ctypes.CDLL(f"{current_dir}/liblbn.so")

lib.lbn_save.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_size_t,
    ctypes.c_int
]
lib.lbn_save.restype = ctypes.c_int

lib.lbn_load.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))),
    ctypes.POINTER(ctypes.POINTER(ctypes.c_size_t)),
    ctypes.POINTER(ctypes.c_size_t)
]
lib.lbn_load.restype = ctypes.c_int

lib.lbn_free_packets.argtypes = [
    ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_size_t
]
lib.lbn_free_packets.restype = None

def LbnWrite(filename, packets, compress=0):
    if isinstance(packets, list):
        pass
    else:
        packets = [packets]
    count = len(packets)
    pkt_ptrs = (ctypes.POINTER(ctypes.c_ubyte) * count)()
    sizes = (ctypes.c_size_t * count)()
    for i, pkt in enumerate(packets):
        data = bytes(pkt)
        sizes[i] = len(data)
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        pkt_ptrs[i] = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
    ret = lib.lbn_save(filename.encode('utf-8'), pkt_ptrs, sizes, count, compress)
    return ret == 0

def LbnRead(filename):
    packets_ptr = ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))()
    sizes_ptr = ctypes.POINTER(ctypes.c_size_t)()
    count = ctypes.c_size_t()
    ret = lib.lbn_load(filename.encode('utf-8'),
                       ctypes.byref(packets_ptr),
                       ctypes.byref(sizes_ptr),
                       ctypes.byref(count))
    if ret != 0:
        return None
    result = []
    for i in range(count.value):
        size = sizes_ptr[i]
        data_ptr = packets_ptr[i]
        result.append(bytes(data_ptr[:size]))
    lib.lbn_free_packets(packets_ptr, sizes_ptr, count)
    return result

class LbnWriteStream:
    def __init__(self, filename, compress=False):
        self.filename = filename
        self.compress = 1 if compress else 0
        self._closed = False
        self._packets_written = 0

    def write(self, packets):
        if self._closed:
            raise RuntimeError("LbnWrite is closed")
        if not isinstance(packets, list):
            packets = [packets]
        if not packets:
            return True

        count = len(packets)

        pkt_ptrs = (ctypes.POINTER(ctypes.c_ubyte) * count)()
        sizes = (ctypes.c_size_t * count)()

        buffers = []
        try:
            for i, pkt in enumerate(packets):
                data = bytes(pkt)
                sizes[i] = len(data)
                buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
                buffers.append(buf)   # prevent GC
                pkt_ptrs[i] = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))

            ret = lib.lbn_save(
                self.filename.encode('utf-8'),
                pkt_ptrs,
                sizes,
                count,
                self.compress,
            )
            if ret != 0:
                raise IOError(f"lbn_save failed (rc={ret})")

            self._packets_written += count
            return True

        finally:
            pass

    def write_one(self, packet):
        return self.write([packet])

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        self._closed = True

    def __len__(self):
        return self._packets_written

    def __repr__(self):
        state = "closed" if self._closed else "open"
        return (f"<LbnWrite file={self.filename!r} "
                f"compressed={bool(self.compress)} "
                f"written={self._packets_written} {state}>")

class LbnReadStream:
    def __init__(self, filename):
        self.filename = filename
        self.packets = []
        self._closed = False

    def read(self):
        if self._closed:
            raise RuntimeError("LbnRead is closed")

        packets_ptr = ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))()
        sizes_ptr = ctypes.POINTER(ctypes.c_size_t)()
        count = ctypes.c_size_t()

        ret = lib.lbn_load(
            self.filename.encode('utf-8'),
            ctypes.byref(packets_ptr),
            ctypes.byref(sizes_ptr),
            ctypes.byref(count),
        )

        if ret != 0:
            raise IOError(f"lbn_load failed (rc={ret})")

        try:
            result = []
            for i in range(count.value):
                size = sizes_ptr[i]
                data_ptr = packets_ptr[i]
                result.append(bytes(data_ptr[:size]))
            return result
        finally:
            lib.lbn_free_packets(packets_ptr, sizes_ptr, count)

    def open(self):
        self.packets = self.read()
        return self

    def __enter__(self):
        return self.open()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __iter__(self):
        return iter(self.packets)

    def __len__(self):
        return len(self.packets)

    def __getitem__(self, idx):
        return self.packets[idx]

    def close(self):
        self._closed = True
        self.packets = []

    def __repr__(self):
        state = "closed" if self._closed else f"{len(self.packets)} packets"
        return f"<LbnRead file={self.filename!r} {state}>"
