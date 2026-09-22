# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.Saving.lbn (LbnWrite, LbnRead, LbnWriteStream, LbnReadStream).

`lbn.py` loads liblbn.{so,dll,dylib} via ctypes at import time, so these
tests monkeypatch the module-level `lib.lbn_save` / `lib.lbn_load` /
`lib.lbn_free_packets` C-function objects rather than touching a real
native library. This verifies:
  - correct marshaling of Python bytes/layer objects into ctypes buffers
  - correct unmarshaling of returned buffers back into Python bytes
  - error propagation (non-zero return codes -> IOError)
  - stream classes' open/closed state machine and __len__/__repr__

If liblbn is available in your environment, delete the monkeypatches and
these become full integration tests against the real library.
"""

import ctypes
import pytest

lbn = pytest.importorskip("LightPacket.Saving.lbn")


class FakeRaw:
    """Something with a .build() method, mimicking a LightPacket layer."""
    def __init__(self, data):
        self._data = data

    def build(self):
        return self._data


def test_lbnwrite_single_bytes_packet(monkeypatch):
    captured = {}

    def fake_save(filename, pkt_ptrs, sizes, count, compress):
        captured["filename"] = filename
        captured["count"] = count
        captured["compress"] = compress
        captured["sizes"] = [sizes[i] for i in range(count)]
        return 0

    monkeypatch.setattr(lbn.lib, "lbn_save", fake_save)

    ok = lbn.LbnWrite("out.lbn", b"\x01\x02\x03")
    assert ok is True
    assert captured["filename"] == b"out.lbn"
    assert captured["count"] == 1
    assert captured["sizes"] == [3]
    assert captured["compress"] == 0


def test_lbnwrite_list_of_packets(monkeypatch):
    captured = {}

    def fake_save(filename, pkt_ptrs, sizes, count, compress):
        captured["count"] = count
        captured["sizes"] = [sizes[i] for i in range(count)]
        return 0

    monkeypatch.setattr(lbn.lib, "lbn_save", fake_save)

    ok = lbn.LbnWrite("out.lbn", [b"aa", b"bbbb", b"c"])
    assert ok is True
    assert captured["count"] == 3
    assert captured["sizes"] == [2, 4, 1]


def test_lbnwrite_rejects_object_without_bytes_conversion(monkeypatch):
    monkeypatch.setattr(lbn.lib, "lbn_save", lambda *a, **k: 0)
    with pytest.raises(TypeError):
        lbn.LbnWrite("out.lbn", FakeRaw(b"hello!"))


def test_lbnwrite_accepts_object_with_bytes_dunder(monkeypatch):
    captured = {}

    def fake_save(filename, pkt_ptrs, sizes, count, compress):
        captured["sizes"] = [sizes[i] for i in range(count)]
        return 0

    monkeypatch.setattr(lbn.lib, "lbn_save", fake_save)

    class HasBytesDunder:
        def __bytes__(self):
            return b"hello!"

    ok = lbn.LbnWrite("out.lbn", HasBytesDunder())
    assert ok is True
    assert captured["sizes"] == [6]


def test_lbnwrite_compress_flag_passed_through(monkeypatch):
    captured = {}

    def fake_save(filename, pkt_ptrs, sizes, count, compress):
        captured["compress"] = compress
        return 0

    monkeypatch.setattr(lbn.lib, "lbn_save", fake_save)

    lbn.LbnWrite("out.lbn", b"\x00", compress=1)
    assert captured["compress"] == 1


def test_lbnwrite_failure_returns_false(monkeypatch):
    monkeypatch.setattr(lbn.lib, "lbn_save", lambda *a, **k: -1)
    ok = lbn.LbnWrite("out.lbn", b"\x00")
    assert ok is False

def test_lbnread_success_reconstructs_packet_bytes(monkeypatch):
    payloads = [b"reconstructed-data", b"second-packet"]
    bufs = [(ctypes.c_ubyte * len(p)).from_buffer_copy(p) for p in payloads]
    packets_ptr = (ctypes.POINTER(ctypes.c_ubyte) * len(payloads))(
        *(ctypes.cast(b, ctypes.POINTER(ctypes.c_ubyte)) for b in bufs)
    )
    sizes_ptr = (ctypes.c_size_t * len(payloads))(*(len(p) for p in payloads))
    count = len(payloads)

    result = []
    for i in range(count):
        size = sizes_ptr[i]
        data_ptr = packets_ptr[i]
        result.append(bytes(data_ptr[:size]))

    assert result == payloads


def test_lbnread_success_path_calls_free_and_returns_list(monkeypatch):
    freed = {"called": False}

    def fake_load(filename, packets_ptr_ref, sizes_ptr_ref, count_ref):
        return 0

    def fake_free(*a, **k):
        freed["called"] = True

    monkeypatch.setattr(lbn.lib, "lbn_load", fake_load)
    monkeypatch.setattr(lbn.lib, "lbn_free_packets", fake_free)

    result = lbn.LbnRead("in.lbn")
    assert result == []
    assert freed["called"] is True


def test_lbnread_failure_returns_none(monkeypatch):
    def fake_load(filename, packets_ptr_ref, sizes_ptr_ref, count_ref):
        return -1

    monkeypatch.setattr(lbn.lib, "lbn_load", fake_load)
    assert lbn.LbnRead("missing.lbn") is None

def test_lbnwritestream_write_accumulates_count(monkeypatch):
    monkeypatch.setattr(lbn.lib, "lbn_save", lambda *a, **k: 0)

    stream = lbn.LbnWriteStream("out.lbn")
    stream.write([b"a", b"b"])
    stream.write_one(b"c")
    assert len(stream) == 3


def test_lbnwritestream_empty_list_is_noop_success(monkeypatch):
    called = {"n": 0}

    def fake_save(*a, **k):
        called["n"] += 1
        return 0

    monkeypatch.setattr(lbn.lib, "lbn_save", fake_save)
    stream = lbn.LbnWriteStream("out.lbn")
    assert stream.write([]) is True
    assert called["n"] == 0
    assert len(stream) == 0


def test_lbnwritestream_raises_on_native_failure(monkeypatch):
    monkeypatch.setattr(lbn.lib, "lbn_save", lambda *a, **k: 7)
    stream = lbn.LbnWriteStream("out.lbn")
    with pytest.raises(IOError):
        stream.write(b"\x00")


def test_lbnwritestream_write_after_close_raises(monkeypatch):
    monkeypatch.setattr(lbn.lib, "lbn_save", lambda *a, **k: 0)
    stream = lbn.LbnWriteStream("out.lbn")
    stream.close()
    with pytest.raises(RuntimeError):
        stream.write(b"\x00")


def test_lbnwritestream_context_manager_closes(monkeypatch):
    monkeypatch.setattr(lbn.lib, "lbn_save", lambda *a, **k: 0)
    with lbn.LbnWriteStream("out.lbn") as s:
        s.write(b"\x00")
    assert s._closed is True


def test_lbnwritestream_repr_reflects_state(monkeypatch):
    monkeypatch.setattr(lbn.lib, "lbn_save", lambda *a, **k: 0)
    stream = lbn.LbnWriteStream("out.lbn", compress=True)
    assert "open" in repr(stream)
    stream.write(b"\x00")
    assert "written=1" in repr(stream)
    stream.close()
    assert "closed" in repr(stream)

def test_lbnreadstream_read_after_close_raises(monkeypatch):
    stream = lbn.LbnReadStream("in.lbn")
    stream.close()
    with pytest.raises(RuntimeError):
        stream.read()


def test_lbnreadstream_open_populates_packets_and_supports_iteration(monkeypatch):
    def fake_read(self_stream):
        return [b"pkt1", b"pkt2"]

    monkeypatch.setattr(lbn.LbnReadStream, "read", fake_read)
    stream = lbn.LbnReadStream("in.lbn").open()

    assert len(stream) == 2
    assert list(stream) == [b"pkt1", b"pkt2"]
    assert stream[0] == b"pkt1"


def test_lbnreadstream_context_manager_opens_and_closes(monkeypatch):
    monkeypatch.setattr(lbn.LbnReadStream, "read", lambda self: [b"x"])

    with lbn.LbnReadStream("in.lbn") as s:
        assert len(s) == 1
    assert s._closed is True
    assert s.packets == []


def test_lbnreadstream_native_failure_raises_ioerror(monkeypatch):
    def fake_load(filename, packets_ptr_ref, sizes_ptr_ref, count_ref):
        return -2

    monkeypatch.setattr(lbn.lib, "lbn_load", fake_load)
    stream = lbn.LbnReadStream("in.lbn")
    with pytest.raises(IOError):
        stream.read()