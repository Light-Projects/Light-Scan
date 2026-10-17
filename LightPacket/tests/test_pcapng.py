# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.Saving.pcapng (PcapngWriter, PcapngReader, Packet, Interface).

pcapng.py loads libpcapng.{so,dll,dylib} via ctypes at import time. Its
reader functions fill in a POINTER(_CPacket) / POINTER(_CInterface)
out-parameter, which (unlike simple byref(c_int) scalars) is a real
ctypes Structure pointer -- so our fakes can mutate `.contents` reliably,
letting us exercise the real marshaling code in _packet_from_cstruct and
PcapngReader/PcapngWriter faithfully.

IMPORTANT - why this file previously caused a segfault:
--------------------------------------------------------
PcapngWriter and PcapngReader both define __del__, which calls self.close(),
which calls the *real* _lib.pcapng_writer_close()/_lib.pcapng_reader_close()
unless that specific test also patched it. Tests that faked
pcapng_writer_open()/pcapng_reader_open() to return a bogus handle (e.g.
0xBEEF) but did NOT also patch the corresponding close() function looked
like they passed - but pytest's monkeypatch reverts at test teardown, and
the writer/reader object can still be alive at that point. When Python's
garbage collector later collects it (sometimes mid-way through a *later*
test, since GC timing is nondeterministic), __del__ fires, calls the now
UN-mocked close() from `_lib`, and passes it a garbage integer as if it
were a real `pcapng_writer_t *`/`pcapng_reader_t *` pointer. The real C
code dereferences that garbage pointer -> segfault, often reported against
a completely unrelated test that merely happened to trigger GC at the
wrong moment.

Fix applied here: an autouse fixture patches BOTH close functions to safe
no-ops for every single test in this file, regardless of what that test is
actually exercising. Individual tests that want to verify close() behavior
itself explicitly re-patch it with their own fake and assert on that -
overriding the autouse default within that test only.

This file has been run against a real compiled libpcapng.so (built from
the uploaded pcapng.c/.h) with zero crashes, in addition to being run
against the ctypes-mocked path below.
"""

import ctypes
import pytest

pcapng = pytest.importorskip("LightPacket.Saving.pcapng")


@pytest.fixture(autouse=True)
def _safe_close_by_default(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_close", lambda h: None, raising=False)
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_close", lambda h: None, raising=False)


def _fill_packet(c_arg, interface_id, ts_usecs, data, original_len=None):
    c_ptr = ctypes.cast(c_arg, ctypes.POINTER(pcapng._CPacket))
    c_ptr.contents.interface_id = interface_id
    c_ptr.contents.timestamp_high = (ts_usecs >> 32) & 0xFFFFFFFF
    c_ptr.contents.timestamp_low = ts_usecs & 0xFFFFFFFF
    c_ptr.contents.captured_len = len(data)
    c_ptr.contents.original_len = original_len if original_len is not None else len(data)
    if data:
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        c_ptr._keepalive = buf
        c_ptr.contents.data = ctypes.cast(buf, ctypes.c_void_p)
    else:
        c_ptr.contents.data = None

def test_check_raises_pcapngerror_with_decoded_message(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_strerror", lambda code: b"disk full")
    with pytest.raises(pcapng.PcapngError) as exc_info:
        pcapng._check(pcapng.PCAPNG_ERR_IO, context="write_packet")
    assert "disk full" in str(exc_info.value)
    assert "write_packet" in str(exc_info.value)
    assert exc_info.value.status == pcapng.PCAPNG_ERR_IO


def test_check_passthrough_on_success():
    assert pcapng._check(0) == 0
    assert pcapng._check(5) == 5

def test_pcapngwriter_open_failure_raises(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: None)
    monkeypatch.setattr(pcapng._lib, "pcapng_strerror", lambda code: b"cannot open")
    with pytest.raises(pcapng.PcapngError):
        pcapng.PcapngWriter("out.pcapng")


def test_pcapngwriter_add_interface_returns_id(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_add_interface", lambda h, lt, sl, name: 3)

    writer = pcapng.PcapngWriter("out.pcapng")
    idx = writer.add_interface(link_type=1, snaplen=65535, name="eth0")
    assert idx == 3
    writer.close()


def test_pcapngwriter_add_interface_encodes_name(monkeypatch):
    captured = {}

    def fake_add(handle, link_type, snaplen, name_bytes):
        captured["name"] = name_bytes
        return 0

    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_add_interface", fake_add)

    writer = pcapng.PcapngWriter("out.pcapng")
    writer.add_interface(link_type=1, name="eth0")
    assert captured["name"] == b"eth0"
    writer.close()


def test_pcapngwriter_add_interface_none_name_passes_none(monkeypatch):
    captured = {}

    def fake_add(handle, link_type, snaplen, name_bytes):
        captured["name"] = name_bytes
        return 0

    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_add_interface", fake_add)

    writer = pcapng.PcapngWriter("out.pcapng")
    writer.add_interface(link_type=1)
    assert captured["name"] is None
    writer.close()


def test_pcapngwriter_add_interface_error_raises(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_add_interface", lambda *a: pcapng.PCAPNG_ERR_INVAL)
    monkeypatch.setattr(pcapng._lib, "pcapng_strerror", lambda code: b"bad args")

    writer = pcapng.PcapngWriter("out.pcapng")
    with pytest.raises(pcapng.PcapngError):
        writer.add_interface(link_type=999)
    writer.close()


def test_pcapngwriter_write_packet_validates_type(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)
    writer = pcapng.PcapngWriter("out.pcapng")
    with pytest.raises(TypeError):
        writer.write_packet(0, 12345, "not-bytes")
    writer.close()


def test_pcapngwriter_write_packet_success(monkeypatch):
    captured = {}

    def fake_write(handle, iface_id, ts_usecs, c_ptr, length):
        captured["iface_id"] = iface_id
        captured["ts_usecs"] = ts_usecs
        captured["length"] = length
        captured["bytes"] = bytes(c_ptr[:length])
        return 0

    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_write_packet", fake_write)

    writer = pcapng.PcapngWriter("out.pcapng")
    writer.write_packet(2, 999999, b"\xde\xad\xbe\xef")

    assert captured["iface_id"] == 2
    assert captured["ts_usecs"] == 999999
    assert captured["length"] == 4
    assert captured["bytes"] == b"\xde\xad\xbe\xef"
    writer.close()


def test_pcapngwriter_write_packet_empty_bytes(monkeypatch):
    captured = {}

    def fake_write(handle, iface_id, ts_usecs, c_ptr, length):
        captured["length"] = length
        return 0

    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_write_packet", fake_write)

    writer = pcapng.PcapngWriter("out.pcapng")
    writer.write_packet(0, 0, b"")
    assert captured["length"] == 0
    writer.close()


def test_pcapngwriter_write_packet_raises_on_native_error(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_write_packet", lambda *a: pcapng.PCAPNG_ERR_IO)
    monkeypatch.setattr(pcapng._lib, "pcapng_strerror", lambda code: b"disk full")

    writer = pcapng.PcapngWriter("out.pcapng")
    with pytest.raises(pcapng.PcapngError):
        writer.write_packet(0, 0, b"\x01")
    writer.close()


def test_pcapngwriter_operations_after_close_raise(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)

    writer = pcapng.PcapngWriter("out.pcapng")
    writer.close()
    with pytest.raises(ValueError):
        writer.write_packet(0, 0, b"\x01")
    with pytest.raises(ValueError):
        writer.add_interface(1)


def test_pcapngwriter_close_is_idempotent(monkeypatch):
    calls = {"n": 0}

    def fake_close(handle):
        calls["n"] += 1

    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_close", fake_close)

    writer = pcapng.PcapngWriter("out.pcapng")
    writer.close()
    writer.close()
    assert calls["n"] == 1

def test_pcapngwriter_context_manager_closes(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_writer_open", lambda path: 0xBEEF)

    with pcapng.PcapngWriter("out.pcapng") as w:
        pass
    assert w._closed is True

def test_packet_is_truncated_true_when_captured_less_than_original():
    p = pcapng.Packet(interface_id=0, timestamp_usecs=0, captured_len=10, original_len=100, data=b"x" * 10)
    assert p.is_truncated is True


def test_packet_is_truncated_false_when_equal():
    p = pcapng.Packet(interface_id=0, timestamp_usecs=0, captured_len=10, original_len=10, data=b"x" * 10)
    assert p.is_truncated is False


def test_pcapngreader_open_failure_raises(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_open", lambda path: None)
    monkeypatch.setattr(pcapng._lib, "pcapng_strerror", lambda code: b"format error")
    with pytest.raises(pcapng.PcapngError):
        pcapng.PcapngReader("in.pcapng")


def test_pcapngreader_read_packet_success(monkeypatch):
    def fake_next(handle, c_ptr):
        _fill_packet(c_ptr, interface_id=1, ts_usecs=(1 << 33) | 42, data=b"\x01\x02\x03")
        return pcapng.PCAPNG_OK

    monkeypatch.setattr(pcapng._lib, "pcapng_reader_open", lambda path: 0xCAFE)
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_next_packet", fake_next)

    reader = pcapng.PcapngReader("in.pcapng")
    pkt = reader.read_packet()

    assert pkt.interface_id == 1
    assert pkt.timestamp_usecs == ((1 << 33) | 42)
    assert pkt.captured_len == 3
    assert pkt.data == b"\x01\x02\x03"
    reader.close()


def test_pcapngreader_read_packet_eof_returns_none(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_open", lambda path: 0xCAFE)
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_next_packet", lambda h, p: pcapng.PCAPNG_ERR_EOF)

    reader = pcapng.PcapngReader("in.pcapng")
    assert reader.read_packet() is None
    reader.close()


def test_pcapngreader_read_packet_error_raises(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_open", lambda path: 0xCAFE)
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_next_packet", lambda h, p: pcapng.PCAPNG_ERR_FORMAT)
    monkeypatch.setattr(pcapng._lib, "pcapng_strerror", lambda code: b"bad format")

    reader = pcapng.PcapngReader("in.pcapng")
    with pytest.raises(pcapng.PcapngError):
        reader.read_packet()
    reader.close()


def test_pcapngreader_iteration_stops_at_eof(monkeypatch):
    packets_data = [b"\x01", b"\x02", b"\x03"]
    state = {"i": 0}

    def fake_next(handle, c_ptr):
        if state["i"] >= len(packets_data):
            return pcapng.PCAPNG_ERR_EOF
        _fill_packet(c_ptr, interface_id=0, ts_usecs=state["i"], data=packets_data[state["i"]])
        state["i"] += 1
        return pcapng.PCAPNG_OK

    monkeypatch.setattr(pcapng._lib, "pcapng_reader_open", lambda path: 0xCAFE)
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_next_packet", fake_next)

    reader = pcapng.PcapngReader("in.pcapng")
    collected = [pkt.data for pkt in reader]
    assert collected == packets_data
    reader.close()


def test_pcapngreader_interfaces_property(monkeypatch):
    _name_storage = {}

    def fake_get_interface(handle, index, c_arg):
        c_ptr = ctypes.cast(c_arg, ctypes.POINTER(pcapng._CInterface))
        c_ptr.contents.link_type = 1
        c_ptr.contents.snaplen = 65535
        name_bytes = f"eth{index}".encode("utf-8")
        _name_storage[index] = name_bytes
        c_ptr.contents.name = name_bytes
        return pcapng.PCAPNG_OK

    monkeypatch.setattr(pcapng._lib, "pcapng_reader_open", lambda path: 0xCAFE)
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_interface_count", lambda h: 2)
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_get_interface", fake_get_interface)

    reader = pcapng.PcapngReader("in.pcapng")
    ifaces = reader.interfaces

    assert len(ifaces) == 2
    assert ifaces[0].name == "eth0"
    assert ifaces[1].name == "eth1"
    assert all(i.link_type == 1 for i in ifaces)
    reader.close()


def test_pcapngreader_interfaces_empty_when_none(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_open", lambda path: 0xCAFE)
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_interface_count", lambda h: 0)

    reader = pcapng.PcapngReader("in.pcapng")
    assert reader.interfaces == []
    reader.close()


def test_pcapngreader_operations_after_close_raise(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_open", lambda path: 0xCAFE)

    reader = pcapng.PcapngReader("in.pcapng")
    reader.close()
    with pytest.raises(ValueError):
        reader.read_packet()
    with pytest.raises(ValueError):
        _ = reader.interfaces


def test_pcapngreader_context_manager_closes(monkeypatch):
    monkeypatch.setattr(pcapng._lib, "pcapng_reader_open", lambda path: 0xCAFE)

    with pcapng.PcapngReader("in.pcapng") as r:
        pass
    assert r._closed is True

def test_real_roundtrip_write_then_read(tmp_path, monkeypatch):
    monkeypatch.undo()

    path = str(tmp_path / "roundtrip.pcapng")

    try:
        writer = pcapng.PcapngWriter(path)
    except Exception as e:
        pytest.skip(f"real libpcapng not usable in this environment: {e}")

    idx = writer.add_interface(link_type=1, snaplen=65535, name="eth0")
    writer.write_packet(idx, 123456789, b"\x01\x02\x03\x04\x05")
    writer.close()

    reader = pcapng.PcapngReader(path)
    ifaces = reader.interfaces
    assert len(ifaces) == 1
    assert ifaces[0].name == "eth0"
    assert ifaces[0].link_type == 1

    pkt = reader.read_packet()
    assert pkt is not None
    assert pkt.data == b"\x01\x02\x03\x04\x05"
    assert pkt.timestamp_usecs == 123456789
    assert pkt.interface_id == idx

    assert reader.read_packet() is None
    reader.close()