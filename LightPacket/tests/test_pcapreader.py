# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.Saving.pcapreader (PcapRead, PcapReadStream).

pcapreader.py loads libpcap_reader.{so,dll,dylib} via ctypes at import
time. Its C functions return ctypes Structures directly (not via
out-pointers), which makes them straightforward to fake: we monkeypatch
`lib.read_pcap_file` to return a real `PcapResult` structure built purely
in Python, so the marshaling/unmarshaling logic in PcapRead/PcapReadStream
is exercised faithfully without a real native library.
"""

import ctypes
import pytest

pcapreader = pytest.importorskip("LightPacket.Saving.pcapreader")


def _make_pcap_result(packets_data, magic=0xA1B2C3D4, snaplen=65535, network=1):
    entries = (pcapreader.PacketEntry * len(packets_data))()
    bufs = []
    for i, data in enumerate(packets_data):
        buf = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        bufs.append(buf)
        entries[i].header.ts_sec = 1000 + i
        entries[i].header.ts_usec = i * 10
        entries[i].header.incl_len = len(data)
        entries[i].header.orig_len = len(data)
        entries[i].data = ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint8))

    result = pcapreader.PcapResult()
    result.packets = ctypes.cast(entries, ctypes.POINTER(pcapreader.PacketEntry))
    result.count = len(packets_data)
    result.global_header.magic_number = magic
    result.global_header.version_major = 2
    result.global_header.version_minor = 4
    result.global_header.thiszone = 0
    result.global_header.sigfigs = 0
    result.global_header.snaplen = snaplen
    result.global_header.network = network

    result.__keepalive__ = (entries, bufs)
    return result


def _empty_pcap_result():
    result = pcapreader.PcapResult()
    result.packets = ctypes.POINTER(pcapreader.PacketEntry)()
    result.count = 0
    return result

def test_pcapread_returns_header_and_packets(monkeypatch):
    fake_result = _make_pcap_result([b"\xaa\xbb", b"\xcc\xdd\xee"])

    monkeypatch.setattr(pcapreader.lib, "read_pcap_file", lambda fname: fake_result)
    monkeypatch.setattr(pcapreader.lib, "free_pcap_result", lambda *a, **k: None)

    header, packets = pcapreader.PcapRead("in.pcap")

    assert header[0]["magic"] == hex(0xA1B2C3D4)
    assert header[0]["snaplen"] == 65535
    assert header[0]["network"] == 1

    assert len(packets) == 2
    assert packets[0]["data"] == b"\xaa\xbb"
    assert packets[0]["incl_len"] == 2
    assert packets[0]["ts_sec"] == 1000
    assert packets[1]["data"] == b"\xcc\xdd\xee"
    assert packets[1]["ts_sec"] == 1001


def test_pcapread_empty_file_returns_empty_list(monkeypatch):
    fake_result = _empty_pcap_result()
    monkeypatch.setattr(pcapreader.lib, "read_pcap_file", lambda fname: fake_result)

    result = pcapreader.PcapRead("empty.pcap")
    assert result == []


def test_pcapread_encodes_filename_as_utf8(monkeypatch):
    captured = {}

    def fake_read(fname):
        captured["fname"] = fname
        return _empty_pcap_result()

    monkeypatch.setattr(pcapreader.lib, "read_pcap_file", fake_read)
    pcapreader.PcapRead("capture.pcap")
    assert captured["fname"] == b"capture.pcap"


def test_pcapread_frees_native_result_on_success(monkeypatch):
    freed = {"called": False}
    fake_result = _make_pcap_result([b"\x01"])

    def fake_free(ref):
        freed["called"] = True

    monkeypatch.setattr(pcapreader.lib, "read_pcap_file", lambda fname: fake_result)
    monkeypatch.setattr(pcapreader.lib, "free_pcap_result", fake_free)

    pcapreader.PcapRead("in.pcap")
    assert freed["called"] is True

def test_pcapreadstream_open_populates_header_and_packets(monkeypatch):
    fake_result = _make_pcap_result([b"\x11\x22"])
    monkeypatch.setattr(pcapreader.lib, "read_pcap_file", lambda fname: fake_result)
    monkeypatch.setattr(pcapreader.lib, "free_pcap_result", lambda *a, **k: None)

    stream = pcapreader.PcapReadStream("in.pcap").open()

    assert stream.header[0]["network"] == 1
    assert len(stream.packets) == 1
    assert stream.packets[0]["data"] == b"\x11\x22"


def test_pcapreadstream_empty_result_leaves_header_none(monkeypatch):
    fake_result = _empty_pcap_result()
    monkeypatch.setattr(pcapreader.lib, "read_pcap_file", lambda fname: fake_result)

    stream = pcapreader.PcapReadStream("empty.pcap").open()
    assert stream.header is None
    assert stream.packets == []


def test_pcapreadstream_getitem_index_0_returns_header_else_packets(monkeypatch):
    fake_result = _make_pcap_result([b"\x01", b"\x02"])
    monkeypatch.setattr(pcapreader.lib, "read_pcap_file", lambda fname: fake_result)
    monkeypatch.setattr(pcapreader.lib, "free_pcap_result", lambda *a, **k: None)

    stream = pcapreader.PcapReadStream("in.pcap").open()
    assert stream[0] == stream.header
    assert stream[1] == stream.packets
    assert stream[99] == stream.packets


def test_pcapreadstream_context_manager_opens_and_closes(monkeypatch):
    fake_result = _make_pcap_result([b"\x01"])
    freed = {"called": False}

    monkeypatch.setattr(pcapreader.lib, "read_pcap_file", lambda fname: fake_result)
    monkeypatch.setattr(pcapreader.lib, "free_pcap_result", lambda ref: freed.__setitem__("called", True))

    with pcapreader.PcapReadStream("in.pcap") as stream:
        assert len(stream.packets) == 1

    assert freed["called"] is True
    assert stream._result is None


def test_pcapreadstream_close_without_open_is_safe():
    stream = pcapreader.PcapReadStream("in.pcap")
    stream.close()
    assert stream._result is None