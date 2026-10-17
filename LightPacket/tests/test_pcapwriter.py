# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.Saving.pcapwriter (create_pcap, PcapWrite, PcapWriteStream).
"""
import pytest

pcapwriter = pytest.importorskip("LightPacket.Saving.pcapwriter")


def test_create_pcap_single_bytes_wraps_in_list():
    arr, count = pcapwriter.create_pcap(b"\x01\x02\x03")
    assert count == 1
    assert arr[0].data_length == 3
    assert bytes(arr[0].payload[:3]) == b"\x01\x02\x03"


def test_create_pcap_list_of_packets_preserves_order_and_lengths():
    arr, count = pcapwriter.create_pcap([b"a", b"bb", b"ccc"])
    assert count == 3
    assert [arr[i].data_length for i in range(3)] == [1, 2, 3]
    assert bytes(arr[1].payload[:2]) == b"bb"
    assert bytes(arr[2].payload[:3]) == b"ccc"


def test_create_pcap_empty_list_gives_zero_count():
    arr, count = pcapwriter.create_pcap([])
    assert count == 0

def test_pcapwrite_calls_native_with_correct_args(monkeypatch):
    captured = {}

    def fake_create(filename, packetarr, totalpackets, linktype):
        captured["filename"] = filename
        captured["count"] = totalpackets
        captured["linktype"] = linktype
        return 0

    monkeypatch.setattr(pcapwriter.lib, "create_pcap_file", fake_create)

    rc = pcapwriter.PcapWrite([b"\x01", b"\x02"], "out.pcap")
    assert rc == 0
    assert captured["filename"] == b"out.pcap"
    assert captured["count"] == 2
    assert captured["linktype"] == pcapwriter.PCAP_LINKTYPE_ETHERNET


def test_pcapwrite_custom_linktype_passed_through(monkeypatch):
    captured = {}

    def fake_create(filename, packetarr, totalpackets, linktype):
        captured["linktype"] = linktype
        return 0

    monkeypatch.setattr(pcapwriter.lib, "create_pcap_file", fake_create)
    pcapwriter.PcapWrite(b"\x01", "out.pcap", linktype=pcapwriter.PCAP_LINKTYPE_IEEE802_11)
    assert captured["linktype"] == pcapwriter.PCAP_LINKTYPE_IEEE802_11


def test_pcapwrite_propagates_native_return_code(monkeypatch):
    monkeypatch.setattr(pcapwriter.lib, "create_pcap_file", lambda *a, **k: -5)
    rc = pcapwriter.PcapWrite(b"\x01", "out.pcap")
    assert rc == -5

def test_pcapwritestream_requires_linktype():
    with pytest.raises(ValueError):
        pcapwriter.PcapWriteStream("out.pcap", linktype=None)


def test_pcapwritestream_write_accumulates_count(monkeypatch):
    monkeypatch.setattr(pcapwriter.lib, "create_pcap_file", lambda *a, **k: 0)

    stream = pcapwriter.PcapWriteStream("out.pcap")
    stream.write([b"a", b"b"])
    stream.write_one(b"c")
    assert len(stream) == 3


def test_pcapwritestream_empty_packets_is_noop(monkeypatch):
    called = {"n": 0}

    def fake_create(*a, **k):
        called["n"] += 1
        return 0

    monkeypatch.setattr(pcapwriter.lib, "create_pcap_file", fake_create)
    stream = pcapwriter.PcapWriteStream("out.pcap")
    assert stream.write([]) is True
    assert called["n"] == 0


def test_pcapwritestream_raises_ioerror_on_native_failure(monkeypatch):
    monkeypatch.setattr(pcapwriter.lib, "create_pcap_file", lambda *a, **k: 3)
    stream = pcapwriter.PcapWriteStream("out.pcap")
    with pytest.raises(IOError):
        stream.write(b"\x01")


def test_pcapwritestream_write_after_close_raises(monkeypatch):
    monkeypatch.setattr(pcapwriter.lib, "create_pcap_file", lambda *a, **k: 0)
    stream = pcapwriter.PcapWriteStream("out.pcap")
    stream.close()
    with pytest.raises(RuntimeError):
        stream.write(b"\x01")


def test_pcapwritestream_context_manager_closes(monkeypatch):
    monkeypatch.setattr(pcapwriter.lib, "create_pcap_file", lambda *a, **k: 0)
    with pcapwriter.PcapWriteStream("out.pcap") as s:
        s.write(b"\x01")
    assert s._closed is True


def test_pcapwritestream_repr_reflects_state(monkeypatch):
    monkeypatch.setattr(pcapwriter.lib, "create_pcap_file", lambda *a, **k: 0)
    stream = pcapwriter.PcapWriteStream("out.pcap", linktype=pcapwriter.PCAP_LINKTYPE_PPP)
    assert "open" in repr(stream)
    assert f"linktype={pcapwriter.PCAP_LINKTYPE_PPP}" in repr(stream)
    stream.write(b"\x01")
    assert "written=1" in repr(stream)
    stream.close()
    assert "closed" in repr(stream)


@pytest.mark.parametrize("linktype", [
    pcapwriter.PCAP_LINKTYPE_ETHERNET,
    pcapwriter.PCAP_LINKTYPE_PPP,
    pcapwriter.PCAP_LINKTYPE_IEEE802_11,
    pcapwriter.PCAP_LINKTYPE_RAW,
])
def test_pcapwritestream_accepts_all_known_linktypes(monkeypatch, linktype):
    monkeypatch.setattr(pcapwriter.lib, "create_pcap_file", lambda *a, **k: 0)
    stream = pcapwriter.PcapWriteStream("out.pcap", linktype=linktype)
    assert stream.linktype == linktype