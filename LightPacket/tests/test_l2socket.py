# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Integration tests for L2Socket (Linux/BSD/macOS libpcap path and Windows Npcap path).

These tests require:
  - root / Administrator privileges (raw sockets need it)
  - a real network interface named "lo" (Linux/BSD) or the Npcap loopback
  - the platform-appropriate libpcap / Npcap installed

They are marked `integration` and skipped by default in CI. Run manually:

    sudo pytest -m integration tests/integration/test_l2socket.py -v
"""

import os
import sys
import time

import pytest

def _is_root() -> bool:
    if sys.platform == "win32":
        return True
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _has_iface(name: str) -> bool:
    """Check the interface exists without needing root."""
    try:
        import socket
        if sys.platform == "win32":
            return True
        socket.if_nametoindex(name)
        return True
    except (OSError, AttributeError):
        return False


needs_root = pytest.mark.skipif(not _is_root(), reason="requires root/Administrator")
needs_loopback = pytest.mark.skipif(
    sys.platform != "win32" and not _has_iface("lo"),
    reason="requires loopback interface 'lo' (Linux/BSD/macOS)",
)


def _load_socket_class():
    """Import the platform-appropriate L2Socket, or skip if unavailable."""
    if sys.platform == "win32":
        try:
            from LightPacket.Layers.L2Socket import L2Socket
            return L2Socket
        except Exception as e:
            pytest.skip(f"Windows Npcap L2Socket unavailable: {e}")
    else:
        try:
            from LightPacket.Layers.L2SocketL import L2Socket
            return L2Socket
        except Exception as e:
            pytest.skip(f"libpcap L2Socket unavailable: {e}")


def _loopback_iface():
    if sys.platform == "win32":
        # Npcap exposes loopback as \\Device\\NPF_Loopback
        return r"\Device\NPF_Loopback"
    return "lo"

@pytest.fixture
def sock():
    """An open L2Socket on the loopback interface, closed after the test."""
    cls = _load_socket_class()
    s = cls(iface=_loopback_iface(), promisc=False)
    try:
        yield s
    finally:
        s.close()


@needs_root
def test_constructs_on_loopback():
    cls = _load_socket_class()
    s = cls(iface=_loopback_iface(), promisc=False)
    try:
        assert s.pcap is not None
        assert not s.closed
    finally:
        s.close()


@needs_root
def test_datalink_returns_int(sock):
    dl = sock.datalink()
    assert isinstance(dl, int)
    assert dl >= 0


@needs_root
def test_context_manager_closes():
    cls = _load_socket_class()
    with cls(iface=_loopback_iface(), promisc=False) as s:
        assert not s.closed
    assert s.closed

@needs_root
@needs_loopback
def test_recv_one_honors_short_timeout(sock):

    t0 = time.monotonic()
    pkt = sock.recv_one(timeout=0.3)
    dt = time.monotonic() - t0
    assert dt < 0.8, f"recv_one(0.3) took {dt:.3f}s — timeout is not honored"
    assert pkt is None or isinstance(pkt, bytes)


@needs_root
@needs_loopback
@pytest.mark.parametrize("timeout", [0.1, 0.25, 0.5])
def test_recv_one_timeout_scales(sock, timeout):
    t0 = time.monotonic()
    sock.recv_one(timeout=timeout)
    dt = time.monotonic() - t0
    assert dt < timeout * 2.0 + 0.2, (
        f"recv_one({timeout}) took {dt:.3f}s — expected ≈ {timeout}s"
    )


@needs_root
def test_recv_one_on_closed_socket_raises():
    cls = _load_socket_class()
    s = cls(iface=_loopback_iface(), promisc=False)
    s.close()
    with pytest.raises(RuntimeError):
        s.recv_one(timeout=0.1)


@needs_root
def test_sendl2_on_closed_socket_raises():
    cls = _load_socket_class()
    s = cls(iface=_loopback_iface(), promisc=False)
    s.close()
    with pytest.raises(RuntimeError):
        s.sendl2(b"\x00" * 14)


@needs_root
def test_double_close_is_safe():
    cls = _load_socket_class()
    s = cls(iface=_loopback_iface(), promisc=False)
    s.close()
    s.close()
    assert s.closed

@needs_root
def test_destructor_without_close_does_not_crash():
    cls = _load_socket_class()
    s = cls(iface=_loopback_iface(), promisc=False)
    del s
    import gc
    gc.collect()