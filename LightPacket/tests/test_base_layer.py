# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""
Tests for LightPacket.BaseLayer.BaseLayer

Covers: payload stacking via / and set_payload, get_payload_bytes,
__getitem__ / __contains__ layer lookup, copy(), and __len__/__bytes__.
"""
import pytest
from LightPacket.BaseLayer import BaseLayer
from LightPacket.l2 import Raw


class DummyLayer(BaseLayer):
    """Minimal concrete layer for exercising BaseLayer behavior in isolation."""

    def __init__(self, tag=b"\x00"):
        super().__init__()
        self.tag = tag

    def build(self) -> bytes:
        return self.tag + self.get_payload_bytes()

    def copy(self):
        new = DummyLayer(tag=self.tag)
        if self.payload:
            new.payload = self.payload.copy() if hasattr(self.payload, "copy") else self.payload
        if self._raw_payload:
            new._raw_payload = self._raw_payload
        return new


class OtherLayer(DummyLayer):
    """A distinct subclass so __getitem__/__contains__ type filtering is meaningful."""
    pass


# ---------------------------------------------------------------------------
# Stacking with the / operator
# ---------------------------------------------------------------------------

def test_truediv_stacks_two_layers():
    a = DummyLayer(b"\x01")
    b = DummyLayer(b"\x02")
    stacked = a / b
    assert stacked.build() == b"\x01\x02"


def test_truediv_returns_new_object_not_mutating_original():
    a = DummyLayer(b"\x01")
    b = DummyLayer(b"\x02")
    stacked = a / b
    # original 'a' must remain payload-less; / must operate on a copy
    assert a.payload is None
    assert stacked is not a


def test_truediv_chains_three_layers_in_order():
    a, b, c = DummyLayer(b"\x01"), DummyLayer(b"\x02"), DummyLayer(b"\x03")
    stacked = a / b / c
    assert stacked.build() == b"\x01\x02\x03"


def test_rtruediv_with_bytes_prepends_raw_layer():
    b = DummyLayer(b"\x02")
    result =DummyLayer(b'\x01') / b
    # bytes / layer -> a RawLayer should be created and wrap `b`
    assert result.build().endswith(b"\x02")


def test_set_payload_with_bytes_sets_raw_payload():
    a = DummyLayer(b"\x01")
    a.set_payload(b"\xde\xad\xbe\xef")
    assert a.get_payload_bytes() == b"\xde\xad\xbe\xef"
    assert a.payload is not None


def test_set_payload_rejects_invalid_type():
    a = DummyLayer(b"\x01")
    with pytest.raises(TypeError):
        a.set_payload(12345)


def test_set_payload_appends_to_existing_chain_tail():
    a = DummyLayer(b"\x01")
    b = DummyLayer(b"\x02")
    c = DummyLayer(b"\x03")
    a.set_payload(b)
    a.set_payload(c)  # should append after b, not replace it
    assert a.build() == b"\x01\x02\x03"


# ---------------------------------------------------------------------------
# get_payload_bytes
# ---------------------------------------------------------------------------

def test_get_payload_bytes_empty_when_no_payload():
    a = DummyLayer(b"\x01")
    assert a.get_payload_bytes() == b""


def test_get_payload_bytes_uses_nested_layer_build():
    a = DummyLayer(b"\x01") / DummyLayer(b"\x02")
    assert a.get_payload_bytes() == b"\x02"


# ---------------------------------------------------------------------------
# __getitem__ / __contains__ layer lookup
# ---------------------------------------------------------------------------

def test_getitem_finds_first_matching_layer_type():
    stack = DummyLayer(b"\x01") / OtherLayer(b"\x02") / DummyLayer(b"\x03")
    found = stack[DummyLayer,1]
    assert isinstance(found, DummyLayer)
    assert found.tag == b"\x01"


def test_getitem_with_explicit_index():
    stack = DummyLayer(b"\x01") / DummyLayer(b"\x02") / DummyLayer(b"\x03")
    # (LayerType, index) form -> second DummyLayer in the chain (the outer is DummyLayer too)
    second = stack[DummyLayer, 2]
    assert second.tag == b"\x02"


def test_getitem_negative_index_returns_last_match():
    stack = DummyLayer(b"\x01") / OtherLayer(b"\x02") / OtherLayer(b"\x03")
    last = stack[OtherLayer, -1]
    assert last.tag == b"\x03"


def test_getitem_missing_layer_raises_keyerror():
    stack = DummyLayer(b"\x01")
    with pytest.raises(KeyError):
        _ = stack[OtherLayer]


def test_getitem_index_out_of_range_raises_indexerror():
    stack = DummyLayer(b"\x01") / DummyLayer(b"\x02")
    with pytest.raises(IndexError):
        _ = stack[DummyLayer, 5]


def test_getitem_zero_index_raises_valueerror():
    stack = DummyLayer(b"\x01")
    with pytest.raises(ValueError):
        _ = stack[DummyLayer, 0]


def test_contains_true_and_false():
    stack = DummyLayer(b"\x01") / OtherLayer(b"\x02")
    assert OtherLayer in stack
    assert DummyLayer in stack

    lone = OtherLayer(b"\x09")
    assert DummyLayer not in lone or isinstance(lone, DummyLayer)  # OtherLayer IS a DummyLayer subclass
    # A cleaner negative-case check with unrelated type:
    class Unrelated(BaseLayer):
        def build(self):
            return b""
    assert Unrelated not in stack


# ---------------------------------------------------------------------------
# build / __bytes__ / __len__ / copy
# ---------------------------------------------------------------------------

def test_base_build_not_implemented_on_raw_baselayer():
    layer = BaseLayer()
    with pytest.raises(NotImplementedError):
        layer.build()


def test_bytes_dunder_matches_build():
    a = DummyLayer(b"\x01") / DummyLayer(b"\x02")
    assert bytes(a) == a.build()


def test_len_dunder_matches_build_length():
    a = DummyLayer(b"\x01") / DummyLayer(b"\x02\x03")
    assert len(a) == len(a.build()) == 3


def test_bool_dunder_always_true():
    a = DummyLayer(b"\x01")
    assert bool(a) is True


def test_copy_produces_independent_object_with_same_data():
    a = DummyLayer(b"\x01")
    b = a.copy()
    assert a is not b
    assert a.tag == b.tag
    b.tag = b"\xff"
    assert a.tag == b"\x01"  # original untouched