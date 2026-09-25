"""Tests for the VISE word-aligned DEFLATE codec."""

from __future__ import annotations

import os

import pytest

from installer_vise.deflate import (
    InflateError,
    deflate_stored,
    inflate,
    inflate_span,
)

SIZES = [0, 1, 2, 3, 7, 8, 15, 16, 17, 255, 256, 257, 1000, 4096, 65535]


@pytest.mark.parametrize("n", SIZES)
def test_stored_roundtrip(n):
    payload = os.urandom(n)
    stream = deflate_stored(payload)
    out, consumed = inflate_span(stream)
    assert out == payload
    assert consumed == len(stream)


def test_stored_stream_is_word_aligned():
    stream = deflate_stored(b"odd length!")   # 10 bytes payload, even total
    assert len(stream) % 2 == 0
    out, _ = inflate_span(stream)
    assert out == b"odd length!"


def test_stored_odd_len_consumes_pad_byte():
    stream = deflate_stored(b"abc")           # odd LEN -> one pad byte
    assert len(stream) == 2 + 4 + 3 + 1
    out, consumed = inflate_span(stream)
    assert out == b"abc"
    assert consumed == len(stream)


def test_consumed_is_even():
    stream = deflate_stored(b"x" * 11)
    _, consumed = inflate_span(stream)
    assert consumed % 2 == 0


def test_two_streams_back_to_back():
    a = deflate_stored(b"first")
    b = deflate_stored(b"second")
    blob = a + b
    out1, end1 = inflate_span(blob)
    out2, end2 = inflate_span(blob, end1)
    assert out1 == b"first" and out2 == b"second"
    assert end2 == len(blob)


def test_rejects_fixed_huffman():
    # BFINAL=1, BTYPE=01 (fixed) -> the Dcmp rejects this with error -9.
    stream = bytes([0x00, 0x03, 0x00, 0x00, 0x00, 0x00])
    with pytest.raises(InflateError):
        inflate(stream)


def test_rejects_bad_stored_nlen():
    stream = deflate_stored(b"hello")[:4] + b"\xff\xff" + deflate_stored(b"hello")[6:]
    with pytest.raises(InflateError):
        inflate(stream)


def test_odd_offset_rejected():
    with pytest.raises(InflateError):
        inflate_span(b"\x00\x01\x00\x00", offset=1)


def test_max_out_bound():
    stream = deflate_stored(b"A" * 100)
    out, _ = inflate_span(stream, max_out=10)
    assert out == b"A" * 10
