"""Tests for the byte-substitution layer."""

from __future__ import annotations

from installer_vise.subst import SUBST_TABLE, invert_table, subst


def test_table_is_permutation():
    assert len(SUBST_TABLE) == 256
    assert len(set(SUBST_TABLE)) == 256


def test_inverse_inverts():
    inv = invert_table()
    for b in range(256):
        assert inv[SUBST_TABLE[b]] == b
        assert SUBST_TABLE[inv[b]] == b


def test_subst_roundtrip():
    payload = bytes(range(256)) * 3
    assert subst(subst(payload, invert_table()), SUBST_TABLE) == payload


def test_known_anchor_values():
    # From the validated table: mapping of 0x00 and 0x01.
    assert SUBST_TABLE[0x00] == 0x6A
    assert SUBST_TABLE[0x01] == 0xB7
    # Raw payload bytes at the first reference block (0xDB6D4) start
    # 31 b3 a0 9a...; mapped through TABLE they must start 7d c4 60 09...
    raw = bytes([0x31, 0xB3, 0xA0, 0x9A])
    assert subst(raw) == bytes([0x7D, 0xC4, 0x60, 0x09])


def test_subst_is_translate_compatible():
    data = bytes(range(256))
    assert data.translate(SUBST_TABLE) == subst(data)
