"""Unit tests for catalog record parsing."""

from __future__ import annotations

import struct

import pytest

from installer_vise.catalog import parse_catalog
from installer_vise.errors import ViseFormatError


def _fvct(name: str, *, flags: int = 0x601, **fields: int) -> bytes:
    body = bytearray(194)
    struct.pack_into(">I", body, 8, flags)
    for off, val in fields.items():
        struct.pack_into(">I", body, int(off) - 4, val)
    nb = name.encode() + b"\0"
    body[0xC2:0xC2 + len(nb)] = nb
    return b"FVCT" + bytes(body)


def test_parses_single_file_record():
    body = _fvct("hello.txt",
                 flags=0x601,
                 **{"68": 16, "72": 32, "96": 0x00030001,
                    "100": 0x1234, "84": 0xDEADBEEF})
    cat = parse_catalog(body)
    assert len(cat.files) == 1
    rec = cat.files[0]
    assert rec.name == "hello.txt"
    assert rec.stored_d == 16
    assert rec.size_d == 32
    assert rec.block_offset == 0x1234
    assert rec.record_crc == 0xDEADBEEF
    assert not rec.is_shared
    assert rec.in_archive


def test_shared_flag_detected():
    body = _fvct("shared.bin", flags=0x10000601)
    rec = parse_catalog(body).files[0]
    assert rec.is_shared


def test_in_archive_flag_from_lo16():
    body = _fvct("far.bin", **{"96": 0x00030000})
    rec = parse_catalog(body).files[0]
    assert rec.source_index == 3
    assert rec.in_archive is False


def test_condition_record_skipped():
    body = _fvct("real.bin", **{"68": 4}) + _fvct("cond", flags=0x08000601)
    cat = parse_catalog(body)
    assert len(cat.files) == 1
    assert cat.skipped == 1


def test_directories_collected():
    dbody = bytearray(194)
    nb = b"Folder\0"
    dbody[0xC2:0xC2 + len(nb)] = nb
    cat = parse_catalog(_fvct("f.bin") + b"DVCT" + bytes(dbody))
    assert cat.directories == ("Folder",)
    assert len(cat.files) == 1


def test_blocks_grouping_order():
    body = (
        _fvct("m0", flags=0x10000601, **{"68": 10, "100": 0x5000, "104": 0})
        + _fvct("m1", flags=0x10000601, **{"68": 10, "100": 0x5000, "104": 5})
        + _fvct("m2", flags=0x10000601, **{"68": 20, "100": 0x6000, "104": 0})
    )
    cat = parse_catalog(body)
    blocks = cat.blocks
    assert [b.offset for b in blocks] == [0x5000, 0x6000]
    assert [m.name for m in blocks[0].members] == ["m0", "m1"]
    assert blocks[0].stored == 10 and blocks[0].expanded == 0


def test_no_records_raises():
    with pytest.raises(ViseFormatError):
        parse_catalog(b"\x00" * 64)
