"""Byte-substitution layer applied to file payloads before VISE DEFLATE.

Reverse-engineered from the main installer PEF of the reference archive
(``sub_444A8`` / ``byte_6B4A8``, TOC base ``0x67910``):

    out[i] = TABLE[in[i]]

The table is a fixed 256-byte permutation, stateless, identical for every
payload block.  The catalog (CVCT) and script streams are *not*
substituted — only the file-payload region is.

Decode direction (what an extractor needs):  plain = subst(stored_bytes).
To *produce* substituted bytes from plain bytes, use
:func:`invert_table` — see the test-suite's synthetic archive builder.

Validated against the reference archive: with this table, all 62 shared
blocks and all 64 plain records decode to exact expected sizes and CRCs
(1288/1288 files verified).

Reference hex dump (512 chars, first byte maps input 0x00):

    6ab736ec15d9c873e8389adf2125d0cc
    fddc16d7e34305c58f48daf23f10236c
    777cf9a0a3e9ed468bd8ac54ce2d195e
    6d7d875dfa5b9be0c7ee9f52a9b90ad1
    fe78764a3d445a96901f269d581b8e57
    59c30b6bfc1de6a27f924f40b406724d
    f434aad249adef221ab5babf29688993
    3e3204f5dee16ffb67e47e08aff0ab41
    82ea500f2ac635b3a8cae54c458a97ae
    d6662753c91c3c0399c1092e69378d2f
    60c2a6184e7ab8cfa73a17d59ef18451
    0da464c41eb13098bb7901f6620eb263
    91cbff8071e7d400db752cbd393394bc
    8c3bb6208524882b70836e7b9cbe1447
    654b5681f8121128eb5574a131f7b013
    86dd5f42d30261950c5ca5cdc007e2f3
"""

from __future__ import annotations

TABLE = bytes.fromhex(
    "6ab736ec15d9c873e8389adf2125d0cc"
    "fddc16d7e34305c58f48daf23f10236c"
    "777cf9a0a3e9ed468bd8ac54ce2d195e"
    "6d7d875dfa5b9be0c7ee9f52a9b90ad1"
    "fe78764a3d445a96901f269d581b8e57"
    "59c30b6bfc1de6a27f924f40b406724d"
    "f434aad249adef221ab5babf29688993"
    "3e3204f5dee16ffb67e47e08aff0ab41"
    "82ea500f2ac635b3a8cae54c458a97ae"
    "d6662753c91c3c0399c1092e69378d2f"
    "60c2a6184e7ab8cfa73a17d59ef18451"
    "0da464c41eb13098bb7901f6620eb263"
    "91cbff8071e7d400db752cbd393394bc"
    "8c3bb6208524882b70836e7b9cbe1447"
    "654b5681f8121128eb5574a131f7b013"
    "86dd5f42d30261950c5ca5cdc007e2f3"
)

assert len(TABLE) == 256 and len(set(TABLE)) == 256, "TABLE must be a permutation"

#: Alias used by the public API (same object as :data:`TABLE`).
SUBST_TABLE = TABLE


def invert_table(table: bytes = TABLE) -> bytes:
    """Return the inverse of a 256-byte permutation table.

    ``invert_table(TABLE)`` maps plain -> stored, i.e. it produces the
    transform the installer's compressor applied before writing payload
    streams.
    """
    out = bytearray(256)
    for i, v in enumerate(table):
        out[v] = i
    return bytes(out)


def subst(data: bytes, table: bytes = TABLE) -> bytes:
    """Apply the substitution transform (decode direction by default)."""
    return data.translate(table)
