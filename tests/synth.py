"""Synthetic Installer VISE archive builder for the test suite.

Encodes payload streams with :func:`installer_vise.deflate.deflate_stored`
(valid VISE DEFLATE; the real compressor emits dynamic blocks, but both
decode identically) and pre-applies the inverse substitution so the archive
mimics the real pipeline.  Assembles a structurally faithful container:

    SVCT (44B) | PEF magic (opt) | payload | CVCT (20B) | PACK (0x50B) | stream

The catalog body itself is encoded with :func:`deflate_stored` — plain
VISE DEFLATE, no substitution, exactly like the real container.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

from installer_vise.deflate import deflate_stored
from installer_vise.subst import invert_table

_INVERSE = invert_table()

_SVCT_SIZE = 0x2C
_CVCT_HEADER = 0x14
_PACK_HEADER = 0x50
_FVCT_BODY = 194


@dataclass
class Fork:
    data: bytes = b""
    rsrc: bytes = b""


@dataclass
class Rec:
    name: str
    fork: Fork
    shared: bool
    file_type: bytes = b"TEXT"
    creator: bytes = b"ttxt"
    in_archive: bool = True
    source: int = 1
    crc: int | None = None   # override to forge a bad record CRC


@dataclass
class _Stream:
    """One encoded payload stream (shared block or plain record)."""

    members: list[Rec] = field(default_factory=list)   # shared only
    plain: Rec | None = None
    offset: int = 0
    stored: int = 0
    expanded: int = 0
    stream: bytes = b""


def build_archive(records: list[Rec], *, with_pef: bool = True) -> bytes:
    """Build a complete archive bytes-object from logical records."""
    streams: list[_Stream] = []

    # group consecutive shared records into one block each
    pending: list[Rec] = []
    for rec in records:
        if rec.shared:
            pending.append(rec)
        else:
            if pending:
                streams.append(_Stream(members=pending))
                pending = []
            streams.append(_Stream(plain=rec))
    if pending:
        streams.append(_Stream(members=pending))

    # encode payloads
    for s in streams:
        if s.members:
            pool = bytearray()
            for m in s.members:
                pool += m.fork.data
                pool += m.fork.rsrc
            s.expanded = len(pool)
        else:
            rec = s.plain
            assert rec is not None
            s.expanded = 0   # plain records store two independent streams
        # Encode stored streams the real way: DEFLATE the plain bytes,
        # then apply the inverse substitution to the *stream bytes*
        # (decode direction is: archive bytes -> TABLE -> inflate).
        if s.members:
            s.stream = deflate_stored(pool).translate(_INVERSE)
            s.stored = len(s.stream)
        else:
            rec = s.plain
            d_stream = deflate_stored(rec.fork.data).translate(_INVERSE)
            r_stream = (deflate_stored(rec.fork.rsrc).translate(_INVERSE)
                        if rec.fork.rsrc else b"")
            s.stream = d_stream + r_stream
            s.stored = len(d_stream)        # data stream size (d_fork boundary)
            s._stored_r = len(r_stream)     # type: ignore[attr-defined]

    # lay out the payload (after SVCT, and after the PEF magic when present:
    # PEF magic "Joy!peffpwpc" occupies 0x30..0x3C)
    payload_start = 0x3C if with_pef else _SVCT_SIZE
    off = payload_start
    for s in streams:
        s.offset = off
        off += s.stored if s.members else (s.stored + s._stored_r)  # type: ignore[attr-defined]
    payload_end = off

    # catalog body
    cat = bytearray()
    for s in streams:
        if s.members:
            cursor = 0
            for m in s.members:
                cat += _fvct_shared(m, s, cursor)
                cursor += len(m.fork.data) + len(m.fork.rsrc)
        else:
            cat += _fvct_plain(s)
    for d in ("Applications", "Documentation"):
        cat += _dvct(d)
    cat += _fvct_condition()               # condition record to skip

    # assemble
    catalog_offset = payload_end
    cat_stream = deflate_stored(bytes(cat))
    pack_off = catalog_offset + _CVCT_HEADER
    total = pack_off + _PACK_HEADER + len(cat_stream)

    out = bytearray(total)
    out[0:4] = b"SVCT"
    struct.pack_into(">I", out, 0x1C, payload_start)
    struct.pack_into(">I", out, 0x24, catalog_offset)
    if with_pef:
        out[0x30:0x3C] = b"Joy!peffpwpc"
    # payload (s.offset is an absolute file offset)
    for s in streams:
        out[s.offset:s.offset + len(s.stream)] = s.stream
    # CVCT header: +4 is the compressed stream span, not the decoded size.
    out[catalog_offset:catalog_offset + 4] = b"CVCT"
    struct.pack_into(">I", out, catalog_offset + 4, len(cat_stream))
    # PACK header
    out[pack_off:pack_off + 4] = b"PACK"
    out[pack_off + 4:pack_off + 8] = b"BBrd"
    struct.pack_into(">I", out, pack_off + 0x1C, len(cat_stream))
    struct.pack_into(">I", out, pack_off + 0x20, len(streams))
    out[pack_off + _PACK_HEADER:] = cat_stream
    return bytes(out)


# ---------------------------------------------------------------- records --

def _fvct_shared(rec: Rec, s: _Stream, cursor: int) -> bytes:
    body = bytearray(_FVCT_BODY)
    struct.pack_into(">I", body, 12 - 4, 0x10000601)
    body[44 - 4:48 - 4] = rec.file_type
    body[48 - 4:52 - 4] = rec.creator
    struct.pack_into(">I", body, 68 - 4, s.stored)
    struct.pack_into(">I", body, 72 - 4, len(rec.fork.data))
    struct.pack_into(">I", body, 76 - 4, s.expanded)
    struct.pack_into(">I", body, 80 - 4, len(rec.fork.rsrc))
    struct.pack_into(">I", body, 84 - 4,
                     rec.crc if rec.crc is not None else _crc(rec.fork.data + rec.fork.rsrc))
    struct.pack_into(">I", body, 96 - 4, (rec.source << 16) | int(rec.in_archive))
    struct.pack_into(">I", body, 100 - 4, s.offset)
    struct.pack_into(">I", body, 104 - 4, cursor)
    struct.pack_into(">I", body, 108 - 4, cursor + len(rec.fork.data))
    _put_name(body, rec.name)
    return b"FVCT" + bytes(body)


def _fvct_plain(s: _Stream) -> bytes:
    rec = s.plain
    assert rec is not None
    body = bytearray(_FVCT_BODY)
    struct.pack_into(">I", body, 12 - 4, 0x601)
    body[44 - 4:48 - 4] = rec.file_type
    body[48 - 4:52 - 4] = rec.creator
    struct.pack_into(">I", body, 68 - 4, s.stored)                # stored_d
    struct.pack_into(">I", body, 72 - 4, len(rec.fork.data))      # size_d
    struct.pack_into(">I", body, 76 - 4, s._stored_r)             # stored_r  (type: ignore[attr-defined])
    struct.pack_into(">I", body, 80 - 4, len(rec.fork.rsrc))      # size_r
    struct.pack_into(">I", body, 84 - 4,
                     rec.crc if rec.crc is not None else _crc(rec.fork.data + rec.fork.rsrc))
    struct.pack_into(">I", body, 96 - 4, (rec.source << 16) | int(rec.in_archive))
    struct.pack_into(">I", body, 100 - 4, s.offset)
    _put_name(body, rec.name)
    return b"FVCT" + bytes(body)


def _dvct(name: str) -> bytes:
    body = bytearray(_FVCT_BODY)
    _put_name(body, name)
    return b"DVCT" + bytes(body)


def _fvct_condition() -> bytes:
    """A condition/action record: FVCT signature with flag bit31 set."""
    body = bytearray(_FVCT_BODY)
    struct.pack_into(">I", body, 12 - 4, 0x08000601)
    _put_name(body, "if.version < 8")
    return b"FVCT" + bytes(body)


def _put_name(body: bytearray, name: str) -> None:
    nb = name.encode("mac-roman") + b"\x00"
    body[0xC6 - 4:0xC6 - 4 + len(nb)] = nb


def _crc(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF
