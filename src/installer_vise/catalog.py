"""Catalog (CVCT body) record parsing.

The decoded catalog body is a flat sequence of variable-length records,
each starting with a 4-byte signature:

* ``FVCT`` — file record: signature + 194-byte fixed body + name.
* ``DVCT`` — directory record: name is what extraction cares about.
* anything else — installer-script condition/action records; skipped.

``FVCT`` field meanings are **overloaded by mode** (plain vs shared-block
member); see :attr:`Record.is_shared` and ``docs/catalog-records.md``.
All multi-byte fields are big-endian; runtime offset = serialized + 24 for
the fields cross-checked against the installer code.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from .errors import ViseFormatError

__all__ = ["Catalog", "Record", "FileBlock", "parse_catalog"]

SIG_FILE = b"FVCT"
SIG_DIR = b"DVCT"

_FLAG_CONDITION = 0x08000000   # condition/action record, not a file
_FLAG_SHARED = 0x10000000      # member of a shared block

_FVCT_BODY = 194
_NAME_OFF = 0xC6


@dataclass(frozen=True)
class Record:
    """One FVCT file record (serialized layout, not runtime)."""

    catalog_offset: int        # offset of the signature within the catalog body
    flags: int
    file_type: str             # 4CC, MacRoman
    creator: str               # 4CC, MacRoman
    # sizes (meaning depends on is_shared — see module docstring)
    stored_d: int              # +68 plain: data stream | shared: block stream
    size_d: int                # +72 plain: expanded data | shared: data slice len
    stored_r: int              # +76 plain: rsrc stream  | shared: block expanded total
    size_r: int                # +80 plain: expanded rsrc | shared: rsrc slice len
    record_crc: int            # +84 CRC32(data || rsrc)
    crc_slot_b: int            # +88 (unnamed; NOT a resource CRC)
    source_index: int          # +96 hi16
    in_archive: bool           # +96 lo16 == 1 → stored in this file
    block_offset: int          # +100 stream/block offset in the archive
    slice_off_d: int           # +104 shared: data slice offset in expanded block
    slice_off_r: int           # +108 shared: rsrc slice offset
    name: str

    @property
    def is_shared(self) -> bool:
        return bool(self.flags & _FLAG_SHARED)

    @property
    def has_data(self) -> bool:
        return self.size_d > 0 if self.is_shared else self.stored_d > 0

    @property
    def has_rsrc(self) -> bool:
        return self.size_r > 0 if self.is_shared else self.stored_r > 0


@dataclass(frozen=True)
class FileBlock:
    """A shared block and its member records, in catalog order."""

    offset: int                # archive offset of the block stream
    stored: int                # stored size (members[0].stored_d)
    expanded: int              # expanded total (members[0].stored_r)
    members: tuple[Record, ...]


@dataclass(frozen=True)
class Catalog:
    """Parsed CVCT body."""

    files: tuple[Record, ...]
    directories: tuple[str, ...]
    skipped: int               # condition/action records

    @property
    def blocks(self) -> list[FileBlock]:
        """Shared blocks in archive order, each with ordered members."""
        groups: dict[int, list[Record]] = {}
        for rec in self.files:
            if rec.is_shared:
                groups.setdefault(rec.block_offset, []).append(rec)
        out = []
        for offset in sorted(groups):
            members = groups[offset]
            first = members[0]
            out.append(FileBlock(offset, first.stored_d, first.stored_r,
                                 tuple(members)))
        return out

    def by_name(self, name: str) -> list[Record]:
        return [r for r in self.files if r.name == name]


def _name_at(body: bytes, off: int) -> str:
    end = body.find(b"\0", off)
    if end < 0:
        end = len(body)
    return body[off:end].decode("mac-roman", "replace")


def parse_catalog(body: bytes) -> Catalog:
    """Parse a decoded CVCT body into a :class:`Catalog`."""
    files: list[Record] = []
    directories: list[str] = []
    skipped = 0

    sigs: list[tuple[int, bytes]] = []
    # Sequential signature scan (records are variable-length).
    pos = 0
    while pos < len(body) - 4:
        sig = body[pos:pos + 4]
        if sig in (SIG_FILE, SIG_DIR):
            sigs.append((pos, sig))
            pos += 4
        else:
            pos += 1

    if not sigs:
        raise ViseFormatError("no FVCT/DVCT records found in catalog body")

    for i, (p, sig) in enumerate(sigs):
        end = sigs[i + 1][0] if i + 1 < len(sigs) else len(body)
        rec = body[p:end]
        name = _name_at(rec, _NAME_OFF) if len(rec) > _NAME_OFF else ""
        if sig == SIG_DIR:
            directories.append(name)
            continue
        if len(rec) < 4 + _FVCT_BODY:
            skipped += 1
            continue
        body_ = rec[4:4 + _FVCT_BODY]
        flags, = struct.unpack_from(">I", body_, 12 - 4)
        if flags & _FLAG_CONDITION:
            skipped += 1
            continue
        ftype = body_[44 - 4:48 - 4].decode("mac-roman", "replace")
        creator = body_[48 - 4:52 - 4].decode("mac-roman", "replace")
        stored_d, = struct.unpack_from(">I", body_, 68 - 4)
        size_d, = struct.unpack_from(">I", body_, 72 - 4)
        stored_r, = struct.unpack_from(">I", body_, 76 - 4)
        size_r, = struct.unpack_from(">I", body_, 80 - 4)
        record_crc, = struct.unpack_from(">I", body_, 84 - 4)
        crc_slot_b, = struct.unpack_from(">I", body_, 88 - 4)
        src_raw, = struct.unpack_from(">I", body_, 96 - 4)
        block_offset, = struct.unpack_from(">I", body_, 100 - 4)
        slice_off_d, = struct.unpack_from(">I", body_, 104 - 4)
        slice_off_r, = struct.unpack_from(">I", body_, 108 - 4)
        files.append(Record(
            catalog_offset=p,
            flags=flags,
            file_type=ftype,
            creator=creator,
            stored_d=stored_d,
            size_d=size_d,
            stored_r=stored_r,
            size_r=size_r,
            record_crc=record_crc,
            crc_slot_b=crc_slot_b,
            source_index=src_raw >> 16,
            in_archive=bool(src_raw & 1),
            block_offset=block_offset,
            slice_off_d=slice_off_d,
            slice_off_r=slice_off_r,
            name=name,
        ))

    return Catalog(files=tuple(files), directories=tuple(directories),
                   skipped=skipped)
