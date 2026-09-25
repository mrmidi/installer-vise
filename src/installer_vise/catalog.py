"""Catalog (CVCT body) record parsing.

The decoded catalog body is a flat sequence of variable-length records,
each starting with a 4-byte signature:

* ``FVCT`` — file record: fixed body + variable-length name.
* ``DVCT`` — directory record: name is what extraction cares about.
* anything else — installer-script condition/action records; skipped.

Two layout profiles are currently known:

* **VISE3_LATE**: name at record offset 0xC6, fixed body 194 bytes
  (validated on Minolta DiMAGE Scan 1.1.5d).
* **VISE_EARLY**: name at record offset 0xBC, fixed body 184 bytes
  (validated on Cythera 1.0.4).

``FVCT`` field meanings are **overloaded by mode** (plain vs shared-block
member); see :attr:`Record.is_shared` and ``docs/catalog-records.md``.
All multi-byte fields are big-endian.

Field offsets in this module are relative to the record start (the FVCT
signature is at offset 0).
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
    crc_slot_b: int            # +88 (unknown; no runtime consumer)
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


def _name_at_late(body: bytes, off: int) -> str:
    """Extract NUL-terminated name (VISE3_LATE profile)."""
    end = body.find(b"\0", off)
    if end < 0:
        end = len(body)
    return body[off:end].decode("mac-roman", "replace")


def _name_at_early(body: bytes, off: int, rec_end: int) -> str:
    """Extract name with no NUL terminator (VISE_EARLY profile).

    The name runs from ``off`` to ``rec_end`` (the start of the next
    record).  Trailing non-printable bytes are stripped.
    """
    raw = body[off:rec_end]
    # Strip trailing bytes that are unlikely to be part of the name.
    end = len(raw)
    while end > 0 and raw[end - 1] < 0x20:
        end -= 1
    return raw[:end].decode("mac-roman", "replace")


def parse_catalog(body: bytes, *, name_offset: int = 0xC6) -> Catalog:
    """Parse a decoded CVCT body into a :class:`Catalog`.

    ``name_offset`` is the byte offset of the name from the FVCT
    signature (0xC6 for VISE3_LATE, 0xBC for VISE_EARLY).
    """
    files: list[Record] = []
    directories: list[str] = []
    skipped = 0

    is_early = (name_offset < 0xC6)

    sigs: list[tuple[int, bytes]] = []
    # Sequential signature scan (records are variable-length).
    # TODO: replace with structural sequential parsing — literal "FVCT"/"DVCT"
    # byte sequences inside a filename/metadata can produce false record
    # boundaries. Revisit once more archives are available to confirm the
    # real framing rule.
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
        rec_len = end - p

        if sig == SIG_DIR:
            if is_early:
                name = _name_at_early(body, p + name_offset, end)
            else:
                name = _name_at_late(rec, name_offset)
            directories.append(name)
            continue

        # Minimum FVCT: signature + fixed body up to slice_off_r (108+4=112).
        if rec_len < 112:
            skipped += 1
            continue

        # Fields are at fixed offsets from the record start.
        flags = struct.unpack_from(">I", rec, 12)[0]
        if flags & _FLAG_CONDITION:
            skipped += 1
            continue

        ftype = rec[44:48].decode("mac-roman", "replace")
        creator = rec[48:52].decode("mac-roman", "replace")
        stored_d, = struct.unpack_from(">I", rec, 68)
        size_d, = struct.unpack_from(">I", rec, 72)
        stored_r, = struct.unpack_from(">I", rec, 76)
        size_r, = struct.unpack_from(">I", rec, 80)
        record_crc, = struct.unpack_from(">I", rec, 84)
        crc_slot_b, = struct.unpack_from(">I", rec, 88)
        src_raw, = struct.unpack_from(">I", rec, 96)
        block_offset, = struct.unpack_from(">I", rec, 100)
        slice_off_d, = struct.unpack_from(">I", rec, 104)
        slice_off_r, = struct.unpack_from(">I", rec, 108)

        if is_early:
            name = _name_at_early(body, p + name_offset, end)
        else:
            name = _name_at_late(rec, name_offset)

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
