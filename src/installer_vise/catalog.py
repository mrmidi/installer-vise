"""Catalog (CVCT body) record parsing.

The decoded catalog body is a flat sequence of variable-length records,
each starting with a 4-byte signature:

* ``FVCT`` — file record: fixed core body + variable-length name.
* ``DVCT`` — directory record: name is what extraction cares about.
* anything else — installer-script condition/action records; skipped.

**Name offset detection.**

The name offset is not hardcoded per archive. Instead, it is derived from
the catalog itself:

1. Record offset ``+0x7A`` contains the filename length as a single byte
   (independently corroborated by old VCT notes describing a "one-byte
   name length" at exactly this position).
2. Given length ``n``, the name is located by:
   * For NUL-terminated catalogs (DEFLATE-compressed): scanning the tail
     for a NUL byte and checking that the preceding ``n`` bytes form a
     valid MacRoman filename.
   * For raw catalogs (Cythera-style): ``name_start = record_end - n``.
3. The modal name-start offset across all genuine FVCT records is used
   for the archive.

This handles the known name offsets (0xBA, 0xBE, 0xC6) without
archive profiling, and should adapt to new layouts automatically.

``FVCT`` field meanings are **overloaded by mode** (plain vs shared-block
member); see :attr:`Record.is_shared` and ``docs/catalog-records.md``.
All multi-byte fields are big-endian.

Field offsets in this module are relative to the record start (the FVCT
signature is at offset 0).
"""

from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass

from .errors import ViseFormatError

__all__ = ["Catalog", "Record", "FileBlock", "parse_catalog"]

SIG_FILE = b"FVCT"
SIG_DIR = b"DVCT"

_FLAG_CONDITION = 0x08000000   # condition/action record, not a file
_FLAG_SHARED = 0x10000000      # member of a shared block

_NAME_LENGTH_OFF = 0x7A        # record offset of the 1-byte filename length


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


def _is_printable_macroman(data: bytes) -> bool:
    """Check if bytes look like a reasonable MacRoman filename."""
    if not data:
        return False
    # Allow high bytes (MacRoman extended), spaces, dots, punctuation.
    # Reject all control characters including NUL.
    return all(b >= 32 for b in data)


def _find_name_at_offset(rec: bytes, start: int, length: int) -> str | None:
    """Try to extract a filename of `length` bytes starting at `start`."""
    if start < 0 or start + length > len(rec):
        return None
    raw = rec[start:start + length]
    if not _is_printable_macroman(raw):
        return None
    return raw.decode("mac-roman", "replace")


def _plausible_name(name: str) -> bool:
    """Check if an extracted name looks like a real filename."""
    if not name or len(name) > 100:
        return False
    # Reject names containing record signatures (indicates false positive).
    if b"FVCT" in name.encode("mac-roman", "ignore"):
        return False
    if b"DVCT" in name.encode("mac-roman", "ignore"):
        return False
    # Reject names that are mostly non-ASCII (likely binary).
    ascii_count = sum(1 for c in name if ord(c) < 128)
    return not ascii_count < len(name) * 0.5


def _detect_name_offset(sigs: list[tuple[int, bytes]], body: bytes,
                        is_raw_catalog: bool) -> int:
    """Derive the FVCT name-start offset from the catalog itself.

    Uses the filename length at record offset 0x7A and validates candidate
    positions against the data. Tries both NUL-terminated and record-
    boundary-terminated name layouts.
    """
    # Histogram of start_offset → count.
    candidates: Counter[int] = Counter()

    for i, (pos, sig) in enumerate(sigs):
        if sig != SIG_FILE:
            continue
        end = sigs[i + 1][0] if i + 1 < len(sigs) else len(body)
        rec = body[pos:end]
        rec_len = end - pos

        if rec_len < _NAME_LENGTH_OFF + 1:
            continue

        # Validate core fields to filter false positives.
        if rec_len < 0x70:
            continue
        flags = struct.unpack_from(">I", rec, 12)[0]
        if flags & _FLAG_CONDITION:
            continue

        ftype = rec[44:48]
        # Type should be printable 4CC or zeros.
        if not all(0x20 <= b < 0x7f or b == 0 for b in ftype):
            continue

        n = rec[_NAME_LENGTH_OFF]
        if n == 0 or n > 100:
            continue

        # Approach 1: name runs to record boundary.
        start_boundary = rec_len - n
        if start_boundary >= 0x7B:
            name = _find_name_at_offset(rec, start_boundary, n)
            if name is not None and _plausible_name(name):
                candidates[start_boundary] += 1

        # Approach 2: name is NUL-terminated within the record.
        for start in range(0xB0, min(rec_len - n, 0xF0)):
            if rec[start + n] != 0:
                continue
            name = _find_name_at_offset(rec, start, n)
            if name is not None and _plausible_name(name):
                candidates[start] += 1

    if not candidates:
        # Fallback to most common known offset.
        return 0xC6

    # Use the modal offset.
    best = candidates.most_common(1)[0]
    return best[0]


def _extract_name(rec: bytes, rec_len: int, name_off: int,
                  is_raw_catalog: bool) -> str:
    """Extract the filename from a record given the known name offset."""
    if name_off >= rec_len:
        return ""

    rec[_NAME_LENGTH_OFF]

    if is_raw_catalog:
        # Name runs to record boundary.
        raw = rec[name_off:rec_len]
    else:
        # NUL-terminated.
        end = rec.find(b"\0", name_off)
        if end < 0:
            end = rec_len
        raw = rec[name_off:end]

    return raw.decode("mac-roman", "replace")


def parse_catalog(body: bytes, *,
                  name_offset: int | None = None,
                  is_raw_catalog: bool = False) -> Catalog:
    """Parse a decoded CVCT body into a :class:`Catalog`.

    ``name_offset`` can be provided explicitly; otherwise it is detected
    from the catalog data using the filename length byte at offset 0x7A.
    """
    files: list[Record] = []
    directories: list[str] = []
    skipped = 0

    sigs: list[tuple[int, bytes]] = []
    # Sequential signature scan (records are variable-length).
    # TODO: replace with structural sequential parsing using +0x7A length.
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

    # Detect name offset if not provided.
    if name_offset is None:
        name_offset = _detect_name_offset(sigs, body, is_raw_catalog)

    for i, (p, sig) in enumerate(sigs):
        end = sigs[i + 1][0] if i + 1 < len(sigs) else len(body)
        rec = body[p:end]
        rec_len = end - p

        if sig == SIG_DIR:
            name = _extract_name(rec, rec_len, name_offset, is_raw_catalog)
            directories.append(name)
            continue

        if rec_len < 112:
            skipped += 1
            continue

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

        name = _extract_name(rec, rec_len, name_offset, is_raw_catalog)

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
