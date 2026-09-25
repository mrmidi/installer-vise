"""Container parsing: SVCT header, embedded PEF, CVCT catalog, PACK.

File layout (offsets from a reference archive ~12 MB):

    0x00  SVCT header (44 bytes)
    0x30  PEF container ("Joy!peffpwpc")  — the installer application
    0xDB6A8   payload region (substituted-DEFLATE streams)
    0xB69E24  CVCT catalog header (20 bytes)
    0xB69E38  PACK header (0x50 bytes)
    0xB69E88  catalog DEFLATE stream, plain (not substituted), ends at EOF

Only the SVCT catalog offset is authoritative; everything else is derived
and re-validated (stream span vs CVCT body length vs EOF).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from .catalog import Catalog, parse_catalog
from .deflate import inflate_span
from .errors import ViseFormatError
from .subst import subst

__all__ = ["Archive", "ArchiveInfo"]

_SVCT_MAGIC = b"SVCT"
_CVCT_MAGIC = b"CVCT"
_PACK_MAGIC = b"PACK"
_PEF_MAGIC = b"Joy!peffpwpc"

_SVCT_CATALOG_OFFSET = 0x24
_SVCT_PAYLOAD_OFFSET = 0x1C
_CVCT_HEADER = 0x14          # CVCT header size
_PACK_HEADER = 0x50          # PACK header size
_PACK_COUNT_OFF = 0x20       # record count within PACK header


@dataclass(frozen=True)
class ArchiveInfo:
    """Container-level facts derived from the SVCT/CVCT/PACK headers."""

    size: int                   # archive size in bytes
    catalog_offset: int         # SVCT+0x24
    payload_offset: int         # SVCT+0x1C
    has_pef: bool               # "Joy!peffpwpc" at 0x30
    stream_offset: int          # catalog DEFLATE stream start
    stream_span: int            # CVCT+4: compressed stream span
    stream_end: int             # stream_offset + stream_span (== EOF if sound)
    pack_count: int | None      # PACK record count, if header present


@dataclass(frozen=True)
class Archive:
    """A parsed Installer VISE archive."""

    data: bytes
    info: ArchiveInfo
    catalog: Catalog
    source_path: Path | None = None

    # ---------------------------------------------------------------- open --

    @classmethod
    def open(cls, path: str | Path) -> "Archive":
        return cls.from_bytes(Path(path).read_bytes(), source=Path(path))

    @classmethod
    def from_bytes(cls, data: bytes, source: Path | None = None) -> "Archive":
        if len(data) < 0x30 or data[:4] != _SVCT_MAGIC:
            raise ViseFormatError("not an Installer VISE archive (no SVCT header)")

        catalog_offset, = struct.unpack_from(">I", data, _SVCT_CATALOG_OFFSET)
        payload_offset, = struct.unpack_from(">I", data, _SVCT_PAYLOAD_OFFSET)
        if not (0 < catalog_offset < len(data)):
            raise ViseFormatError(f"bad catalog offset {catalog_offset:#x}")
        if not (0 < payload_offset <= catalog_offset):
            raise ViseFormatError(f"bad payload offset {payload_offset:#x}")

        if data[0x30:0x3C] == _PEF_MAGIC:
            has_pef = True
        else:
            has_pef = False  # tolerated: payload-only dumps may lack the PEF

        # CVCT header at catalog_offset; PACK header follows.
        cvct = data[catalog_offset:catalog_offset + _CVCT_HEADER]
        if len(cvct) < _CVCT_HEADER or cvct[:4] != _CVCT_MAGIC:
            raise ViseFormatError(f"no CVCT header at {catalog_offset:#x}")
        # CVCT+4 is the compressed catalog stream span (not the decoded size).
        stream_span, = struct.unpack_from(">I", cvct, 4)

        pack_off = catalog_offset + _CVCT_HEADER
        pack = data[pack_off:pack_off + _PACK_HEADER]
        pack_count: int | None = None
        if len(pack) >= _PACK_HEADER and pack[:4] == _PACK_MAGIC:
            pack_count, = struct.unpack_from(">I", pack, _PACK_COUNT_OFF)

        stream_offset = pack_off + _PACK_HEADER
        stream_end = stream_offset + stream_span
        if stream_end > len(data):
            raise ViseFormatError(
                f"catalog stream overruns file: {stream_end:#x} > {len(data):#x}")

        # The catalog stream is plain VISE DEFLATE (no substitution).
        body = inflate_span_checked(
            data, stream_offset, stream_span, what="catalog")[0]

        catalog = parse_catalog(body)

        info = ArchiveInfo(
            size=len(data),
            catalog_offset=catalog_offset,
            payload_offset=payload_offset,
            has_pef=has_pef,
            stream_offset=stream_offset,
            stream_span=stream_span,
            stream_end=stream_end,
            pack_count=pack_count,
        )
        return cls(data=data, info=info, catalog=catalog, source_path=source)

    # ------------------------------------------------------------ payloads --

    def decode_block(self, offset: int, stored: int,
                     expected: int | None = None,
                     *, substitute: bool = True,
                     strict_consumed: bool = True) -> tuple[bytes, int]:
        """Decode one payload stream (SUBST -> VISE DEFLATE).

        Returns ``(output, consumed)``.  If ``expected`` is given the
        output length is checked against it.  Payload streams are always
        substituted; pass ``substitute=False`` only for raw (e.g. catalog)
        streams, which :meth:`open` handles internally.

        Some tail records reserve more stored bytes than the stream needs
        (the stream ends early inside its window); pass
        ``strict_consumed=False`` for those plain data streams — the next
        stream still starts at ``offset + stored``.
        """
        window = self.data[offset:offset + stored]
        if substitute:
            window = subst(window)
        out, consumed = inflate_span(window, 0)
        if strict_consumed and consumed != stored:
            raise ViseFormatError(
                f"payload: stream consumed {consumed} bytes, expected {stored}")
        if expected is not None and len(out) != expected:
            raise ViseFormatError(
                f"payload: expanded to {len(out)} bytes, expected {expected}")
        return out, consumed


def inflate_span_checked(data: bytes, offset: int, stored: int, *,
                         what: str, expected_out: int | None = None):
    """Decode a stream of exactly ``stored`` bytes; validate consumed size."""
    if offset & 1:
        raise ViseFormatError(f"{what}: stream offset {offset:#x} is not word-aligned")
    window = data[offset:offset + stored]
    out, consumed = inflate_span(window, 0)
    if consumed != stored:
        raise ViseFormatError(
            f"{what}: stream consumed {consumed} bytes, expected {stored}")
    if expected_out is not None and len(out) != expected_out:
        raise ViseFormatError(
            f"{what}: expanded to {len(out)} bytes, expected {expected_out}")
    return out, consumed
