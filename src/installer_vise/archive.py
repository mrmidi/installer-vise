"""Container parsing: SVCT header, CVCT catalog, PACK.

Supported catalog encodings:

* **VISE3_LATE** (e.g. Minolta DiMAGE Scan): DEFLATE-compressed catalog,
  optional embedded PEF at SVCT+0x30, catalog ends at EOF.
* **VISE_EARLY** (e.g. Cythera 1.x): raw (uncompressed) catalog, no PEF,
  catalog followed by script/table data.

The profile is detected from structural evidence, not file metadata:

* PEF at +0x30 → VISE3_LATE; else VISE_EARLY.
* Catalog stream starts with FVCT/DVCT → raw catalog; else DEFLATE.

Both profiles share the same SVCT → CVCT → PACK chain, the same SUBST
table, the same VISE word-aligned DEFLATE payload codec, and the same
CRC32(data || rsrc) per-record verification.
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

_SVCT_HEADER = 0x2C          # SVCT header size (44 bytes)
_SVCT_CATALOG_OFF = 0x24     # catalog offset field
_SVCT_PAYLOAD_OFF = 0x1C     # optional first-payload/PEF boundary
_CVCT_HEADER = 0x14          # CVCT header size (20 bytes)
_PACK_HEADER = 0x50          # PACK header size

# FVCT name offset from record start (FVCT signature = offset 0).
# Late 3.x: 0xC6 (Minolta). Early 3.x: 0xBC (Cythera).
_NAME_OFF_VISE3_LATE = 0xC6
_NAME_OFF_VISE_EARLY = 0xBC


@dataclass(frozen=True)
class ArchiveInfo:
    """Container-level facts derived from the SVCT/CVCT/PACK headers."""

    size: int
    catalog_offset: int
    payload_offset: int
    has_pef: bool
    catalog_encoding: str        # "raw" or "deflate"
    catalog_offset_in_stream: int  # offset of first FVCT/DVCT in catalog body
    catalog_span: int            # stored catalog payload span (CVCT+4)
    pack_count: int | None
    profile: str                 # "vise3_late" or "vise_early"


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

        catalog_offset, = struct.unpack_from(">I", data, _SVCT_CATALOG_OFF)
        payload_offset, = struct.unpack_from(">I", data, _SVCT_PAYLOAD_OFF)

        if not (0 < catalog_offset < len(data)):
            raise ViseFormatError(f"bad catalog offset {catalog_offset:#x}")
        if not (0 <= payload_offset <= catalog_offset):
            raise ViseFormatError(f"bad payload offset {payload_offset:#x}")

        has_pef = data[0x30:0x3C] == _PEF_MAGIC

        # CVCT header at catalog_offset; PACK header follows.
        cvct = data[catalog_offset:catalog_offset + _CVCT_HEADER]
        if len(cvct) < _CVCT_HEADER or cvct[:4] != _CVCT_MAGIC:
            raise ViseFormatError(f"no CVCT header at {catalog_offset:#x}")

        catalog_span, = struct.unpack_from(">I", cvct, 4)

        pack_off = catalog_offset + _CVCT_HEADER
        pack = data[pack_off:pack_off + _PACK_HEADER]
        pack_count: int | None = None
        if len(pack) >= _PACK_HEADER and pack[:4] == _PACK_MAGIC:
            pack_count, = struct.unpack_from(">I", pack, 0x20)

        stream_offset = pack_off + _PACK_HEADER
        stream_end = stream_offset + catalog_span
        if stream_end > len(data):
            raise ViseFormatError(
                f"catalog stream overruns file: {stream_end:#x} > {len(data):#x}")

        catalog_raw = data[stream_offset:stream_end]

        # Detect catalog encoding from structural evidence.
        # The first 4 bytes of the stored catalog payload are FVCT/DVCT
        # for raw catalogs, or a DEFLATE header for compressed ones.
        if catalog_raw[:4] in (b"FVCT", b"DVCT"):
            catalog_encoding = "raw"
            name_offset = _NAME_OFF_VISE_EARLY  # 0xBA
            profile = "vise_raw_catalog"
        else:
            catalog_encoding = "deflate"
            name_offset = _NAME_OFF_VISE3_LATE  # 0xC6
            profile = "vise_compressed_catalog"

        # Decode catalog.
        if catalog_encoding == "raw":
            catalog_body = catalog_raw
        else:
            out, consumed = inflate_span(catalog_raw, 0)
            if consumed != len(catalog_raw):
                raise ViseFormatError(
                    f"catalog DEFLATE: consumed {consumed} of "
                    f"{len(catalog_raw)} bytes")
            catalog_body = out

        catalog = parse_catalog(catalog_body, name_offset=name_offset)

        info = ArchiveInfo(
            size=len(data),
            catalog_offset=catalog_offset,
            payload_offset=payload_offset,
            has_pef=has_pef,
            catalog_encoding=catalog_encoding,
            catalog_offset_in_stream=stream_offset,
            catalog_span=catalog_span,
            pack_count=pack_count,
            profile=profile,
        )

    # ------------------------------------------------------------------
    # Attributes: data, info, catalog, source_path from the dataclass.
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
        streams, which :meth:`from_bytes` handles internally.

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
