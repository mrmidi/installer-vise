"""Extraction pipeline: decode payload blocks, slice forks, verify CRCs.

Implements the reverse-engineered model:

* shared blocks: one substituted-DEFLATE stream per block expands to a
  pool of concatenated forks; each member record slices its data fork at
  ``slice_off_d`` (length ``size_d``) and its rsrc fork at
  ``slice_off_r`` (length ``size_r``).
* plain records: data stream at ``block_offset`` (stored ``stored_d``),
  rsrc stream right after at ``block_offset + stored_d`` (stored
  ``stored_r``) — note the second stream starts at the *stored* boundary;
  the first stream pads to even length internally.
* verification: one CRC32 per record over ``data ‖ rsrc`` (records
  without an rsrc fork therefore verify CRC32(data) only).
* records with ``in_archive == False`` belong to another distribution
  disk and are reported, not extracted.
"""

from __future__ import annotations

import csv
import enum
import os
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from .archive import Archive
from .errors import ViseError

__all__ = ["RecordStatus", "FileResult", "Summary", "extract_archive"]


class RecordStatus(str, enum.Enum):
    OK = "OK"
    CRC_MISMATCH = "CRC-MISMATCH"
    OTHER_SOURCE = "OTHER SOURCE"
    FAILED = "FAILED"


@dataclass(frozen=True)
class FileResult:
    """Per-record outcome."""

    catalog_offset: int
    name: str
    written_as: str             # "" when nothing was written
    status: RecordStatus
    detail: str = ""


@dataclass
class Summary:
    """Aggregate outcome of one extraction run."""

    blocks: int = 0
    written: int = 0
    crc_ok: int = 0
    crc_bad: int = 0
    other_source: int = 0
    failed: int = 0
    results: list[FileResult] = field(default_factory=list)

    @property
    def ok(self) -> int:
        return self.crc_ok

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return (f"blocks={self.blocks} written={self.written} "
                f"crc_ok={self.crc_ok} crc_bad={self.crc_bad} "
                f"other_source={self.other_source} failed={self.failed}")


# --------------------------------------------------------------- helpers --

_FORBIDDEN = set('/:"?*<>|\\')


def _clean_name(name: str, catalog_offset: int) -> str:
    # Some tail records absorb the following structure's magic into their
    # name field (e.g. "loginwindow.plistPACK"); strip it.
    if name.endswith("PACK"):
        name = name[:-4]
    name = "".join("_" if c in _FORBIDDEN or ord(c) < 32 else c for c in name)
    name = name.strip()
    if name in (".", ".."):
        name = f"{name}_{catalog_offset:x}"
    return name or f"unnamed_{catalog_offset:x}"


def _unique(name: str, used: set[str], catalog_offset: int) -> str:
    # Case-insensitive: macOS volumes commonly collide on case-folded names.
    low = name.lower()
    if low not in {n.lower() for n in used}:
        used.add(name)
        return name
    stem, dot, ext = name.rpartition(".")
    candidate = f"{stem} (r{catalog_offset:x}).{ext}" if dot else \
        f"{name} (r{catalog_offset:x})"
    existing = {n.lower() for n in used}
    while candidate.lower() in existing:
        candidate += "_"
    used.add(candidate)
    return candidate


def _crc(data: bytes, rsrc: bytes) -> int:
    return zlib.crc32(data + rsrc) & 0xFFFFFFFF


# ------------------------------------------------------------ extraction --

def _decode_record(arc: Archive, rec) -> tuple[bytes, bytes] | ViseError:
    """Decode a plain record's data and rsrc forks. Returns (data, rsrc) or an error."""
    try:
        if rec.stored_d:
            data, _ = arc.decode_block(rec.block_offset, rec.stored_d,
                                       expected=rec.size_d,
                                       strict_consumed=False)
        else:
            data = b""
        if rec.stored_r:
            rsrc, _ = arc.decode_block(
                rec.block_offset + rec.stored_d, rec.stored_r,
                expected=rec.size_r)
        else:
            rsrc = b""
        return (data, rsrc)
    except ViseError as exc:
        return exc


def _decode_block_members(arc: Archive, blk) -> tuple[bytes, list[tuple]] | ViseError:
    """Decode a shared block and prepare member slices. Returns (pool, member_slices) or error."""
    try:
        pool, consumed = arc.decode_block(blk.offset, blk.stored,
                                          expected=blk.expanded)
    except ViseError as exc:
        return exc
    slices = []
    for rec in blk.members:
        if rec.slice_off_d + rec.size_d > len(pool) or \
           rec.slice_off_r + rec.size_r > len(pool):
            continue
        data = pool[rec.slice_off_d:rec.slice_off_d + rec.size_d]
        rsrc = pool[rec.slice_off_r:rec.slice_off_r + rec.size_r] \
            if rec.size_r else b""
        slices.append((rec, data, rsrc))
    return (pool, slices)


def extract_archive(arc: Archive, out_dir: str | Path, *,
                    write_manifest: bool = True,
                    progress: bool = True,
                    max_workers: int | None = None) -> Summary:
    """Extract every record stored in this archive into ``out_dir``.

    Writes data forks as named files and resource forks as ``<name>.rsrc``
    sidecars.  With ``write_manifest`` (default) also writes
    ``manifest.csv`` and ``directories.txt`` next to the files.

    ``progress`` prints per-file status to stdout.  ``max_workers``
    controls the thread pool size (defaults to min(32, cpu_count + 4)).
    """
    out = Path(out_dir)
    files_dir = out / "files"
    files_dir.mkdir(parents=True, exist_ok=True)

    if max_workers is None:
        max_workers = min(32, (os.cpu_count() or 4) + 4)

    summary = Summary()
    used_names: set[str] = set()
    name_lock = __import__("threading").Lock()

    total = sum(1 for r in arc.catalog.files if r.in_archive)
    done = 0

    _prog_ctx = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TextColumn("{task.fields[name]}"),
    ) if progress and total else None

    _task_id = _prog_ctx.add_task("extracting", total=total, name="") if _prog_ctx else None

    def _pb(name: str = ""):
        nonlocal done
        if _prog_ctx:
            trunc = (name[:40] + "…") if len(name) > 41 else name
            _prog_ctx.update(_task_id, advance=1, name=trunc)

    def finish(rec, data: bytes, rsrc: bytes, status: RecordStatus,
               detail: str = "", wrote: bool = False) -> None:
        if status is RecordStatus.OK:
            summary.crc_ok += 1
        elif status is RecordStatus.CRC_MISMATCH:
            summary.crc_bad += 1
        elif status is RecordStatus.OTHER_SOURCE:
            summary.other_source += 1
        else:
            summary.failed += 1
        summary.results.append(FileResult(
            catalog_offset=rec.catalog_offset,
            name=rec.name,
            written_as=detail if wrote else "",
            status=status,
            detail=detail,
        ))

    def emit(rec, data: bytes, rsrc: bytes) -> None:
        base = _clean_name(rec.name, rec.catalog_offset)
        with name_lock:
            fname = _unique(base, used_names, rec.catalog_offset)
        (files_dir / fname).write_bytes(data)
        if rsrc:
            (files_dir / f"{fname}.rsrc").write_bytes(rsrc)
        summary.written += 1
        crc = _crc(data, rsrc)
        if crc == rec.record_crc:
            finish(rec, data, rsrc, RecordStatus.OK, detail=fname, wrote=True)
        else:
            finish(rec, data, rsrc, RecordStatus.CRC_MISMATCH,
                   detail=f"crc {crc:08x} != {rec.record_crc:08x}",
                   wrote=True)

    if _prog_ctx:
        _prog_ctx.start()

    # ---- shared blocks: decode once, slice per member --------------------
    shared_recs = set()
    for blk in arc.catalog.blocks:
        result = _decode_block_members(arc, blk)
        if isinstance(result, ViseError):
            for rec in blk.members:
                finish(rec, b"", b"", RecordStatus.FAILED,
                       f"block {blk.offset:#x}: {result}")
            continue
        pool, slices = result
        summary.blocks += 1
        for rec, data, rsrc in slices:
            emit(rec, data, rsrc)
            shared_recs.add(rec.catalog_offset)
            done += 1
            _pb(rec.name)

    # ---- plain records: two independent streams ---------------------------
    plain_recs = [rec for rec in arc.catalog.files
                  if not rec.is_shared and rec.in_archive]

    if not plain_recs:
        pass  # nothing to do
    elif len(plain_recs) == 1 or max_workers <= 1:
        # Single-threaded for small batches
        for rec in plain_recs:
            result = _decode_record(arc, rec)
            if isinstance(result, ViseError):
                finish(rec, b"", b"", RecordStatus.FAILED, str(result))
            else:
                data, rsrc = result
                emit(rec, data, rsrc)
            done += 1
            _pb(rec.name)
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_decode_record, arc, rec): rec
                       for rec in plain_recs}
            for future in as_completed(futures):
                rec = futures[future]
                result = future.result()
                if isinstance(result, ViseError):
                    finish(rec, b"", b"", RecordStatus.FAILED, str(result))
                else:
                    data, rsrc = result
                    emit(rec, data, rsrc)
                done += 1
                _pb(rec.name)

    # Handle other-source records (not stored in this archive)
    for rec in arc.catalog.files:
        if not rec.is_shared and not rec.in_archive:
            finish(rec, b"", b"", RecordStatus.OTHER_SOURCE,
                   f"source {rec.source_index}, not stored in this archive")

    if _prog_ctx:
        _prog_ctx.stop()

    if write_manifest:
        _write_manifest(out, arc, summary)
        (out / "directories.txt").write_text(
            "\n".join(arc.catalog.directories) + "\n", encoding="utf-8")

    return summary


def _write_manifest(out: Path, arc: Archive, summary: Summary) -> None:
    type_by_offset = {r.catalog_offset: r for r in arc.catalog.files}
    with open(out / "manifest.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cat_off", "written_as", "catalog_name", "type", "creator",
                    "flags", "src_idx", "blk", "status", "detail"])
        for res in summary.results:
            rec = type_by_offset[res.catalog_offset]
            w.writerow([hex(res.catalog_offset), res.written_as, rec.name,
                        rec.file_type, rec.creator, hex(rec.flags),
                        rec.source_index, hex(rec.block_offset),
                        res.status.value, res.detail])
