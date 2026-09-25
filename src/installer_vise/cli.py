"""Command-line interface: ``installer-vise inspect|extract``."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .archive import Archive
from .errors import ViseError
from .extract import extract_archive

EXIT_OK = 0
EXIT_NOT_VISE = 1
EXIT_PARTIAL = 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="installer-vise",
        description="Extract Installer VISE 3.x archives (classic Mac OS). "
                    "Experimental — validated on one reference archive only.")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("inspect", help="show archive summary")
    pi.add_argument("archive", type=Path)

    pe = sub.add_parser("extract", help="extract the archive")
    pe.add_argument("archive", type=Path)
    pe.add_argument("-o", "--out", type=Path, default=Path("extracted"),
                    help="output directory (default: ./extracted)")
    pe.add_argument("--no-manifest", action="store_true",
                    help="skip manifest.csv / directories.txt")
    pe.add_argument("-q", "--quiet", action="store_true",
                    help="suppress per-file progress")
    pe.add_argument("-j", "--jobs", type=int, default=None,
                    metavar="N", help="number of worker threads")
    return p


def _cmd_inspect(args: argparse.Namespace) -> int:
    arc = Archive.open(args.archive)
    print(f"archive      : {args.archive}")
    print(f"size         : {arc.info.size:,} bytes")
    print(f"installer PEF: {'yes' if arc.info.has_pef else 'no'}")
    print(f"payload      : {arc.info.payload_offset:#x}")
    print(f"catalog      : {arc.info.catalog_offset:#x}, "
          f"encoding {arc.info.catalog_encoding}")
    print(f"profile      : {arc.info.profile}")
    print(f"records      : {len(arc.catalog.files)} files, "
          f"{len(arc.catalog.directories)} directories, "
          f"{arc.catalog.skipped} condition/action")
    print(f"shared blocks: {len(arc.catalog.blocks)}")
    missing = sum(1 for r in arc.catalog.files if not r.in_archive)
    if missing:
        print(f"other source : {missing} records (not stored in this file)")
    return EXIT_OK


def _dir_size(path: Path) -> int:
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _cmd_extract(args: argparse.Namespace) -> int:
    arc = Archive.open(args.archive)
    t0 = time.monotonic()
    summary = extract_archive(arc, args.out,
                              write_manifest=not args.no_manifest,
                              progress=not args.quiet,
                              max_workers=args.jobs)
    elapsed = time.monotonic() - t0

    files_dir = Path(args.out) / "files"
    size = _dir_size(files_dir) if files_dir.is_dir() else 0
    rate = size / elapsed if elapsed > 0 else 0

    ok = summary.crc_ok
    print(f"\n  {summary.written} files extracted to {args.out}/files")
    print(f"  CRC: {ok}/{summary.written} verified, "
          f"{summary.crc_bad} mismatch, "
          f"{summary.other_source} other-source, "
          f"{summary.failed} failed")
    print(f"  size: {_human_size(size)}  time: {elapsed:.1f}s  "
          f"rate: {_human_size(rate)}/s" if rate else f"  size: {_human_size(size)}  time: {elapsed:.1f}s")
    if summary.failed or summary.crc_bad:
        return EXIT_PARTIAL
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "inspect":
            return _cmd_inspect(args)
        return _cmd_extract(args)
    except ViseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_NOT_VISE
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_NOT_VISE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
