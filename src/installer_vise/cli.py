"""Command-line interface: ``installer-vise inspect|extract``."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .archive import Archive
from .errors import ViseError
from .extract import RecordStatus, extract_archive

EXIT_OK = 0
EXIT_NOT_VISE = 1
EXIT_PARTIAL = 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="installer-vise",
        description="Extract Installer VISE 3.x archives (classic Mac OS).")
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
    return p


def _cmd_inspect(args: argparse.Namespace) -> int:
    arc = Archive.open(args.archive)
    print(f"archive      : {args.archive}")
    print(f"size         : {arc.info.size:,} bytes")
    print(f"installer PEF: {'yes' if arc.info.has_pef else 'no'}")
    print(f"payload      : {arc.info.payload_offset:#x}")
    print(f"catalog      : {arc.info.catalog_offset:#x}, "
          f"stream {arc.info.stream_offset:#x}..{arc.info.stream_end:#x}")
    print(f"records      : {len(arc.catalog.files)} files, "
          f"{len(arc.catalog.directories)} directories, "
          f"{arc.catalog.skipped} condition/action")
    print(f"shared blocks: {len(arc.catalog.blocks)}")
    missing = sum(1 for r in arc.catalog.files if not r.in_archive)
    if missing:
        print(f"other source : {missing} records (not stored in this file)")
    return EXIT_OK


def _cmd_extract(args: argparse.Namespace) -> int:
    arc = Archive.open(args.archive)
    summary = extract_archive(arc, args.out,
                              write_manifest=not args.no_manifest)
    ok = summary.crc_ok
    print(f"extracted {summary.written} files to {args.out}/files "
          f"({ok}/{summary.written} CRC-verified, "
          f"{summary.crc_bad} crc-mismatch, "
          f"{summary.other_source} other-source, "
          f"{summary.failed} failed)")
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
