"""End-to-end extraction tests on synthetic archives.

The builder (``synth.py``) constructs structurally faithful archives —
SVCT/CVCT/PACK headers, substituted stored-DEFLATE payload blocks, real
FVCT records with the overloaded field layout — so the full pipeline is
exercised without the proprietary reference file.
"""

from __future__ import annotations

import csv

import pytest

from installer_vise import Archive, RecordStatus, extract_archive
from installer_vise.errors import ViseFormatError
from synth import Fork, Rec, build_archive


def test_minimal_plain_roundtrip(tmp_path):
    payload = b"hello, Installer VISE!"
    arc_bytes = build_archive([
        Rec("readme.txt", Fork(data=payload), shared=False),
    ])
    arc = Archive.from_bytes(arc_bytes)
    assert arc.info.has_pef
    assert len(arc.catalog.files) == 1
    rec = arc.catalog.files[0]
    assert rec.name == "readme.txt"
    assert rec.in_archive

    summary = extract_archive(arc, tmp_path)
    assert summary.failed == 0
    assert summary.crc_ok == 1
    assert (tmp_path / "files" / "readme.txt").read_bytes() == payload


def test_shared_block_two_members(tmp_path):
    arc_bytes = build_archive([
        Rec("a.txt", Fork(data=b"AAAA"), shared=True),
        Rec("b.bin", Fork(data=b"BB", rsrc=b"R"*16), shared=True),
    ])
    arc = Archive.from_bytes(arc_bytes)
    assert len(arc.catalog.blocks) == 1
    blk = arc.catalog.blocks[0]
    assert blk.expanded == 4 + 2 + 16
    assert [m.name for m in blk.members] == ["a.txt", "b.bin"]

    summary = extract_archive(arc, tmp_path)
    assert summary.blocks == 1
    assert summary.crc_ok == 2 and summary.failed == 0
    files = tmp_path / "files"
    assert (files / "a.txt").read_bytes() == b"AAAA"
    assert (files / "b.bin").read_bytes() == b"BB"
    assert (files / "b.bin.rsrc").read_bytes() == b"R" * 16
    assert not (files / "a.txt.rsrc").exists()


def test_plain_record_with_rsrc(tmp_path):
    arc_bytes = build_archive([
        Rec("app", Fork(data=b"MZDATA", rsrc=b"RSRC-FORK-BYTES"), shared=False),
    ])
    arc = Archive.from_bytes(arc_bytes)
    summary = extract_archive(arc, tmp_path)
    assert summary.crc_ok == 1 and summary.failed == 0
    files = tmp_path / "files"
    assert (files / "app").read_bytes() == b"MZDATA"
    assert (files / "app.rsrc").read_bytes() == b"RSRC-FORK-BYTES"


def test_rsrc_only_record(tmp_path):
    arc_bytes = build_archive([
        Rec("forkless", Fork(data=b"", rsrc=b"ONLY-RSRC"), shared=False),
    ])
    arc = Archive.from_bytes(arc_bytes)
    summary = extract_archive(arc, tmp_path)
    assert summary.crc_ok == 1
    assert (tmp_path / "files" / "forkless").read_bytes() == b""
    assert (tmp_path / "files" / "forkless.rsrc").read_bytes() == b"ONLY-RSRC"


def test_other_source_record_reported_not_extracted(tmp_path):
    arc_bytes = build_archive([
        Rec("here.bin", Fork(data=b"local"), shared=False),
        Rec("disk2.bin", Fork(data=b"remote"), shared=False, in_archive=False,
            source=2),
    ])
    arc = Archive.from_bytes(arc_bytes)
    summary = extract_archive(arc, tmp_path)
    assert summary.other_source == 1
    assert summary.crc_ok == 1
    names = {r.name: r.status for r in summary.results}
    assert names["disk2.bin"] is RecordStatus.OTHER_SOURCE
    assert not (tmp_path / "files" / "disk2.bin").exists()


def test_duplicate_names_deduplicated(tmp_path):
    arc_bytes = build_archive([
        Rec("PkgInfo", Fork(data=b"APPL????"), shared=False),
        Rec("PkgInfo", Fork(data=b"APPL??!?", shared=False) if False
            else Fork(data=b"APPL??!?"), shared=False),
    ])
    arc = Archive.from_bytes(arc_bytes)
    summary = extract_archive(arc, tmp_path)
    assert summary.crc_ok == 2
    files = sorted(p.name for p in (tmp_path / "files").iterdir())
    assert files == ["PkgInfo", "PkgInfo (r1)"] or len(files) == 2


def test_condition_records_skipped(tmp_path):
    arc_bytes = build_archive([Rec("x.txt", Fork(data=b"x"), shared=False)])
    arc = Archive.from_bytes(arc_bytes)
    # builder emits one CNDA condition record and two DVCT dirs
    assert arc.catalog.skipped == 1
    assert arc.catalog.directories == ("Applications", "Documentation")
    assert len(arc.catalog.files) == 1


def test_manifest_written(tmp_path):
    arc_bytes = build_archive([
        Rec("doc.bin", Fork(data=b"d", rsrc=b"r"), shared=False),
    ])
    arc = Archive.from_bytes(arc_bytes)
    extract_archive(arc, tmp_path)
    rows = list(csv.DictReader(open(tmp_path / "manifest.csv")))
    assert len(rows) == 1
    assert rows[0]["catalog_name"] == "doc.bin"
    assert rows[0]["status"] == "OK"
    assert rows[0]["type"] == "TEXT"


def test_corrupt_crc_detected(tmp_path):
    arc_bytes = build_archive([
        Rec("bad.bin", Fork(data=b"original"), shared=False, crc=0xDEADBEEF),
    ])
    arc = Archive.from_bytes(arc_bytes)
    summary = extract_archive(arc, tmp_path)
    assert summary.crc_bad == 1 and summary.crc_ok == 0


def test_not_an_archive_rejected():
    with pytest.raises(ViseFormatError):
        Archive.from_bytes(b"PK\x03\x04 not a vise archive" * 8)


def test_empty_shared_pool(tmp_path):
    arc_bytes = build_archive([
        Rec("empty", Fork(data=b""), shared=True),
    ])
    arc = Archive.from_bytes(arc_bytes)
    summary = extract_archive(arc, tmp_path)
    assert summary.crc_ok == 1
    assert (tmp_path / "files" / "empty").read_bytes() == b""


def test_multi_block_layout(tmp_path):
    recs = []
    for i in range(5):
        recs.append(Rec(f"f{i}.txt", Fork(data=bytes([65 + i]) * 100),
                        shared=True))
    recs.append(Rec("solo.bin", Fork(data=b"standalone"), shared=False))
    arc = Archive.from_bytes(build_archive(recs))
    assert len(arc.catalog.blocks) == 1     # 5 consecutive shared -> 1 block
    assert len(arc.catalog.files) == 6
    summary = extract_archive(arc, tmp_path)
    assert summary.crc_ok == 6 and summary.failed == 0
