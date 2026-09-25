"""Regression tests against the real reference archive.

These run only when the proprietary reference archive file is
present next to the package (see ``conftest.py``); otherwise they skip,
keeping the suite hermetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from installer_vise import Archive, RecordStatus, extract_archive

EXPECTED_FILES = 1288
EXPECTED_BLOCKS = 62
EXPECTED_OTHER_SOURCE = 5


@pytest.fixture(scope="session")
def extracted(tmp_path_factory, reference_archive: Path):
    out = tmp_path_factory.mktemp("ref") / "extracted"
    arc = Archive.open(reference_archive)
    summary = extract_archive(arc, out)
    return arc, summary, out


def test_info(extracted, reference_archive):
    arc, _, _ = extracted
    assert arc.info.size == reference_archive.stat().st_size
    assert arc.info.has_pef
    assert arc.info.profile == "vise3_late"
    assert arc.info.catalog_encoding == "deflate"


def test_record_counts(extracted):
    arc, summary, _ = extracted
    assert len(arc.catalog.files) == 1293
    assert len(arc.catalog.directories) == 83
    assert arc.catalog.skipped == 17
    assert len(arc.catalog.blocks) == EXPECTED_BLOCKS


def test_full_extraction_verifies(extracted):
    arc, summary, _ = extracted
    assert summary.blocks == EXPECTED_BLOCKS
    assert summary.written == EXPECTED_FILES
    assert summary.crc_ok == EXPECTED_FILES
    assert summary.crc_bad == 0
    assert summary.failed == 0
    assert summary.other_source == EXPECTED_OTHER_SOURCE


def test_known_files(extracted):
    _, summary, out = extracted
    files = out / "files"
    # At least one extracted file should have a PEF header
    pef_files = [p for p in files.iterdir()
                 if p.is_file() and p.read_bytes()[:4] in (b"Joy!", b"\xfe\xed\xfa\xce")]
    assert pef_files, "no PEF files found in extraction"
    # duplicates got unique names: check for at least one parenthesized rename
    renamed = [p for p in files.iterdir() if "(r" in p.name]
    assert renamed, "expected at least one duplicate-renamed file"


def test_no_failed_records(extracted):
    _, summary, _ = extracted
    bad = [r for r in summary.results
           if r.status in (RecordStatus.FAILED, RecordStatus.CRC_MISMATCH)]
    assert bad == []
