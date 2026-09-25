"""Regression tests against the Crescendo reference archive.

Crescendo (2005) is a VISE archive with a DEFLATE-compressed catalog but
no embedded PEF. It demonstrates that catalog encoding (not PEF presence)
determines the FVCT record layout.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from installer_vise import Archive, RecordStatus, extract_archive

EXPECTED_CRC_OK = 9
EXPECTED_OTHER_SOURCE = 3


@pytest.fixture(scope="session")
def extracted(tmp_path_factory, vise_compressed_no_pef_archive: Path):
    out = tmp_path_factory.mktemp("crescendo") / "extracted"
    arc = Archive.open(vise_compressed_no_pef_archive)
    summary = extract_archive(arc, out)
    return arc, summary, out


def test_profile(extracted):
    arc, _, _ = extracted
    assert arc.info.profile == "vise_compressed_catalog"
    assert arc.info.catalog_encoding == "deflate"
    assert not arc.info.has_pef


def test_full_extraction_verifies(extracted):
    _, summary, _ = extracted
    assert summary.crc_ok == EXPECTED_CRC_OK
    assert summary.crc_bad == 0
    assert summary.failed == 0
    assert summary.other_source == EXPECTED_OTHER_SOURCE


def test_known_files(extracted):
    _, summary, out = extracted
    files = out / "files"
    names = [p.name for p in files.iterdir() if p.is_file()]
    # Crescendo firmware utilities should be present.
    assert any("Sonnet" in n for n in names), f"no Sonnet files: {names[:5]}"
    assert any("Metronome" in n for n in names), f"no Metronome: {names[:5]}"


def test_no_failed_records(extracted):
    _, summary, _ = extracted
    bad = [r for r in summary.results
           if r.status in (RecordStatus.FAILED, RecordStatus.CRC_MISMATCH)]
    assert bad == []
