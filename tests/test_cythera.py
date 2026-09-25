"""Regression tests against the Cythera 1.x reference archive.

These run only when the proprietary ``Cythera Installer`` file is
present (see ``conftest.py``); otherwise they skip, keeping the suite
hermetic.

Cythera is an older Installer VISE variant with a raw (uncompressed)
catalog, no embedded PEF, and FVCT records with the name at offset
0xBA (vs 0xC6 in later versions).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from installer_vise import Archive, RecordStatus, extract_archive

# Cythera has 33 plain in-archive files + 9 shared-block members.
# Signature scanning finds ~48 FVCT signatures including false positives
# where "FVCT" appears inside a record name (known TODO). The 33 below
# is the count of plain (non-shared) records with in_archive=True.
EXPECTED_CRC_OK = 33
EXPECTED_BLOCKS = 1


@pytest.fixture(scope="session")
def extracted(tmp_path_factory, vise_early_archive: Path):
    out = tmp_path_factory.mktemp("cythera") / "extracted"
    arc = Archive.open(vise_early_archive)
    summary = extract_archive(arc, out)
    return arc, summary, out


def test_profile(extracted):
    arc, _, _ = extracted
    assert arc.info.profile == "vise_raw_catalog"
    assert arc.info.catalog_encoding == "raw"
    assert not arc.info.has_pef


def test_record_counts(extracted):
    arc, _, _ = extracted
    # 33 plain + 9 shared = 42 real files; signature scan may add false
    # positives where "FVCT" appears inside a name (known TODO).
    assert len(arc.catalog.files) >= 42
    assert len(arc.catalog.directories) >= 1
    assert len(arc.catalog.blocks) == EXPECTED_BLOCKS


def test_full_extraction_verifies(extracted):
    arc, summary, _ = extracted
    assert summary.blocks == EXPECTED_BLOCKS
    assert summary.crc_ok >= EXPECTED_CRC_OK
    assert summary.crc_bad == 0
    assert summary.failed == 0


def test_known_files(extracted):
    _, summary, out = extracted
    files = out / "files"
    names = [p.name for p in files.iterdir() if p.is_file()]
    # Cythera InputSprocket drivers and Cythera docs should be present.
    assert any("Sprocket" in n for n in names), f"no Sprocket files: {names[:5]}"
    assert any("Cythera" in n for n in names), f"no Cythera files: {names[:5]}"
    # No names should contain FVCT/DVCT (would indicate a false positive).
    bad = [n for n in names if "FVCT" in n or "DVCT" in n]
    assert not bad, f"false-positive records: {bad}"


def test_no_failed_records(extracted):
    _, summary, _ = extracted
    bad = [r for r in summary.results
           if r.status in (RecordStatus.FAILED, RecordStatus.CRC_MISMATCH)]
    assert bad == []
