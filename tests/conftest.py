"""Pytest configuration: make ``synth`` importable and locate reference
archives when available.

Tests that need proprietary archives skip gracefully when absent, so the
suite stays hermetic.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
PKG_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(TESTS_DIR))

# Candidate locations for proprietary reference archives.
REFERENCE_ARCHIVES = {
    "vise3_late": [
        PKG_ROOT.parent / "DiMAGE Scan Installer",
        PKG_ROOT / "archive" / "DiMAGE Scan Installer",
    ],
    "vise_early": [
        PKG_ROOT / "tmp" / "Cythera Installer",
        PKG_ROOT.parent / "Cythera Installer",
        PKG_ROOT / "archive" / "Cythera Installer",
    ],
}


def _find_archive(candidates: list[Path]) -> Path | None:
    for p in candidates:
        if p.is_file():
            return p
    return None


@pytest.fixture(scope="session")
def vise3_late_archive() -> Path:
    path = _find_archive(REFERENCE_ARCHIVES["vise3_late"])
    if path is None:
        pytest.skip("VISE3_LATE reference archive not available")
    return path


@pytest.fixture(scope="session")
def vise_early_archive() -> Path:
    path = _find_archive(REFERENCE_ARCHIVES["vise_early"])
    if path is None:
        pytest.skip("VISE_EARLY reference archive not available")
    return path


# Backward compat
@pytest.fixture(scope="session")
def reference_archive(vise3_late_archive: Path) -> Path:
    return vise3_late_archive
