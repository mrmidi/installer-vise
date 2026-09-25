"""Pytest configuration: make ``synth`` importable and locate the reference
archive when it is available."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
PKG_ROOT = TESTS_DIR.parent
sys.path.insert(0, str(TESTS_DIR))

# Candidate locations for the proprietary reference archive.  Tests that
# need it skip gracefully when absent, so the suite stays hermetic.
REFERENCE_CANDIDATES = [
    PKG_ROOT.parent / "ReferenceArchive",   # ../ sibling of the package
    PKG_ROOT / "archive" / "ReferenceArchive",
]


def _find_reference() -> Path | None:
    for p in REFERENCE_CANDIDATES:
        if p.is_file():
            return p
    return None


@pytest.fixture(scope="session")
def reference_archive() -> Path:
    path = _find_reference()
    if path is None:
        pytest.skip("reference archive not available")
    return path
