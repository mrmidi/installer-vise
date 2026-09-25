"""CLI tests (invoked in-process via main())."""

from __future__ import annotations

import pytest

from installer_vise.cli import EXIT_OK, EXIT_PARTIAL, main
from synth import Fork, Rec, build_archive


@pytest.fixture()
def archive_file(tmp_path):
    p = tmp_path / "test-installer"
    p.write_bytes(build_archive([
        Rec("good.txt", Fork(data=b"payload"), shared=False),
    ]))
    return p


def test_inspect(archive_file, capsys):
    rc = main(["inspect", str(archive_file)])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "1 files" in out
    assert "shared blocks: 0" in out
    assert "vise_compressed_catalog" in out


def test_extract_success(archive_file, tmp_path, capsys):
    out_dir = tmp_path / "out"
    rc = main(["extract", str(archive_file), "-o", str(out_dir)])
    assert rc == EXIT_OK
    assert (out_dir / "files" / "good.txt").read_bytes() == b"payload"
    assert "CRC-verified" in capsys.readouterr().out


def test_extract_partial_reports_exit_code(tmp_path):
    p = tmp_path / "bad"
    p.write_bytes(build_archive([
        Rec("bad.txt", Fork(data=b"payload"), shared=False, crc=0xDEADBEEF),
    ]))
    rc = main(["extract", str(p), "-o", str(tmp_path / "out")])
    assert rc == EXIT_PARTIAL


def test_not_vise_reports_error(tmp_path, capsys):
    p = tmp_path / "nope"
    p.write_bytes(b"garbage" * 100)
    rc = main(["inspect", str(p)])
    assert rc == 1
    assert "error" in capsys.readouterr().err
