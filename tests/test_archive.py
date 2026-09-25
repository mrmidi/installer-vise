"""Container-level tests (SVCT/CVCT/PACK handling)."""

from __future__ import annotations

import struct

import pytest

from installer_vise import Archive
from installer_vise.errors import ViseFormatError
from synth import Fork, Rec, build_archive


def test_header_facts():
    arc = Archive.from_bytes(build_archive(
        [Rec("x", Fork(data=b"x"), shared=False)]))
    assert arc.info.has_pef
    assert arc.info.payload_offset == 0x3C     # after SVCT + PEF magic
    assert arc.info.stream_end == arc.info.size   # stream ends exactly at EOF


def test_stream_span_is_compressed_size():
    data = build_archive([Rec("x", Fork(data=b"x"), shared=False)])
    arc = Archive.from_bytes(data)
    cvct_off = arc.info.catalog_offset
    span, = struct.unpack_from(">I", data, cvct_off + 4)
    assert span == arc.info.stream_span
    # definitional: the span covers the stream exactly to EOF
    assert arc.info.stream_offset + span == arc.info.size


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda b: b"XVCT" + b[4:], id="bad-svct-magic"),
    pytest.param(lambda b: b[:0x24] + struct.pack(">I", 0xFFFFFFF0) + b[0x28:],
                 id="catalog-offset-out-of-range"),
    pytest.param(lambda b: b[:-10], id="truncated-stream"),
])
def test_malformed_containers_rejected(mutate):
    good = build_archive([Rec("x", Fork(data=b"x"), shared=False)])
    bad = mutate(bytearray(good))
    with pytest.raises(ViseFormatError):
        Archive.from_bytes(bytes(bad))


def test_without_pef_still_opens():
    data = build_archive([Rec("x", Fork(data=b"x"), shared=False)],
                         with_pef=False)
    arc = Archive.from_bytes(data)
    assert not arc.info.has_pef
    assert arc.catalog.files[0].name == "x"
