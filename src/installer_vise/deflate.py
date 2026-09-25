"""VISE word-aligned DEFLATE — the Installer VISE compression codec.

Reverse-engineered from the installer's own decompressor resources
(``'Dcmp'`` #1005, PPC, and #1004, 68K) and validated against every
payload stream in the reference archive.

Deviations from RFC 1951 (see ``docs/compression.md``):

1. Input is consumed as big-endian 16-bit words; bits are LSB-first.
2. Block headers follow the bit stream continuously (not word-aligned).
3. Stored (BTYPE=0) blocks align to a 16-bit boundary before LEN/NLEN;
   payload bytes travel 8 stream bits at a time, i.e. **pair-swapped**
   relative to the file.  An odd LEN consumes one pad byte.
4. BTYPE=1 (fixed Huffman) and BTYPE=3 are rejected (Dcmp error -9);
   VISE compressors only emit stored and dynamic blocks.
5. After a final block, whole prefetched words are returned, so streams
   end on a 16-bit boundary.  ``inflate_span`` reports ``consumed`` as the
   even byte offset just past the last word containing stream bits.

The dynamic-Huffman path is bit-for-bit RFC 1951.

This module also provides :func:`deflate_stored`, a *stored-block*
encoder producing valid VISE streams.  It exists so the test suite can
build synthetic archives without carrying a dynamic-Huffman compressor;
the real VISE compressor emits dynamic blocks, but both are valid inputs
to the decoder (and to the original Dcmp).
"""

from __future__ import annotations

import zlib

from .errors import ViseInflateError

__all__ = [
    "InflateError",
    "deflate_stored",
    "inflate",
    "inflate_span",
]

InflateError = ViseInflateError

# --------------------------------------------------------------------------
# RFC 1951 tables (identical to the reference implementation)
# --------------------------------------------------------------------------

LENGTH_BASE = (
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
    67, 83, 99, 115, 131, 163, 195, 227, 258,
)
LENGTH_EXTRA = (
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4,
    5, 5, 5, 5, 0,
)
DIST_BASE = (
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
    769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
)
DIST_EXTRA = (
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10,
    10, 11, 11, 12, 12, 13, 13,
)
CLEN_ORDER = (16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2,
              14, 1, 15)

_FIXED_LIT_LENGTHS = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
_FIXED_DIST_LENGTHS = [5] * 30


class HuffTable:
    """Canonical Huffman decoder built from code lengths (LSB-first bits)."""

    __slots__ = ("counts", "symbols")

    def __init__(self, lengths):
        self.counts = [0] * 16
        for ln in lengths:
            self.counts[ln] += 1
        self.counts[0] = 0
        offs = [0] * 16
        total = 0
        for ln in range(1, 16):
            offs[ln] = total
            total += self.counts[ln]
        self.symbols = [0] * total
        for sym, ln in enumerate(lengths):
            if ln:
                self.symbols[offs[ln]] = sym
                offs[ln] += 1


_FIXED_LIT = HuffTable(_FIXED_LIT_LENGTHS)
_FIXED_DIST = HuffTable(_FIXED_DIST_LENGTHS)


# --------------------------------------------------------------------------
# Decoder
# --------------------------------------------------------------------------

class _BitReader:
    """Word-aligned bit reader: BE16 words, LSB-first delivery."""

    __slots__ = ("data", "pos", "bitbuf", "bitcnt")

    def __init__(self, data: bytes, offset: int = 0):
        if offset & 1:
            raise ViseInflateError("stream offset must be word-aligned")
        self.data = data
        self.pos = offset
        self.bitbuf = 0
        self.bitcnt = 0

    def _fill(self) -> None:
        if self.pos + 2 <= len(self.data):
            w = (self.data[self.pos] << 8) | self.data[self.pos + 1]
            self.pos += 2
        else:
            w = 0  # past end: feed zero words (decoding will fail soon anyway)
        self.bitbuf |= w << self.bitcnt
        self.bitcnt += 16

    def bits(self, need: int) -> int:
        if need == 0:
            return 0
        while self.bitcnt < need:
            self._fill()
        val = self.bitbuf & ((1 << need) - 1)
        self.bitbuf >>= need
        self.bitcnt -= need
        return val

    def align16(self) -> None:
        """Discard buffered bits down to a multiple of 16."""
        drop = self.bitcnt & 0xF
        self.bitbuf >>= drop
        self.bitcnt -= drop


def _decode(reader: _BitReader, table: HuffTable) -> int:
    code = 0
    first = 0
    index = 0
    for ln in range(1, 16):
        code |= reader.bits(1)
        count = table.counts[ln]
        if code - first < count:
            return table.symbols[index + (code - first)]
        index += count
        first = (first + count) << 1
        code <<= 1
    raise ViseInflateError("invalid huffman code")


def _read_dynamic_tables(reader: _BitReader):
    hlit = reader.bits(5) + 257
    hdist = reader.bits(5) + 1
    hclen = reader.bits(4) + 4
    clen_lengths = [0] * 19
    for i in range(hclen):
        clen_lengths[CLEN_ORDER[i]] = reader.bits(3)
    clen_table = HuffTable(clen_lengths)

    lengths = []
    n = hlit + hdist
    while len(lengths) < n:
        sym = _decode(reader, clen_table)
        if sym < 16:
            lengths.append(sym)
        elif sym == 16:
            if not lengths:
                raise ViseInflateError("repeat with no previous length")
            lengths.extend([lengths[-1]] * (3 + reader.bits(2)))
        elif sym == 17:
            lengths.extend([0] * (3 + reader.bits(3)))
        else:  # 18
            lengths.extend([0] * (11 + reader.bits(7)))
    if len(lengths) > n:
        raise ViseInflateError("dynamic table length overflow")
    return HuffTable(lengths[:hlit]), HuffTable(lengths[hlit:])


def _inflate_engine(reader: _BitReader, out: bytearray, limit: int) -> int:
    """Run all blocks; return the consumed byte offset after the flush.

    Stops early (without consuming the rest of the stream) once ``limit``
    output bytes have been produced.
    """
    while True:
        final = reader.bits(1)
        btype = reader.bits(2)
        if btype == 0:
            reader.align16()
            ln = reader.bits(16)
            nlen = reader.bits(16)
            if ln ^ nlen != 0xFFFF:
                raise ViseInflateError("stored LEN/NLEN mismatch")
            total = ln + (ln & 1)
            if reader.pos - (reader.bitcnt // 16) * 2 + total > len(reader.data) + 2:
                raise ViseInflateError("truncated stored data")
            # Word-aligned here, so payload bytes are the pair-swapped raw
            # file bytes starting at the current even buffer position.
            k = reader.bitcnt // 16
            buf_start = reader.pos - 2 * k
            raw = bytearray(reader.data[buf_start:buf_start + total + 2])
            if len(raw) < total:
                raise ViseInflateError("truncated stored data")
            raw[0::2], raw[1::2] = raw[1::2], raw[0::2]
            take = min(ln, max(0, limit - len(out)))
            out += raw[:take]
            adv = total * 8
            reader.bitcnt -= adv
            while reader.bitcnt < 0:
                reader.bitcnt += 16
                reader.pos += 2
            if reader.pos > len(reader.data) + 1:
                raise ViseInflateError("stored data past end of input")
            if take < ln:
                return reader.pos
        elif btype == 2:
            lit_table, dist_table = _read_dynamic_tables(reader)
            while True:
                sym = _decode(reader, lit_table)
                if sym < 256:
                    if len(out) >= limit:
                        return reader.pos
                    out.append(sym)
                elif sym == 256:
                    break
                else:
                    li = sym - 257
                    if li >= len(LENGTH_BASE):
                        raise ViseInflateError("bad length symbol")
                    length = LENGTH_BASE[li] + reader.bits(LENGTH_EXTRA[li])
                    dsym = _decode(reader, dist_table)
                    if dsym >= len(DIST_BASE):
                        raise ViseInflateError("bad distance symbol")
                    dist = DIST_BASE[dsym] + reader.bits(DIST_EXTRA[dsym])
                    if dist > len(out):
                        raise ViseInflateError("distance too far back")
                    length = min(length, max(0, limit - len(out)))
                    start = len(out) - dist
                    if start + length <= len(out):
                        out += out[start:start + length]
                    else:
                        # Overlapping LZ77 run: bytes are consumed as they
                        # are produced.  A plain slice would silently short.
                        for i in range(length):
                            out.append(out[start + i])
                    if len(out) >= limit and length:
                        return reader.pos
        else:  # btype 1 (fixed) and btype 3: both rejected by the Dcmp
            raise ViseInflateError(
                "invalid block type (Dcmp supports stored/dynamic only)")

        if final:
            # Flush trailing partial word: give whole words back.
            while reader.bitcnt >= 16:
                reader.bitcnt -= 16
                reader.pos -= 2
            return reader.pos


def inflate_native(data: bytes, expected: int | None = None) -> bytes | None:
    """Fast native zlib path for extraction.

    VISE stores data as big-endian 16-bit words with LSB-first bit order.
    Pair-swapping converts this to standard RFC 1951 byte order.  Returns
    decoded bytes on success, or None if the stream is not compatible with
    raw DEFLATE (caller should fall back to inflate_span).
    """
    if len(data) < 4:
        return None

    buf = bytearray(data)
    n = len(buf) & ~1
    buf[0:n:2], buf[1:n:2] = buf[1:n:2], buf[0:n:2]

    try:
        d = zlib.decompressobj(-15)
        out = d.decompress(bytes(buf))
        out += d.flush()
    except zlib.error:
        return None

    if not d.eof:
        return None

    if expected is not None and len(out) != expected:
        return None

    return out


def inflate_span(data: bytes, offset: int = 0,
                 max_out: int | None = None) -> tuple[bytes, int]:
    """Decode one VISE DEFLATE stream starting at byte ``offset``.

    ``offset`` must be even (word-aligned).  Returns ``(output, consumed)``
    where ``consumed`` is the even byte offset just past the final block
    (after the word-boundary flush).  Exact reference implementation —
    handles every VISE block variant.
    """
    reader = _BitReader(data, offset)
    out = bytearray()
    limit = max_out if max_out is not None else 1 << 62
    end = _inflate_engine(reader, out, limit)
    return bytes(out), end


def inflate(data: bytes, offset: int = 0, max_out: int | None = None) -> bytes:
    """Like :func:`inflate_span` but returns only the decoded bytes."""
    return inflate_span(data, offset, max_out)[0]


# --------------------------------------------------------------------------
# Stored-block encoder (test infrastructure)
# --------------------------------------------------------------------------

def deflate_stored(data: bytes) -> bytes:
    """Encode ``data`` as a single final stored block (valid VISE stream).

    The stream is minimal and word-aligned; ``inflate_span`` on the result
    yields ``(data, len(stream))``.
    """
    out = bytearray()
    # Block header: BFINAL=1, BTYPE=0, then padding to the word boundary.
    # Bits are delivered LSB-first from each BE16 word, so the first bit
    # (BFINAL) is the LSB of the *second* file byte: the header word is
    # 0x0001 -> file bytes 00 01 -> bits 1,0,0 (BFINAL=1, BTYPE=00), rest pad.
    out.append(0x00)
    out.append(0x01)
    out += len(data).to_bytes(2, "big")
    out += (len(data) ^ 0xFFFF).to_bytes(2, "big")
    # Payload bytes are consumed 8 stream bits at a time = pair-swapped.
    # The pad byte for odd LEN is part of the swapped buffer.
    full = data + (b"\x00" if len(data) & 1 else b"")
    swapped = bytearray(full)
    swapped[0::2], swapped[1::2] = swapped[1::2], swapped[0::2]
    out += swapped
    return bytes(out)
