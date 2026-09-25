# Compression

Two independent layers compose the file-payload transform. The catalog
stream uses layer 2 only.

## Layer 1 — byte substitution (`SUBST`)

Applied to file-payload streams **only**, before DEFLATE.

```
out[i] = TABLE[in[i]]
```

* Discovered as `sub_444A8` in the installer PEF operating on the Dcmp
  input buffer (`byte_6B4A8`, TOC base `0x67910`).
* The table is a fixed 256-byte **permutation** (all values distinct —
  verified), stateless, identical for every payload block.
* Not applied to: the catalog stream, the script stream, or any other
  structure.

### The table

Canonical dump (512 hex chars = 256 bytes; first byte is the mapping of
input `0x00`, etc.):

```
6ab736ec15d9c873e8389adf2125d0cc
fddc16d7e34305c58f48daf23f10236c
777cf9a0a3e9ed468bd8ac54ce2d195e
6d7d875dfa5b9be0c7ee9f52a9b90ad1
fe78764a3d445a96901f269d581b8e57
59c30b6bfc1de6a27f924f40b406724d
f434aad249adef221ab5babf29688993
3e3204f5dee16ffb67e47e08aff0ab41
82ea500f2ac635b3a8cae54c458a97ae
d6662753c91c3c0399c1092e69378d2f
60c2a6184e7ab8cfa73a17d59ef18451
0da464c41eb13098bb7901f6620eb263
91cbff8071e7d400db752cbd393394bc
8c3bb6208524882b70836e7b9cbe1447
654b5681f8121128eb5574a131f7b013
86dd5f42d30261950c5ca5cdc007e2f3
```

Validation: with this table, all 62 shared blocks and all 64 plain
records decode to exact expected sizes and CRCs (1288/1288 files).

## Layer 2 — VISE word-aligned DEFLATE (`DCMP`)

A DEFLATE variant implemented by the installer's own decompressor
(`'Dcmp'` #1004, 68K / `'Dcmp'` #1005, PPC; PPC version RE'd
instruction-by-instruction). It deviates from RFC 1951 in the stream
framing:

1. **Word-based input.** The stream is consumed as big-endian 16-bit
   words; bits are taken **LSB-first** from each word. (Equivalently:
   the whole stream is a classic DEFLATE bitstream in which every pair of
   bytes is swapped — both phrasings produce identical decoders.)

2. **Continuous block headers.** Block headers (`BFINAL`/`BTYPE`) are
   read straight from the bit stream — they are *not* aligned to the
   16-bit word boundary.

3. **Stored blocks align to 16 bits, not 8.** When `BTYPE = 0`, the
   decoder drops buffered bits down to a multiple of 16, then reads
   `LEN` and `NLEN` as two 16-bit stream units (i.e. big-endian u16s at
   an even file offset). Payload bytes are taken 8 stream bits at a
   time — which means the raw bytes appear **pair-swapped** relative to
   the file. An odd `LEN` consumes one pad byte.

4. **`BTYPE = 1` (fixed Huffman) is rejected** with error −9, as is
   `BTYPE = 3`. The VISE compressor only emits stored and dynamic blocks.

5. **Post-final flush.** After a final block, whole prefetched words are
   returned to the input, so streams end on a 16-bit boundary. An
   extractor should report `consumed` as the even byte offset just past
   the last word containing stream bits.

Everything else (dynamic Huffman table encoding, length/distance tables,
the 3-bit code-length alphabet, `LEN/NLEN` one's-complement check) matches
RFC 1951.

### Reference pseudocode

```
reader: words = BE16 stream; bits LSB-first
loop:
    bfinal = bits(1)
    btype  = bits(2)
    if btype == 0:
        align to 16 bits
        len  = bits(16); nlen = bits(16)     # len ^ nlen == 0xFFFF
        emit next len bytes (8 stream bits each; pad to even len)
    elif btype == 2:
        read dynamic Huffman tables (RFC 1951)
        decode literal/length/distance symbols (RFC 1951 semantics)
    else:
        error(-9)                            # fixed & invalid rejected
    until bfinal
flush trailing partial word
```

### Sizes

Streams carry no in-band size; expected output and stored sizes come from
the catalog record (see [catalog-records.md](catalog-records.md)).
A well-formed stream satisfies `consumed == stored_size` and
`len(output) == expanded_size`.
