# Reverse-engineering Installer VISE

This document describes how the Installer VISE archive format was
reverse-engineered and how the pieces fit together.

It is intentionally higher-level than the individual format notes in this
directory. For exact field layouts and codec details, see:

- [compression.md](compression.md)
- [catalog-records.md](catalog-records.md)
- [validation.md](validation.md)

The implementation was derived independently from Installer VISE binaries and
archive behavior, then validated against unrelated real-world installers using
their own embedded CRCs as a correctness oracle.

At a high level, the extraction path turned out to be:

```text
SVCT
  ↓
CVCT
  ↓
PACK
  ↓
FVCT / DVCT catalog records
  ↓
payload location / shared-block geometry
  ↓
SUBST byte permutation
  ↓
VISE word-oriented DEFLATE
  ↓
data fork + resource fork
  ↓
CRC32(data || rsrc)
```

The interesting part is that none of those layers was obvious from the raw
archive.

---

## 1. Container structure: `SVCT → CVCT → PACK`

Installer VISE archives begin with an `SVCT` header.

One of its stable fields is a big-endian pointer at `SVCT + 0x24` to the
catalog structure:

```text
SVCT
  +0x24 ──────────────┐
                      ↓
                    CVCT
                      ↓
                    PACK
```

`CVCT` describes the stored catalog span. Immediately after its header is a
`PACK` structure containing additional project/runtime metadata.

The exact contents behind `PACK` are not required for file extraction. They
appear to belong to the larger Installer VISE project/runtime system rather
than to the archive payload itself.

This was one of the first indications that VISE is not merely an archive
format with an installer UI attached to it. The archive is one subsystem of a
larger installation framework.

Some archives also contain an embedded PowerPC PEF near the beginning of the
file, while others do not. PEF presence is therefore not a reliable format
version discriminator.

Likewise, the `SVCT + 0x1C` payload-related field is non-zero in some archives
and zero in others. Extraction does not depend on it.

---

## 2. The catalog: `FVCT` and `DVCT`

After decoding the catalog, the records relevant to extraction are:

```text
FVCT    file record
DVCT    directory record
```

Other record types contain installer conditions/actions and are not files.

The useful part of `FVCT` is remarkably stable across the archives tested.
Among the important fields are:

```text
+0x0C   flags
+0x2C   file type
+0x30   creator

+0x44   stored data size / shared-block stored size
+0x48   expanded data size / data slice length
+0x4C   stored resource size / shared-block expanded size
+0x50   expanded resource size / resource slice length
+0x54   CRC32

+0x60   source selector
+0x64   archive/block offset
+0x68   shared data slice offset
+0x6C   shared resource slice offset

+0x7A   filename length byte
```

The tail of an `FVCT` record is not fixed across VISE generations.

Six unrelated installers produced three different filename offsets:

| Archive | Approx. year | Catalog | Name offset |
|---|---:|---|---:|
| Cythera | 1999 | raw | `0xBA` |
| Driver Installer | ~2001 | DEFLATE | `0xBE` |
| Toast | ~2002 | DEFLATE | `0xBE` |
| Minolta | 2004 | DEFLATE | `0xC6` |
| Crescendo | 2005 | DEFLATE | `0xC6` |
| Installer VISE 6.0.1 | ~2006 | DEFLATE | `0xBE` |

The important discovery was that the parser does not need to hardcode any of
these layouts.

`FVCT + 0x7A` contains the filename length. Using that value together with the
record boundary or NUL terminator allows the actual filename position to be
derived from the catalog itself.

So the parser treats the stable core and the variable record tail separately.

That removed an early and incorrect assumption that there was one
"early" and one "late" `FVCT` layout.

---

## 3. Payload transform: `SUBST → DEFLATE`

Reading the payload bytes directly does not produce a valid DEFLATE stream.

IDA analysis of the Installer VISE host showed an unconditional transform
before the decompressor:

```text
stored payload
    ↓
256-byte substitution table
    ↓
Dcmp
```

The substitution operation is simply:

```text
output[i] = TABLE[input[i]]
```

The table is a fixed 256-byte permutation. It is stateless and identical for
all payload streams tested.

After applying this substitution, the data becomes recognizable as the input
expected by VISE's `Dcmp` decompressor.

The catalog itself does **not** use the substitution layer.

---

## 4. VISE's word-oriented DEFLATE

VISE includes its own decompressor resources:

```text
'Dcmp' #1004    68K
'Dcmp' #1005    PowerPC
```

Reverse-engineering `Dcmp` revealed that the compression algorithm is very
close to RFC 1951 DEFLATE, but its input framing is unusual.

The essential difference is:

```text
VISE reads big-endian 16-bit words,
then consumes bits LSB-first from each word.
```

For the common dynamic-Huffman case, this is equivalent to taking an ordinary
raw DEFLATE byte stream and swapping every adjacent pair of bytes.

For example:

```text
VISE representation:

    12 34  56 78  9a bc

standard DEFLATE byte order:

    34 12  78 56  bc 9a
```

Dynamic Huffman coding, literal/length symbols and distance coding otherwise
follow normal DEFLATE semantics.

There are, however, important differences around stored blocks:

- `BTYPE=0` aligns to a **16-bit** boundary rather than an 8-bit boundary.
- `LEN` and `NLEN` are consumed as 16-bit stream units.
- an odd stored payload consumes a pad byte.
- `BTYPE=1` fixed-Huffman blocks are rejected by the original Dcmp.
- `BTYPE=3` is also rejected.
- after the final block, prefetched complete words are returned so the
  reported compressed span ends on a 16-bit boundary.

Because of these details, Installer VISE is not simply "DEFLATE with swapped
bytes".

The project therefore keeps an exact Python implementation of the VISE
decoder in `inflate_span()`.

---

## 5. Shared compressed blocks

A major part of the archive initially looked confusing because many `FVCT`
records point to the same compressed offset.

They are not duplicate files.

VISE can place many files into one compressed pool:

```text
compressed shared block
        ↓
      Dcmp
        ↓
┌─────────────────────────────────────┐
│ file A data                         │
│ file A resource fork                │
│ file B data                         │
│ file B resource fork                │
│ file C data                         │
│ ...                                 │
└─────────────────────────────────────┘
```

Each shared `FVCT` then describes slices within that expanded pool.

For shared records:

```text
+0x44   stored size of the whole compressed block
+0x48   this file's data length
+0x4C   total expanded block size
+0x50   this file's resource-fork length
+0x64   compressed block offset
+0x68   data slice offset
+0x6C   resource slice offset
```

The resource offset follows the data slice:

```text
resource_offset = data_offset + data_length
```

Members are laid out sequentially as:

```text
data, resource, data, resource, ...
```

A shared block is therefore decompressed once and then sliced for every member.

This matters considerably for real installers. The ~83 MB Driver installer,
for example, contains 273 shared blocks.

---

## 6. CRC32 became the correctness oracle

Every file record carries a CRC at `FVCT + 0x54$.

Reverse-engineering the runtime showed that this is standard reflected
IEEE CRC-32, with one persistent state spanning both forks:

```text
CRC32(data_fork || resource_fork)
```

Equivalent Python:

```python
crc = zlib.crc32(data)
crc = zlib.crc32(rsrc, crc) & 0xffffffff
```

This was enormously useful during reverse engineering.

Instead of judging an interpretation by whether extracted bytes merely
"looked plausible", every hypothesis could be tested against the CRC stored
by the original installer.

That helped distinguish, among other things:

- correct vs incorrect shared-block slicing,
- data/resource ordering,
- true record offsets,
- source-selection fields,
- and false-positive catalog interpretations.

Across the current validation corpus:

```text
3260 / 3260 extracted files pass their original Installer VISE CRC.
```

---

## 7. The unexpected native-zlib fast path

The first correct implementation used the exact Python VISE decoder for every
payload.

It worked, but extracting the 83 MB Driver installer took roughly:

```text
84 seconds on an Apple M4
```

Profiling made the reason obvious: dynamic Huffman decoding was happening one
bit and symbol at a time in Python.

The exact reverse engineering then suggested a much simpler fast path.

For the overwhelmingly common dynamic-Huffman streams:

```text
stored bytes
   ↓
SUBST
   ↓
swap adjacent bytes
   ↓
standard raw DEFLATE
   ↓
zlib
```

In code, conceptually:

```python
buf = bytearray(subst(data))
buf[0::2], buf[1::2] = buf[1::2], buf[0::2]

out = zlib.decompress(buf, wbits=-15)
```

The production extractor therefore uses two decoders:

```text
decode_block_data()
       │
       ├── try inflate_native()
       │       SUBST → pair-swap → native zlib
       │
       └── on incompatibility
               ↓
           inflate_span()
           exact VISE decoder
```

This deliberately does **not** try to emulate VISE stored blocks inside
zlib. If native zlib cannot decode a stream, extraction simply falls back to
the exact implementation.

The result on the Driver installer:

```text
exact Python decoder     ~84 s
native fast path          ~2.4 s
```

All six validation archives still produce exactly the same results:

```text
3260 / 3260 CRC verified
```

The exact decoder remains important: besides supporting unusual streams, it
provides authoritative consumed-byte accounting and documents the real VISE
bitstream semantics.

Ironically, building the precise custom decompressor was what made it possible
to prove that most real-world VISE payloads are only one byte permutation
away from standard DEFLATE.

---

## 8. VISE is larger than the archive format

The file-extraction path is only part of Installer VISE.

Reverse-engineering the host also exposed machinery for:

```text
multi-volume / multi-source installations
condition and action records
project/script data behind PACK
embedded executable code
progress and I/O callbacks
raw/stored fork mode
password protection
DES/eSellerate protection
traditional ZipCrypto
```

These features explain much of the apparent complexity of the format.

VISE appears to have been a full installation authoring and runtime system,
with the archive representation acting as an internal serialization format
for compiled installer projects.

The extractor intentionally implements only the pieces required to recover
files correctly.

---

## 9. Validation corpus

The current implementation has been tested against six unrelated archives
spanning approximately seven years:

| Archive | Year | Size | Catalog | Files verified |
|---|---:|---:|---|---:|
| Cythera | 1999 | 6.8 MB | raw | 33/33 |
| Driver Installer | ~2001 | 83 MB | DEFLATE | 1665/1665 |
| Toast | ~2002 | 2.6 MB | DEFLATE | 13/13 |
| Minolta | 2004 | 12 MB | DEFLATE | 1288/1288 |
| Crescendo | 2005 | 392 KB | DEFLATE | 9/9 |
| Installer VISE 6.0.1 | ~2006 | 7.8 MB | DEFLATE | 252/252 |

Total:

```text
3260 / 3260 CRC verified
```

The samples exercise:

- raw and compressed catalogs,
- three different `FVCT` filename layouts,
- archives with and without embedded PEF code,
- plain files,
- resource forks,
- large numbers of shared blocks,
- and source records referring to unavailable distribution media.

This does not prove support for every Installer VISE release or feature.

In particular, the following remain interesting targets:

- a complete multi-volume distribution,
- raw/stored fork mode,
- `'PsWd'` password-protected archives,
- DES/eSellerate-protected payloads,
- and VISE Lite variants.

---

## 10. What made the reverse engineering work

Three sources of evidence complemented each other:

```text
IDA / original runtime
    tells us what the installer does

archive experiments
    tell us which serialized layouts vary

CRC verification
    tells us whether the interpretation is actually correct
```

Any one of these alone would have been much weaker.

Decompiler output provided semantics but not necessarily format boundaries.
Archive comparison exposed version differences but could not explain them.
Plausible-looking extracted files were not sufficient evidence.

The combination produced a format model that survived six unrelated
installers and thousands of independently verified records.
