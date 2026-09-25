# Container Layout

All offsets below are from the reference archive (~12 MB). Field notation: `>` = big-endian (classic Mac).

## SVCT header — file offset `0x00`, 44 bytes (0x2C)

```
offset  size  field                       reference value
0x00    4     magic "SVCT"                53 56 43 54
0x04    4     unknown/version?            (unidentified)
0x08    4     id/guid word A              0x7FEBC9F4
0x0C    4     id/guid word B              0xBCCA9A2F
0x1C    4     first-payload offset?       0x000DB6A8   ← payload region starts here
0x24    4     catalog offset              0x00B69E24   ← CVCT header
0x2C          (header ends; PEF starts)
```

Only +0x24 (`catalogOffset`) and +0x1C were load-bearing for extraction;
the id words at +0x08/+0x0C are likely a volume-set GUID (candidate DES key
material in older analyses — see [runtime-pipeline.md](runtime-pipeline.md)).

## Embedded PEF — file offset `0x30`

Standard PEF container (`"Joy!peffpwpc"`). Header at 0x30, section
headers at 0x58 (28-byte stride, 3 sections in the reference archive):

```
section  kind             file offset      stored size
0        0 = code         0x21C0           0x6820C
1        2 = pattern-init 0x6A3A0           0x593C
2        4 = loader       0xB0             0x2108
```

The code section contains the entire extraction runtime
(see [runtime-pipeline.md](runtime-pipeline.md)).
The resource fork of the installer file carries the UI resources plus the
decompressors `'Dcmp'` #1004 (68K) and #1005 (PPC).

## Payload region — `0xDB6A8` … `0xB69E24`

All installable file forks, as concatenated substituted-DEFLATE streams.
Structure (all values are u32 BE fields inside catalog records):

```
[shared block 0][shared block 1]...[plain record streams][link records]
```

Tiling invariants (validated 62/62 blocks):

```
block[n].offset + block[n].stored == block[n+1].offset
first block starts at SVCT+0x1C (+0x2C in one reading: 0xDB6D4 = 0xDB6A8 + 0x2C)
last block ends exactly at catalogOffset (0xB69E24)
```

The payload region ends with a few "tail" plain records
(`PkgInfo`, `InfoPlist.strings`, `loginwindow.plist`-style plists).

## CVCT catalog — file offset `catalogOffset` (0xB69E24)

```
offset size field              reference value
0x00   4    magic "CVCT"       43 56 43 54
0x04   4    body length        0x000094C2
0x08   4    record count       0x00000001?  (see note)
0x0C   4    reserved           0x00000000
0x10   2    count              0x0571 = 1393  (all records: FVCT+DVCT+cond)
0x12   ...  (rest of 20-byte header)
```

Note: the exact split of count fields between +0x08/+0x10 was not pinned
down further; extractors should parse the catalog body sequentially by
signature instead of relying on counts.

## PACK header — `catalogOffset + 0x14` (0xB69E38), 0x50 bytes

```
0x00  4  "PACK"
0x04  4  "BBrd"
0x08  4  "CODE"
0x0C  4  "BDIR"
0x10  4  "PROJ"
0x14  4  "INDN"
0x18  4  "DfIL"
0x1C  4  catalog body length (0x94C2)
0x20  4  record count (0x571)
...
0x28  7 × u32 absolute pointers (script/table data): 0xB2AFCE, 0xB2B731,
      0xB2B803, 0xB2B839, 0xB2B83F, 0xB2E0A3, 0xB2E0F4
0x50     catalog DEFLATE stream starts (0xB69E88)
```

Pointer 0 (`0xB2AFCE`) is the **installer script stream** — a plain (not
substituted) DEFLATE stream that expands to VISE script bytecode
(alphabet bytes 0–7 ≈ 3-bit-packed opcodes). It is *not* needed for
extraction; the catalog records are sufficient.

## Catalog stream — `0xB69E88` … EOF

Plain VISE word-aligned DEFLATE (see [compression.md](compression.md)),
**no substitution**. Expands to the catalog body (298,519 bytes here),
which is a flat sequence of variable-length records:

```
"FVCT" + 194-byte body    file record (see catalog-records.md)
"DVCT" + body             directory record
others                    condition/action records (flags bit31 at +12)
```

Records are variable-length; the reference extractor scans for the
signature and takes the body length by record kind. `FVCT` names are
Pascal/length-prefixed-ish at body offset 0xC6 onward, NUL-terminated,
MacRoman encoded.
