# Format Overview

## What an Installer VISE 3.x archive is

A single-file classic-Mac installer. Despite being distributed inside a
StuffIt wrapper, the installer file itself is **not** StuffIt — it is a
custom MindVision container that embeds, in order:

1. a small plain header (`SVCT`),
2. a complete PowerPC (PEF) installer application,
3. the transformed/compressed payload of every installable file,
4. a compressed catalog (`CVCT`) describing the payload,
5. a small `PACK` header in front of the catalog stream.

## The stack

```
┌─────────────────────────────────────────────────────────┐
│ 0x00  SVCT header (44 bytes)                            │
│ 0x30  PEF container ("Joy!peffpwpc")                    │
│       ├─ section 0: code                                │
│       ├─ section 1: pattern-initialized data            │
│       └─ section 2: loader                              │
│ 0xDB6A8  payload region (all installable file forks)    │
│ 0xB69E24 CVCT catalog header                            │
│ 0xB69E38 PACK header (0x50 bytes)                       │
│ 0xB69E88 catalog DEFLATE stream (ends exactly at EOF)   │
└─────────────────────────────────────────────────────────┘
```

## How file data is stored

Two orthogonal mechanisms compose into the final pipeline:

1. **Catalog → record.** The DEFLATE-compressed catalog expands to the
   CVCT body: a flat sequence of variable-length records
   (`FVCT` = file, `DVCT` = directory, plus condition/action records).
   Each `FVCT` record describes one *logical file fork* (data fork and/or
   resource fork) and points into the payload region.

2. **Payload → bytes.** File-payload streams are **not plain DEFLATE**.
   They are stored as:

   ```
   archive bytes
       → 256-byte substitution table (sub_444A8, layer "SUBST")
       → VISE word-aligned DEFLATE ('Dcmp' #1005 / #1004, layer "DCMP")
       → original bytes
   ```

   This substitution layer is why naive DEFLATE scanning finds **zero**
   streams in an 11 MB payload region while the catalog itself decodes
   fine — the catalog stream is *not* substituted.

   Both layers are stateless; there is **no encryption** in a normal
   archive (see [runtime-pipeline.md](runtime-pipeline.md) for the
   DES/eSellerate and ZipCrypto gates that exist in the code but are
   unused here).

## Shared blocks (deduplication)

Many files — here 1229 of 1293 records — are members of a **shared
block**: one substituted-DEFLATE stream per block that expands to a
single buffer containing every member's data fork and resource fork
back to back (see [catalog-records.md](catalog-records.md)).
The runtime decompresses a block once into a cache and slices each
member file out of the expanded buffer.

```
shared block @ cat+100, stored = cat+68
        │ subst + DEFLATE
        ▼
expanded buffer, total = cat+76
┌───────────────┬───────────────┬───────────────┬───────┐
│ rec0 data     │ rec0 rsrc     │ rec1 data     │ ...   │
└───────────────┴───────────────┴───────────────┴───────┘
        ▲ cat+104       ▲ cat+108
        (offset)        (offset = data_off + data_len)
        len cat+72      len cat+80
```

Plain (non-shared) records store two independent streams instead:
data fork at `cat+100` (stored `cat+68` → expanded `cat+72`), then
resource fork at `cat+100 + cat+68` (stored `cat+76` → expanded `cat+80`).

## Verification story

Every structural claim was tested against the archive and is listed in
[validation.md](validation.md). Highlights:

* 62/62 shared blocks decode with `consumed == stored`, `len == total`,
  and slice offsets that tile the expanded buffer **exactly**.
* 1288/1288 file records verify against a single combined
  `CRC32(data_fork ‖ resource_fork)` stored at record offset +84.
* The catalog stream ends precisely at EOF (span check).
