# Installer VISE 3.x — Format Documentation

Reverse-engineered documentation of the **Installer VISE 3.x** archive format
(MindVision Installer VISE, classic Mac OS), reconstructed end-to-end from
multiple real archives spanning 1999–2006.

Everything here was derived by static analysis of the installer PEF (IDA),
the embedded decompressor resources (`'Dcmp'` #1004 68K / #1005 PPC), and
validated exhaustively across six independent reference archives — final
result **3260/3260 file records CRC32-verified, 0 failures**.

## Document map

| Document | Contents |
|---|---|
| [format-overview.md](format-overview.md) | Big picture: container stack, payload pipeline, verification summary |
| [container-layout.md](container-layout.md) | SVCT header, embedded PEF, payload region, CVCT, PACK header, catalog stream — with real offsets |
| [catalog-records.md](catalog-records.md) | FVCT/DVCT record layouts, the overloaded field table (plain vs shared-block), flags, CRC rule, source field |
| [compression.md](compression.md) | The VISE word-aligned DEFLATE variant (complete algorithm spec) + the byte-substitution layer |
| [runtime-pipeline.md](runtime-pipeline.md) | How the installer runtime extracts files: record→runtime mapping, shared-block cache, crypto gates (DES / ZipCrypto) and why they are unused here |
| [validation.md](validation.md) | Every claim in these docs and the experiment that proved it |
| [reverse-engineering.md](reverse-engineering.md) | Narrative: how the format was reverse-engineered end-to-end |

## Reference archive numbers

| Item | Value |
|---|---|
| File records | 1293 (1229 shared-block members + 64 plain) |
| Shared blocks | 62, exact-tiling verified |
| Directories (DVCT) | 83 |
| Condition/action records | 17 (skipped by extractors) |
| Extracted | 3260 files CRC32-verified across 6 archives |
| Not in this archive | 5 records (`inArchive = 0`): belong to a second distribution disk |

## Implementations

- `installer_vise/` (this package) — clean, typed extractor with native zlib fast path.
- Historical/research code: `../vise-tool/` (probe scripts, not for sharing).

## Licensing note

The *format documentation* and *code* in this package are yours to share.
The **archive contents** remain copyright of their respective publishers —
distribute only what you have a right to.
