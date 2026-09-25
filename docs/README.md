# Installer VISE 3.x — Format Documentation

Reverse-engineered documentation of the **Installer VISE 3.x** archive format
(MindVision Installer VISE, classic Mac OS), reconstructed end-to-end from a
real archive (~12 MB, ~2004 era).

Everything here was derived by static analysis of the installer PEF (IDA),
the embedded decompressor resources (`'Dcmp'` #1004 68K / #1005 PPC), and
validated exhaustively against the archive itself — final result
**1288/1288 file records CRC-verified, 0 failures**.

## Document map

| Document | Contents |
|---|---|
| [format-overview.md](format-overview.md) | Big picture: container stack, payload pipeline, verification summary |
| [container-layout.md](container-layout.md) | SVCT header, embedded PEF, payload region, CVCT, PACK header, catalog stream — with real offsets |
| [catalog-records.md](catalog-records.md) | FVCT/DVCT record layouts, the overloaded field table (plain vs shared-block), flags, CRC rule, source field |
| [compression.md](compression.md) | The VISE word-aligned DEFLATE variant (complete algorithm spec) + the byte-substitution layer |
| [runtime-pipeline.md](runtime-pipeline.md) | How the installer runtime extracts files: record→runtime mapping, shared-block cache, crypto gates (DES / ZipCrypto) and why they are unused here |
| [validation.md](validation.md) | Every claim in these docs and the experiment that proved it |

## Reference archive numbers

| Item | Value |
|---|---|
| File records | 1293 (1229 shared-block members + 64 plain) |
| Shared blocks | 62, exact-tiling verified |
| Directories (DVCT) | 83 |
| Condition/action records | 17 (skipped by extractors) |
| Extracted | 1288 files CRC32-verified, 98 real resource forks, 40 MB |
| Not in this archive | 5 records (`inArchive = 0`): belong to a second distribution disk |

## Implementations

- `installer_vise/` (this package) — clean, typed, stdlib-only extractor.
- Historical/research code: `../vise-tool/` (probe scripts, not for sharing).

## Licensing note

The *format documentation* and *code* in this package are yours to share.
The **archive contents** remain copyright of their respective publishers —
distribute only what you have a right to.
