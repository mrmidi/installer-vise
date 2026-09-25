# Validation Log

Every structural claim in these documents, with the experiment that
established it against the reference archive. "Catalog" = the decoded
CVCT body (298,519 bytes); "payload" = the archive's file-payload region.

## Engine correctness

| claim | evidence |
|---|---|
| VISE DEFLATE engine (BTYPE 0/2, word-aligned, LSB-first) is correct | catalog stream decodes bit-exactly: 298,519 bytes, span `0x94C2`, ends precisely at EOF; identical to an independently produced decode |
| BTYPE 1/3 rejection matches the Dcmp | mirrored from Dcmp #1005 control flow; no valid stream in the archive uses them |
| overlapping LZ77 copies | byte-wise copy; fix was required — slice-based copy silently truncated run copies |
| SUBST table is a permutation | 256 distinct values verified programmatically |

## Payload transform

| claim | evidence |
|---|---|
| file payloads are SUBST→DEFLATE; raw scanning finds nothing | full-file dynamic-header sweep calibrated on the catalog: 0 hits in 11 MB payload; all probes fail pre-SUBST |
| SUBST applies to every payload stream | first probe block (0xDB6D4): `consumed 23418 == stored 23418`, output 52795 == catalog expected; then 4/4 further probes identical |
| SUBST does **not** apply to the catalog stream | catalog decodes without it (and fails with it) |

## Catalog model

| claim | evidence |
|---|---|
| record count 1393 (1310 FVCT + 83 DVCT), 17 condition/action records | sequential signature parse of the catalog body |
| record stride / name offset (+0xC6, NUL-terminated MacRoman) | names match visible file inventory |
| +12 bit31 = condition/action | count matches the installer's script-gated records; skipping them yields exactly the installable set |

## Shared-block architecture

| claim | evidence |
|---|---|
| blocks tile the payload exactly | 62/62 blocks: `offset + stored == next offset`; last block ends at `catalogOffset` |
| +68 = block stored size, +76 = block expanded total | 62/62 streams: `consumed == +68`, `len(out) == +76`; Σ(member lens) == +76 |
| +104 = data slice offset (interleaved layout) | 1196/1196 records equal the running cursor |
| +108 = +104 + +72 (rsrc slice offset) | 33/33 slices |
| 33 shared rsrc slices are real resource forks | decode to valid fork headers (e.g. 410-byte BNDL forks), not to the empty 286-byte template — after fixing the slice offset source |
| interleaved (data,rsrc) per record is the layout | chosen among interleave/grouped/brute hypotheses by CRC vote: interleave uniquely consistent with +104 |

## CRC semantics

| claim | evidence |
|---|---|
| CRC32 is standard zlib (reflected IEEE) | installer table dump starts `00000000 77073096 EE0E612C 990951BA` |
| one CRC per record over data‖rsrc | 37/37 plain records with rsrc match `crc32(data‖rsrc)` (data-only failed); 33/33 shared with-rsrc match; the code shows one persistent CRC state across both fork iterations |
| final extractor | 1288/1288 records `crc_ok`, 0 `crc_bad`, 0 fails |
| spot-check via manifest (duplicates incl.) | 16/16 across `Bitte lesen`, `Info.plist` ×3, `PkgInfo` ×4, `Plug-in.8ba` ×3, `Utility`, `CarbonLib`, `Queen20Lib` ×2, `DS_Elite2.bin` |

## Source selection

| claim | evidence |
|---|---|
| +96 hi16 = source index, lo16 = inArchive flag | histogram over 1293 records: `{0x30001:335, 0x40001:898, 0x30000:4, 0x10001:33, 0x20001:1, 0x10000:1, 0x1:18, 0x50001:3}`; lo16=0 set = exactly the 5 non-extractable records |
| the 5 lo16=0 records are not in this file | their +100 offsets point into the first 64 KB (PEF code region) — meaningless for payloads |
| the second disk is not in `Ds115d.sit` | the .sit contains exactly one member: this same installer |

## Crypto gates unused

| claim | evidence |
|---|---|
| DES never applied | `BitTst(record+208, 6)` false for 1310/1310 FVCT bodies (byte @+71 values: 0x08 ×1278, 0x88, 0x48, 0x09 …) |
| ZipCrypto never applied | gate requires `'PsWd'` #500; resource fork inventory (318,835-byte fork, 28 types) contains no such type |
| substitution is not crypto-adjacent | it is a plain permutation on payload bytes, bypassed for the catalog |

## Negative results worth keeping

* **`+88` is unresolved**: early hypotheses (resource CRC slot, "inblk"
  offset) were disproven — low values at +88 are just low CRC32 bytes from
  +84 wrapping. No runtime consumer reads +88. Treated as **unknown**.
* **No hidden codecs**: the installer's own resource fork contains only
  Dcmp #1004/#1005; no second decompressor exists.
* **No password**: no `'PsWd'` resource; the ZipCrypto gate is dead code.
* **`sub_15000`'s `+142 bit7` (stored/raw) mode exists** but is unused in
  this archive (no record takes the raw path); extractors can ignore it,
  but should be aware VISE archives in general may store raw forks.
