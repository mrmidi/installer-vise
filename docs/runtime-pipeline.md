# Runtime Pipeline (Installer Internals)

How the installer itself extracts a file — reconstructed from the PPC code
section of the embedded PEF (`/tmp/main_ppc.asm` equivalents; addresses are
virtual addresses from the reference build).

## End-to-end path for one record

```
sub_15000 (extraction entry)
    │
    ├─ record source check: runtime+120 vs word_6DFA4 (current source index)
    │     differs → sub_17564 + sub_13C6C: close current source,
    │     open next 90-byte source descriptor, read 44-byte source header
    │
    ├─ SetFPos(refnum, fsFromStart, runtime+110)      ← catalog +100
    │
    ├─ read runtime+90 bytes into buffer              ← stored size
    │
    ├─ sub_143AC (crypto gate):
    │     if BitTst(record+208, 6): sub_33878(buffer, len)   ← DES path (NOT USED here)
    │
    ├─ read-loop path:
    │     if (dword_6DF3C) sub_287C8(buffer, count)          ← ZipCrypto path (NOT USED here)
    │
    ├─ sub_444A8: out[i] = table[in[i]]               ← SUBST layer (ALWAYS for payload)
    │
    ├─ sub_15000 mode select: BitTst(record+142, 7)
    │     1 → raw/stored copy
    │     0 → VISE Dcmp ('Dcmp' #1005 PPC, #1004 68K fallback)
    │
    ├─ sub_14568 (chunk consumer)
    │     plain mode: write chunk to fork
    │     shared mode: BlockMoveData into cache; when offset == runtime+94,
    │       all members slice from the cache
    │
    └─ CRC: sub_44458 persistent state (dword_6DFBC), one state per record
          across both fork chunks; final compare against runtime+122
          → catalog +84. Mismatch → integrity alert.
```

## Runtime record ↔ serialized catalog mapping

`sub_7B4C` repacks the 194-byte serialized `FVCT` body into a 270-byte
runtime record; the field mappings below were individually traced (there is
no constant offset between serialized and runtime layouts):

| runtime | catalog | meaning |
|---|---|---|
| +114 | +104 | shared: data slice offset |
| +118 | +108 | shared: rsrc slice offset |
| +120 | +96 | source selector (hi16 index / lo16 inArchive) |
| +122 | +84 | record CRC32 |

Bit operations use Mac Toolbox `BitTst` semantics (bit 0 = MSB of the
byte), so `BitTst(record+208, 6)` tests mask `0x02` and
`BitTst(record+142, 7)` tests mask `0x01`.

## Crypto gates — present in code, unused in normal archives

### DES / eSellerate (`sub_143AC` → `sub_33878`)

* `sub_59BCC`: one DES block (IP via shift/mask tricks, 16 Feistel
  rounds, SP tables at `unk_6C08C`, key schedule = 16 round keys × 2 words).
* `sub_596F8`: mode wrapper — 0 = DES, 1 = DESX (XOR whitening), 2 = 3DES.
* `sub_33704`: descriptor → plain DES-ECB, 1×8-byte key.
* `sub_5BAAC`: rejects lengths not multiple of 8.
* Gated by `BitTst(record+208, 6)`; **none of the 1310 file records in the
  reference archive have this bit set** (flags byte values seen:
  0x08 dominant, 0x88/0x48/0x09 variants).

### ZipCrypto (`sub_287C8`)

* Classic PKZIP traditional encryption: `decrypt_byte()`
  (`(key2|2) * ((key2|2)^1) >> 8`), `update_keys`
  (`crc32`, `*134775813 + 1`, `crc32(key1>>24)`) — constants at
  `0x2605c`–`0x260d4`, seeds `0x12345678/0x23456789/0x34567890` at
  `0x260d8`, key state `dword_6E1B0/4/8` + CRC table `dword_6E1BC`.
* Password-check function at `0x26154` decrypts a 12-byte header and
  returns true iff decrypted bytes [10] and [11] are both zero.
* Gated by `dword_6DF3C` (the handle of resource `'PsWd'` #500 — a
  password resource). **The reference archive has no `'PsWd'` resource**;
  the gate never fires.

Consequence for extractors: implement the gates only if you also want to
read *other* VISE archives; for password-less archives like this one they
are dead code paths. The SUBST layer, by contrast, is **always** applied
to file payloads.

## Shared-block cache

Globals (`sub_14568` / `sub_15000`):

```
dword_6DFD0   base of the persistent expanded-block cache
dword_6DFB8   current write offset into the cache
dword_6DFAC   current block's archive offset (cache identity)
byte_6DFD8    shared mode active
byte_6DFD9    cache already populated for this block
```

Flow: the first member record decompresses the whole block into the cache
(Dcmp emits chunks; each is `BlockMoveData`-copied); when the write offset
reaches runtime+94 (= catalog +76, the block's expanded total), the block
is complete. Subsequent members skip decompression entirely and slice
directly:

```
data fork  = cache[ runtime+114 .. +114 + +98  )
rsrc fork  = cache[ runtime+118 .. +118 + +102 )
```

## Multi-source handling (`sub_13C6C`)

Sources are 90-byte descriptors indexed by `word_6DFA4`. On source
mismatch: `sub_17564(0, ...)` cleanup → `word_6DFA4 = record_source - 1` →
open next source (`sub_134F8`) or prompt for a volume → read 44-byte
source header → proceed. This is why `catalog +96 lo16 = 0` records must
not be read from the present file.
