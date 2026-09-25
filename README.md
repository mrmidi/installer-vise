# installer-vise

A clean, dependency-free Python extractor for **Installer VISE 3.x**
archives (MindVision, classic Mac OS) — reverse-engineered end-to-end from
a real archive with every extracted file verified by the installer's own CRC.

```text
1288/1288 file records extracted, CRC32-verified, 0 failures
```

## Why this exists

Installer VISE archives are *not* StuffIt and not plain DEFLATE:

* file payloads are stored as **byte-substituted, word-aligned DEFLATE**
  (a VISE-specific DEFLATE variant that rejects fixed-Huffman blocks and
  aligns stored blocks to 16 bits), and
* most files are members of **shared blocks** — one compressed stream that
  expands to a pool of concatenated forks, sliced per record.

The full format is documented in [`docs/`](docs/README.md), including the
runtime pipeline, catalog record layout, and a claim-by-claim validation
log.

## Install

```bash
pip install .            # or: uv pip install .
```

Python 3.10+, standard library only.

## CLI

```bash
installer-vise inspect "SomeInstaller"
installer-vise extract  "SomeInstaller" -o extracted/
```

Exit codes: `0` success · `1` not a VISE archive · `2` extraction completed
with per-record failures.

## Library use

```python
from installer_vise import Archive, extract_archive, Summary

arc = Archive.open("SomeInstaller")
print(arc.info.size, "bytes")

summary: Summary = extract_archive(arc, "out/")
print(summary.ok, "ok,", summary.failed, "failed")
```

Low-level access:

```python
from installer_vise import inflate, inflate_span, subst

stream = subst(arc.data[block.offset : block.offset + block.stored])
blob, consumed = inflate_span(stream)     # VISE DEFLATE -> bytes
```

## What gets extracted

* every file record's **data fork** and, where present, **resource fork**
  (written as `<name>.rsrc` sidecars),
* the catalog's directory list, and
* a `manifest.csv` mapping each catalog record to its written file,
  type/creator, flags, source block and verification status.

Records belonging to other disks of a multi-disc distribution
(`inArchive = 0`) are reported in the manifest as `OTHER SOURCE` rather
than guessed at.

## Package layout

```
src/installer_vise/
    subst.py      byte-substitution layer (payload de-obfuscation)
    deflate.py    VISE word-aligned DEFLATE decoder + stored-block encoder
    catalog.py    catalog record parsing (FVCT / DVCT)
    archive.py    container parsing (SVCT / PEF / CVCT / PACK)
    extract.py    extraction pipeline, CRC verification, manifest
    cli.py        command-line interface
docs/             format specification (6 documents)
tests/            pytest suite (synthetic archives + real-file regression)
```

## Scope notes

* DES/eSellerate and ZipCrypto gates exist in the VISE runtime but are
  unused in ordinary archives; they are documented but not implemented.
* `'PsWd'` password-protected archives are not supported (none was
  available for analysis).
* Raw/stored fork mode (`record+142 bit7`) is unused by this archive
  family and currently unimplemented.

## License

MIT for the code and format documentation. Extracted archive *contents*
remain the copyright of their respective publishers.
