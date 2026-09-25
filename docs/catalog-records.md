# Catalog Records

The decoded catalog body is a sequence of records. Each starts with a
4-byte signature. Extraction needs `FVCT` (file) and `DVCT` (directory);
all other records (17 in the reference archive) are condition/action
records used by the installer script and must be skipped.

## Distinguishing fields

```
+12  flags (u32 BE)
       bit31 (0x08000000): condition/action record — skip
       bit28 (0x10000000): shared-block member
+44  file type     (4CC)
+48  creator       (4CC)
0xC6 name (MacRoman, NUL-terminated)
```

## `FVCT` file record — 194-byte body after the signature

The field meaning is **overloaded by mode**. `plain` = record with its own
streams; `shared` = member of a shared block (flags bit28 set).

```
offset  size  plain meaning                       shared meaning
+64     4     (padding/sync, unused)
+68     4     stored size, data fork stream       stored size of the whole block
+72     4     expanded size, data fork            length of this record's data slice
+76     4     stored size, resource fork stream   expanded size of the whole block
+80     4     expanded size, resource fork        length of this record's rsrc slice
+84     4     record CRC32  (see below)           record CRC32  (same rule)
+88     4     (unknown; no runtime consumer found)   (same; do not use)
+92     4     (unnamed)
+96     4     source selector:  hi16 = source index
                                                  lo16 = 1 → stored in this archive
                                                          0 → other distribution disk
+100    4     archive offset of data stream       archive offset of the shared block
+104    4     (unnamed; 0 in plain records)       offset of data slice in expanded block
+108    4     (unnamed; 0 in plain records)       offset of rsrc slice (= data_off + data_len)
```

Reference-archive field verification status:

| claim | verified |
|---|---|
| shared +104 = data slice offset (equals running cursor) | 1196/1196 records |
| shared +108 = +104 + +72 (rsrc slice offset) | 33/33 slices |
| shared +76 = Σ(member data lens + rsrc lens) = block expanded total | 62/62 blocks |
| block tiling: block_offset(+100) + stored_size(+68) = next block's +100 | 62/62 |
| +96 lo16 = inArchive flag (0 ⇔ the 5 missing records) | 1293/1293 |

### CRC rule (single, uniform)

```
record_crc32 = CRC32( data_fork_bytes ‖ resource_fork_bytes )
```

* One CRC **per record**, not per fork — the runtime keeps a single CRC
  state across the two fork iterations (`sub_44458`, persistent state in
  `dword_6DFBC`, compared against runtime `record+122`).
* Standard reflected IEEE CRC-32 (`zlib.crc32`) — the installer's own
  256-entry table at `dword_6B0A8` is the canonical one
  (`0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, ...`).
* Records without a resource fork therefore simply verify
  `CRC32(data_fork)`.
* Serialized +84 = this value; runtime offset +122.

## `DVCT` directory record

Carries a directory name (same layout region as `FVCT` names) and no
payload fields. The reference archive has 83; they define the install
tree (see the `directories.txt` output).

## Multi-source archives

`+96 hi16` is an index into a runtime table of **90-byte source/volume
descriptors** (`sub_13C6C`). When a record's source differs from the
currently open one, the runtime closes, opens the next source, reads its
44-byte header, then seeks to `+100` *inside that source*. Extractors
should treat any record with `+96 lo16 == 0` (or `hi16 != current`) as
not stored in the present file.

Reference archive: 1288 records have `lo16 == 1` (all extract from this
file), 5 have `lo16 == 0` (scanner profiles and a shared library — a second
distribution disk that is not contained in the shipping archive).
