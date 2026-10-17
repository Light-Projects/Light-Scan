# LBN — Light Binary Notation

> **Module:** `lib/lbn.c`, `lib/lbn.h`
> **Part of:** **LightPacket** — the packet capture and serialization library of the **Light-Projects**.

---

## 1. What LBN is

**LBN** (**Light Binary Notation**) is the lightweight, self-contained, packet-oriented
file format used by the LightPacket library. It is designed to do one job well: **store
a sequence of raw packet byte blobs on disk, optionally compressed, and read them back
byte-for-byte, with as little ceremony as possible.**

It is *not* a capture format. It does not know about interfaces, link types,
timestamps-in-nanoseconds, name resolution, statistics blocks, or any of the things a
real capture file needs. If you want those, use PCAPNG (see §2).

LBN gives you:

- A tiny, fixed header.
- Per-packet records with an explicit on-disk length **and** an explicit uncompressed
  length.
- Optional zlib compression, per file.
- A CRC over the header fields so corruption is caught early.
- A versioning scheme that lets the reader support **old minor versions** while the
  writer always emits the **newest minor version it knows**.

That is it. The whole reader and writer fit in one `lbn.c` file.

---

## 2. When to use LBN vs PCAP vs PCAPNG

Be honest with yourself about what your file needs to do:

| You need… | Use |
|---|---|
| To store raw packet bytes for your own program to read back later | **LBN** |
| Interoperability with Wireshark / tcpdump / `libpcap` | PCAP (classic) |
| Multiple interfaces, per-packet interface IDs, nanosecond timestamps, options, comments, and future extensibility | **PCAPNG** |
| A small, human-inspectable, self-describing, *maintainable* format you fully control | **LBN** |

- **LBN** is deliberately *less* capable than PCAP. That is the point. It has no
  per-packet metadata beyond a timestamp and a pair of lengths, no interface table, no
  options. In exchange it is trivial to implement, trivial to audit, and it does not
  silently grow a new block type every two years.
- **Classic PCAP** is a fixed 24-byte header plus fixed 16-byte per-packet headers. It
  is also small, but it is endian-sensitive in a way that has caused decades of
  confusion, and it has no notion of compression or of an uncompressed length.
- **PCAPNG** is the format you want when the capture itself is the product — when you
  need to ship a file that other tools can open and that can carry per-interface
  metadata, comments, and future block types. It is more complex on purpose.
  LightPacket ships a `pcapng.c` reader/writer too, and you should use it whenever
  "a capture file" is what you actually mean.

Rule of thumb inside LightPacket:

> If the file is an internal artifact that only LightPacket reads and writes, use **LBN**.
> If the file is meant to leave the program — to be opened in Wireshark, archived,
> shared — use **PCAPNG**.

---

## 3. Versioning rules for LightPacket I/O modules

These rules apply to **every** file format that LightPacket owns (LBN today; any future
format the project adds). They exist so that writers and readers can evolve
independently without ever producing files that cannot be read.

### 3.1 Version numbers have two parts

```
MAJOR.MINOR
```

- **MAJOR** changes when the on-disk layout changes in a way that is **not backward
  compatible** — an old reader cannot parse a new file, and a new reader cannot parse
  an old file without explicit compatibility code.
- **MINOR** changes when the layout gains something **backward compatible** — a new
  reader can still read old files, and the change is additive or the old behaviour is
  preserved.

### 3.2 The writer rule

> **A writer MUST always emit the newest MINOR version of the newest MAJOR version it
> supports.**

It does **not** get to write old versions "for compatibility". Compatibility is the
reader's job (§3.3). This keeps the writer simple and guarantees that every file
produced by any current LightPacket binary uses the current, best-understood layout.

In practice this means: when you fix a layout bug (as we did in §5), you bump MINOR,
update the writer, and you are done. You do not add a `write_old_format` option.

### 3.3 The reader rule, same MAJOR

> **A reader MUST be able to read every MINOR version of the MAJOR version it
> targets.**

If a reader is written for `LBN 1.x`, it must accept `LBN 1.0` and `LBN 1.1` — and any
future `1.y` where `y` is at most the highest minor it was built against. It may
*refuse* to read a higher minor than it knows (that is the "this file is newer than me,
upgrade your LightPacket" case), but it must never silently misparse an old one.

### 3.4 The reader rule, different MAJOR

> **A reader MAY refuse any file whose MAJOR version differs from the one it targets.**

Supporting a previous MAJOR is optional and must be an explicit choice, not an
accident. A future `LBN 2.x` reader that also reads `LBN 1.x` files would be fine, but
it would have to do so with a clearly-marked compatibility branch and must never
confuse the two layouts.

Refusing is the default. The error should be clear:

```
LightPacket: LBN file uses major version 2, this build only reads major version 1
```

### 3.5 Why this scheme

- **Files written by any current build are always in the current layout.** No "which
  version did this come from" guessing at write time.
- **Old files keep working within a major.** Users do not lose data when you fix a bug.
- **Major bumps are honest.** When they happen, users know their old files may need to
  be migrated, and the reader tells them so instead of producing garbage.

---

## 4. LBN on-disk layout

All multi-byte integers are **little-endian**. The `double` timestamp is the host's
IEEE-754 binary64 in the host's byte order; LBN does not currently normalise it,
because it is only meaningful to the program that wrote it.

### 4.1 File structure

```
+-----------------------------+
| Magic (4 bytes)             |   "LBN" + minor_version_byte
+-----------------------------+
| Header (20 bytes)           |
+-----------------------------+
| Packet record 0             |
| Packet record 1             |
| ...                         |
| Packet record N-1           |
+-----------------------------+
```

There is no footer, no terminator, no index. The packet count in the header is
authoritative.

### 4.2 Magic

```
Byte 0: 'L'
Byte 1: 'B'
Byte 2: 'N'
Byte 3: minor_version_byte
```

The fourth byte encodes the **minor version**, which is how the reader tells `1.0` and
`1.1` apart without reading the header. This is the only place a minor version appears
on disk.

| Format | Magic bytes | Minor byte |
|---|---|---|
| `LBN 1.0` | `4C 42 4E 00` | `0x00` |
| `LBN 1.1` | `4C 42 4E 01` | `0x01` |

The three letters `LBN` never change. Only the fourth byte moves.

### 4.3 Header (20 bytes)

| Offset | Size | Field | Rule |
|---|---|---|---|
| 0 | 4 | `version` | MAJOR version. Currently always `1` for both `1.0` and `1.1`. Must not be `0`. |
| 4 | 4 | `created` | Unix timestamp (seconds, UTC) of when the file was created. Informational only; readers must not rely on it. |
| 8 | 4 | `count` | Number of packet records that follow. A file with `count == 0` is valid and contains no records. |
| 12 | 4 | `flags` | Bit field. Bit `0` = `LBN_FLAG_COMPRESSED`. All other bits reserved and must be `0` when writing; readers must ignore unknown bits. |
| 16 | 4 | `checksum` | CRC-32 (zlib polynomial) over the first 16 bytes of this header (i.e. `version`, `created`, `count`, `flags`). The checksum field itself is not included. |

The header does **not** protect the packet records. There is no per-packet checksum,
and no whole-file checksum. If you need integrity beyond "the header fields weren't
corrupted in transit", use a container that does (e.g. wrap the LBN file in something
with a real digest).

### 4.4 Packet record — `LBN 1.0`

```
+-----------------------------+
| Timestamp (8 bytes)         |   host double, seconds since epoch
+-----------------------------+
| On-disk length (4 bytes)    |   uint32
+-----------------------------+
| Payload (N bytes)           |
+-----------------------------+
```

| Field | Rule |
|---|---|
| Timestamp | Recorded by the writer via `time(NULL)` and cast to `double`. Semantically "when this packet was saved", not "when it was captured". |
| On-disk length | Length in bytes of the payload that follows. May be smaller than the uncompressed length if the file's `LBN_FLAG_COMPRESSED` bit is set. Must not exceed the remaining file size. |
| Payload | `N` bytes. Either the raw packet, or the zlib stream of the raw packet. |

**Known limitation.** In `1.0` there is no uncompressed length. A compressed `1.0` file
therefore cannot be reliably decompressed by a reader, because `uncompress()` requires
the destination buffer to be pre-sized and gives no way to discover the needed size up
front. This is the reason `1.1` exists.

A `1.0` file that is **uncompressed** is perfectly fine and fully supported. A `1.0`
file that is **compressed** is refused by the reader with a clear error — see §5.3.
`1.0`-compressed files cannot be read correctly, and pretending otherwise would
silently hand the caller corrupt data.

### 4.5 Packet record — `LBN 1.1`

```
+-----------------------------+
| Timestamp (8 bytes)         |   host double, seconds since epoch
+-----------------------------+
| On-disk length (4 bytes)    |   uint32
+-----------------------------+
| Uncompressed length (4)     |   uint32
+-----------------------------+
| Payload (N bytes)           |
+-----------------------------+
```

| Field | Rule |
|---|---|
| Timestamp | Same as `1.0`. |
| On-disk length | Same as `1.0`. |
| Uncompressed length | Length of the payload **after** decompression. For uncompressed files this must equal the on-disk length. For compressed files this is the exact size of the output of `uncompress()`. A value of `0` is legal and means an empty packet. |
| Payload | Same as `1.0`. |

`1.1` differs from `1.0` **only** by the addition of the 4-byte uncompressed-length
field. Everything before and after it is byte-identical in meaning.

### 4.6 Flags

| Bit | Name | Meaning |
|---|---|---|
| 0 | `LBN_FLAG_COMPRESSED` | Payloads are zlib streams. Decompress each one after reading. |
| 1–31 | — | Reserved. Writers must set them to `0`. Readers must not depend on them. |

The flag is **per file**, not per packet. A file is either fully compressed or fully
uncompressed.

---

## 5. Implementation notes (the current `lbn.c`)

The shipped `lib/lbn.c` and `lib/lbn.h` implement exactly what is described above. A few
implementation details worth calling out, because they are the sort of thing that gets
"cleaned up" later and breaks compatibility:

### 5.1 Magic constants

```c
#define LBN_MAGIC     "LBN\x01"   /* what the writer emits: 1.1 */
#define LBN_MAGIC_OLD "LBN\x00"   /* what a 1.0 writer emitted   */
#define LBN_VERSION   1           /* MAJOR version for both      */
```

- The writer always writes `LBN_MAGIC`. There is no option to write `1.0`.
- The reader accepts either magic. If it sees `LBN_MAGIC_OLD`, it sets `old = 1` and
  uses the `1.0` record layout for the rest of the file.
- The `version` field in the header is `1` for both minor versions. **The minor version
  lives in the magic byte, not in the header.** This is deliberate: it lets the reader
  pick the record layout before it has parsed the header, and it keeps the header
  layout identical between `1.0` and `1.1`.

### 5.2 The writer

- Computes `created` once, from `time(NULL)`.
- Computes the header CRC over `(version, created, count, flags)`.
- For each packet:
  - Writes the timestamp.
  - If compressing: allocates a `compressBound()` buffer, calls `compress2()` at
    level `6`, records the compressed size as the on-disk length and the original size
    as the uncompressed length.
  - Writes `on_disk_length` and `uncompressed_length`, then the payload.

### 5.3 The reader

- Reads and validates the magic.
- Reads the header, recomputes the CRC, and refuses the file if it does not match.
- **If the file is `1.0` and the `LBN_FLAG_COMPRESSED` bit is set, refuses the file
  with a clear error.** The `1.0` layout has no uncompressed-length field, so
  decompression cannot be done reliably. See §4.4.
- Chooses the record layout based on the magic (`old == 0` → `1.1`, `old == 1` →
  `1.0`).
- For each record:
  - Reads the timestamp.
  - Reads the lengths according to the chosen layout.
  - Reads the payload.
  - If the file is compressed, calls `uncompress()` into a buffer of exactly
    `uncompressed_length` bytes, and treats a size mismatch as a hard error.
  - If the file is uncompressed, hands the raw buffer back.

- If a read fails partway through, the function returns success with `*packet_count`
  set to the number of records that *were* read, and the caller is responsible for the
  returned arrays. This is intentional: partial recovery is more useful than
  all-or-nothing for a diagnostics format.

### 5.4 Public API

Defined in `lib/lbn.h`:

```c
LBN_API int  lbn_save(const char *filename,
                      const unsigned char **packets,
                      const size_t *sizes,
                      size_t count,
                      int compress);

LBN_API int  lbn_load(const char *filename,
                      unsigned char ***packets,
                      size_t **sizes,
                      size_t *packet_count);

LBN_API void lbn_free_packets(unsigned char **packets,
                              size_t *sizes,
                              size_t count);
```

- `lbn_save` returns `0` on success, `-1` on any failure (bad path, allocation failure,
  zlib failure). The partial file is left on disk; callers who care should delete it on
  failure.
- `lbn_load` returns `0` on success even if only some packets were read;
  `*packet_count` tells you how many. Returns `-1` on failure (file not found, bad
  magic, header CRC mismatch, `1.0`-compressed file). On failure the output pointers
  are not written.
- `lbn_free_packets` frees every element of `packets`, then `packets` and `sizes`
  themselves. It uses `count` as the number of valid elements; passing the value
  returned in `*packet_count` is always correct.

---

## 6. Worked example — reading a `1.0` file with the current reader

Suppose you have `old.lbn` written by a `1.0` writer, uncompressed, with two packets:

```
Offset  Bytes                                    Meaning
------  ---------------------------------------  ---------------------------------------
0       4C 42 4E 00                              magic "LBN\x00" -> 1.0
4       01 00 00 00                              version = 1
8       67 12 34 56                              created  (unix time)
12      02 00 00 00                              count    = 2
16      00 00 00 00                              flags    = 0 (uncompressed)
20      ...                                      header CRC
24      ...                                      timestamp of packet 0
32      ...                                      on-disk length of packet 0
36      ...                                      payload of packet 0
...
```

The current reader:

1. Reads the first 4 bytes, compares against `LBN_MAGIC` (`LBN\x01`) — no match.
   Compares against `LBN_MAGIC_OLD` (`LBN\x00`) — match. Sets `old = 1`.
2. Reads the 20-byte header, verifies the CRC.
3. Checks the compressed flag. It is unset, so the file is accepted.
4. For each packet, uses the `1.0` layout: timestamp, 4-byte on-disk length, payload.
5. Returns the packets.

A `1.1` file with the same payloads would have `4C 42 4E 01` as its magic, and each
packet record would have 4 extra bytes (the uncompressed length) between the on-disk
length and the payload.

---

## 7. LightPacket and Light-Projects

LBN is one of the file formats provided by **LightPacket**, the I/O and serialization
module of the **Light-Projects** project. LightPacket currently provides:

- `lib/lbn.c`, `lib/lbn.h` — the format described in this document.
- `lib/pcap_writer.c`, `lib/pcap_writer.h` — a classic-PCAP writer.
- `lib/pcap_reader.c`, `lib/pcap_reader.h` — a classic-PCAP reader.
- `lib/pcapng.c`, `lib/pcapng.h`, `lib/pcapng_format.h` — a PCAPNG reader/writer with
  both endiannesses on the read side.

> **Light-Projects link:** _https://github.com/Light-Projects/LightPacket_

If you are extending LBN, remember that this document is the specification: update it
*before* you update the code, and bump the version according to §3.