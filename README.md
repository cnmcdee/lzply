# lzply — lzip + BCH archives

Renamed twice to follow the code and then the domain name: `lzrs`
(lzip + Reed-Solomon) → `lzbch` (lzip + BCH) → `lzply`. The archive
magic followed the same path (`LZRS` → `LZBC` → `LZPL`), and the
extension is now `.lzply`. Version 4 also removed the AES-256-GCM
encryption that v3 had, so v3 archives are rejected outright, like
the old magics — there is no legacy support.

One archive file (like zip) holding many entries. Every entry is an
independent byte stream:

```
compress -> BCH encode     (on write, v4)
BCH-decode -> decompress   (on read)
```

* **Compression:** lzip (LZMA) via `liblz`, levels `-1`..`-9`, default `-6`.
  The level table matches the `lzip` command-line tool exactly — the
  compressed stream inside an `lzply` entry is byte-identical to what
  `lzip -N` produces (verified by the test suite).
* **Store mode (level 0):** when the compressed blob would be no
  smaller than the original — already-compressed files, random data,
  empty files — the entry is stored uncompressed instead (level 0 in
  the header, shown as `lvl 0` by `-l`, `-i`, and `lzply_stat`), and
  BCH error correction still applies to the stored bytes exactly as
  for compressed entries. `-0` forces store mode for every entry.
* **Error correction: binary BCH.** `-e <0..7>` selects the correction
  level t: 0 = none, 1 -> t=1, 2 -> t=2, 3 -> t=4, 4 -> t=8,
  5 -> t=16, 6 -> t=32, 7 -> t=32. Default is `-e 4` (t=8). BCH
  corrects *bit* errors, and the 82 narrow-sense primitive generator
  polynomials embedded in the binary (parents N = 2^m - 1, m = 7..22,
  found by the rssearch exhaustive search) need 39-42% less parity
  than Reed-Solomon for the same t. With no poly given, the most
  efficient polynomial for each entry's blob length is picked
  automatically (smallest parent whose codeword covers the blob).
  `poly=NN` pins one polynomial by id, hex (`poly=003a`) or decimal
  (`poly=58`); it overrides `-e`. A blob longer than one block's
  capacity is split into blocks of that poly's max payload (m=22,
  t=32: 524,199 bytes/block); the decoder rebuilds the boundaries
  from blob_size + the poly. Damage beyond t fails cleanly — never
  silently.
* **Integrity:** every entry carries a SHA-256 of its original data.
  This matters because a bounded-distance BCH decoder can *miscorrect*
  a damage pattern that exceeds t, landing on a different valid
  codeword. The SHA-256 check catches that, so a miscorrection is
  reported as corruption, never as silent damage. (For small t the
  miscorrection rate is not negligible — e.g. t=1, 2-bit errors
  miscorrect ~50% of the time at the codec level — which is why the
  SHA-256 is load-bearing, not decorative.)
* **Timestamps:** every entry stores the source file's or directory's
  mtime (seconds since epoch, UTC) in its header. `-i` prints it,
  and `-datestart` / `-dateend` / `-year` filter on it (see below).
  File mode is preserved too; ownership is not.

## The tools

Seven programs, one family. All are plain C, built by `make`
(see "Building" below), and share the BCH codec (`bch.c`) and the
SHA-256 implementation (`sha256.c`).

* **`lzply`** — the archiver. Create, extract, test, list, inspect
  (`-i`), tree (`-tr`), append (`-a`), date filters, store mode.
  The core of the repo.
* **`lzply_mount`** — mount a `.lzply` archive as a writable
  filesystem (FUSE). `mount -t lzply` works too.
* **`lzply_stat`** — statistics for an archive or a mount point:
  sizes, compression %, polynomial, t, parity bits, ECC overhead %.
* **`lzply_heal`** — strip the BCH parity and re-encode it, at the
  same level or a higher one, without touching the compressed data.
* **`lzply_check`** — measure the bit-error rate (BER) of an archive
  or a mount, to watch for filesystem degradation.
* **`lzply_refresh`** — rewrite a file over itself (1–3 passes) to
  freshen the platter on older spinning disks.
* **`lzply_hyper`** — a striped volume (8 bit-plane data stripes +
  P/Q/R parity) that rebuilds up to 3 dead stripes. See
  `README-hyper.md` for the full documentation.

License: MIT — see `LICENSE`.

## The BCH study — the numbers behind the polynomials

The 82 generator polynomials embedded in the binaries come from
`rssearch`, an exhaustive search over shortened binary BCH codes
(parent N = 2^m − 1), comparing each against Reed-Solomon for the
same payload length and error level, under a parity cap of
r ≤ n/8. The search covered payloads 8–524,287 bytes,
t ∈ {1, 2, 4, 8, 16, 32}.

* **3,145,030 finds** across 3,145,680 (length, t) pairs —
  **99.979% coverage**. The 650 non-finds are all small payloads
  (L = 8..383, t ≥ 2) where the parity cap chokes, not RS wins.
* **495,386,012 parity bits saved** in total (~59 MiB) versus
  Reed-Solomon.
* **Best single saving: 512 bits** — payload 524,287 bytes, t=32:
  BCH 704 bits vs RS 1,216.
* **Saving by band:** m=17: 39.3%, m=18: 40.0%, m=19: 40.6%,
  m=20: 41.2%, m=21: 41.7%, m=22: 42.1%. The ratio approaches
  50% as m grows; direct (orbit-only) construction reaches
  49.41% at m=256 (t=32: 8,192 vs 16,192 RS bits).
* **The 36 polynomials for m=17–22 (IDs 002f–0052) are not in any
  published table** — they had to be computed. The m≤16 polys are
  the standard textbook narrow-sense primitive BCH generators.
* **Frontier: m=22.** The exhaustive scan stopped there because
  m=23 was estimated at ~12 hours (band cost grows ~4× per m).
  The original crawl (m≤18, 16,377 lengths) finished in 274
  seconds; m=22 alone took 3.04 hours.

Full write-up, including the prior-art check and the per-length
tables:
https://www.lzply.com/reed-solomon-is-leaving-40-of-your-parity-on-the-table-i-searched-16-377-payload-lengths-and-found-97-612-codes-that-beat-it-all-58-polynomials-full-source/

## Format (v4; a single format, all integers little-endian)

```
global header (16 bytes):
  magic "LZPL", version u8 (4), flags u8, entry_count u32, reserved u64
entries, each:
  u16 path_len, u8 level, u8 rs_level, u8 flags, u8 reserved,
  u64 orig_size, u64 stored_size, u64 blob_size, u8 sha256[32],
  u32 mode, u64 mtime, u32 header_crc32,
  path[path_len], data[stored_size]
end marker: u16 path_len == 0
```

`header_crc32` covers the 74 bytes before it. `blob_size` is the
length of the compressed (or, for a stored entry, raw) stream
before error-correction
parity was added. `mtime` is the source's modification time in
seconds since the epoch (UTC). Level is the lzip level (1..9) of
the blob, or 0 for a stored (uncompressed) entry. Flags: bit 0 is
unused (it was used
by v3), bit 1 =
directory, bit 2 = BCH mode. For a BCH entry, `poly_id = rs_level |
(reserved << 8)`; for an entry with no error correction, `rs_level`
and `reserved` are 0. Paths are stored relative to the input's
parent, so `lzply -c photos/` stores `photos/...` and restores the
tree on extract. Entry paths containing `..` or starting with `/`
are rejected on extract.

There is no legacy support: v1 (Reed-Solomon), v2, and v3 archives
are not readable (v3 had AES-256-GCM encryption, removed in v4),
and neither is any archive with an old magic (`LZRS`
or `LZBC`) — the magic is now `LZPL`, and old magics are rejected
outright. The format was never used anywhere yet, so it changes
freely — a single current format, no version branches.

The 82 polynomials are compiled into the binary from `bch_polys.h`,
generated by `gen_bch_polys.py` from the rssearch results
(`~/workspace/rssearch/polys.txt` + `finds.txt`). The generator
re-derives every polynomial orbit-only from its parent's primitive
polynomial and checks it byte-identical to `polys.txt`, so the
embedded table is verified, not just copied. Regenerate with
`python3 gen_bch_polys.py` (or `make bch_polys.h`).

## Building

```sh
apt install build-essential liblz-dev   # Debian/Ubuntu
make            # produces ./lzply, ./lzply_mount, ./lzply_stat, ./lzply_heal, ./lzply_check, ./lzply_refresh
make test       # BCH unit tests + full archive test suite
sudo make install   # /usr/local/bin/lzply*, /sbin/mount.lzply
```

## Usage

```
lzply -c [-0..-9] [-e 0..7] [poly=NN] [-y|-n|--ask] <file|dir> [output]
lzply -a [-0..-9] [-e 0..7] [poly=NN] <archive.lzply> <file|dir> [...]
lzply -d [-y|-n|--ask] <archive.lzply> [dest dir] [selector...]
lzply -l <archive.lzply> [selector...]
lzply -t <archive.lzply> [selector...]
lzply -i <archive.lzply> [selector...]
lzply -tr <archive.lzply> [selector...]
```

Any of `-d`, `-l`, `-t`, `-i`, `-tr` also takes `-datestart <date>`,
`-dateend <date>`, and/or `-year <YYYY>` (see "Date filters" below).
Options may appear before or after the archive and selectors, so
`lzply -d backup.lzply out/ -year 2024` works.

`-y` overwrite, `-n` never overwrite (skip), `--ask` ask (default).
`lzply -l` shows the BCH poly id (`BCH 003a`) or `-` for no error correction, per entry.

## Inspect (-i) and tree (-tr)

`lzply -i <archive.lzply>` reads **only the entry headers** — it seeks
past each entry's stored data without reading or decoding it, and
never decompresses anything. That makes it fast on large archives
and usable even on an archive whose data is corrupted (the headers
are intact, so `-i` still succeeds where `-t` fails). For each entry
it prints: stored path, type (file/directory), permissions (octal
and symbolic, e.g. `0640 -rw-r-----`), mtime (`2024-03-15 10:30:00
UTC`), original size, stored size, level (`0` for a stored entry,
otherwise the lzip level), error correction (BCH poly id,
or `-`). A summary line gives
the entry count.

`lzply -tr <archive.lzply>` prints the archive as a tree, like the
Linux `tree` command, with each file's original size, and a
`N directories, M files` summary. The hierarchy is rebuilt from
the stored paths. Directories that are entries themselves (stored
with a trailing `/`) are nodes; a directory with no explicit entry
but files under it is shown as an implied node (this happens when
a filter drops the directory entry but keeps its files).

```
$ lzply -tr backup.lzply
backup.lzply
└── photos/
    ├── 2024/
    │   ├── a.jpg (2.1 MiB)
    │   └── b.jpg (1.8 MiB)
    └── 2025/
        └── c.jpg (2.4 MiB)

3 directories, 3 files
```

## Date filters

`-datestart <date>` and `-dateend <date>` match entries by mtime.
Dates are `YYYY-MM-DD` (a whole day, inclusive: datestart is from
00:00:00, dateend is through 23:59:59) or `YYYY-MM-DDTHH:MM:SS`
(exact). `-year <YYYY>` matches entries whose mtime falls in that
year (the same as that year's Jan 1 – Dec 31). The filters apply to
`-d`, `-i`, `-tr` (and `-t` / `-l` for consistency) and AND with
each other and with any path selector: an entry must match the
selector (if any) AND the date range (if given) AND the year (if
given). A filter matching nothing prints a clear message and exits
0, like a no-match selector. Bad dates (e.g. `2024-02-30`,
`2024/01/01`) and bad years are usage errors.

```
lzply -d backup.lzply out/ -datestart 2024-01-01 -dateend 2024-06-30
lzply -d backup.lzply out/ -year 2024
lzply -i backup.lzply photos/ -year 2025
lzply -tr backup.lzply -datestart 2024-01-01 -dateend 2024-12-31
lzply -d backup.lzply out/ photos/ -year 2024   # selector AND year
```

## Appending (-a) and selective extract

`lzply -a <archive.lzply> <file|dir> [...]` adds one directory, several
files, or a mix to an archive. Stored paths are relative to each
input's parent, exactly as `-c` does, and the new entries use the
same `-e` / `poly=` options as `-c` (default BCH
auto-pick, t=8). The source mtime of each appended file/dir is
recorded, like `-c`. If the archive does not exist it is created,
like `-c`. Without duplicates the append is truly incremental: the
new entries are staged to a temp file, appended just before the end
marker, and the global entry count is updated in place — the
existing entry bytes are not rewritten. If a stored path being added
already exists, the archive is rewritten via a temp file (kept
entries copied byte-for-byte, replaced entries dropped, new entries
appended) and renamed over the original, so exactly one entry per
path remains and the new content wins.

`lzply -d <archive.lzply> <dest> <selector> [...]` (and `-t`, and
`-l`) extracts, tests, or lists only the entries matching a
selector. A selector matches an entry if it equals the entry's
stored path exactly, or is a prefix of it and the next character
after the prefix is `/` (so `photos` matches `photos/a.jpg` but not
`photos2/a.jpg`); a selector ending in `/` matches everything under
it. For `-d` the dest dir must be given explicitly when selectors
are used (`lzply -d backup.lzply . photos/`); for `-t` and `-l` the
selectors go right after the archive. A selector matching nothing
prints a message and exits 0, extracting nothing.

Note: `-a` used to mean "ask before overwriting"; it is now the
append mode, and ask-overwrite is `--ask` only (it is the default).

Exit codes: 0 ok, 1 usage, 2 I/O error, 3 corrupt/unrecoverable.

## Tests

`tests/run_tests.sh` (147 tests) covers: roundtrips at every level
`-1`..`-9`; byte-identical cross-check against system `lzip -6` (at
`-e 0`, so the stored bytes are the raw lzip stream); roundtrips at
BCH levels 0..7; BCH corruption with pinned polys (t bit errors
recovered, t+1 bit errors fail cleanly); combined `-9 -e 5`
(BCH t=16) with 16 corrupted bits; a v3 archive (version byte
patched back to 3) is rejected; the removed option is a usage error
(exit 1); overwrite flags `-y`/`-n`/`--ask`; empty directory, empty
file, 1-byte file, filenames with spaces, truncated and non-archive
inputs; a 50 MiB file (BCH t=4, multi-block); `poly=` pinning (hex
and decimal), unknown-poly rejection, and the version byte (4, with
or without BCH); a 600 KiB split-blob roundtrip with corruption in
the first block. Append and selective extract are covered by 21
more tests: `-a` a single directory (nested tree preserved), several
files at once, `-a` on a missing archive (creates it), replacing an
existing file (new content wins, exactly one entry per path, other
entries intact), `-a` a file onto an existing archive (appended
entry extracts, old entries intact), `-a` with `poly=003a` and
`-e 6`, incremental append preserving existing entry bytes
byte-for-byte, and selective `-d`/`-t`/`-l` (directory prefix,
trailing slash, exact file, a non-boundary prefix that must not
match, a selector matching nothing). Inspect, tree, and date
filters are covered by 27 tests: `-i` correctness (known mtimes set
with `touch -d`, permissions, sizes, BCH poly ids) and `-i`
succeeding on a data-corrupted archive while `-t` fails; `-tr`
exact expected output (nested tree, implied directories, empty
directories, summary counts); `-datestart` / `-dateend` with `-d`,
`-i`, and `-tr` (files with mtimes spread across days, only the
in-range ones appear), including a single-day range and the
exact-datetime form; `-year` with `-d` and `-i` (2024 vs 2025
files); combined filters (path selector AND `-year`; `-year` AND
`-datestart`/`-dateend`); an empty range (datestart after dateend)
and bad date/year formats (usage errors); `-a` preserving mtime;
and `-i`/`-tr` on an appended archive (mtimes shown for both
entries, tree shows both files). A v1-style archive (version byte
1) is rejected, and archives with the old magics (`LZRS`, `LZBC`)
are rejected, proving there is no legacy read path. `lzply_stat`
is covered by 4 tests (poly ids, t values, ECC overhead %, totals,
a selector, a non-archive input). `lzply_heal` is covered by 8
tests: pure heal (no-op on a healthy archive), level raise (`-e 6`,
data byte-identical), ECC strip (`-e 0`), 5 flipped bits corrected
(t=8) with data recovered, 9 flipped bits exiting non-zero with the
entry kept, `-o` (original untouched, output healed), heal with a
level raise on a plain archive (data byte-identical), and a
selector (only that entry healed). `lzply_check` is covered by 8
tests: a clean archive (BER 0, exit 0), 5 injected bit errors (the
reported corrected count is exactly 5 and the BER matches 5 /
stored bits, verified through `--json`), 9 injected bit errors
(exit 3, uncorrectable), a no-ECC entry (reported unmeasurable,
exit 0), `--warn-ber` below the BER (warning, exit 0), `--fail-ber`
below the BER (exit 3) and above it (exit 0), and a mount-point
check on the server. `lzply_refresh` is covered by 9 tests: 1 pass
and 3 passes (same inode, SHA-256 unchanged), `n=4` and `n=0`
rejected as usage errors, a directory refresh (several files
refreshed, a symlink skipped, contents unchanged), and on the
server a file inside a mount, a whole mount point (several files,
mount noted in the output), a mounted archive refused, and the
post-unmount roundtrip (archive verifies with `lzply -t`, all
contents unchanged). Mount write-back is covered by 3 tests: a mount
started with a relative archive path (writes persist in the real
archive, no stray file appears in `/`, and `lzply_stat` resolves
the archive from the mount). Store mode is covered by 16 tests:
a 1 MiB random file stored as level 0 (shown by `-l`, `-i`, and
`lzply_stat`) and extracted byte-identical, a compressible file
still compressing, `-0` forcing store via `-c` and `-a`, 1 flipped
bit in a stored entry (still tests OK, check reports exactly 1
corrected bit, heal recovers the data), an empty file stored as
level 0, directories keeping the requested level, and a mount
repack storing an incompressible file. `bch_test.c` validates the BCH codec in
isolation (table remainder vs brute-force division for all 82
polys, roundtrips at many sizes, corruption at several t, auto-pick
band correctness, block splitting with corruption).

Set `LZPLY_TEST_ROOT` to point the suite at a different tree root
(default: the parent of the `tests/` directory, so it works both
from the repo layout `~/workspace/lzply` and from `/opt/lzply/src`).

## Limitations (v4)

* Whole files are buffered in memory (compress, BCH, and
  the archive entry). A 50 MiB file is fine; multi-gigabyte files
  need a streaming rewrite.
* Symlinks and special files are skipped with a warning, not stored.
* File mode and mtime are preserved; ownership is not.
* BCH is a bit-error code: it corrects scattered bit flips, not
  whole lost bytes. A burst that wipes many consecutive bits in one
  block can exceed t even when the byte count is small.
* The BCH decoder builds GF(2^m) log/exp tables (up to 32 MiB
  transient for m=22) the first time it has to correct an error in
  a block; the no-error path needs no tables and stays fast.
* A crash mid-append on the incremental path can leave orphan
  entries.

## lzply_mount — mount an archive as a writable filesystem

`lzply_mount` (needs libfuse3; `make lzply_mount`, installed to
`/usr/local/bin/lzply_mount` by `make install`, with `mount.lzply` to
`/sbin/mount.lzply`) mounts a `.lzply` archive as a normal directory
you can read, write, create, delete, rename, chmod, and touch:

```
lzply_mount backup.lzply /mnt/backup
ls /mnt/backup            # browse (getattr, readdir)
cat /mnt/backup/docs/a.txt
echo "new line" >> /mnt/backup/docs/a.txt
mkdir /mnt/backup/photos
cp photo.jpg /mnt/backup/photos/
mv /mnt/backup/docs/a.txt /mnt/backup/docs/a-renamed.txt
chmod 640 /mnt/backup/docs/a-renamed.txt
touch -d "2020-06-15 12:00:00 UTC" /mnt/backup/docs/a-renamed.txt
fusermount3 -u /mnt/backup
```

Or through mount(8):

```
mount -t lzply backup.lzply /mnt/backup
mount -t lzply -o cache=64 backup.lzply /mnt/backup
umount /mnt/backup
```

Options: `-f` foreground, `-d` debug, `-o opt` FUSE mount option
(`cache=` is consumed by lzply_mount and never reaches FUSE's mount
options), `-e N` BCH level for re-encoded entries (0-7,
default 4), `poly=NN` pin a BCH polynomial, `-0` store re-encoded
entries uncompressed, `-cache N` read-cache cap in MiB
(default 256).

Archive and mountpoint paths are canonicalised to absolute paths at
startup (libfuse changes the daemon's working directory to `/`
while mounting), so relative paths work the same as absolute ones.

How it works: at mount, lzply_mount scans the archive headers into an
in-memory index. File contents are decoded on demand (decode-on-
open, cached, 256 MiB soft cap, LRU eviction of clean entries
only). Writes go to an in-memory working copy; new files, deletes,
renames, and metadata changes update the index. On clean unmount
(or `fsync`), the archive is repacked: unmodified entries are
copied verbatim (their stored bytes and BCH poly are unchanged),
modified and new entries are encoded fresh (lzip -> BCH),
and the new archive atomically replaces the old one (temp file +
rename). A corrupt entry is `EIO` — never silently wrong data.

Durability: changes are durable only after a clean unmount or an
`fsync` (both trigger a repack). A killed daemon (`kill -9`, crash,
power loss) loses unflushed changes but never corrupts the on-disk
archive — the repack is atomic, and the old archive is untouched
until the new one is complete. Mounting the same archive twice at
once is refused (exclusive `flock`), so two daemons cannot lose
each other's changes.

Limitations: whole files are buffered in memory (same as `lzply`);
the read cache is a 256 MiB soft cap (a single entry larger than
the cap still loads); `chown` is a no-op that succeeds (the
archive stores a mode, not an owner — every entry appears owned
by the mounting user); `rename` with `RENAME_EXCHANGE` returns
`EINVAL`; deleted entries stay in the in-memory index as tombstones
for the session; atime is reported as mtime (only mtime is
stored); mounting requires FUSE (`/dev/fuse`) and is single-
threaded.

## lzply_stat — statistics for an archive or a mount

`lzply_stat <path> [selector...]` reports per-entry statistics for
an `.lzply` archive, for a `lzply_mount` mount point, or for a file
or directory inside a mount. It reads headers only (like `lzply -i`):
nothing is decompressed, so it works on an archive whose data is corrupted. For each entry it
shows the uncompressed size, the compressed size (blob, pre-ECC),
the stored size (on disk, including ECC), compression as
stored/original, the level (`0` for a stored entry), the BCH poly id
and t, the parity bits, the ECC overhead % (parity bits /
(8 * blob size), the same definition as the overhead tables in the
article), and the mtime —
plus a totals footer (entry count, total sizes, overall compression
%, total parity bits, overall ECC overhead %).

```
$ lzply_stat backup.lzply
path                  type   original compressed     stored   comp%  poly   t   parity    ecc% mtime (UTC)
photos/a.jpg          file     2.1 MiB    2.1 MiB    2.1 MiB  100.0%  0038   8      208  0.001% 2024-03-15 10:30:00 UTC
...
2 entries (0 directories, 2 files)
total uncompressed: 4.2 MiB, total compressed (blob): 4.2 MiB, total stored: 4.2 MiB
overall compression: 100.0% (stored/original)
total parity bits: 416, overall ECC overhead: 0.001%
```

For a mount point the backing archive is found via `/proc/mounts`
(fstype `fuse.lzply_mount`) plus a scan of `/proc` for the
`lzply_mount` daemon's command line. The figures are the on-disk
(committed) state — unflushed changes in the mount are not
included, and a file created in the mount but not yet repacked is
reported as having no committed statistics rather than showing
stale numbers.

## lzply_heal — strip and reapply the error correction

`lzply_heal <archive.lzply> [-e <level>] [poly=<id>] [-o <output.lzply>] [selector...]`
strips the BCH parity from each entry and reapplies a new one. The
compressed blob is never touched — no recompression — so the per-entry SHA-256 still
verifies the original data. Only the poly id, the stored size and
the header CRC change.

```
lzply_heal backup.lzply              # pure heal: same poly/t, corrects bit errors
lzply_heal -e 6 backup.lzply         # raise the level (t=8 -> t=32)
lzply_heal poly=003a backup.lzply    # pin one polynomial for every entry
lzply_heal -e 0 backup.lzply         # strip the error correction entirely
lzply_heal -e 6 -o healed.lzply backup.lzply   # write to a new file
lzply_heal -e 6 backup.lzply photos/  # only entries under photos/
```

With neither `-e` nor `poly=`, each entry is re-encoded with the
same poly and t it already has — a pure heal pass that corrects bit
errors up to t and writes back clean parity, so a later read no
longer needs the correction. With `-e`, the most efficient poly per
blob is auto-picked at the new t (as in `lzply -c`); `poly=` pins
one poly for every entry and overrides `-e`. An entry whose BCH
decode fails (more errors than t) is kept byte-for-byte unchanged,
reported, and the program exits non-zero at the end; the other
entries are still healed.

Correctness: a bounded-distance BCH decoder can *miscorrect* when
the errors exceed t, and at small t the rate is high (t=1 with
2-bit errors miscorrects about half the time). So before re-encoding, every entry's stripped blob is verified by
decompressing it and checking the SHA-256 — a miscorrection is
caught and the entry is kept unchanged instead of being re-encoded
with wrong data.

The archive must not be mounted while healing: `lzply_heal` takes
the same exclusive `flock` the mount daemon holds, so a mounted
archive is refused with a clear message, and a mount cannot start
mid-heal. The rewrite is atomic (temp file + rename), so a failure
leaves the original intact.

## lzply_check — bit error rate (BER) detector

`lzply_check <path> [selector...] [--json] [--warn-ber <value>] [--fail-ber <value>]`
is read-only: it never modifies the archive. The path may be an
`.lzply` archive, an `lzply_mount` mount point, or a file or
directory inside a mount (same mount resolution as `lzply_stat`).
For each BCH entry it runs `bch_decode()` on the stored bytes in
memory and counts the bit errors the decoder corrects. This
operates on the stored codeword below the compression layer, so it does NOT
decompress anything.

BER per entry = corrected bit errors / total stored bits
(8 × stored_size). The point is degradation watching: run it
periodically (e.g. from cron) over an archive that lives on an
ageing drive and watch the BER rise. A BER of 0 on a healthy
archive is the baseline; a rising BER means the medium is
degrading and it is time to heal (or copy the archive elsewhere)
before the errors exceed t.

```
$ lzply_check backup.lzply
path                                      poly   t  corrected   total_bits          ber status
tiny.txt                                  000b   8          0          488            0 clean
1 entries checked (1 BCH, 0 no-ECC)
with errors: 0, uncorrectable: 0
total corrected: 0 bits over 488 total stored bits
overall BER: 0 (worst: tiny.txt 0)
BER = corrected bit errors / total stored bits (8 x stored size), as seen by the BCH decoder on the stored codeword. No-ECC entries cannot be measured.
```

(Measured output. The same archive with 5 bits flipped at t=8
reports `corrected 5`, BER `0.0102`, status `correctable`; with 9
bits flipped it reports `uncorrectable` and exits 3.)

* Entries with no BCH (t=0) are reported as `no-ecc` — "BER cannot
  be measured". No full decode is attempted for these; that is not
  this tool's purpose.
* Uncorrectable entries are reported as `uncorrectable`
  (data-loss risk) and are NOT folded into the BER number; they
  are counted separately.
* Totals: overall BER across all decodable BCH entries (total
  corrected / total stored bits), the worst entry, and counts of
  entries with errors, uncorrectable entries, and no-ECC entries.
* Exit codes: 0 = OK (no errors, or only correctable errors and
  the overall BER is below `--fail-ber`); 3 = any uncorrectable
  entry, or the overall BER is above `--fail-ber`. `--warn-ber`
  prints a warning but still exits 0. With no thresholds given,
  only uncorrectable entries fail.
* `--json` prints one JSON object with per-entry results and
  totals, for scripting, monitoring, and cron.

Caveat: the BER is as seen by the BCH decoder. For small t, if
the true error count exceeds t the decoder may miscorrect and the
reported BER is unreliable — so a high BER or any uncorrectable
entry means: run `lzply_heal`, then `lzply -t` to fully verify.
That is the documented workflow: `lzply_check` detects,
`lzply_heal` repairs, `lzply -t` proves the data is intact.

## lzply_refresh — rewrite a file over itself to freshen the platter

`lzply_refresh <path> [n]` refreshes a file by writing it over
itself, so it freshens the magnetic signal on older physical
(spinning) drives. n = number of rewrite passes, 1-3, default 1;
n outside 1..3 is a usage error. The whole file is read into
memory, then each pass opens the file O_WRONLY — the same inode,
never deleted and recreated — writes the bytes back from offset 0
and fsyncs. SHA-256 before the first pass and after the last pass
must match; both hashes are reported (in practice the one hash,
with "verified unchanged").

```
$ lzply_refresh old-drive-file.txt 3
old-drive-file.txt: 32 bytes, 3 passes, sha256 5949996cf671a8ca6ce9a87bbbac211d41a11b239533c908e6166c616c01b178, verified unchanged
```

(Measured output: the same inode, the same SHA-256 before and
after, 3 passes.)

The path may also be a directory or a mount point: every regular
file under it is refreshed recursively with the same pass count,
and a summary is printed (files refreshed, files skipped).
Symlinks and special files are skipped, the same rule as
`lzply -c`. A mount point is detected via the same mount
resolution as `lzply_stat` (`/proc/mounts`) and noted in the
output ("refreshing mount at /mnt/point: N files").

```
$ lzply_refresh /mnt/archive 2
refreshing mount at /mnt/archive: (archive /data/backup.lzply)
photos/a.jpg: 2097152 bytes, 2 passes, sha256 …, verified unchanged
...
summary: 3 files refreshed (2 passes each), 0 skipped, 0 failed
```

A file inside an `lzply_mount` mount works too: the write goes
through FUSE and the entry is re-encoded on repack, which also
refreshes the archive. But an `.lzply` archive file that is
currently mounted is refused (same rule as `lzply_heal` —
modifying the archive under a live mount corrupts the daemon's
view); unmount it first.

Caveats: on copy-on-write filesystems (btrfs, ZFS) an overwrite
may allocate new blocks rather than rewriting the same sectors,
so the platter refresh may not happen — this tool is aimed at
traditional overwrite filesystems (ext4) and older spinning
disks. On SSDs wear-levelling means a rewrite does not hit the
same cells, so it is specifically for older physical (magnetic)
drives. The whole file is buffered in memory, like the rest of
the lzply family.

## lzply_hyper — a striped volume that rebuilds up to 3 dead stripes

`lzply_hyper` is a separate program in this repo: a config-file
driven striped volume. Eight data stripes hold the file's bits
(one bit per stripe, bit-plane layout), and one to three parity
stripes hold P (XOR), Q and R (GF(256)) parity, so the volume
survives the loss of 1, 2, or 3 data stripes. BCH error correction
and SHA-256 cover bit rot on top of that. Writes can be slow;
reads are the priority (~35 MiB/s, BCH syndrome bound).

Full documentation — config format, commands (`-init`, `write`,
`read`, `list`, `check`, `-rebuild`), the parity scheme, the
1/2/3-stripe-loss demos, and the 56-test suite — is in
`README-hyper.md`.
