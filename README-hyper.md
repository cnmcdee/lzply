# lzply_hyper — a striped volume that heals itself

`lzply_hyper` is the striped-volume sibling of `lzply`. It is **not**
an archive and it does not compress. It takes a file, splits it
bit-plane across 8 data stripes, and stores independent parity
stripes plus BCH parity so a dead stripe — or three — can be rebuilt
and bit rot can be corrected on read. Write speed is not a design
goal (bit-packing costs). **Read speed is.** A read reassembles the
file from the surviving stripes, checks it, and verifies it, and the
parity stripes are only touched when a stripe is actually dead.

The name is a pun that stuck: the archiver went `lzrs` → `lzbch` →
`lzply`, and this one stripes *hyper* — many stripes, many parities.

## Layout: 8 bit-plane data stripes

A file is split byte by byte, bit by bit. Byte `i` splits into its 8
bits; bit `j` goes to stripe `j`. Stripe `j` holds one bit of every
byte, packed. So each data stripe is `ceil(file_len / 8)` bytes, and
the 8 stripes together hold exactly the file, no more, no less. No
compression: an incompressible file costs the same as a compressible
one.

Reassembly uses an 8x8 bit-matrix transpose (SWAR — three
shift/mask/xor stages on a `uint64`), not per-bit extraction. The
transpose is an involution, so the same function splits on write and
merges on read. The on-disk layout is checked against hand-computed
values in the test suite (e.g. bytes `01 02 04 08 10 20 40 80`
transpose to themselves; `FF 00 00 00 00 00 00 00` gives every stripe
byte `01`).

```
file bytes:  b0 b1 b2 b3 b4 b5 b6 b7 b8 ...
stripe 0:    bit0(b0) bit0(b1) ... bit0(b7) | bit0(b8) ...
stripe 1:    bit1(b0) bit1(b1) ... bit1(b7) | bit1(b8) ...
...
stripe 7:    bit7(b0) bit7(b1) ... bit7(b7) | bit7(b8) ...
```

## Two parity layers, both in each file's parity record

Every file gets one parity record per parity stripe. The record
header (96 bytes) holds the name, original length, poly id and `t`,
the stripe offset and length, the parity and BCH lengths, and a
SHA-256 of the original file. After the header come the parity bytes
(`stripe_len` bytes) and the BCH parity bytes. The record is appended
to each parity stripe when the file is written; the stripes are
written first, then the records, so a crash leaves orphaned stripe
data, never a dangling record.

### Layer 1 — stripe loss (P, Q, R)

Three **independent** parity stripes, not mirrors of each other:

* **P** = XOR across the 8 data stripes. Recovers any **1** lost stripe.
* **Q** = GF(256) weighted sum, `sum g^j * s_j` (g = 2, the field
  generator, primitive polynomial `0x11d`). Recovers a **2nd** lost
  stripe, RAID-6 style.
* **R** = GF(256) weighted sum with different coefficients,
  `sum g^(2j) * s_j`. Recovers a **3rd** lost stripe.

The number of parity stripes in the config sets the tolerance:
1 parity → 1 loss, 2 parities → 2 losses, 3 parities → 3 losses.
Recovery solves the small (k×k, k ≤ 3) coefficient system over
GF(256) by Gauss-Jordan inversion, per byte position. It uses
whichever parity rows survive — Q alone rebuilds 1 lost stripe if P
is dead. A 4th lost stripe is beyond tolerance: `read` and
`-rebuild` fail clearly and never return wrong data.

BCH alone cannot do this. Poly `0044` (m=20, t=8) holds 131,051 data
bytes per block with 160 parity bits (20 bytes) of erasure capacity,
while one dead stripe of 5 loses 26,210 bytes per block — ~1,300x
over capacity. Stripe loss needs parity *across* the stripes.

### Layer 2 — bit rot (BCH + SHA-256)

BCH parity over the whole file, using the config's poly and error
level, stored after the parity bytes. It corrects bit rot in the
reassembled file — including a bit error that propagated through a
stripe rebuild, since that lands as a single-bit error in the
reassembled file. The poly is taken from the **first** parity line;
all parity lines must agree on poly + error level or the config is
rejected. The BCH parity is the same on every parity stripe.
SHA-256 over the original file is the final guard: a BCH
miscorrection (a damage pattern beyond `t` landing on a different
valid codeword) is caught by the hash and reported as corruption,
never as silent damage.

Read order: reassemble surviving stripes → rebuild any dead stripe
via parity → BCH check/correct → SHA-256 verify. The BCH syndrome
is computed streaming on read (a cheap linear pass); full correction
only runs if the syndrome is non-zero. XOR/Q/R parity is read only
when a stripe is dead. I/O works in 64 KiB bursts.

## Config

```
stripe:<label>:<file>:<rw|ro>:<size>
parity:<label>:<file>:<rw|ro>:<poly>:<error_level>
```

* `stripe` lines: exactly **8** (the bit-plane layout fixes the
  count; any other number is an error).
* `parity` lines: **1–3** (more than 3 is an error for v1).
* `rw` = read-write, `ro` = read-only (never written; usable for
  reads and recovery). A write requires every stripe and parity to
  be `rw`.
* `size` = capacity with K/M/G suffixes (`10G`). A write that would
  exceed a stripe's remaining capacity fails instead of silently
  wrapping. `-init` checks that the filesystem actually has room for
  the configured sizes.
* `poly` is a hex id (as in the polynomial tables: `0044` is m=20,
  t=8; `003a` is m=18, t=32). It is authoritative; `error_level`
  must agree with it (`bch_t_for_level`: 1→1, 2→2, 3→4, 4→8, 5→16,
  6→32, 7→32) or the config is rejected.
* A stripe or parity file can live anywhere — the config is just
  paths. Labels must be unique across all entries.

Example (8 stripes + 3 parities, poly `0044`, level 4):

```
stripe:s0:/mnt/disk0/s0.hyper:rw:1G
stripe:s1:/mnt/disk1/s1.hyper:rw:1G
stripe:s2:/mnt/disk2/s2.hyper:rw:1G
stripe:s3:/mnt/disk3/s3.hyper:rw:1G
stripe:s4:/mnt/disk4/s4.hyper:rw:1G
stripe:s5:/mnt/disk5/s5.hyper:rw:1G
stripe:s6:/mnt/disk6/s6.hyper:rw:1G
stripe:s7:/mnt/disk7/s7.hyper:rw:1G
parity:p0:/mnt/disk8/p0.hyper:rw:0044:4
parity:p1:/mnt/disk9/p1.hyper:rw:0044:4
parity:p2:/mnt/diska/p2.hyper:rw:0044:4
```

## Commands

```
lzply_hyper -c config.txt <command> [args]
```

* `-init [--force]` — validate the config; check each parent
  directory exists and is writable (if `rw`) and that the filesystem
  has room for the configured stripe sizes; create the empty stripe
  and parity files. Refuses to overwrite existing files without
  `--force`. An `ro` file must already exist (it is verified, never
  created).
* `write <file> [name]` — stripe a file into the volume. The name
  defaults to the file's basename. Refuses to overwrite an existing
  name (no overwrite in v1). Requires all stripes and parities `rw`,
  all stripe files present and the same size, and enough remaining
  capacity.
* `read <name> <out>` — read a file back out. Rebuilds a dead stripe
  via parity if needed, corrects bit rot via BCH, verifies SHA-256.
  Reports rebuilds and corrections.
* `list` — list the files in the volume (scans the parity-stripe
  index; uses the parity stripe with the most records).
* `check <name>` — verify a file (stripe parity + BCH + SHA-256),
  no output file.
* `-rebuild` — rebuild lost/corrupt stripes. Detects missing or
  wrong-size data stripes and parity stripes; reconstructs the data
  stripes from the surviving stripes + parity (P/Q/R as needed for
  1/2/3 losses); reconstructs a missing parity stripe from the data
  stripes. Rebuilt data goes to temp files and is renamed into place
  only on success, so a failed rebuild leaves the damaged files
  untouched. Reports what was rebuilt and what could **not** be
  rebuilt. Fails clearly, never silently returns wrong data.

## The index, and its failure mode

The index lives in the parity stripes: each file's record is appended
to every parity stripe, so `list` (and `read`, `check`, `-rebuild`)
scan the parity stripe with the most records. If **every** parity
stripe is dead but the data stripes are intact, the files are still
readable in principle — just unverifiable and unrecoverable, because
there is no record of their names, lengths, or hashes. That failure
mode is worth knowing, not hiding: keep at least one parity stripe
alive, and it does not matter which one.

`-rebuild` only detects missing or wrong-size stripes. Bit rot
*inside* a stripe file (right size, wrong bytes) is corrected on read
by BCH, but `-rebuild` does not rewrite a stripe file for bit rot
alone — it rebuilds a stripe from parity only when the stripe is
missing or the wrong size, and then only from parity, never from the
stripe's own possibly-corrupt old bytes.

## Read speed (measured)

Measured on the server (107.152.42.152, 4 vCPU, 3.8 GiB RAM) reading
a 100 MiB random file, poly `0044` (m=20, t=8), 3 parity stripes:

| operation | throughput |
|---|---|
| raw `cat` of the 8 stripe files (I/O floor) | 2,424 MiB/s |
| SHA-256 alone (`sha256sum`, 100 MiB) | 178 MiB/s |
| BCH syndrome alone (clean, 100 MiB) | 50.8 MiB/s |
| `lzply_hyper read` (100 MiB, 3 runs) | **35.2 / 34.0 / 35.4 MiB/s** |
| `lzply_hyper check` (100 MiB, 3 runs, no output) | **37.2 / 33.4 / 37.1 MiB/s** |

The BCH syndrome is the bottleneck: it is a serial LFSR remainder,
O(n·r/8), and it cannot be vectorised (each byte depends on the
previous remainder). Two targeted speedups in `bch.c` helped: fusing
the shift-left-by-one-byte and the table XOR into a single pass
(37 → 50.8 MiB/s for the syndrome), and computing the syndrome
straight from the input instead of copying the block first. The
read path is ~1.6x faster than the first build (22 → 35 MiB/s).
The remaining cost is the syndrome plus SHA-256; the transpose and
the I/O are negligible by comparison.

## Tests

`tests/run_hyper_tests.sh` — 56 tests, all passing on the server and
locally (no FUSE needed; it is a plain CLI). Run via `make test`
(which also runs the `bch_test` unit suite, 7,406 checks, and the
`lzply` archive suite, 147 tests).

Covered: config parsing (valid, mismatched poly/level, wrong stripe
count, bad size, 0/4 parities, unknown poly, missing config, `ro`
behaviour); `-init` (creates files, missing dir, insufficient space,
refuses overwrite, `--force`); write/read roundtrips (empty, 1 byte,
small, 1 MiB, 8 MiB random); bit-plane layout against hand-computed
values (4 cases); 1-stripe loss (delete + truncate, P); 2-stripe loss
(P+Q, and must-fail with only 1 parity); 3-stripe loss (P+Q+R, and
must-fail with only 2 parities); Q-alone rebuild when P is dead;
4-stripe loss (read and `-rebuild` must fail, never silently return
wrong data); bit-flip correction (3 bits in a data stripe → BCH
corrects, `read` and `check` report it; 3 bits in a parity stripe →
data still readable); parity-stripe loss (delete 1 → readable,
`-rebuild` restores; delete all → read fails, no index); capacity
overflow (exact fill, then a further write fails and the volume is
intact); SHA-256 tamper (12 bits in one BCH block → `check` and
`read` fail, no byte-identical output); read-speed benchmark.

## Demo (server, measured)

```
$ lzply_hyper -c cfg.txt -init
volume initialized: 8 data stripes, 3 parity stripe(s), poly 0x0044 t=8
$ lzply_hyper -c cfg.txt write big.bin big
wrote 'big': 104857600 bytes, stripe_off 0, stripe_len 13107200,
  bch 16020 bytes, sha256 a89cc4d7bcd5621d0b0fee033380628861aab5c48c0e2bab2218e211a3cb76bd
$ rm vol/s0.bin vol/s4.bin vol/s7.bin        # delete 3 data stripes
$ lzply_hyper -c cfg.txt read big big.out
read 'big': 104857600 bytes -> big.out (rebuilt 3 dead stripes)
$ cmp big.bin big.out                          # byte-identical
$ lzply_hyper -c cfg.txt -rebuild
rebuilt data stripe s0 (vol/s0.bin)
rebuilt data stripe s4 (vol/s4.bin)
rebuilt data stripe s7 (vol/s7.bin)
rebuild complete
$ lzply_hyper -c cfg.txt check big
check 'big': OK (104857600 bytes, sha256 verified)
```

Per-stripe files for the 100 MiB file: each data stripe 13,107,200
bytes; each parity stripe 13,123,319 bytes (record header + name +
parity + BCH). Overhead for 3 parities: 3 × 12.5% + 16,020 BCH bytes
+ 3 × 113-byte headers ≈ 37.5%.

## Build / install

```sh
make lzply_hyper        # links bch.o + sha256.o only (no liblz, no FUSE)
make install            # installs /usr/local/bin/lzply_hyper
make test               # bch_test + lzply suite + hyper suite
```

Sources: `lzply_hyper.c` (the whole tool), `bch.c`/`bch.h`/
`bch_polys.h` (BCH codec + the 82 polys), `sha256.c`/`sha256.h`
(in-tree SHA-256). Design draft: `lzply_hyper-design.md`.
