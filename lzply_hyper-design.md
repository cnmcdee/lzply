# lzply_hyper — as-built design

Status: **BUILT, Nov 25, 2026.** CLI v1 complete, 56/56 tests pass on
the server and locally, installed at `/usr/local/bin/lzply_hyper`.
This document is the as-built record; the DRAFT it replaces is
superseded. Deviations from the draft are marked.

## The fork, resolved: both — two layers, not one

The user's design as sketched (BCH parity over the file, stored on the
parity stripe) recovers **bit rot only**. It cannot rebuild a dead stripe,
and the numbers say so plainly:

- BCH block, poly `0044` (m=20, t=8): max 131,051 data bytes per block,
  r = 160 parity bits = 20 bytes. Erasure capacity per block is 20 bytes.
- If one of 8 data stripes dies, a 131,051-byte block loses
  131,051 / 8 = 16,381 bytes — ~800x the erasure capacity.
- So BCH alone is the wrong tool for stripe loss. Stripe loss needs
  parity computed **across the stripes**, which is a different scheme
  from the BCH poly in the config.

As built, each file's parity record stores **two things**:

1. **Stripe-loss parity (REQUIRED — user: recover a lost stripe).**
   Independent parity stripes P, Q, R (see below). P alone rebuilds
   any ONE dead data stripe. Overhead is 1/8 (12.5%) per parity stripe.
2. **BCH parity over the file (bit-rot layer).** Computed over the whole
   original file with the config's poly, stored after the parity bytes.
   It corrects bit rot in the reassembled file — including a bit error
   that propagated through a stripe rebuild, since that lands as a
   single-bit error in the reassembled file. Cost is tiny: a 1 MiB file
   with poly `0044` is 8 BCH blocks x 20 bytes = 160 bytes total.
   A 100 MiB file is 16,020 BCH bytes.

Read order: reassemble surviving stripes -> rebuild any dead stripe
via parity -> BCH check/correct -> SHA-256 verify (reuse `sha256.c`).

## Config (user's format, as built)

```
stripe:<label>:<file>:<rw>:<size>
parity:<label>:<file>:<rw>:<poly>:<error_level>
```

- `rw`: `rw` = read-write, `ro` = read-only (never written; usable for
  reads/recovery). Anything else is a config error. A write requires
  every stripe and parity to be `rw`.
- `size`: capacity in bytes, K/M/G suffixes allowed (`10G`). A write
  that would exceed a stripe's remaining capacity fails instead of
  silently wrapping. `-init` checks the filesystem has room.
- `poly` is a **hex** id, authoritative; `error_level` must agree with
  it or the config is rejected. Poly id already fixes (m, t) — e.g.
  `0044` is m=20, t=8 (`bch_polys.h`), and `-e` level 4 also means t=8
  (`bch_t_for_level`: 1->1, 2->2, 3->4, 4->8, 5->16, 6->32). Example:
  `parity:p0:/mnt/disk6/parity.hyper:rw:0044:4`. (The parser reads the
  poly as hex — `0044` is 0x0044, m=20 — not decimal 44, which would be
  m=16. An optional `0x` prefix is accepted.)
- 8 data stripes (one per bit — the bit-plane layout fixes the count
  at 8). **1–3 parity stripes** (more than 3 is an error for v1).
  Poly lookup reuses `bch_poly_by_id()`; BCH encoding reuses
  `bch_encode_block` from `bch.c`. The poly is taken from the **first**
  parity line; all parity lines must agree on poly + error level.

## Striping: 8 bit-plane stripes

- Layout: 8 data stripes, one per bit. Byte i splits into its 8 bits,
  bit j goes to stripe j. Stripe j holds one bit of every byte, packed.
  For a 1 MiB file each stripe is 131,072 bytes, all eight exactly the
  same size. No compression anywhere.
- Write speed is not a constraint (user: write can be super slow), so
  bit-packing cost on write is acceptable.
- Read speed is the priority (user: read must be super fast). Read
  reassembles with an efficient 8x8 bit-matrix transpose (SWAR), not
  per-bit extraction. BCH syndrome is computed streaming on read
  (cheap linear pass); full correction runs only if the syndrome is
  non-zero. XOR/Q/R parity is read only when a stripe is dead. Full
  verify (parity + BCH + SHA-256) is the separate `check` command.
- I/O is 64 KiB bursts in memory, then one sequential write per stripe
  per burst.

## Parity stripes: independent P, Q, R (mirrors superseded)

DEVIATION from the draft: the draft proposed mirrored parity copies
as the v1 default, with Q as a later option. The user instead approved
2-stripe and 3-stripe loss options, which require **independent**
parities. So v1 has no mirrors — each parity stripe is a different
function of the data stripes:

- **P** (parity row 0) = XOR across the 8 data stripes. Recovers 1.
- **Q** (parity row 1) = GF(256) weighted sum, `sum g^j * s_j`, g = 2
  (field generator, primitive polynomial `0x11d`). Recovers a 2nd.
- **R** (parity row 2) = GF(256) weighted sum, `sum g^(2j) * s_j`.
  Recovers a 3rd.

Recovery solves the k×k coefficient system over GF(256) by
Gauss-Jordan inversion, per byte position, using whichever parity rows
survive (at least k of them). Q alone rebuilds 1 lost stripe if P is
dead. 4 lost stripes is beyond tolerance: `read` and `-rebuild` fail
clearly, never silently return wrong data.

## Where files live: index in the parity stripe

- `lzply_hyper` is a CLI in v1, not a mount:
  `lzply_hyper -c config.txt <command>`, with `-init [--force]`,
  `write <file> [name]`, `read <name> <out>`, `list`, `check <name>`,
  `-rebuild`.
- Each file's parity record, appended to each parity stripe: a 96-byte
  header (magic `HYPR`, version 1, parity_idx 0=P/1=Q/2=R, name_len,
  poly_id, t, npar, orig_len, stripe_off, stripe_len, parity_len,
  bch_len, sha256[32], header_crc32) + name + parity bytes
  (`stripe_len`) + BCH parity bytes. The record's `stripe_off` is the
  offset of this file's data in the stripe files (all 8 stripes hold
  the same offset for a given file).
- `list` scans the parity stripe with the most records (a truncated
  parity stripe yields a short index; a crashed write may leave one
  parity stripe one record ahead, and that record's stripe data is
  already on disk, so the longest index is the right one).
  If every parity stripe is dead but the data stripes are intact,
  files are still readable in principle — just unverifiable and
  unrecoverable. That failure mode is worth knowing, not hiding.
- `write` refuses to overwrite an existing name (no overwrite in v1).
  `-rebuild` writes rebuilt data stripes to temp files and renames
  them into place only on success; a failed rebuild leaves the damaged
  files untouched. A damaged stripe is rebuilt purely from parity,
  never from its own possibly-corrupt old bytes.
- `-rebuild` detects missing or wrong-size stripes only. Bit rot
  *inside* a stripe file (right size, wrong bytes) is corrected on
  read by BCH, but does not trigger a stripe rewrite.

## Worked example (8 data + 3 parities, 100 MiB file, poly 0044)

Measured on the server, Nov 25, 2026 (demo file sha256
`a89cc4d7bcd5621d0b0fee033380628861aab5c48c0e2bab2218e211a3cb76bd`):

- Each data stripe: 13,107,200 bytes. Each parity stripe:
  13,123,319 bytes (record header + name + parity + BCH).
- BCH parity: 16,020 bytes. SHA-256: 32 bytes in the header.
- Overhead for 3 parities: 3 × 12.5% + 16,020 BCH bytes ≈ 37.5%.
- Survives: any 1, 2, or 3 dead data stripes (via P, P+Q, P+Q+R),
  a dead parity stripe (data still readable, `-rebuild` restores it),
  or scattered bit errors up to t=8 per 131 KiB BCH block.
- Does not survive: 4 dead data stripes, or all parity stripes dead
  (no index — files unreadable by name, though the data stripes are
  intact), or more than t bit errors in the same BCH block (detected
  by SHA-256, reported, never silently returned).

## Read speed (measured, server)

100 MiB random file, poly `0044`, 3 parities:

| operation | throughput |
|---|---|
| raw `cat` of the 8 stripe files | 2,424 MiB/s |
| SHA-256 alone | 178 MiB/s |
| BCH syndrome alone (clean) | 50.8 MiB/s |
| `lzply_hyper read` | 35.2 / 34.0 / 35.4 MiB/s |
| `lzply_hyper check` | 37.2 / 33.4 / 37.1 MiB/s |

First build read at ~22 MiB/s. Two `bch.c` speedups raised it to
~35 MiB/s: fusing the remainder shift-left-by-one-byte and the table
XOR into a single pass (syndrome 37 → 50.8 MiB/s), and computing the
syndrome straight from the input instead of copying the block first.
The BCH syndrome is the bottleneck — a serial LFSR remainder,
O(n·r/8), not vectorisable (each byte depends on the previous
remainder). The transpose and the I/O are negligible by comparison.

## Decisions (all resolved)

1. Recovery scope: 1/2/3 dead stripes via P/Q/R (user approved the
   2- and 3-stripe loss options).
2. Extra parity stripes: independent P/Q/R, not mirrors (mirrors
   superseded — they cannot add tolerance for a 2nd dead stripe).
3. CLI v1, not a mount.
4. Burst size 64 KiB.
5. No overwrite on `write` in v1; no legacy format concerns (the
   format is new and can change freely).
