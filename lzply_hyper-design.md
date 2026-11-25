# lzply_hyper — DRAFT design (not built yet)

Status: DRAFT for user review, 2026-11-25. Updated 13:11 NZDT: 8 bit-plane
stripes, recovering a lost stripe is required, write speed is not a
constraint, read speed is the priority. No code written; nothing here is
decided until the user says so.

## The fork, resolved: both — two layers, not one

The user's design as sketched (BCH parity over the file, stored on the parity
stripe) recovers **bit rot only**. It cannot rebuild a dead stripe, and the
numbers say so plainly:

- BCH block, poly `0044` (m=20, t=8): max 131,051 data bytes per block,
  r = 160 parity bits = 20 bytes. Erasure capacity per block is 20 bytes.
- If one of 5 data stripes dies, a 131,051-byte block loses
  131,051 / 5 = 26,210 bytes — ~1,300x the erasure capacity.
- So BCH alone is the wrong tool for stripe loss. Stripe loss needs parity
  computed **across the stripes** (XOR, RAID-5 style), which is a different
  scheme from the BCH poly in the config.

Recommendation: keep the user's config exactly as sketched, and store **two
things** in each file's parity record:

1. **XOR parity (stripe-loss layer, REQUIRED — user: recover a lost
   stripe).** For each byte position, P = XOR of the 8 bits (one from
   each data stripe). One parity stripe rebuilds any ONE dead data
   stripe: missing bit = XOR of the 7 surviving bits + the parity bit.
   Overhead is 1/8 (12.5%).
2. **BCH parity over the file (bit-rot layer).** Computed over the whole
   original file with the config's poly, stored after the XOR bytes.
   It corrects bit rot in the reassembled file — including a bit error that
   propagated through the XOR rebuild, since that lands as a single-bit
   error in the reassembled file. Cost is tiny: a 1 MiB file with poly
   `0044` is 8 BCH blocks x 20 bytes = 160 bytes total.

Read order: reassemble surviving stripes -> XOR-rebuild any dead stripe ->
reassemble file -> BCH check/correct -> SHA-256 verify (reuse `sha256.c`).

## Config (user's format, nailed down)

```
stripe:<label>:<file>:<rw>:<size>
parity:<label>:<file>:<rw>:<poly>:<error_level>
```

- `rw`: `rw` = read-write, `ro` = read-only (never written; usable for
  reads/recovery). Anything else is a config error.
- `size`: capacity in bytes, K/M/G suffixes allowed (`10G`). A write that
  would exceed a stripe's remaining capacity fails instead of silently
  wrapping.
- `poly` is authoritative; `error_level` must agree with it or the config
  is rejected. Poly id already fixes (m, t) — e.g. `0044` is m=20, t=8
  (`bch_polys.h`), and `-e` level 4 also means t=8 (`bch_t_for_level` in
  `bch.h`: 1->1, 2->2, 3->4, 4->8, 5->16, 6->32). Example, consistent:
  `parity:p0:/mnt/disk6/parity.hyper:rw:0044:4`
- 8 data stripes (one per bit — the bit-plane layout fixes the count
  at 8). Any number of parity stripes (1, 2, 3, ...). Poly lookup reuses
  `bch_poly_by_id()`; encoding reuses `bch_encode()` from `bch.c` — no new
  ECC code for layer 2.

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
  non-zero. XOR parity is read only when a stripe is dead. Full verify
  (XOR + BCH + SHA-256) is the separate `check` command.
- I/O is **not** 1-byte syscalls: work in 64 KiB bursts in memory,
  then one sequential write per stripe per burst. (64 KiB is a default;
  make it a flag later if the user wants it tuned.)

## Second / third parity stripe: mirror vs independent (user to decide)

The user said extra parity slices are "just redundancy". That is true, with
one sharp consequence:

- **Mirrored copies (default reading):** parity stripes 2 and 3 hold byte
  copies of parity stripe 1's records. They protect against losing the
  parity file itself. They do **not** add tolerance for a second dead data
  stripe — rebuilding two dead stripes from one XOR equation is impossible.
- **Independent Q (RAID-6 style, phase 3):** second parity is a weighted
  XOR (GF(256) coefficients) over the same rows. Then any TWO dead data
  stripes rebuild. Costs a second parity stripe's worth of space and a
  GF(256) multiply per byte on write.

Default proposal: v1 mirrors; Q is a named phase-3 option, not silently
assumed.

## Where files live: index in the parity stripe

- `lzply_hyper` is a CLI in v1, not a mount: 
  `lzply_hyper -c config.txt write <file> [name]`,
  `read <name> <out>`, `list`, `check <name>` (verify XOR + BCH + SHA-256,
  no output file).
- Each file's parity record, appended to the parity stripe(s):
  header (name, original length, N, poly, t, xor length, bch length,
  SHA-256 of the original) + XOR bytes + BCH parity bytes.
- `list` scans parity stripe 0 (any surviving parity copy will do).
  If every parity stripe is dead but the data stripes are intact, files
  are still readable — just unverifiable and unrecoverable. That failure
  mode is worth knowing, not hiding.

## Worked example (8 data + 1 parity, 1 MiB file, poly 0044)

- Each data stripe: 131,072 bytes. XOR parity: 131,072 bytes (12.5%).
- BCH parity: ~160 bytes. SHA-256: 32 bytes in the header.
- Survives: any 1 dead data stripe (via XOR, then BCH cleanup), or the
  parity stripe itself (data still readable), or scattered bit errors up
  to t=8 per 131 KiB BCH block.
- Does not survive: 2 dead data stripes (needs Q), or a dead stripe plus
  more than t bit errors in the same BCH block.

## Build phases (proposed, not started)

1. Config parser + stripe engine + XOR layer + CLI (write/read/list/check).
2. BCH layer reusing `bch.c` + SHA-256 verify.
3. Multi-parity: mirrors, then Q if the user wants 2-stripe survival.
4. Tests (dead-stripe rebuild, bit-flip correction, capacity overflow,
   config mismatch) + docs.

## Decisions still with the user

1. Recovery scope: DECIDED — 1 dead stripe via XOR (user: recover a
   lost stripe is required). 2 dead stripes (needs Q) is a later
   option, not v1.
2. Extra parity stripes: mirrors (default) or independent Q?
3. CLI v1 vs mount from the start? (Recommend CLI; mount reuses
   `lzply_mount.c` patterns later.)
4. Burst size 64 KiB OK, or a different default?
