#!/bin/bash
# run_hyper_tests.sh - lzply_hyper test suite.
# Usage: run_hyper_tests.sh [path-to-lzply_hyper]
# ROOT is the lzply tree root (testdata/, testwork/, tests/ live under
# it): taken from $LZPLY_TEST_ROOT, else the parent of this script's
# directory (works for ~/workspace/lzply and for /opt/lzply/src).
# No FUSE needed (lzply_hyper is a plain CLI), so this runs locally
# and on the server.
set -u
HYPER="${1:-/opt/lzply/src/lzply_hyper}"
case "$HYPER" in
    /*) ;;
    *) HYPER="$(cd "$(dirname "$HYPER")" && pwd)/$(basename "$HYPER")" ;;
esac
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${LZPLY_TEST_ROOT:-$(dirname "$SCRIPT_DIR")}"
WORK=$ROOT/testwork-hyper
CORRUPT_BITS=/tmp/corrupt_bits_hyper
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }

rm -rf "$WORK"
mkdir -p "$WORK"
gcc -O2 -Wall -o "$CORRUPT_BITS" "$ROOT/tests/corrupt_bits.c" || { echo "cannot build corrupt_bits helper"; exit 1; }
[ -x "$HYPER" ] || { echo "lzply_hyper binary not found: $HYPER"; exit 1; }

# mkcfg <dir> <npar> [poly] [level] [stripe-size]
# Writes $dir/cfg.txt (8 stripes + npar parities) and $dir/vol/.
# Defaults: poly 0044 (m=20 t=8), level 4, stripe size 64M.
mkcfg() {
    local dir=$1 npar=${2:-3} poly=${3:-0044} lvl=${4:-4} sz=${5:-64M}
    mkdir -p "$dir/vol"
    : > "$dir/cfg.txt"
    for j in 0 1 2 3 4 5 6 7; do
        echo "stripe:s$j:$dir/vol/s$j.bin:rw:$sz" >> "$dir/cfg.txt"
    done
    for ((p = 0; p < npar; p++)); do
        echo "parity:p$p:$dir/vol/p$p.bin:rw:$poly:$lvl" >> "$dir/cfg.txt"
    done
}

# mkvol <dir> [npar] [poly] [level] [stripe-size]
# mkcfg + -init. Returns non-zero if -init fails.
mkvol() {
    mkcfg "$@"
    "$HYPER" -c "$1/cfg.txt" -init >/dev/null 2>&1
}

# randfile <path> <bytes> : deterministic pseudo-random file.
randfile() {
    python3 -c "
import random,sys
random.seed(12345)
n=$2
with open('$1','wb') as f:
    while n > 0:
        chunk = min(n, 65536)
        f.write(bytes(random.getrandbits(8) for _ in range(chunk)))
        n -= chunk
"
}

# byte_at <file> <offset> : 2-digit hex of the byte at offset (via od).
byte_at() { od -An -tx1 -v -j "$2" -N 1 "$1" | tr -d ' \n'; }

# --- 1. Config parsing -----------------------------------------------
T=$WORK/cfg
mkdir -p "$T"
# 1a. valid config loads (init succeeds)
mkvol "$T/valid" 3 >/dev/null 2>&1 && [ -f "$T/valid/vol/s0.bin" ] && \
    ok "config: valid 8+3 parses and -init creates files" || bad "config: valid 8+3 parses and -init creates files"
# 1b. mismatched poly/error_level (0044 is t=8, level 5 is t=16)
mkcfg "$T/badlevel" 1 0044 5
"$HYPER" -c "$T/badlevel/cfg.txt" -init >/dev/null 2>&1 && \
    bad "config: poly 0044 + level 5 (t=16) rejected" || ok "config: poly 0044 + level 5 (t=16) rejected"
# 1c. wrong data-stripe count (7 stripes)
mkdir -p "$T/seven/vol"
: > "$T/seven/cfg.txt"
for j in 0 1 2 3 4 5 6; do echo "stripe:s$j:$T/seven/vol/s$j.bin:rw:10M" >> "$T/seven/cfg.txt"; done
echo "parity:p0:$T/seven/vol/p0.bin:rw:0044:4" >> "$T/seven/cfg.txt"
"$HYPER" -c "$T/seven/cfg.txt" -init >/dev/null 2>&1 && \
    bad "config: 7 data stripes rejected" || ok "config: 7 data stripes rejected"
# 1d. bad size
mkdir -p "$T/badsize/vol"
: > "$T/badsize/cfg.txt"
for j in 0 1 2 3 4 5 6 7; do echo "stripe:s$j:$T/badsize/vol/s$j.bin:rw:10X" >> "$T/badsize/cfg.txt"; done
echo "parity:p0:$T/badsize/vol/p0.bin:rw:0044:4" >> "$T/badsize/cfg.txt"
"$HYPER" -c "$T/badsize/cfg.txt" -init >/dev/null 2>&1 && \
    bad "config: bad size '10X' rejected" || ok "config: bad size '10X' rejected"
# 1e. mismatched poly across parity lines
mkdir -p "$T/mismatch/vol"
: > "$T/mismatch/cfg.txt"
for j in 0 1 2 3 4 5 6 7; do echo "stripe:s$j:$T/mismatch/vol/s$j.bin:rw:10M" >> "$T/mismatch/cfg.txt"; done
echo "parity:p0:$T/mismatch/vol/p0.bin:rw:0044:4" >> "$T/mismatch/cfg.txt"
echo "parity:p1:$T/mismatch/vol/p1.bin:rw:003a:4" >> "$T/mismatch/cfg.txt"
"$HYPER" -c "$T/mismatch/cfg.txt" -init >/dev/null 2>&1 && \
    bad "config: parity lines disagreeing on poly rejected" || ok "config: parity lines disagreeing on poly rejected"
# 1f. 4 parity stripes (more than 3 is an error for v1)
mkcfg "$T/fourpar" 4
"$HYPER" -c "$T/fourpar/cfg.txt" -init >/dev/null 2>&1 && \
    bad "config: 4 parity stripes rejected" || ok "config: 4 parity stripes rejected"
# 1g. 0 parity stripes
mkdir -p "$T/nopar/vol"
: > "$T/nopar/cfg.txt"
for j in 0 1 2 3 4 5 6 7; do echo "stripe:s$j:$T/nopar/vol/s$j.bin:rw:10M" >> "$T/nopar/cfg.txt"; done
"$HYPER" -c "$T/nopar/cfg.txt" -init >/dev/null 2>&1 && \
    bad "config: 0 parity stripes rejected" || ok "config: 0 parity stripes rejected"
# 1h. unknown poly id
mkcfg "$T/badpoly" 1 00ff 4
"$HYPER" -c "$T/badpoly/cfg.txt" -init >/dev/null 2>&1 && \
    bad "config: unknown poly 00ff rejected" || ok "config: unknown poly 00ff rejected"
# 1i. missing config file
"$HYPER" -c "$T/does-not-exist.txt" -init >/dev/null 2>&1 && \
    bad "config: missing config file rejected" || ok "config: missing config file rejected"
# 1j. ro stripe: write must fail, read must work after a rw write
# (build the volume rw, write a file, then flip one stripe to ro)
mkvol "$T/rotest" 1 >/dev/null 2>&1
echo "ro test content" > "$T/rotest/f.txt"
"$HYPER" -c "$T/rotest/cfg.txt" write "$T/rotest/f.txt" f.txt >/dev/null 2>&1
sed -i 's|/vol/s0.bin:rw:|/vol/s0.bin:ro:|' "$T/rotest/cfg.txt"
"$HYPER" -c "$T/rotest/cfg.txt" write "$T/rotest/f.txt" f2.txt >/dev/null 2>&1 && \
    bad "config: write with an ro stripe rejected" || ok "config: write with an ro stripe rejected"
"$HYPER" -c "$T/rotest/cfg.txt" read f.txt "$T/rotest/f.out" >/dev/null 2>&1 && \
    cmp -s "$T/rotest/f.txt" "$T/rotest/f.out" && \
    ok "config: read works with an ro stripe" || bad "config: read works with an ro stripe"

# --- 2. -init ----------------------------------------------------------
T=$WORK/init
mkdir -p "$T"
# 2a. creates all 11 files, empty
mkvol "$T/a" 3 >/dev/null 2>&1
n=$(ls "$T/a/vol" | wc -l)
[ "$n" = 11 ] && [ ! -s "$T/a/vol/s0.bin" ] && [ ! -s "$T/a/vol/p0.bin" ] && \
    ok "-init: creates 8 stripes + 3 parities, all empty" || bad "-init: creates 8 stripes + 3 parities, all empty (n=$n)"
# 2b. missing parent directory
mkdir -p "$T/missing"
: > "$T/missing/cfg.txt"
for j in 0 1 2 3 4 5 6 7; do echo "stripe:s$j:$T/missing/nodir/s$j.bin:rw:10M" >> "$T/missing/cfg.txt"; done
echo "parity:p0:$T/missing/nodir/p0.bin:rw:0044:4" >> "$T/missing/cfg.txt"
"$HYPER" -c "$T/missing/cfg.txt" -init >/dev/null 2>&1 && \
    bad "-init: missing parent directory rejected" || ok "-init: missing parent directory rejected"
# 2c. insufficient space (8 x 100T can never fit)
mkcfg "$T/nospace" 1 0044 4 100T
"$HYPER" -c "$T/nospace/cfg.txt" -init >/dev/null 2>&1 && \
    bad "-init: insufficient space rejected" || ok "-init: insufficient space rejected"
# 2d. refuses to overwrite without --force
mkvol "$T/ow" 1 >/dev/null 2>&1
"$HYPER" -c "$T/ow/cfg.txt" -init >/dev/null 2>&1 && \
    bad "-init: refuses to overwrite existing files" || ok "-init: refuses to overwrite existing files"
# 2e. --force replaces
"$HYPER" -c "$T/ow/cfg.txt" -init --force >/dev/null 2>&1 && \
    [ ! -s "$T/ow/vol/s0.bin" ] && \
    ok "-init --force: replaces existing files" || bad "-init --force: replaces existing files"

# --- 3. Write/read roundtrip ------------------------------------------
T=$WORK/rt
mkdir -p "$T"
mkvol "$T/v" 3 >/dev/null 2>&1
: > "$T/empty.bin"
"$HYPER" -c "$T/v/cfg.txt" write "$T/empty.bin" empty >/dev/null 2>&1 && \
"$HYPER" -c "$T/v/cfg.txt" read empty "$T/empty.out" >/dev/null 2>&1 && \
cmp -s "$T/empty.bin" "$T/empty.out" && \
    ok "roundtrip: empty file" || bad "roundtrip: empty file"
printf 'x' > "$T/one.bin"
"$HYPER" -c "$T/v/cfg.txt" write "$T/one.bin" one >/dev/null 2>&1 && \
"$HYPER" -c "$T/v/cfg.txt" read one "$T/one.out" >/dev/null 2>&1 && \
cmp -s "$T/one.bin" "$T/one.out" && \
    ok "roundtrip: 1-byte file" || bad "roundtrip: 1-byte file"
printf 'hello hyper world, striped across 8 bit-planes.' > "$T/small.txt"
"$HYPER" -c "$T/v/cfg.txt" write "$T/small.txt" small >/dev/null 2>&1 && \
"$HYPER" -c "$T/v/cfg.txt" read small "$T/small.out" >/dev/null 2>&1 && \
cmp -s "$T/small.txt" "$T/small.out" && \
    ok "roundtrip: small text file" || bad "roundtrip: small text file"
randfile "$T/rand1m.bin" 1048576
"$HYPER" -c "$T/v/cfg.txt" write "$T/rand1m.bin" rand1m >/dev/null 2>&1 && \
"$HYPER" -c "$T/v/cfg.txt" read rand1m "$T/rand1m.out" >/dev/null 2>&1 && \
cmp -s "$T/rand1m.bin" "$T/rand1m.out" && \
    ok "roundtrip: 1 MiB random file" || bad "roundtrip: 1 MiB random file"
randfile "$T/rand8m.bin" 8388608
"$HYPER" -c "$T/v/cfg.txt" write "$T/rand8m.bin" rand8m >/dev/null 2>&1 && \
"$HYPER" -c "$T/v/cfg.txt" read rand8m "$T/rand8m.out" >/dev/null 2>&1 && \
cmp -s "$T/rand8m.bin" "$T/rand8m.out" && \
    ok "roundtrip: 8 MiB random file" || bad "roundtrip: 8 MiB random file"
# list shows all 5 files
"$HYPER" -c "$T/v/cfg.txt" list 2>/dev/null | grep -c "^  " | grep -q "^5$" && \
    ok "list: shows all 5 files" || bad "list: shows all 5 files"
# check passes on a clean file
"$HYPER" -c "$T/v/cfg.txt" check rand1m >/dev/null 2>&1 && \
    ok "check: clean file passes" || bad "check: clean file passes"
# duplicate write refused (no overwrite in v1)
"$HYPER" -c "$T/v/cfg.txt" write "$T/small.txt" small >/dev/null 2>&1 && \
    bad "write: duplicate name refused" || ok "write: duplicate name refused"

# --- 4. Bit-plane layout (hand-computed) -------------------------------
# A fresh volume per case so each stripe file holds only this file.
# Case A: bytes 01 02 04 08 10 20 40 80 -> stripes are themselves.
T=$WORK/layout
mkdir -p "$T"
mkvol "$T/a" 1 >/dev/null 2>&1
python3 -c "open('$T/a/in.bin','wb').write(bytes([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80]))"
"$HYPER" -c "$T/a/cfg.txt" write "$T/a/in.bin" in >/dev/null 2>&1
la_ok=1
for j in 0 1 2 3 4 5 6 7; do
    want=$(printf '%02x' $((1 << j)))
    got=$(byte_at "$T/a/vol/s$j.bin" 0)
    [ "$got" = "$want" ] || la_ok=0
done
[ $la_ok = 1 ] && ok "layout: 01 02 04 08 10 20 40 80 -> stripes are themselves" || bad "layout: 01 02 04 08 10 20 40 80 -> stripes are themselves"
# Case B: bytes FF 00 00 00 00 00 00 00 -> every stripe is 01.
mkvol "$T/b" 1 >/dev/null 2>&1
python3 -c "open('$T/b/in.bin','wb').write(bytes([0xFF,0,0,0,0,0,0,0]))"
"$HYPER" -c "$T/b/cfg.txt" write "$T/b/in.bin" in >/dev/null 2>&1
lb_ok=1
for j in 0 1 2 3 4 5 6 7; do
    got=$(byte_at "$T/b/vol/s$j.bin" 0)
    [ "$got" = "01" ] || lb_ok=0
done
[ $lb_ok = 1 ] && ok "layout: FF 00..00 -> every stripe is 01" || bad "layout: FF 00..00 -> every stripe is 01"
# Case C: bytes 80 40 20 10 08 04 02 01 -> stripes are themselves (anti-diagonal).
mkvol "$T/c" 1 >/dev/null 2>&1
python3 -c "open('$T/c/in.bin','wb').write(bytes([0x80,0x40,0x20,0x10,0x08,0x04,0x02,0x01]))"
"$HYPER" -c "$T/c/cfg.txt" write "$T/c/in.bin" in >/dev/null 2>&1
lc_ok=1
for j in 0 1 2 3 4 5 6 7; do
    want=$(printf '%02x' $((0x80 >> j)))
    got=$(byte_at "$T/c/vol/s$j.bin" 0)
    [ "$got" = "$want" ] || lc_ok=0
done
[ $lc_ok = 1 ] && ok "layout: 80 40 20 10 08 04 02 01 -> stripes are themselves" || bad "layout: 80 40 20 10 08 04 02 01 -> stripes are themselves"
# Case D: 16 bytes 00..0F. First group is 00..07 (all zero -> stripes 00);
# second group 08..0F: stripe j byte = bit j of 08..0F packed.
# byte 08=00001000 ... 0F=00001111. stripe0: bits0 of 08..0F = 0,1,0,1,0,1,0,1
#   (byte p of the group sits at bit p) = 0b10101010 = 0xAA. stripe1: bits1 =
#   0,0,1,1,0,0,1,1 -> 0b11001100 = 0xCC. stripe2: 0,0,0,0,1,1,1,1 -> 0xF0.
#   stripe3: 1,1,1,1,1,1,1,1 -> 0xFF. stripes 4-7: all zero.
mkvol "$T/d" 1 >/dev/null 2>&1
python3 -c "open('$T/d/in.bin','wb').write(bytes(range(16)))"
"$HYPER" -c "$T/d/cfg.txt" write "$T/d/in.bin" in >/dev/null 2>&1
ld_ok=1
for j in 0 1 2 3 4 5 6 7; do :; done
[ "$(byte_at "$T/d/vol/s0.bin" 1)" = "aa" ] || ld_ok=0
[ "$(byte_at "$T/d/vol/s1.bin" 1)" = "cc" ] || ld_ok=0
[ "$(byte_at "$T/d/vol/s2.bin" 1)" = "f0" ] || ld_ok=0
[ "$(byte_at "$T/d/vol/s3.bin" 1)" = "ff" ] || ld_ok=0
[ "$(byte_at "$T/d/vol/s4.bin" 1)" = "00" ] || ld_ok=0
[ "$(byte_at "$T/d/vol/s7.bin" 1)" = "00" ] || ld_ok=0
[ $ld_ok = 1 ] && ok "layout: bytes 00..0F second group -> AA CC F0 FF 00.." || bad "layout: bytes 00..0F second group -> AA CC F0 FF 00.."

# --- 5. 1-stripe loss (1 parity) ---------------------------------------
T=$WORK/loss1
mkdir -p "$T"
mkvol "$T/v" 1 >/dev/null 2>&1
randfile "$T/f.bin" 1048576
"$HYPER" -c "$T/v/cfg.txt" write "$T/f.bin" f >/dev/null 2>&1
rm "$T/v/vol/s3.bin"
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out" >/dev/null 2>&1 && \
cmp -s "$T/f.bin" "$T/f.out" && \
    ok "1-stripe loss: read rebuilds via P, byte-identical" || bad "1-stripe loss: read rebuilds via P, byte-identical"
"$HYPER" -c "$T/v/cfg.txt" -rebuild >/dev/null 2>&1 && \
[ -f "$T/v/vol/s3.bin" ] && \
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out2" >/dev/null 2>&1 && \
cmp -s "$T/f.bin" "$T/f.out2" && \
    ok "1-stripe loss: -rebuild restores the stripe" || bad "1-stripe loss: -rebuild restores the stripe"
# corrupt (not just delete) 1 stripe: truncate it to half
python3 -c "
p='$T/v/vol/s5.bin'
d=open(p,'rb').read()
open(p,'wb').write(d[:len(d)//2])
"
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out3" >/dev/null 2>&1 && \
cmp -s "$T/f.bin" "$T/f.out3" && \
    ok "1-stripe loss: truncated stripe reads back via P" || bad "1-stripe loss: truncated stripe reads back via P"
"$HYPER" -c "$T/v/cfg.txt" -rebuild >/dev/null 2>&1 && \
"$HYPER" -c "$T/v/cfg.txt" check f >/dev/null 2>&1 && \
    ok "1-stripe loss: -rebuild restores a truncated stripe" || bad "1-stripe loss: -rebuild restores a truncated stripe"

# --- 6. 2-stripe loss (2 parities, P+Q) --------------------------------
T=$WORK/loss2
mkdir -p "$T"
mkvol "$T/v" 2 >/dev/null 2>&1
randfile "$T/f.bin" 1048576
"$HYPER" -c "$T/v/cfg.txt" write "$T/f.bin" f >/dev/null 2>&1
rm "$T/v/vol/s1.bin" "$T/v/vol/s6.bin"
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out" >/dev/null 2>&1 && \
cmp -s "$T/f.bin" "$T/f.out" && \
    ok "2-stripe loss: read rebuilds via P+Q, byte-identical" || bad "2-stripe loss: read rebuilds via P+Q, byte-identical"
"$HYPER" -c "$T/v/cfg.txt" -rebuild >/dev/null 2>&1 && \
[ -f "$T/v/vol/s1.bin" ] && [ -f "$T/v/vol/s6.bin" ] && \
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out2" >/dev/null 2>&1 && \
cmp -s "$T/f.bin" "$T/f.out2" && \
    ok "2-stripe loss: -rebuild restores both stripes" || bad "2-stripe loss: -rebuild restores both stripes"
# 2-stripe loss must FAIL with only 1 parity stripe
mkvol "$T/v1" 1 >/dev/null 2>&1
"$HYPER" -c "$T/v1/cfg.txt" write "$T/f.bin" f >/dev/null 2>&1
rm "$T/v1/vol/s1.bin" "$T/v1/vol/s6.bin"
"$HYPER" -c "$T/v1/cfg.txt" read f "$T/f.out" >/dev/null 2>&1 && \
    bad "2-stripe loss: read with only 1 parity must FAIL" || ok "2-stripe loss: read with only 1 parity must FAIL"

# --- 7. 3-stripe loss (3 parities, P+Q+R) ------------------------------
T=$WORK/loss3
mkdir -p "$T"
mkvol "$T/v" 3 >/dev/null 2>&1
randfile "$T/f.bin" 1048576
"$HYPER" -c "$T/v/cfg.txt" write "$T/f.bin" f >/dev/null 2>&1
rm "$T/v/vol/s0.bin" "$T/v/vol/s4.bin" "$T/v/vol/s7.bin"
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out" >/dev/null 2>&1 && \
cmp -s "$T/f.bin" "$T/f.out" && \
    ok "3-stripe loss: read rebuilds via P+Q+R, byte-identical" || bad "3-stripe loss: read rebuilds via P+Q+R, byte-identical"
"$HYPER" -c "$T/v/cfg.txt" -rebuild >/dev/null 2>&1 && \
[ -f "$T/v/vol/s0.bin" ] && [ -f "$T/v/vol/s4.bin" ] && [ -f "$T/v/vol/s7.bin" ] && \
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out2" >/dev/null 2>&1 && \
cmp -s "$T/f.bin" "$T/f.out2" && \
    ok "3-stripe loss: -rebuild restores all three stripes" || bad "3-stripe loss: -rebuild restores all three stripes"
# 3-stripe loss must FAIL with only 2 parity stripes
mkvol "$T/v2" 2 >/dev/null 2>&1
"$HYPER" -c "$T/v2/cfg.txt" write "$T/f.bin" f >/dev/null 2>&1
rm "$T/v2/vol/s0.bin" "$T/v2/vol/s4.bin" "$T/v2/vol/s7.bin"
"$HYPER" -c "$T/v2/cfg.txt" read f "$T/f.out" >/dev/null 2>&1 && \
    bad "3-stripe loss: read with only 2 parities must FAIL" || ok "3-stripe loss: read with only 2 parities must FAIL"
# Q alone rebuilds 1 lost stripe when P is dead (parity-row independence)
mkvol "$T/vq" 3 >/dev/null 2>&1
"$HYPER" -c "$T/vq/cfg.txt" write "$T/f.bin" f >/dev/null 2>&1
rm "$T/vq/vol/s2.bin" "$T/vq/vol/p0.bin"
"$HYPER" -c "$T/vq/cfg.txt" read f "$T/f.out" >/dev/null 2>&1 && \
cmp -s "$T/f.bin" "$T/f.out" && \
    ok "recovery: Q alone rebuilds 1 lost stripe when P is dead" || bad "recovery: Q alone rebuilds 1 lost stripe when P is dead"

# --- 8. 4-stripe loss (beyond tolerance) -------------------------------
T=$WORK/loss4
mkdir -p "$T"
mkvol "$T/v" 3 >/dev/null 2>&1
randfile "$T/f.bin" 1048576
"$HYPER" -c "$T/v/cfg.txt" write "$T/f.bin" f >/dev/null 2>&1
rm "$T/v/vol/s0.bin" "$T/v/vol/s2.bin" "$T/v/vol/s5.bin" "$T/v/vol/s7.bin"
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out" >/dev/null 2>&1 && \
    bad "4-stripe loss: read must FAIL, never silently return wrong data" || ok "4-stripe loss: read must FAIL, never silently return wrong data"
[ -f "$T/f.out" ] && cmp -s "$T/f.bin" "$T/f.out" && \
    bad "4-stripe loss: no output file may be byte-identical" || ok "4-stripe loss: no byte-identical output produced"
"$HYPER" -c "$T/v/cfg.txt" -rebuild >/dev/null 2>&1 && \
    bad "4-stripe loss: -rebuild must FAIL" || ok "4-stripe loss: -rebuild must FAIL"

# --- 9. Bit-flip correction (BCH) ---------------------------------------
T=$WORK/bitflip
mkdir -p "$T"
mkvol "$T/v" 3 >/dev/null 2>&1
randfile "$T/f.bin" 1048576
"$HYPER" -c "$T/v/cfg.txt" write "$T/f.bin" f >/dev/null 2>&1
# flip 3 bits in one data stripe (poly 0044, t=8: correctable)
"$CORRUPT_BITS" "$T/v/vol/s4.bin" 7 3 >/dev/null 2>&1
out=$("$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out" 2>&1)
rc=$?
cmp -s "$T/f.bin" "$T/f.out" && [ $rc = 0 ] && \
    ok "bit-flip: 3 flipped bits in a stripe, read corrects via BCH" || bad "bit-flip: 3 flipped bits in a stripe, read corrects via BCH (rc=$rc)"
echo "$out" | grep -q "BCH corrected 3 bit" && \
    ok "bit-flip: read reports the correction" || bad "bit-flip: read reports the correction (got: $out)"
# check reports the correction too
out=$("$HYPER" -c "$T/v/cfg.txt" check f 2>&1)
echo "$out" | grep -q "BCH corrected 3 bit" && \
    ok "bit-flip: check reports the correction" || bad "bit-flip: check reports the correction (got: $out)"
# flip 3 bits in a parity stripe's parity-bytes region (offset 200..100000,
# well inside the parity bytes for a 1 MiB file; the header and BCH bytes
# are untouched): data is intact, read must still work
"$CORRUPT_BITS" "$T/v/vol/p0.bin" 11 3 200 100000 >/dev/null 2>&1
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out2" >/dev/null 2>&1 && \
cmp -s "$T/f.bin" "$T/f.out2" && \
    ok "bit-flip: 3 flipped bits in a parity stripe, data still readable" || bad "bit-flip: 3 flipped bits in a parity stripe, data still readable"

# --- 10. Parity stripe loss ---------------------------------------------
T=$WORK/parloss
mkdir -p "$T"
mkvol "$T/v" 3 >/dev/null 2>&1
randfile "$T/f.bin" 1048576
"$HYPER" -c "$T/v/cfg.txt" write "$T/f.bin" f >/dev/null 2>&1
rm "$T/v/vol/p1.bin"
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out" >/dev/null 2>&1 && \
cmp -s "$T/f.bin" "$T/f.out" && \
    ok "parity loss: delete 1 parity stripe, data still readable" || bad "parity loss: delete 1 parity stripe, data still readable"
"$HYPER" -c "$T/v/cfg.txt" -rebuild >/dev/null 2>&1 && \
[ -f "$T/v/vol/p1.bin" ] && \
"$HYPER" -c "$T/v/cfg.txt" list 2>/dev/null | grep -q "f " && \
    ok "parity loss: -rebuild restores the parity stripe" || bad "parity loss: -rebuild restores the parity stripe"
# delete ALL parity stripes: data is still readable in principle, but
# the index is gone, so read must fail clearly (documented failure mode)
rm "$T/v/vol/p0.bin" "$T/v/vol/p1.bin" "$T/v/vol/p2.bin"
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out2" >/dev/null 2>&1 && \
    bad "parity loss: all parity stripes dead, read must FAIL (no index)" || ok "parity loss: all parity stripes dead, read must FAIL (no index)"

# --- 11. Capacity overflow ----------------------------------------------
T=$WORK/cap
mkdir -p "$T"
mkvol "$T/v" 1 0044 4 1K >/dev/null 2>&1
randfile "$T/big.bin" 8192
"$HYPER" -c "$T/v/cfg.txt" write "$T/big.bin" big >/dev/null 2>&1 && \
    ok "capacity: 8 KiB file exactly fills 1 KiB stripes" || bad "capacity: 8 KiB file exactly fills 1 KiB stripes"
randfile "$T/small.bin" 64
"$HYPER" -c "$T/v/cfg.txt" write "$T/small.bin" small >/dev/null 2>&1 && \
    bad "capacity: write past the stripe size must FAIL" || ok "capacity: write past the stripe size must FAIL"
# and the first file is still intact
"$HYPER" -c "$T/v/cfg.txt" read big "$T/big.out" >/dev/null 2>&1 && \
cmp -s "$T/big.bin" "$T/big.out" && \
    ok "capacity: failed write leaves the volume intact" || bad "capacity: failed write leaves the volume intact"

# --- 12. SHA-256 verification (tamper) -----------------------------------
T=$WORK/tamper
mkdir -p "$T"
mkvol "$T/v" 3 >/dev/null 2>&1
randfile "$T/f.bin" 1048576
"$HYPER" -c "$T/v/cfg.txt" write "$T/f.bin" f >/dev/null 2>&1
# flip 12 bits in the first 1024 bytes of a data stripe: those map to
# file bytes 0..8191, all inside BCH block 0 (poly 0044, t=8, max block
# 131,051 bytes), so 12 errors > t=8 and the block is uncorrectable.
# (Flipping 12 bits spread over the whole stripe would land ~1-2 per
# block and be correctable — that is the bit-flip test above, not this one.)
"$CORRUPT_BITS" "$T/v/vol/s6.bin" 99 12 0 1024 >/dev/null 2>&1
"$HYPER" -c "$T/v/cfg.txt" check f >/dev/null 2>&1 && \
    bad "tamper: 12 flipped bits in one BCH block, check must FAIL" || ok "tamper: 12 flipped bits in one BCH block, check must FAIL"
"$HYPER" -c "$T/v/cfg.txt" read f "$T/f.out" >/dev/null 2>&1 && \
    bad "tamper: 12 flipped bits in one BCH block, read must FAIL" || ok "tamper: 12 flipped bits in one BCH block, read must FAIL"
[ -f "$T/f.out" ] && cmp -s "$T/f.bin" "$T/f.out" && \
    bad "tamper: no byte-identical output may be produced" || ok "tamper: no byte-identical output produced"

# --- 13. Read-speed benchmark --------------------------------------------
T=$WORK/bench
mkdir -p "$T"
mkvol "$T/v" 3 >/dev/null 2>&1
randfile "$T/big.bin" 33554432
"$HYPER" -c "$T/v/cfg.txt" write "$T/big.bin" big >/dev/null 2>&1
t0=$(date +%s%N)
"$HYPER" -c "$T/v/cfg.txt" read big "$T/big.out" >/dev/null 2>&1
t1=$(date +%s%N)
cmp -s "$T/big.bin" "$T/big.out" || bad "bench: 32 MiB roundtrip byte-identical"
ms=$(( (t1 - t0) / 1000000 ))
mbps=$(python3 -c "print(f'{33554432 / ($ms / 1000.0) / 1048576:.1f}')")
echo "BENCH: read 32 MiB in ${ms} ms = ${mbps} MiB/s"
[ "$ms" -gt 0 ] && ok "bench: read 32 MiB in ${ms} ms (${mbps} MiB/s)" || bad "bench: read timing failed"

# --- summary --------------------------------------------------------------
echo
echo "lzply_hyper tests: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
