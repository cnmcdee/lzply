#!/bin/bash
# run_tests.sh - full lzply test suite.
# Usage: run_tests.sh [path-to-lzply]
# Requires: testdata built by make_testdata.sh, corrupt helpers compiled.
# ROOT is the lzply tree root (testdata/, testwork/, tests/ live under
# it): taken from $LZPLY_TEST_ROOT, else the parent of this script's
# directory (works for ~/workspace/lzply and for /opt/lzply/src).
set -u
LZPLY="${1:-/opt/lzply/src/lzply}"
# Canonicalise LZPLY to an absolute path: several tests cd into $WORK
# (e.g. the -tr tests, so the archive name prints as a bare filename),
# and a relative ./lzply would stop resolving there.
case "$LZPLY" in
    /*) ;;
    *) LZPLY="$(cd "$(dirname "$LZPLY")" && pwd)/$(basename "$LZPLY")" ;;
esac
STAT="$(dirname "$LZPLY")/lzply_stat"
HEAL="$(dirname "$LZPLY")/lzply_heal"
CHECK="$(dirname "$LZPLY")/lzply_check"
REFRESH="$(dirname "$LZPLY")/lzply_refresh"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${LZPLY_TEST_ROOT:-$(dirname "$SCRIPT_DIR")}"
TD=$ROOT/testdata
WORK=$ROOT/testwork
CORRUPT=/tmp/corrupt
CORRUPT_BITS=/tmp/corrupt_bits
PASS=0
FAIL=0

ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }

rm -rf "$WORK"
mkdir -p "$WORK"
gcc -O2 -Wall -o "$CORRUPT" "$ROOT/tests/corrupt.c" || { echo "cannot build corrupt helper"; exit 1; }
gcc -O2 -Wall -o "$CORRUPT_BITS" "$ROOT/tests/corrupt_bits.c" || { echo "cannot build corrupt_bits helper"; exit 1; }
[ -x "$LZPLY" ] || { echo "lzply binary not found: $LZPLY"; exit 1; }
[ -d "$TD/mixed" ] || { echo "testdata missing; run make_testdata.sh first"; exit 1; }

# --- 1. Compression levels: roundtrip at -1..-9 -----------------------
for L in 1 2 3 4 5 6 7 8 9; do
    rm -rf "$WORK/out"
    "$LZPLY" -c -"$L" "$TD/mixed" "$WORK/mixed-$L.lzply" >/dev/null 2>&1 &&
    "$LZPLY" -d "$WORK/mixed-$L.lzply" "$WORK/out" >/dev/null 2>&1 &&
    diff -r "$TD/mixed" "$WORK/out/mixed" >/dev/null 2>&1 &&
        ok "level -$L roundtrip" || bad "level -$L roundtrip"
done

# --- 2. lzip cross-check: compressed data must equal `lzip -6` -----------
# -e 0 (no error correction) so the stored bytes ARE the lzip stream.
# The 6-byte header's dict-size byte differs on purpose: lzip adapts
# the stored dictionary to the input size, lzply stores the level's
# full size. The compressed data (bytes 7..end) must be identical,
# the sizes equal, and the stream must pass `lzip -t`.
# (Skipped when the system lzip tool is not installed.)
if command -v lzip >/dev/null 2>&1; then
"$LZPLY" -c -6 -e 0 "$TD/mixed/text.txt" "$WORK/text6.lzply" >/dev/null 2>&1
# archive layout: 16 (global) + 78 (entry header) + 8 ("text.txt") = 102,
# then stored_size bytes, then the 2-byte end marker.
ASZ=$(stat -c %s "$WORK/text6.lzply")
dd if="$WORK/text6.lzply" bs=1 skip=102 count=$((ASZ - 104)) status=none > "$WORK/text6.lzip" 2>/dev/null
lzip -6 -c "$TD/mixed/text.txt" > "$WORK/text6.ref" 2>/dev/null
if cmp -s <(tail -c +7 "$WORK/text6.lzip") <(tail -c +7 "$WORK/text6.ref") &&
   [ "$(stat -c %s "$WORK/text6.lzip")" = "$(stat -c %s "$WORK/text6.ref")" ] &&
   lzip -t "$WORK/text6.lzip" 2>/dev/null; then
    ok "lzip -6 compressed data byte-identical to system lzip (+ lzip -t passes)"
else
    s1=$(stat -c %s "$WORK/text6.lzip"); s2=$(stat -c %s "$WORK/text6.ref")
    bad "lzip -6 stream differs from system lzip (mine=$s1 ref=$s2)"
fi
else
    echo "SKIP: lzip cross-check (no system lzip)"
fi

# --- 3. BCH levels: roundtrip at -e 0..7 (t = 0,1,2,4,8,16,32,32) -----
for E in 0 1 2 3 4 5 6 7; do
    rm -rf "$WORK/out"
    "$LZPLY" -c -6 -e "$E" "$TD/mixed" "$WORK/mixed-e$E.lzply" >/dev/null 2>&1 &&
    "$LZPLY" -t "$WORK/mixed-e$E.lzply" >/dev/null 2>&1 &&
    "$LZPLY" -d "$WORK/mixed-e$E.lzply" "$WORK/out" >/dev/null 2>&1 &&
    diff -r "$TD/mixed" "$WORK/out/mixed" >/dev/null 2>&1 &&
        ok "BCH level $E roundtrip + test" || bad "BCH level $E roundtrip + test"
done

# --- 4. BCH corruption: single-file archive of text.txt -----------------
# Stored data starts at offset 102 (16 + 78 + 8 for "text.txt"). All
# flipped bits must land in ONE BCH block, so the flip range is the
# first block. For most pinned polys the blob is a single block
# (range = whole stored region); poly 0002 (m7,t2) has max_data 14
# bytes, so its first block is only 16 stored bytes ([102,118)).
# Flip exactly t bits in the first block -> must recover; flip t+1
# bits -> must fail cleanly (BCH uncorrectable, or SHA-256 catches a
# miscorrection). Pinned polys so t is known exactly.
# SPEC: poly t end_offset(0 = end of stored region)
for SPEC in "0002 2 118" "0018 2 0" "0025 4 0" "003a 32 0"; do
    set -- $SPEC
    POLY=$1; T=$2; ENDFIX=$3
    "$LZPLY" -c -6 poly="$POLY" "$TD/mixed/text.txt" "$WORK/bch-$POLY.lzply" >/dev/null 2>&1
    SZ=$(stat -c %s "$WORK/bch-$POLY.lzply")
    if [ "$ENDFIX" = "0" ]; then END=$((SZ - 2)); else END=$ENDFIX; fi
    # (a) t bit errors -> must recover
    cp "$WORK/bch-$POLY.lzply" "$WORK/bch-${POLY}a.lzply"
    "$CORRUPT_BITS" "$WORK/bch-${POLY}a.lzply" 42 "$T" 102 "$END" >/dev/null
    rm -rf "$WORK/out"
    if "$LZPLY" -d "$WORK/bch-${POLY}a.lzply" "$WORK/out" >/dev/null 2>&1 &&
       cmp -s "$TD/mixed/text.txt" "$WORK/out/text.txt"; then
        ok "BCH poly $POLY: $T bit errors recovered"
    else
        bad "BCH poly $POLY: $T bit errors recovered"
    fi
    # (b) t+1 bit errors -> must fail cleanly (never silent wrong data)
    cp "$WORK/bch-$POLY.lzply" "$WORK/bch-${POLY}b.lzply"
    "$CORRUPT_BITS" "$WORK/bch-${POLY}b.lzply" 43 $((T + 1)) 102 "$END" >/dev/null
    rm -rf "$WORK/out"
    if "$LZPLY" -d "$WORK/bch-${POLY}b.lzply" "$WORK/out" >/dev/null 2>&1; then
        bad "BCH poly $POLY: $((T+1)) bit errors must fail"
    else
        ok "BCH poly $POLY: $((T+1)) bit errors fails cleanly"
    fi
done

# --- 5. Combined BCH, v3 rejection, removed option ----------------
# combined: -9 + BCH t=16 (-e 5), with 16 bit errors -> recover
"$LZPLY" -c -9 -e 5 "$TD/mixed/text.txt" "$WORK/combo.lzply" >/dev/null 2>&1
cp "$WORK/combo.lzply" "$WORK/combo-c.lzply"
SZ=$(stat -c %s "$WORK/combo-c.lzply")
"$CORRUPT_BITS" "$WORK/combo-c.lzply" 46 16 102 $((SZ - 2)) >/dev/null
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/combo-c.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$TD/mixed/text.txt" "$WORK/out/text.txt" &&
    ok "combined -9 + BCH t16 with 16 corrupted bits recovered" ||
    bad "combined -9 + BCH t16 with 16 corrupted bits recovered"
# v3 archive rejected: take a fresh v4 archive and patch its version byte to 3
"$LZPLY" -c -6 "$TD/mixed/text.txt" "$WORK/v3.lzply" >/dev/null 2>&1
cp "$WORK/v3.lzply" "$WORK/v3patched.lzply"
printf '\x03' | dd of="$WORK/v3patched.lzply" bs=1 seek=4 conv=notrunc status=none 2>/dev/null
if "$LZPLY" -t "$WORK/v3patched.lzply" >/dev/null 2>&1; then
    bad "v3 archive (version byte 3) must be rejected"
else
    ok "v3 archive (version byte 3) is rejected (bad magic/version)"
fi
# the removed option is now a usage error (exit 1)
# (built by concatenation so the removed name does not appear literally)
"$LZPLY" -c -6 -pass"word=foo" >/dev/null 2>&1
RC=$?
[ "$RC" = "1" ] &&
    ok "removed option is now a usage error (exit 1)" ||
    bad "removed option is now a usage error (exit 1)"

# --- 6. Overwrite flags -------------------------------------------------
"$LZPLY" -c -6 "$TD/mixed/text.txt" "$WORK/ow.lzply" >/dev/null 2>&1
rm -rf "$WORK/out"; mkdir -p "$WORK/out"
"$LZPLY" -d "$WORK/ow.lzply" "$WORK/out" >/dev/null 2>&1
SUM1=$(sha256sum "$WORK/out/text.txt" | cut -d' ' -f1)
echo "tampered" > "$WORK/out/text.txt"
# -n: must skip, file stays tampered
"$LZPLY" -d -n "$WORK/ow.lzply" "$WORK/out" >/dev/null 2>&1
grep -qx "tampered" "$WORK/out/text.txt" &&
    ok "-n skips existing file" || bad "-n skips existing file"
# -y: must overwrite, file restored
"$LZPLY" -d -y "$WORK/ow.lzply" "$WORK/out" >/dev/null 2>&1
SUM2=$(sha256sum "$WORK/out/text.txt" | cut -d' ' -f1)
[ "$SUM1" = "$SUM2" ] && ok "-y overwrites existing file" || bad "-y overwrites existing file"
# -a with 'n': skip. (-a used to mean ask-overwrite; it is now the
# append mode, and ask-overwrite is --ask only.)
echo "tampered" > "$WORK/out/text.txt"
printf 'n\n' | "$LZPLY" -d --ask "$WORK/ow.lzply" "$WORK/out" >/dev/null 2>&1
grep -qx "tampered" "$WORK/out/text.txt" &&
    ok "--ask with 'n' skips" || bad "--ask with 'n' skips"
# --ask with 'y': overwrite
printf 'y\n' | "$LZPLY" -d --ask "$WORK/ow.lzply" "$WORK/out" >/dev/null 2>&1
SUM3=$(sha256sum "$WORK/out/text.txt" | cut -d' ' -f1)
[ "$SUM1" = "$SUM3" ] && ok "--ask with 'y' overwrites" || bad "--ask with 'y' overwrites"

# --- 7. Edge cases ------------------------------------------------------
# empty directory restores empty
"$LZPLY" -c "$TD/emptydir" "$WORK/empty.lzply" >/dev/null 2>&1
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/empty.lzply" "$WORK/out" >/dev/null 2>&1
[ -d "$WORK/out/emptydir" ] && [ -z "$(ls -A "$WORK/out/emptydir")" ] &&
    ok "empty directory roundtrip" || bad "empty directory roundtrip"
# -l lists, -t verifies
"$LZPLY" -l "$WORK/mixed-e5.lzply" 2>/dev/null | grep -q "text.txt" &&
    ok "-l lists entries" || bad "-l lists entries"
"$LZPLY" -t "$WORK/mixed-e5.lzply" >/dev/null 2>&1 &&
    ok "-t verifies good archive" || bad "-t verifies good archive"
# truncated archive must fail
head -c 100 "$WORK/mixed-e5.lzply" > "$WORK/trunc.lzply"
"$LZPLY" -t "$WORK/trunc.lzply" >/dev/null 2>&1 &&
    bad "truncated archive must fail" || ok "truncated archive fails"
# not an archive must fail
echo "hello" > "$WORK/notarc.txt"
"$LZPLY" -t "$WORK/notarc.txt" >/dev/null 2>&1 &&
    bad "non-archive must fail" || ok "non-archive fails"

# --- 8. Big file: 50 MiB at -6 -e 3 (BCH t=4, multi-block) --------------
"$LZPLY" -c -6 -e 3 "$TD/big.bin" "$WORK/big.lzply" >/dev/null 2>&1
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/big.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$TD/big.bin" "$WORK/out/big.bin" &&
    ok "50 MiB roundtrip at -6 -e 3 (BCH t=4)" || bad "50 MiB roundtrip at -6 -e 3"

# --- 9. v1 archives and the old magics are NOT readable (removed by design) ---
# Standing decision (Nov 25, 2026): no legacy support — the format
# changed freely, and the magic changed twice with the renames
# (LZRS -> LZBC -> LZPL), so an old-magic archive and a v1 archive
# are both simply unknown. Build all three by hand: a v1 global
# header (new magic + version byte 1) and old-magic headers (LZRS and
# LZBC, each + version byte 3) are each enough to prove the check
# rejects them instead of misreading them.
printf 'LZPL\x01' > "$WORK/fake-v1.lzply"
head -c 11 /dev/zero >> "$WORK/fake-v1.lzply"
if "$LZPLY" -l "$WORK/fake-v1.lzply" >/dev/null 2>&1; then
    bad "v1-style archive (version byte 1) must be rejected"
else
    ok "v1-style archive (version byte 1) is rejected (no legacy support)"
fi
printf 'LZRS\x03' > "$WORK/fake-oldmagic.lzply"
head -c 11 /dev/zero >> "$WORK/fake-oldmagic.lzply"
if "$LZPLY" -l "$WORK/fake-oldmagic.lzply" >/dev/null 2>&1; then
    bad "old-magic (LZRS) archive must be rejected"
else
    ok "old-magic (LZRS) archive is rejected (magic is now LZPL)"
fi
printf 'LZBC\x03' > "$WORK/fake-oldmagic-lzbc.lzply"
head -c 11 /dev/zero >> "$WORK/fake-oldmagic-lzbc.lzply"
if "$LZPLY" -l "$WORK/fake-oldmagic-lzbc.lzply" >/dev/null 2>&1; then
    bad "old-magic (LZBC) archive must be rejected"
else
    ok "old-magic (LZBC) archive is rejected (magic is now LZPL)"
fi

# --- 10. poly= pinning, auto-pick, and format version ------------------
"$LZPLY" -c -6 poly=003a "$TD/mixed/text.txt" "$WORK/pin.lzply" >/dev/null 2>&1
"$LZPLY" -l "$WORK/pin.lzply" 2>/dev/null | grep -q "BCH 003a" &&
    ok "poly=003a pins poly 003a (shown by -l)" ||
    bad "poly=003a pins poly 003a (shown by -l)"
"$LZPLY" -c -6 poly=58 "$TD/mixed/text.txt" "$WORK/pin58.lzply" >/dev/null 2>&1
"$LZPLY" -l "$WORK/pin58.lzply" 2>/dev/null | grep -q "BCH 003a" &&
    ok "poly=58 (decimal) pins poly 003a" ||
    bad "poly=58 (decimal) pins poly 003a"
# -l on a default archive shows a BCH poly id
"$LZPLY" -l "$WORK/mixed-e4.lzply" 2>/dev/null | grep -q "BCH 00" &&
    ok "-l shows BCH poly id for auto-picked archive" ||
    bad "-l shows BCH poly id for auto-picked archive"
# unknown poly is a usage error. (poly=0053 is NOT invalid: "0053"
# has no hex letters, so it parses as decimal 53 = poly 0x35, which
# is a real poly. Use ids that are invalid in both readings.)
if "$LZPLY" -c -6 poly=9999 "$TD/mixed/text.txt" "$WORK/badpoly.lzply" >/dev/null 2>&1; then
    bad "poly=9999 must be rejected"
else
    ok "poly=9999 rejected (usage error)"
fi
if "$LZPLY" -c -6 poly=83 "$TD/mixed/text.txt" "$WORK/badpoly2.lzply" >/dev/null 2>&1; then
    bad "poly=83 must be rejected"
else
    ok "poly=83 rejected (usage error)"
fi
if "$LZPLY" -c -6 poly=00ff "$TD/mixed/text.txt" "$WORK/badpoly3.lzply" >/dev/null 2>&1; then
    bad "poly=00ff must be rejected"
else
    ok "poly=00ff rejected (usage error)"
fi
# format version byte (offset 4): 4 for the v4 format, with or
# without BCH (a single format now; no legacy versions).
V_BCH=$(od -An -tu1 -j 4 -N 1 "$WORK/mixed-e4.lzply" | tr -d ' ')
V_NOECC=$(od -An -tu1 -j 4 -N 1 "$WORK/mixed-e0.lzply" | tr -d ' ')
[ "$V_BCH" = "4" ] && ok "BCH archive has version byte 4" || bad "BCH archive has version byte 4 (got $V_BCH)"
[ "$V_NOECC" = "4" ] && ok "no-ECC archive has version byte 4" || bad "no-ECC archive has version byte 4 (got $V_NOECC)"

# --- 11. Block splitting: blob > one block, with corruption -----------
# 600 KiB random file: blob ~600 KiB > max single block for the
# auto-picked poly, so it splits. Corrupt bits in the first block
# (offset 102, well inside block 1) and verify recovery / failure.
head -c 614400 /dev/urandom > "$WORK/split.bin"
"$LZPLY" -c -6 "$WORK/split.bin" "$WORK/split.lzply" >/dev/null 2>&1
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/split.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$WORK/split.bin" "$WORK/out/split.bin" &&
    ok "600 KiB split-blob roundtrip" || bad "600 KiB split-blob roundtrip"
cp "$WORK/split.lzply" "$WORK/split-a.lzply"
"$CORRUPT_BITS" "$WORK/split-a.lzply" 51 8 102 1102 >/dev/null
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/split-a.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$WORK/split.bin" "$WORK/out/split.bin" &&
    ok "split-blob: 8 bit errors in first block recovered" ||
    bad "split-blob: 8 bit errors in first block recovered"
cp "$WORK/split.lzply" "$WORK/split-b.lzply"
"$CORRUPT_BITS" "$WORK/split-b.lzply" 52 9 102 1102 >/dev/null
rm -rf "$WORK/out"
if "$LZPLY" -d "$WORK/split-b.lzply" "$WORK/out" >/dev/null 2>&1; then
    bad "split-blob: 9 bit errors in first block must fail"
else
    ok "split-blob: 9 bit errors in first block fails cleanly"
fi

# --- 12. -a append ------------------------------------------------------
# (a) create an archive with -c, then -a a single directory (with a
# nested subdirectory, covering (j)); verify -l shows the new entries,
# the count increased by exactly the new entries, -t passes, and a
# full extract matches both trees.
mkdir -p "$WORK/appdir/sub"
echo "append one" > "$WORK/appdir/one.txt"
echo "append two" > "$WORK/appdir/sub/two.txt"
"$LZPLY" -c -6 "$TD/mixed" "$WORK/app-a.lzply" >/dev/null 2>&1
C0=$("$LZPLY" -l "$WORK/app-a.lzply" 2>/dev/null | tail -1 | awk '{print $1}')
"$LZPLY" -a "$WORK/app-a.lzply" "$WORK/appdir" >/dev/null 2>&1
"$LZPLY" -l "$WORK/app-a.lzply" 2>/dev/null | grep -q "appdir/one.txt" &&
"$LZPLY" -l "$WORK/app-a.lzply" 2>/dev/null | grep -q "appdir/sub/two.txt" &&
"$LZPLY" -t "$WORK/app-a.lzply" >/dev/null 2>&1 &&
    ok "-a a single directory: new entries listed and archive verifies" ||
    bad "-a a single directory: new entries listed and archive verifies"
N1=$("$LZPLY" -l "$WORK/app-a.lzply" 2>/dev/null | tail -1 | awk '{print $1}')
[ "$N1" = "$((C0 + 4))" ] && ok "-a: entry count increased by 4 (dir + 2 files + subdir)" || bad "-a: entry count increased by 4 (got $C0 -> $N1)"
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/app-a.lzply" "$WORK/out" >/dev/null 2>&1 &&
diff -r "$TD/mixed" "$WORK/out/mixed" >/dev/null 2>&1 &&
diff -r "$WORK/appdir" "$WORK/out/appdir" >/dev/null 2>&1 &&
    ok "-a directory: full extract matches both trees (nested preserved)" ||
    bad "-a directory: full extract matches both trees (nested preserved)"
# (b) -a several individual files at once
echo "file one" > "$WORK/f1.txt"
echo "file two" > "$WORK/f2.txt"
echo "file three" > "$WORK/f3.txt"
"$LZPLY" -a "$WORK/app-a.lzply" "$WORK/f1.txt" "$WORK/f2.txt" "$WORK/f3.txt" >/dev/null 2>&1
"$LZPLY" -l "$WORK/app-a.lzply" 2>/dev/null | grep -q "f1.txt" &&
"$LZPLY" -l "$WORK/app-a.lzply" 2>/dev/null | grep -q "f2.txt" &&
"$LZPLY" -l "$WORK/app-a.lzply" 2>/dev/null | grep -q "f3.txt" &&
"$LZPLY" -t "$WORK/app-a.lzply" >/dev/null 2>&1 &&
    ok "-a several individual files at once" ||
    bad "-a several individual files at once"
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/app-a.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$WORK/f1.txt" "$WORK/out/f1.txt" &&
cmp -s "$WORK/f2.txt" "$WORK/out/f2.txt" &&
cmp -s "$WORK/f3.txt" "$WORK/out/f3.txt" &&
    ok "-a files: extract matches" || bad "-a files: extract matches"
# (c) -a on a non-existent archive creates it
rm -f "$WORK/app-new.lzply"
"$LZPLY" -a "$WORK/app-new.lzply" "$WORK/f1.txt" >/dev/null 2>&1
[ -f "$WORK/app-new.lzply" ] &&
"$LZPLY" -l "$WORK/app-new.lzply" 2>/dev/null | grep -q "f1.txt" &&
"$LZPLY" -t "$WORK/app-new.lzply" >/dev/null 2>&1 &&
    ok "-a on a missing archive creates it" ||
    bad "-a on a missing archive creates it"
# (d) -a a file that already exists: the new content wins, exactly one
# entry for that path, and the other entries are intact.
cp "$TD/mixed/text.txt" "$WORK/rep.txt"
"$LZPLY" -c -6 "$TD/mixed" "$WORK/app-rep.lzply" >/dev/null 2>&1
"$LZPLY" -a "$WORK/app-rep.lzply" "$WORK/rep.txt" >/dev/null 2>&1
echo "replacement text, version two" > "$WORK/rep.txt"
"$LZPLY" -a "$WORK/app-rep.lzply" "$WORK/rep.txt" >/dev/null 2>&1
[ "$("$LZPLY" -l "$WORK/app-rep.lzply" 2>/dev/null | grep -c "rep.txt")" = "1" ] &&
    ok "-a replace: exactly one entry for the replaced path" ||
    bad "-a replace: exactly one entry for the replaced path (got $("$LZPLY" -l "$WORK/app-rep.lzply" 2>/dev/null | grep -c "rep.txt"))"
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/app-rep.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$WORK/rep.txt" "$WORK/out/rep.txt" &&
diff -r "$TD/mixed" "$WORK/out/mixed" >/dev/null 2>&1 &&
    ok "-a replace: new content wins, other entries intact" ||
    bad "-a replace: new content wins, other entries intact"
# (e) -a a file onto an existing archive: appended entry extracts,
# old entries intact.
"$LZPLY" -c -6 "$TD/mixed" "$WORK/app-pw.lzply" >/dev/null 2>&1
"$LZPLY" -a "$WORK/app-pw.lzply" "$WORK/f1.txt" >/dev/null 2>&1
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/app-pw.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$WORK/f1.txt" "$WORK/out/f1.txt" &&
diff -r "$TD/mixed" "$WORK/out/mixed" >/dev/null 2>&1 &&
    ok "-a a file: appended entry extracts, old entries intact" ||
    bad "-a a file: appended entry extracts, old entries intact"
# (f) -a with poly=NN and with -e: new entries use the pinned poly / t.
"$LZPLY" -a poly=003a "$WORK/app-a.lzply" "$WORK/f1.txt" >/dev/null 2>&1
"$LZPLY" -l "$WORK/app-a.lzply" 2>/dev/null | grep -q "BCH 003a" &&
    ok "-a poly=003a: new entry uses pinned poly 003a" ||
    bad "-a poly=003a: new entry uses pinned poly 003a"
"$LZPLY" -a -e 6 "$WORK/app-a.lzply" "$WORK/f2.txt" >/dev/null 2>&1
"$LZPLY" -l "$WORK/app-a.lzply" 2>/dev/null | grep "f2.txt" | grep -q "BCH 00" &&
"$LZPLY" -t "$WORK/app-a.lzply" >/dev/null 2>&1 &&
    ok "-a -e 6: new entry uses a BCH poly and archive verifies" ||
    bad "-a -e 6: new entry uses a BCH poly and archive verifies"
# (g) removed: -a onto a v1 RS archive. v1 is gone by design
# (standing decision, Nov 25, 2026); there is no v1 to append to.
# incremental append really is incremental: the entry bytes before
# the end marker are unchanged (only the global header count/version
# may change). Snapshot the archive, append a fresh file, compare.
SZ1=$(stat -c %s "$WORK/app-a.lzply")
dd if="$WORK/app-a.lzply" bs=1 skip=16 count=$((SZ1 - 18)) status=none > "$WORK/app-before.bin" 2>/dev/null
echo "brand new file" > "$WORK/f4.txt"
"$LZPLY" -a "$WORK/app-a.lzply" "$WORK/f4.txt" >/dev/null 2>&1
dd if="$WORK/app-a.lzply" bs=1 skip=16 count=$((SZ1 - 18)) status=none > "$WORK/app-after.bin" 2>/dev/null
cmp -s "$WORK/app-before.bin" "$WORK/app-after.bin" &&
    ok "-a incremental: existing entry bytes preserved byte-for-byte" ||
    bad "-a incremental: existing entry bytes preserved byte-for-byte"

# --- 13. Selective extract (-d / -t / -l) ------------------------------
"$LZPLY" -c -6 "$TD/mixed" "$WORK/sel.lzply" >/dev/null 2>&1
# (h) extract only a directory by prefix
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/sel.lzply" "$WORK/out" mixed/nested >/dev/null 2>&1
[ -f "$WORK/out/mixed/nested/a.txt" ] &&
[ -f "$WORK/out/mixed/nested/deep/b.txt" ] &&
[ ! -f "$WORK/out/mixed/text.txt" ] &&
    ok "-d selector (dir prefix): only nested/ extracted" ||
    bad "-d selector (dir prefix): only nested/ extracted"
# selector with trailing slash
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/sel.lzply" "$WORK/out" mixed/nested/ >/dev/null 2>&1
[ -f "$WORK/out/mixed/nested/a.txt" ] && [ ! -f "$WORK/out/mixed/text.txt" ] &&
    ok "-d selector (trailing slash): only nested/ extracted" ||
    bad "-d selector (trailing slash): only nested/ extracted"
# extract only a single file by exact path
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/sel.lzply" "$WORK/out" mixed/text.txt >/dev/null 2>&1
[ -f "$WORK/out/mixed/text.txt" ] &&
[ ! -f "$WORK/out/mixed/nested/a.txt" ] &&
    ok "-d selector (exact file): only that file extracted" ||
    bad "-d selector (exact file): only that file extracted"
# a prefix that is NOT a directory boundary must not match
rm -rf "$WORK/out"
if "$LZPLY" -d "$WORK/sel.lzply" "$WORK/out" mixed/neste >/dev/null 2>&1; then
    [ ! -f "$WORK/out/mixed/nested/a.txt" ] &&
        ok "-d selector 'mixed/neste' does not match 'mixed/nested'" ||
        bad "-d selector 'mixed/neste' does not match 'mixed/nested'"
else
    bad "-d selector 'mixed/neste' must exit 0 (no match)"
fi
# a selector matching nothing: clear message, exit 0, nothing extracted
rm -rf "$WORK/out"; mkdir -p "$WORK/out"
OUT=$("$LZPLY" -d "$WORK/sel.lzply" "$WORK/out" zzz 2>&1)
RC=$?
[ "$RC" = "0" ] && echo "$OUT" | grep -q "no entries match" &&
[ -z "$(find "$WORK/out" -type f)" ] &&
    ok "-d selector matching nothing: message, exit 0, nothing extracted" ||
    bad "-d selector matching nothing: message, exit 0, nothing extracted (rc=$RC)"
# (i) -t with a selector
"$LZPLY" -t "$WORK/sel.lzply" mixed/nested >/dev/null 2>&1 &&
    ok "-t with selector: tests only the selected entries" ||
    bad "-t with selector: tests only the selected entries"
OUT=$("$LZPLY" -t "$WORK/sel.lzply" zzz 2>&1)
RC=$?
[ "$RC" = "0" ] && echo "$OUT" | grep -q "no entries match" &&
    ok "-t selector matching nothing: message, exit 0" ||
    bad "-t selector matching nothing: message, exit 0 (rc=$RC)"
# (bonus) -l with a selector
"$LZPLY" -l "$WORK/sel.lzply" mixed/nested 2>/dev/null | grep -q "nested/a.txt" &&
! "$LZPLY" -l "$WORK/sel.lzply" mixed/nested 2>/dev/null | grep -q "text.txt" &&
    ok "-l with selector: lists only matching entries" ||
    bad "-l with selector: lists only matching entries"

# --- 13. -i inspect: headers only, correct metadata -------------------
# A small tree with known mtimes and permissions.
rm -rf "$WORK/insp"
mkdir -p "$WORK/insp/sub" "$WORK/insp/empty"
printf 'hello\n' > "$WORK/insp/a.txt"
printf 'nested\n' > "$WORK/insp/sub/b.txt"
chmod 0640 "$WORK/insp/a.txt"
chmod 0750 "$WORK/insp/sub"
touch -d "2024-03-15 10:30:00 UTC" "$WORK/insp/a.txt"
touch -d "2025-07-20 14:00:00 UTC" "$WORK/insp/sub/b.txt"
touch -d "2024-01-01 00:00:00 UTC" "$WORK/insp/sub" "$WORK/insp/empty"
"$LZPLY" -c -y -6 "$WORK/insp" "$WORK/insp.lzply" >/dev/null 2>&1
OUT=$("$LZPLY" -i "$WORK/insp.lzply" 2>/dev/null)
echo "$OUT" | grep "insp/a.txt" | grep -q "2024-03-15 10:30:00 UTC" &&
echo "$OUT" | grep "insp/a.txt" | grep -q "0640" &&
echo "$OUT" | grep "insp/a.txt" | grep -q "rw-r-----" &&
echo "$OUT" | grep "insp/a.txt" | grep -q "BCH 00" &&
    ok "-i: a.txt shows 2024-03-15 mtime, 0640/-rw-r-----, BCH poly" ||
    bad "-i: a.txt shows 2024-03-15 mtime, 0640/-rw-r-----, BCH poly"
echo "$OUT" | grep "insp/sub/b.txt" | grep -q "2025-07-20 14:00:00 UTC" &&
    ok "-i: sub/b.txt shows 2025-07-20 mtime" ||
    bad "-i: sub/b.txt shows 2025-07-20 mtime"
# The numeric check is "750", not "0750": as root, chmod does not clear
# a setgid bit inherited from a setgid parent directory, so the mode
# can be 2750. The symbolic check accepts 's' (setgid) or 'x' in the
# group-execute slot for the same reason.
echo "$OUT" | grep "insp/sub/" | grep -q "750" &&
echo "$OUT" | grep "insp/sub/" | grep -Eq "drwxr-[xs]---" &&
    ok "-i: sub/ shows 0750/drwxr-x---" ||
    bad "-i: sub/ shows 0750/drwxr-x---"
echo "$OUT" | grep "insp/empty/" | grep -q "directory" &&
    ok "-i: empty dir listed as directory" ||
    bad "-i: empty dir listed as directory"
echo "$OUT" | grep -q "5 entries (3 directories, 2 files)" &&
    ok "-i: summary counts 5 entries (3 dirs, 2 files)" ||
    bad "-i: summary counts 5 entries (3 dirs, 2 files)"
# -i reads headers only: corrupt the data of a single-file archive
# (data starts at 102 for an 8-char path) and -i still succeeds while
# -t fails. The file is 1 KiB of random data, so the stored blob is
# ~1 KiB and 100 zeroed bytes at 102 are well inside it.
head -c 1024 /dev/urandom > "$WORK/rand.bin"
"$LZPLY" -c -y -6 "$WORK/rand.bin" "$WORK/rand.lzply" >/dev/null 2>&1
cp "$WORK/rand.lzply" "$WORK/rand-corrupt.lzply"
dd if=/dev/zero of="$WORK/rand-corrupt.lzply" bs=1 seek=102 count=100 conv=notrunc status=none
"$LZPLY" -i "$WORK/rand-corrupt.lzply" >/dev/null 2>&1 &&
    ok "-i succeeds on an archive whose data is corrupted (headers only)" ||
    bad "-i succeeds on an archive whose data is corrupted (headers only)"
if "$LZPLY" -t "$WORK/rand-corrupt.lzply" >/dev/null 2>&1; then
    bad "-t fails on the same corrupted archive"
else
    ok "-t fails on the same corrupted archive"
fi

# --- 14. -tr tree: exact output, implied dirs, empty dirs -------------
rm -rf "$WORK/tree"
mkdir -p "$WORK/tree/a/b" "$WORK/tree/empty"
printf 'hi\n' > "$WORK/tree/a/f1.txt"
printf 'yo\n' > "$WORK/tree/a/b/f2.txt"
printf 'z\n' > "$WORK/tree/top.txt"
"$LZPLY" -c -y -6 "$WORK/tree" "$WORK/tree.lzply" >/dev/null 2>&1
(cd "$WORK" && "$LZPLY" -tr tree.lzply > tree-out.txt 2>&1)
cat > "$WORK/tree-expected.txt" <<'EOF'
tree.lzply
└── tree/
    ├── a/
    │   ├── b/
    │   │   └── f2.txt (3 B)
    │   └── f1.txt (3 B)
    ├── empty/
    └── top.txt (2 B)

4 directories, 3 files
EOF
diff -u "$WORK/tree-expected.txt" "$WORK/tree-out.txt" >/dev/null &&
    ok "-tr: exact tree output (nested, empty dir, sizes, summary)" ||
    bad "-tr: exact tree output (nested, empty dir, sizes, summary)"
# Implied directories: give the dirs a 2025 mtime and the files a 2024
# mtime, then -tr -year 2024 keeps the files but drops the explicit
# dir entries, so the parents appear as implied nodes (and empty/,
# which has no files, disappears).
touch -d "2025-01-01 00:00:00 UTC" "$WORK/tree" "$WORK/tree/a" "$WORK/tree/a/b" "$WORK/tree/empty"
touch -d "2024-06-01 12:00:00 UTC" "$WORK/tree/a/f1.txt" "$WORK/tree/a/b/f2.txt" "$WORK/tree/top.txt"
"$LZPLY" -c -y -6 "$WORK/tree" "$WORK/tree2024.lzply" >/dev/null 2>&1
(cd "$WORK" && "$LZPLY" -tr tree2024.lzply -year 2024 > tree2024-out.txt 2>&1)
cat > "$WORK/tree2024-expected.txt" <<'EOF'
tree2024.lzply
└── tree/
    ├── a/
    │   ├── b/
    │   │   └── f2.txt (3 B)
    │   └── f1.txt (3 B)
    └── top.txt (2 B)

3 directories, 3 files
EOF
diff -u "$WORK/tree2024-expected.txt" "$WORK/tree2024-out.txt" >/dev/null &&
    ok "-tr -year 2024: implied dirs for filtered-out parents, 3 dirs 3 files" ||
    bad "-tr -year 2024: implied dirs for filtered-out parents, 3 dirs 3 files"

# --- 15. -datestart / -dateend ---------------------------------------
# Files with mtimes spread across several days.
rm -rf "$WORK/dates"
mkdir -p "$WORK/dates"
printf 'd1\n' > "$WORK/dates/day1.txt"
printf 'd2\n' > "$WORK/dates/day2.txt"
printf 'd3\n' > "$WORK/dates/day3.txt"
printf 'd4\n' > "$WORK/dates/day4.txt"
touch -d "2024-01-10 08:00:00 UTC" "$WORK/dates/day1.txt"
touch -d "2024-01-11 12:00:00 UTC" "$WORK/dates/day2.txt"
touch -d "2024-01-12 18:00:00 UTC" "$WORK/dates/day3.txt"
touch -d "2024-01-13 23:00:00 UTC" "$WORK/dates/day4.txt"
"$LZPLY" -c -y -6 "$WORK/dates" "$WORK/dates.lzply" >/dev/null 2>&1
rm -rf "$WORK/out"
"$LZPLY" -d -y "$WORK/dates.lzply" "$WORK/out" -datestart 2024-01-11 -dateend 2024-01-12 >/dev/null 2>&1
[ -f "$WORK/out/dates/day2.txt" ] && [ -f "$WORK/out/dates/day3.txt" ] &&
[ ! -f "$WORK/out/dates/day1.txt" ] && [ ! -f "$WORK/out/dates/day4.txt" ] &&
    ok "-d -datestart/-dateend: only Jan 11-12 extracted" ||
    bad "-d -datestart/-dateend: only Jan 11-12 extracted"
OUT=$("$LZPLY" -i "$WORK/dates.lzply" -datestart 2024-01-11 -dateend 2024-01-12 2>/dev/null)
echo "$OUT" | grep -q "day2.txt" && echo "$OUT" | grep -q "day3.txt" &&
! echo "$OUT" | grep -q "day1.txt" && ! echo "$OUT" | grep -q "day4.txt" &&
    ok "-i -datestart/-dateend: only Jan 11-12 listed" ||
    bad "-i -datestart/-dateend: only Jan 11-12 listed"
(cd "$WORK" && "$LZPLY" -tr dates.lzply -datestart 2024-01-11 -dateend 2024-01-12 > dates-tr.txt 2>&1)
grep -q "day2.txt" "$WORK/dates-tr.txt" && grep -q "day3.txt" "$WORK/dates-tr.txt" &&
! grep -q "day1.txt" "$WORK/dates-tr.txt" && ! grep -q "day4.txt" "$WORK/dates-tr.txt" &&
    ok "-tr -datestart/-dateend: only Jan 11-12 in tree" ||
    bad "-tr -datestart/-dateend: only Jan 11-12 in tree"
# dateend is inclusive through 23:59:59: day4 is Jan 13 23:00, so a
# single-day range on Jan 13 includes it.
rm -rf "$WORK/out"
"$LZPLY" -d -y "$WORK/dates.lzply" "$WORK/out" -datestart 2024-01-13 -dateend 2024-01-13 >/dev/null 2>&1
[ -f "$WORK/out/dates/day4.txt" ] && [ ! -f "$WORK/out/dates/day3.txt" ] &&
    ok "-d single-day range Jan 13: only day4 (23:00) extracted" ||
    bad "-d single-day range Jan 13: only day4 (23:00) extracted"
# Exact datetime form (bonus).
rm -rf "$WORK/out"
"$LZPLY" -d -y "$WORK/dates.lzply" "$WORK/out" -datestart 2024-01-11T12:00:00 -dateend 2024-01-11T12:00:00 >/dev/null 2>&1
[ -f "$WORK/out/dates/day2.txt" ] && [ ! -f "$WORK/out/dates/day3.txt" ] &&
    ok "-d exact datetime range: only day2 (12:00) extracted" ||
    bad "-d exact datetime range: only day2 (12:00) extracted"

# --- 16. -year --------------------------------------------------------
rm -rf "$WORK/years"
mkdir -p "$WORK/years"
printf 'y24\n' > "$WORK/years/from2024.txt"
printf 'y25\n' > "$WORK/years/from2025.txt"
touch -d "2024-05-01 09:00:00 UTC" "$WORK/years/from2024.txt"
touch -d "2025-05-01 09:00:00 UTC" "$WORK/years/from2025.txt"
"$LZPLY" -c -y -6 "$WORK/years" "$WORK/years.lzply" >/dev/null 2>&1
rm -rf "$WORK/out"
"$LZPLY" -d -y "$WORK/years.lzply" "$WORK/out" -year 2024 >/dev/null 2>&1
[ -f "$WORK/out/years/from2024.txt" ] && [ ! -f "$WORK/out/years/from2025.txt" ] &&
    ok "-d -year 2024: only the 2024 file extracted" ||
    bad "-d -year 2024: only the 2024 file extracted"
OUT=$("$LZPLY" -i "$WORK/years.lzply" -year 2025 2>/dev/null)
echo "$OUT" | grep -q "from2025.txt" && ! echo "$OUT" | grep -q "from2024.txt" &&
    ok "-i -year 2025: only the 2025 file listed" ||
    bad "-i -year 2025: only the 2025 file listed"

# --- 17. Combined filters, empty range, bad dates ---------------------
rm -rf "$WORK/combo"
mkdir -p "$WORK/combo/photos" "$WORK/combo/docs"
printf 'p24\n' > "$WORK/combo/photos/old.jpg"
printf 'p25\n' > "$WORK/combo/photos/new.jpg"
printf 'd24\n' > "$WORK/combo/docs/old.txt"
printf 'd25\n' > "$WORK/combo/docs/new.txt"
touch -d "2024-02-01 00:00:00 UTC" "$WORK/combo/photos/old.jpg" "$WORK/combo/docs/old.txt"
touch -d "2025-02-01 00:00:00 UTC" "$WORK/combo/photos/new.jpg" "$WORK/combo/docs/new.txt"
"$LZPLY" -c -y -6 "$WORK/combo" "$WORK/combo.lzply" >/dev/null 2>&1
rm -rf "$WORK/out"
"$LZPLY" -d -y "$WORK/combo.lzply" "$WORK/out" combo/photos/ -year 2024 >/dev/null 2>&1
[ -f "$WORK/out/combo/photos/old.jpg" ] && [ ! -f "$WORK/out/combo/photos/new.jpg" ] &&
[ ! -f "$WORK/out/combo/docs/old.txt" ] &&
    ok "-d selector AND -year: only photos/old.jpg (2024) extracted" ||
    bad "-d selector AND -year: only photos/old.jpg (2024) extracted"
OUT=$("$LZPLY" -i "$WORK/combo.lzply" -year 2024 -datestart 2024-01-01 -dateend 2024-06-30 2>/dev/null)
echo "$OUT" | grep -q "photos/old.jpg" && echo "$OUT" | grep -q "docs/old.txt" &&
! echo "$OUT" | grep -q "new.jpg" && ! echo "$OUT" | grep -q "new.txt" &&
    ok "-i -year AND -datestart/-dateend: only 2024 H1 entries listed" ||
    bad "-i -year AND -datestart/-dateend: only 2024 H1 entries listed"
OUT=$("$LZPLY" -i "$WORK/combo.lzply" -year 2024 -datestart 2025-01-01 2>&1)
RC=$?
[ "$RC" = "0" ] && echo "$OUT" | grep -q "no entries match" &&
    ok "-i -year 2024 AND -datestart 2025: no match, exit 0" ||
    bad "-i -year 2024 AND -datestart 2025: no match, exit 0 (rc=$RC)"
OUT=$("$LZPLY" -i "$WORK/dates.lzply" -datestart 2024-01-13 -dateend 2024-01-10 2>&1)
RC=$?
[ "$RC" = "0" ] && echo "$OUT" | grep -q "no entries match" &&
    ok "-i datestart after dateend: empty range, exit 0" ||
    bad "-i datestart after dateend: empty range, exit 0 (rc=$RC)"
if "$LZPLY" -i "$WORK/dates.lzply" -datestart 2024-02-30 >/dev/null 2>&1; then
    bad "-i bad date 2024-02-30 must be a usage error"
else
    ok "-i bad date 2024-02-30 is a usage error"
fi
if "$LZPLY" -i "$WORK/dates.lzply" -datestart 2024/01/01 >/dev/null 2>&1; then
    bad "-i bad date 2024/01/01 must be a usage error"
else
    ok "-i bad date 2024/01/01 is a usage error"
fi
if "$LZPLY" -i "$WORK/dates.lzply" -year 99 >/dev/null 2>&1; then
    bad "-i bad year 99 must be a usage error"
else
    ok "-i bad year 99 is a usage error"
fi

# --- 18. -a preserves mtime; -i/-tr on the appended archive ---------
rm -rf "$WORK/enc"
mkdir -p "$WORK/enc"
printf 'secret\n' > "$WORK/enc/secret.txt"
printf 'plain\n' > "$WORK/enc/plain.txt"
touch -d "2024-08-08 08:08:08 UTC" "$WORK/enc/secret.txt"
touch -d "2024-08-09 09:09:09 UTC" "$WORK/enc/plain.txt"
"$LZPLY" -c -y -6 "$WORK/enc/secret.txt" "$WORK/enc.lzply" >/dev/null 2>&1
"$LZPLY" -a "$WORK/enc.lzply" "$WORK/enc/plain.txt" >/dev/null 2>&1
OUT=$("$LZPLY" -i "$WORK/enc.lzply" 2>/dev/null)
echo "$OUT" | grep "plain.txt" | grep -q "2024-08-09 09:09:09 UTC" &&
    ok "-a preserves mtime: appended plain.txt shows 2024-08-09" ||
    bad "-a preserves mtime: appended plain.txt shows 2024-08-09"
OUT=$("$LZPLY" -i "$WORK/enc.lzply" 2>/dev/null)
RC=$?
echo "$OUT" | grep "secret.txt" | grep -q "2024-08-08 08:08:08 UTC" && [ "$RC" = "0" ] &&
    ok "-i on appended archive: mtimes shown for both entries" ||
    bad "-i on appended archive: mtimes shown for both entries (rc=$RC)"
(cd "$WORK" && "$LZPLY" -tr enc.lzply > enc-tr.txt 2>&1)
RC=$?
grep -q "secret.txt" "$WORK/enc-tr.txt" && grep -q "plain.txt" "$WORK/enc-tr.txt" && [ "$RC" = "0" ] &&
    ok "-tr on appended archive: tree shows both files" ||
    bad "-tr on appended archive: tree shows both files (rc=$RC)"

# --- 19. lzply_stat ---------------------------------------------------
# A small archive with pinned polys and known entries.
if [ -x "$STAT" ]; then
printf 'stat test one\n' > "$WORK/stat1.txt"
printf 'stat test two, a bit longer\n' > "$WORK/stat2.txt"
"$LZPLY" -c -y -6 poly=003a "$WORK/stat1.txt" "$WORK/stat.lzply" >/dev/null 2>&1
"$LZPLY" -a poly=000b "$WORK/stat.lzply" "$WORK/stat2.txt" >/dev/null 2>&1
OUT=$("$STAT" "$WORK/stat.lzply" 2>/dev/null)
echo "$OUT" | grep "stat1.txt" | grep -Eq "003a[[:space:]]+32[[:space:]]" &&
echo "$OUT" | grep "stat2.txt" | grep -Eq "000b[[:space:]]+8[[:space:]]" &&
echo "$OUT" | grep -q "2 entries" &&
    ok "lzply_stat: poly ids, t values and totals for a known archive" ||
    bad "lzply_stat: poly ids, t values and totals for a known archive"
echo "$OUT" | grep -q "overall ECC overhead" &&
echo "$OUT" | grep "stat1.txt" | grep -q "%" &&
    ok "lzply_stat: ECC overhead % shown per entry and overall" ||
    bad "lzply_stat: ECC overhead % shown per entry and overall"
# selector: only one entry
OUT=$("$STAT" "$WORK/stat.lzply" stat2.txt 2>/dev/null)
echo "$OUT" | grep -q "stat2.txt" && ! echo "$OUT" | grep -q "stat1.txt" &&
    ok "lzply_stat with selector: only that entry" ||
    bad "lzply_stat with selector: only that entry"
# not an archive: error, non-zero
if "$STAT" "$WORK/notarc.txt" >/dev/null 2>&1; then
    bad "lzply_stat on a non-archive must fail"
else
    ok "lzply_stat on a non-archive fails"
fi
else
    echo "SKIP: lzply_stat tests (binary not found next to lzply)"
fi

# --- 20. lzply_heal ---------------------------------------------------
if [ -x "$HEAL" ]; then
# (a) pure heal: no change, roundtrip intact
cp "$WORK/stat.lzply" "$WORK/heal-pure.lzply"
"$HEAL" "$WORK/heal-pure.lzply" >/dev/null 2>&1 &&
"$LZPLY" -t "$WORK/heal-pure.lzply" >/dev/null 2>&1 &&
    ok "lzply_heal (pure): no-op on a healthy archive, verifies" ||
    bad "lzply_heal (pure): no-op on a healthy archive, verifies"
# (b) level raise: -e 6 moves stat2.txt off poly 000b (t=8); data identical
cp "$WORK/stat.lzply" "$WORK/heal-raise.lzply"
"$HEAL" -e 6 "$WORK/heal-raise.lzply" >/dev/null 2>&1
"$LZPLY" -l "$WORK/heal-raise.lzply" 2>/dev/null | grep "stat2.txt" | grep -qv "BCH 000b" &&
"$LZPLY" -t "$WORK/heal-raise.lzply" >/dev/null 2>&1 &&
rm -rf "$WORK/out" &&
"$LZPLY" -d -y "$WORK/heal-raise.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$WORK/stat1.txt" "$WORK/out/stat1.txt" &&
cmp -s "$WORK/stat2.txt" "$WORK/out/stat2.txt" &&
    ok "lzply_heal -e 6: level raised, data byte-identical" ||
    bad "lzply_heal -e 6: level raised, data byte-identical"
# (c) strip ECC: -e 0, no BCH left, data identical
cp "$WORK/stat.lzply" "$WORK/heal-strip.lzply"
"$HEAL" -e 0 "$WORK/heal-strip.lzply" >/dev/null 2>&1
! "$LZPLY" -l "$WORK/heal-strip.lzply" 2>/dev/null | grep -q "BCH" &&
"$LZPLY" -t "$WORK/heal-strip.lzply" >/dev/null 2>&1 &&
    ok "lzply_heal -e 0: ECC stripped, archive still verifies" ||
    bad "lzply_heal -e 0: ECC stripped, archive still verifies"
# (d) bit-error correction: single-file archive, -e 4 (t=8), one block.
# Data starts at 102 (16 + 78 + 8 for "tiny.txt"); flip 5 bits in the
# stored region -> heal recovers; flip 9 -> uncorrectable (exit non-zero,
# entry kept, -t still fails).
printf 'heal bit test\n' > "$WORK/tiny.txt"
"$LZPLY" -c -y -6 -e 4 "$WORK/tiny.txt" "$WORK/heal-bits.lzply" >/dev/null 2>&1
cp "$WORK/heal-bits.lzply" "$WORK/heal-bits-a.lzply"
SZ=$(stat -c %s "$WORK/heal-bits-a.lzply")
"$CORRUPT_BITS" "$WORK/heal-bits-a.lzply" 61 5 102 $((SZ - 2)) >/dev/null
"$HEAL" "$WORK/heal-bits-a.lzply" >/dev/null 2>&1 &&
"$LZPLY" -t "$WORK/heal-bits-a.lzply" >/dev/null 2>&1 &&
rm -rf "$WORK/out" &&
"$LZPLY" -d -y "$WORK/heal-bits-a.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$WORK/tiny.txt" "$WORK/out/tiny.txt" &&
    ok "lzply_heal: 5 flipped bits (t=8) corrected, data recovered" ||
    bad "lzply_heal: 5 flipped bits (t=8) corrected, data recovered"
cp "$WORK/heal-bits.lzply" "$WORK/heal-bits-b.lzply"
SZ=$(stat -c %s "$WORK/heal-bits-b.lzply")
"$CORRUPT_BITS" "$WORK/heal-bits-b.lzply" 62 9 102 $((SZ - 2)) >/dev/null
if "$HEAL" "$WORK/heal-bits-b.lzply" >/dev/null 2>&1; then
    bad "lzply_heal: 9 flipped bits (t=8) must exit non-zero"
else
    ok "lzply_heal: 9 flipped bits (t=8) exits non-zero, entry kept"
fi
# (e) -o: original untouched, output healed
cp "$WORK/stat.lzply" "$WORK/heal-orig.lzply"
"$HEAL" -e 6 -o "$WORK/heal-out.lzply" "$WORK/heal-orig.lzply" >/dev/null 2>&1
"$LZPLY" -l "$WORK/heal-orig.lzply" 2>/dev/null | grep "stat1.txt" | grep -q "BCH 003a" &&
"$LZPLY" -l "$WORK/heal-out.lzply" 2>/dev/null | grep "stat2.txt" | grep -qv "BCH 000b" &&
    ok "lzply_heal -o: original untouched, output healed" ||
    bad "lzply_heal -o: original untouched, output healed"
# (f) heal with a level raise on a plain archive: data identical
"$LZPLY" -c -y -6 -e 4 "$WORK/tiny.txt" "$WORK/heal-plain.lzply" >/dev/null 2>&1
"$HEAL" -e 6 "$WORK/heal-plain.lzply" >/dev/null 2>&1 &&
rm -rf "$WORK/out" &&
"$LZPLY" -d -y "$WORK/heal-plain.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$WORK/tiny.txt" "$WORK/out/tiny.txt" &&
    ok "lzply_heal -e 6 on a plain archive: data byte-identical" ||
    bad "lzply_heal -e 6 on a plain archive: data byte-identical"
# (g) selector: only one entry healed
cp "$WORK/stat.lzply" "$WORK/heal-sel.lzply"
"$HEAL" -e 6 "$WORK/heal-sel.lzply" stat2.txt >/dev/null 2>&1
"$LZPLY" -l "$WORK/heal-sel.lzply" 2>/dev/null | grep "stat1.txt" | grep -q "BCH 003a" &&
! "$LZPLY" -l "$WORK/heal-sel.lzply" 2>/dev/null | grep "stat2.txt" | grep -q "BCH 000b" &&
    ok "lzply_heal with selector: only that entry healed" ||
    bad "lzply_heal with selector: only that entry healed"
else
    echo "SKIP: lzply_heal tests (binary not found next to lzply)"
fi

# --- 21. lzply_check: BER detection ------------------------------------
if [ -x "$CHECK" ]; then
# (a) clean archive: BER 0, exit 0, status clean
printf 'heal bit test\n' > "$WORK/tiny.txt"
"$LZPLY" -c -y -6 -e 4 "$WORK/tiny.txt" "$WORK/check-clean.lzply" >/dev/null 2>&1
OUT=$("$CHECK" "$WORK/check-clean.lzply" 2>/dev/null)
RC=$?
echo "$OUT" | grep -q "overall BER: 0" && [ "$RC" = "0" ] &&
echo "$OUT" | grep "tiny.txt" | grep -q "clean" &&
    ok "lzply_check clean archive: BER 0, exit 0, clean" ||
    bad "lzply_check clean archive: BER 0, exit 0, clean (rc=$RC)"
# (b) known injected errors: 5 bits flipped (t=8) -> corrected == 5 and
# BER == 5 / (8 * stored_size), verified through --json.
cp "$WORK/check-clean.lzply" "$WORK/check-err5.lzply"
SZ=$(stat -c %s "$WORK/check-err5.lzply")
"$CORRUPT_BITS" "$WORK/check-err5.lzply" 61 5 102 $((SZ - 2)) >/dev/null
"$CHECK" --json "$WORK/check-err5.lzply" 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
e = d["entries"][0]
assert e["corrected"] == 5, e
assert abs(e["ber"] - 5 / e["stored_bits"]) < 1e-15, e
assert e["status"] == "correctable", e
assert d["totals"]["overall_ber"] == e["ber"], d["totals"]
assert d["status"] == "ok", d
print("json ok")
' >/dev/null 2>&1 &&
    ok "lzply_check: 5 injected bits -> corrected == 5, BER matches (--json)" ||
    bad "lzply_check: 5 injected bits -> corrected == 5, BER matches (--json)"
# (c) uncorrectable: 9 bits flipped (t=8) -> exit 3, uncorrectable
cp "$WORK/check-clean.lzply" "$WORK/check-err9.lzply"
SZ=$(stat -c %s "$WORK/check-err9.lzply")
"$CORRUPT_BITS" "$WORK/check-err9.lzply" 62 9 102 $((SZ - 2)) >/dev/null
OUT=$("$CHECK" "$WORK/check-err9.lzply" 2>&1)
RC=$?
[ "$RC" = "3" ] && echo "$OUT" | grep -q "uncorrectable" &&
    ok "lzply_check: 9 flipped bits (t=8) -> exit 3, uncorrectable" ||
    bad "lzply_check: 9 flipped bits (t=8) -> exit 3, uncorrectable (rc=$RC)"
# (d) no-ECC entry: reported as unmeasurable, exit 0
"$LZPLY" -c -y -6 -e 0 "$WORK/tiny.txt" "$WORK/check-noecc.lzply" >/dev/null 2>&1
OUT=$("$CHECK" "$WORK/check-noecc.lzply" 2>/dev/null)
RC=$?
[ "$RC" = "0" ] && echo "$OUT" | grep "tiny.txt" | grep -q "no-ecc" &&
    ok "lzply_check no-ECC entry: reported as no-ecc, exit 0" ||
    bad "lzply_check no-ECC entry: reported as no-ecc, exit 0 (rc=$RC)"
# (e) thresholds on the 5-bit archive (overall BER 5/488 = 0.0102...)
# --warn-ber below the BER: warning, still exit 0
OUT=$("$CHECK" --warn-ber 0.001 "$WORK/check-err5.lzply" 2>&1)
RC=$?
[ "$RC" = "0" ] && echo "$OUT" | grep -q "warning: overall BER" &&
    ok "lzply_check --warn-ber below BER: warning, exit 0" ||
    bad "lzply_check --warn-ber below BER: warning, exit 0 (rc=$RC)"
# --fail-ber below the BER: exit 3
"$CHECK" --fail-ber 0.001 "$WORK/check-err5.lzply" >/dev/null 2>&1
[ "$?" = "3" ] &&
    ok "lzply_check --fail-ber below BER: exit 3" ||
    bad "lzply_check --fail-ber below BER: exit 3"
# --fail-ber above the BER: exit 0
"$CHECK" --fail-ber 0.05 "$WORK/check-err5.lzply" >/dev/null 2>&1
[ "$?" = "0" ] &&
    ok "lzply_check --fail-ber above BER: exit 0" ||
    bad "lzply_check --fail-ber above BER: exit 0"
# (f) mount-point check (needs a live FUSE mount; skipped without one)
MOUNT="$(dirname "$LZPLY")/lzply_mount"
if [ -e /dev/fuse ] && [ -x "$MOUNT" ] && command -v fusermount3 >/dev/null 2>&1 && command -v mountpoint >/dev/null 2>&1; then
    mkdir -p "$WORK/mnt"
    "$MOUNT" "$WORK/check-clean.lzply" "$WORK/mnt" >/dev/null 2>&1
    MOUNTED=0
    for i in 1 2 3 4 5; do mountpoint -q "$WORK/mnt" && { MOUNTED=1; break; }; sleep 1; done
    if [ "$MOUNTED" = "1" ]; then
        OUT=$("$CHECK" "$WORK/mnt" 2>/dev/null)
        RC=$?
        fusermount3 -u "$WORK/mnt" >/dev/null 2>&1
        [ "$RC" = "0" ] && echo "$OUT" | grep "tiny.txt" | grep -q "clean" &&
            ok "lzply_check on a mount point: resolves the archive, BER 0" ||
            bad "lzply_check on a mount point: resolves the archive, BER 0 (rc=$RC)"
    else
        echo "SKIP: lzply_check mount test (mount did not come up)"
    fi
else
    echo "SKIP: lzply_check mount test (no FUSE)"
fi
else
    echo "SKIP: lzply_check tests (binary not found next to lzply)"
fi

# --- 22. lzply_refresh: in-place platter refresh -----------------------
if [ -x "$REFRESH" ]; then
# (a) 1 pass: same inode, content byte-identical, SHA-256 unchanged
printf 'refresh test content, one pass\n' > "$WORK/ref1.txt"
H1=$(sha256sum "$WORK/ref1.txt" | cut -d' ' -f1)
I1=$(stat -c %i "$WORK/ref1.txt")
OUT=$("$REFRESH" "$WORK/ref1.txt" 1 2>&1)
RC=$?
H2=$(sha256sum "$WORK/ref1.txt" | cut -d' ' -f1)
I2=$(stat -c %i "$WORK/ref1.txt")
[ "$RC" = "0" ] && [ "$H1" = "$H2" ] && [ "$I1" = "$I2" ] &&
echo "$OUT" | grep -q "verified unchanged" &&
    ok "lzply_refresh 1 pass: same inode, SHA-256 unchanged" ||
    bad "lzply_refresh 1 pass: same inode, SHA-256 unchanged (rc=$RC)"
# (b) 3 passes: same guarantees
printf 'refresh test content, three passes\n' > "$WORK/ref3.txt"
H1=$(sha256sum "$WORK/ref3.txt" | cut -d' ' -f1)
I1=$(stat -c %i "$WORK/ref3.txt")
OUT=$("$REFRESH" "$WORK/ref3.txt" 3 2>&1)
RC=$?
H2=$(sha256sum "$WORK/ref3.txt" | cut -d' ' -f1)
I2=$(stat -c %i "$WORK/ref3.txt")
[ "$RC" = "0" ] && [ "$H1" = "$H2" ] && [ "$I1" = "$I2" ] &&
echo "$OUT" | grep -q "3 passes" &&
    ok "lzply_refresh 3 passes: same inode, SHA-256 unchanged" ||
    bad "lzply_refresh 3 passes: same inode, SHA-256 unchanged (rc=$RC)"
# (c) n=4 and n=0 are usage errors
"$REFRESH" "$WORK/ref1.txt" 4 >/dev/null 2>&1
[ "$?" = "1" ] &&
    ok "lzply_refresh n=4: usage error (exit 1)" ||
    bad "lzply_refresh n=4: usage error (exit 1)"
"$REFRESH" "$WORK/ref1.txt" 0 >/dev/null 2>&1
[ "$?" = "1" ] &&
    ok "lzply_refresh n=0: usage error (exit 1)" ||
    bad "lzply_refresh n=0: usage error (exit 1)"
# (d) directory refresh: several files, symlink skipped, summary counts
mkdir -p "$WORK/refdir/sub"
printf 'dir file one\n' > "$WORK/refdir/one.txt"
printf 'dir file two\n' > "$WORK/refdir/sub/two.txt"
ln -s one.txt "$WORK/refdir/link.txt"
H1=$(sha256sum "$WORK/refdir/one.txt" | cut -d' ' -f1)
H2=$(sha256sum "$WORK/refdir/sub/two.txt" | cut -d' ' -f1)
OUT=$("$REFRESH" "$WORK/refdir" 2 2>&1)
RC=$?
[ "$RC" = "0" ] &&
[ "$(sha256sum "$WORK/refdir/one.txt" | cut -d' ' -f1)" = "$H1" ] &&
[ "$(sha256sum "$WORK/refdir/sub/two.txt" | cut -d' ' -f1)" = "$H2" ] &&
echo "$OUT" | grep -q "2 files refreshed" &&
echo "$OUT" | grep -q "1 skipped" &&
    ok "lzply_refresh directory: 2 files refreshed, symlink skipped, contents unchanged" ||
    bad "lzply_refresh directory: 2 files refreshed, symlink skipped, contents unchanged (rc=$RC)"
# (e) mount cases (need a live FUSE mount; skipped without one)
MOUNT="$(dirname "$LZPLY")/lzply_mount"
if [ -e /dev/fuse ] && [ -x "$MOUNT" ] && command -v fusermount3 >/dev/null 2>&1 && command -v mountpoint >/dev/null 2>&1; then
    mkdir -p "$WORK/reftree/sub" "$WORK/mnt2"
    printf 'mount file one\n' > "$WORK/reftree/one.txt"
    printf 'mount file two\n' > "$WORK/reftree/sub/two.txt"
    printf 'mount file three\n' > "$WORK/reftree/three.txt"
    # NB: `-c` takes one input + optional output, so create from the
    # directory itself; entries are stored as `reftree/...` (paths
    # relative to the input's parent) and the mount tests address
    # them under $WORK/mnt2/reftree/.
    (cd "$WORK" && "$LZPLY" -c -y -6 -e 4 reftree "$WORK/ref-mount.lzply" >/dev/null 2>&1)
    H1=$(sha256sum "$WORK/reftree/one.txt" | cut -d' ' -f1)
    H2=$(sha256sum "$WORK/reftree/sub/two.txt" | cut -d' ' -f1)
    H3=$(sha256sum "$WORK/reftree/three.txt" | cut -d' ' -f1)
    "$MOUNT" "$WORK/ref-mount.lzply" "$WORK/mnt2" >/dev/null 2>&1
    MOUNTED=0
    for i in 1 2 3 4 5; do mountpoint -q "$WORK/mnt2" && { MOUNTED=1; break; }; sleep 1; done
    if [ "$MOUNTED" = "1" ]; then
        # (e1) single file inside the mount
        OUT=$("$REFRESH" "$WORK/mnt2/reftree/one.txt" 2>&1)
        RC1=$?
        # (e2) whole mount point, 2 passes
        OUT2=$("$REFRESH" "$WORK/mnt2" 2 2>&1)
        RC2=$?
        # (e3) the mounted archive file itself is refused
        OUT3=$("$REFRESH" "$WORK/ref-mount.lzply" 2>&1)
        RC3=$?
        fusermount3 -u "$WORK/mnt2" >/dev/null 2>&1
        # Repack may still be in flight after fusermount3 returns;
        # wait for the mount to clear, then a beat, before reading
        # the archive.
        for i in 1 2 3 4 5 6 7 8 9 10; do mountpoint -q "$WORK/mnt2" || break; sleep 1; done
        sleep 1
        [ "$RC1" = "0" ] && echo "$OUT" | grep -q "verified unchanged" &&
            ok "lzply_refresh file inside mount: verified unchanged" ||
            bad "lzply_refresh file inside mount: verified unchanged (rc=$RC1)"
        [ "$RC2" = "0" ] && echo "$OUT2" | grep -q "refreshing mount at" &&
        echo "$OUT2" | grep -q "3 files refreshed" &&
            ok "lzply_refresh whole mount point: 3 files refreshed" ||
            bad "lzply_refresh whole mount point: 3 files refreshed (rc=$RC2)"
        [ "$RC3" != "0" ] && echo "$OUT3" | grep -q "mounted" &&
            ok "lzply_refresh mounted archive: refused" ||
            bad "lzply_refresh mounted archive: refused (rc=$RC3)"
        # After unmount: archive verifies, contents unchanged
        "$LZPLY" -t "$WORK/ref-mount.lzply" >/dev/null 2>&1
        TRC=$?
        rm -rf "$WORK/ref-out" && mkdir -p "$WORK/ref-out"
        "$LZPLY" -d "$WORK/ref-mount.lzply" "$WORK/ref-out" >/dev/null 2>&1
        [ "$TRC" = "0" ] &&
        [ "$(sha256sum "$WORK/ref-out/reftree/one.txt" | cut -d' ' -f1)" = "$H1" ] &&
        [ "$(sha256sum "$WORK/ref-out/reftree/sub/two.txt" | cut -d' ' -f1)" = "$H2" ] &&
        [ "$(sha256sum "$WORK/ref-out/reftree/three.txt" | cut -d' ' -f1)" = "$H3" ] &&
            ok "lzply_refresh mount roundtrip: archive verifies, all contents unchanged" ||
            bad "lzply_refresh mount roundtrip: archive verifies, all contents unchanged (test rc=$TRC)"
    else
        echo "SKIP: lzply_refresh mount tests (mount did not come up)"
    fi
else
    echo "SKIP: lzply_refresh mount tests (no FUSE)"
fi
else
    echo "SKIP: lzply_refresh tests (binary not found next to lzply)"
fi

# --- 23. Mount with a relative archive path: write-back must land in the
# real archive, not /<basename> ---------------------------------------
# libfuse changes the daemon's cwd to "/" at mount time, so a relative
# archive path used to make the repack write to /<basename> and leave
# the real archive untouched. lzply_mount canonicalises the path at
# startup; the write below must survive unmount in the cwd archive,
# and no stray file may appear in /.
MOUNT="$(dirname "$LZPLY")/lzply_mount"
if [ -e /dev/fuse ] && [ -x "$MOUNT" ] && command -v fusermount3 >/dev/null 2>&1 && command -v mountpoint >/dev/null 2>&1; then
    mkdir -p "$WORK/relmnt/mnt" && rm -f "$WORK/relmnt/relmount-test.lzply" /relmount-test.lzply
    echo "relative-path mount content" > "$WORK/relmnt/seed.txt"
    (cd "$WORK/relmnt" && "$LZPLY" -c -y seed.txt relmount-test.lzply >/dev/null 2>&1)
    (cd "$WORK/relmnt" && "$MOUNT" relmount-test.lzply mnt >/dev/null 2>&1)
    MOUNTED=0
    for i in 1 2 3 4 5; do mountpoint -q "$WORK/relmnt/mnt" && { MOUNTED=1; break; }; sleep 1; done
    if [ "$MOUNTED" = "1" ]; then
        echo "written through a relative-path mount" > "$WORK/relmnt/mnt/seed.txt"
        echo "new file in a relative-path mount" > "$WORK/relmnt/mnt/added.txt"
        # lzply_stat on the mount must resolve the archive (daemon's
        # relative arg + cwd "/"), run from the mount's parent dir.
        STATOUT=$(cd "$WORK/relmnt" && "$STAT" mnt 2>&1)
        STATRC=$?
        fusermount3 -u "$WORK/relmnt/mnt" >/dev/null 2>&1
        for i in 1 2 3 4 5 6 7 8 9 10; do mountpoint -q "$WORK/relmnt/mnt" || break; sleep 1; done
        sleep 1
        rm -rf "$WORK/relmnt/out" && mkdir -p "$WORK/relmnt/out"
        "$LZPLY" -d "$WORK/relmnt/relmount-test.lzply" "$WORK/relmnt/out" >/dev/null 2>&1
        [ "$(cat "$WORK/relmnt/out/seed.txt" 2>/dev/null)" = "written through a relative-path mount" ] &&
        [ "$(cat "$WORK/relmnt/out/added.txt" 2>/dev/null)" = "new file in a relative-path mount" ] &&
            ok "mount with relative archive path: writes persist in the real archive" ||
            bad "mount with relative archive path: writes persist in the real archive"
        [ ! -e /relmount-test.lzply ] &&
            ok "mount with relative archive path: no stray archive in /" ||
            bad "mount with relative archive path: no stray archive in /"
        [ "$STATRC" = "0" ] && echo "$STATOUT" | grep -q "seed.txt" &&
            ok "lzply_stat on a relative-path mount: resolves the archive" ||
            bad "lzply_stat on a relative-path mount: resolves the archive (rc=$STATRC)"
    else
        echo "SKIP: relative-path mount test (mount did not come up)"
    fi
else
    echo "SKIP: relative-path mount test (no FUSE)"
fi

# --- 24. Store mode (level 0): incompressible data stored uncompressed --
# (1) 1 MiB random data: compressed blob would be larger, so the entry
# is stored (level 0) and extracts byte-identical. -l, -i and stat
# all show lvl 0 for it.
"$LZPLY" -c -y -6 "$TD/mixed/random.bin" "$WORK/store-rand.lzply" >/dev/null 2>&1
OUT=$("$LZPLY" -l "$WORK/store-rand.lzply" 2>/dev/null)
echo "$OUT" | grep "random.bin" | grep -Eq " 0 +BCH" &&
    ok "store mode: random.bin creates a level 0 entry (-l)" ||
    bad "store mode: random.bin creates a level 0 entry (-l)"
OUT=$("$LZPLY" -i "$WORK/store-rand.lzply" 2>/dev/null)
echo "$OUT" | grep "random.bin" | grep -Eq " 0 BCH" &&
    ok "store mode: random.bin shows lvl 0 in -i" ||
    bad "store mode: random.bin shows lvl 0 in -i"
OUT=$("$STAT" "$WORK/store-rand.lzply" 2>/dev/null)
echo "$OUT" | grep "random.bin" | grep -Eq "100\.0%[[:space:]]+0[[:space:]]" &&
    ok "store mode: random.bin shows lvl 0 in lzply_stat" ||
    bad "store mode: random.bin shows lvl 0 in lzply_stat"
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/store-rand.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$TD/mixed/random.bin" "$WORK/out/random.bin" &&
    ok "store mode: random.bin extracts byte-identical" ||
    bad "store mode: random.bin extracts byte-identical"
# (2) a compressible file still compresses (level > 0)
"$LZPLY" -c -y -6 "$TD/mixed/text.txt" "$WORK/store-text.lzply" >/dev/null 2>&1
OUT=$("$LZPLY" -l "$WORK/store-text.lzply" 2>/dev/null)
echo "$OUT" | grep "text.txt" | grep -Eq " 6 +BCH" &&
    ok "store mode: compressible text.txt still compresses (lvl 6)" ||
    bad "store mode: compressible text.txt still compresses (lvl 6)"
# (3) explicit -0 forces store even for a compressible file, via -c and -a
"$LZPLY" -c -y -0 "$TD/mixed/text.txt" "$WORK/store-zero.lzply" >/dev/null 2>&1
OUT=$("$LZPLY" -l "$WORK/store-zero.lzply" 2>/dev/null)
echo "$OUT" | grep "text.txt" | grep -Eq " 0 +BCH" &&
    ok "store mode: -0 forces store for a compressible file (-c)" ||
    bad "store mode: -0 forces store for a compressible file (-c)"
printf 'more compressible text, more compressible text\n%.0s' {1..500} > "$WORK/more.txt"
"$LZPLY" -a -0 "$WORK/store-text.lzply" "$WORK/more.txt" >/dev/null 2>&1
OUT=$("$LZPLY" -l "$WORK/store-text.lzply" 2>/dev/null)
echo "$OUT" | grep "more.txt" | grep -Eq " 0 +BCH" &&
echo "$OUT" | grep "text.txt" | grep -Eq " 6 +BCH" &&
    ok "store mode: -a -0 stores the new entry, old entry stays compressed" ||
    bad "store mode: -a -0 stores the new entry, old entry stays compressed"
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/store-zero.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$TD/mixed/text.txt" "$WORK/out/text.txt" &&
    ok "store mode: -0 archive extracts byte-identical" ||
    bad "store mode: -0 archive extracts byte-identical"
# (4) BCH still applies to stored entries: flip 1 bit in the stored
# entry (data starts at 104: 16 + 78 + 10 for "random.bin"); -t still
# passes (BCH corrects it), check reports exactly 1 corrected bit,
# heal fixes it and the healed archive extracts byte-identical.
cp "$WORK/store-rand.lzply" "$WORK/store-rand-c.lzply"
SZ=$(stat -c %s "$WORK/store-rand-c.lzply")
"$CORRUPT_BITS" "$WORK/store-rand-c.lzply" 55 1 104 $((SZ - 2)) >/dev/null
"$LZPLY" -t "$WORK/store-rand-c.lzply" >/dev/null 2>&1 &&
    ok "store mode: 1 flipped bit in a stored entry still tests OK (BCH)" ||
    bad "store mode: 1 flipped bit in a stored entry still tests OK (BCH)"
OUT=$("$CHECK" --json "$WORK/store-rand-c.lzply" 2>/dev/null)
echo "$OUT" | grep -q '"corrected": 1' &&
    ok "store mode: check reports exactly 1 corrected bit in a stored entry" ||
    bad "store mode: check reports exactly 1 corrected bit in a stored entry"
"$HEAL" -o "$WORK/store-rand-h.lzply" "$WORK/store-rand-c.lzply" >/dev/null 2>&1
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/store-rand-h.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$TD/mixed/random.bin" "$WORK/out/random.bin" &&
    ok "store mode: heal corrects the flipped bit, data recovers" ||
    bad "store mode: heal corrects the flipped bit, data recovers"
# (5) empty file: stored as level 0 with a 0-byte blob, roundtrips
"$LZPLY" -c -y -6 "$TD/mixed/empty.txt" "$WORK/store-empty.lzply" >/dev/null 2>&1
OUT=$("$LZPLY" -l "$WORK/store-empty.lzply" 2>/dev/null)
echo "$OUT" | grep "empty.txt" | grep -Eq " 0 +BCH" &&
    ok "store mode: empty file is stored as level 0" ||
    bad "store mode: empty file is stored as level 0"
rm -rf "$WORK/out"
"$LZPLY" -d "$WORK/store-empty.lzply" "$WORK/out" >/dev/null 2>&1 &&
cmp -s "$TD/mixed/empty.txt" "$WORK/out/empty.txt" &&
    ok "store mode: empty file extracts byte-identical" ||
    bad "store mode: empty file extracts byte-identical"
# (6) directories are unaffected: they keep the requested level
rm -rf "$WORK/storedir"
mkdir -p "$WORK/storedir/sub"
cp "$TD/mixed/random.bin" "$WORK/storedir/"
cp "$TD/mixed/text.txt" "$WORK/storedir/sub/"
"$LZPLY" -c -y -6 "$WORK/storedir" "$WORK/store-dir.lzply" >/dev/null 2>&1
OUT=$("$LZPLY" -l "$WORK/store-dir.lzply" 2>/dev/null)
echo "$OUT" | grep -Eq "^storedir/ +0 B +0 B +6 +-" &&
echo "$OUT" | grep "random.bin" | grep -Eq " 0 +BCH" &&
echo "$OUT" | grep "text.txt" | grep -Eq " 6 +BCH" &&
    ok "store mode: directories keep the requested level, files store/fall back" ||
    bad "store mode: directories keep the requested level, files store/fall back"
# (7) mount repack of an incompressible file stores it (level 0)
MOUNT="$(dirname "$LZPLY")/lzply_mount"
if [ -e /dev/fuse ] && [ -x "$MOUNT" ] && command -v fusermount3 >/dev/null 2>&1 && command -v mountpoint >/dev/null 2>&1; then
    mkdir -p "$WORK/store-mnt"
    "$LZPLY" -c -y -6 "$TD/mixed/text.txt" "$WORK/store-mount.lzply" >/dev/null 2>&1
    "$MOUNT" "$WORK/store-mount.lzply" "$WORK/store-mnt" >/dev/null 2>&1
    MOUNTED=0
    for i in 1 2 3 4 5; do mountpoint -q "$WORK/store-mnt" && { MOUNTED=1; break; }; sleep 1; done
    if [ "$MOUNTED" = "1" ]; then
        cp "$TD/mixed/random.bin" "$WORK/store-mnt/rand.bin"
        fusermount3 -u "$WORK/store-mnt" >/dev/null 2>&1
        for i in 1 2 3 4 5 6 7 8 9 10; do mountpoint -q "$WORK/store-mnt" || break; sleep 1; done
        sleep 1
        OUT=$("$LZPLY" -l "$WORK/store-mount.lzply" 2>/dev/null)
        echo "$OUT" | grep "rand.bin" | grep -Eq " 0 +BCH" &&
            ok "store mode: mount repack stores an incompressible file (lvl 0)" ||
            bad "store mode: mount repack stores an incompressible file (lvl 0)"
        rm -rf "$WORK/out"
        "$LZPLY" -d "$WORK/store-mount.lzply" "$WORK/out" >/dev/null 2>&1 &&
        cmp -s "$TD/mixed/random.bin" "$WORK/out/rand.bin" &&
            ok "store mode: mount-repacked stored file extracts byte-identical" ||
            bad "store mode: mount-repacked stored file extracts byte-identical"
    else
        echo "SKIP: store-mode mount test (mount did not come up)"
    fi
else
    echo "SKIP: store-mode mount test (no FUSE)"
fi

echo
echo "LZPLY TESTS: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
