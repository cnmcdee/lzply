#!/bin/bash
# make_testdata.sh - build the lzply test corpus under <ROOT>/testdata.
# ROOT is taken from $LZPLY_TEST_ROOT, else the parent of this script's
# directory (works for ~/workspace/lzply and for /opt/lzply).
# Deterministic where it matters (text/zeros); random.bin uses urandom.
set -eu
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${LZPLY_TEST_ROOT:-$(dirname "$SCRIPT_DIR")}"
TD="$ROOT/testdata"
# lzply.c lives at the repo root locally, under src/ on the server.
if [ -f "$ROOT/lzply.c" ]; then SRC="$ROOT/lzply.c";
elif [ -f "$ROOT/src/lzply.c" ]; then SRC="$ROOT/src/lzply.c";
else echo "lzply.c not found under $ROOT"; exit 1; fi
rm -rf "$TD"
mkdir -p "$TD/mixed/nested/deep" "$TD/mixed/empty dir" "$TD/emptydir"

# Compressible text: lorem + code, ~200 KiB.
{
    for i in $(seq 1 400); do
        echo "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
        echo "int main(int argc, char **argv) { if (argc < 2) return 1; printf(\"hello %s\\n\", argv[1]); return 0; }"
    done
} > "$TD/mixed/text.txt"

# Real source code (compressible, realistic).
cp "$SRC" "$TD/mixed/source.c"

# Random binary (incompressible): 1 MiB.
head -c 1048576 /dev/urandom > "$TD/mixed/random.bin"

# Zeros (maximally compressible): 1 MiB.
head -c 1048576 /dev/zero > "$TD/mixed/zeros.bin"

# Edge cases.
: > "$TD/mixed/empty.txt"
printf 'x' > "$TD/mixed/onebyte.txt"
echo "nested file one" > "$TD/mixed/nested/a.txt"
echo "nested file two, deeper" > "$TD/mixed/nested/deep/b.txt"
echo "a file with spaces in its name" > "$TD/mixed/empty dir/file with spaces.txt"

# One big file: 50 MiB random (exercises multi-block RS + memory).
head -c 52428800 /dev/urandom > "$TD/big.bin"

echo "testdata ready in $TD"
find "$TD" -type f | sort
du -sh "$TD"
