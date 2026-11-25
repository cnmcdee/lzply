#!/usr/bin/env python3
"""gen_bch_polys.py - generate bch_polys.h for lzply from the rssearch data.

Reads ~/workspace/rssearch/polys.txt (id, deg, hex) and finds.txt
(parent, t, poly) and emits a C header embedding the 82 narrow-sense
primitive BCH generator polynomials (m=7..22, t in {1,2,4,8,16,32}).

For each poly the header stores: id (u16), m (u8), t (u8), r=deg (u16),
parent N (u32), and the generator bytes (LSB-first hex, as in polys.txt).
It also emits a (m,t)->poly_id lookup table used by the auto-pick, and
the primitive polynomial P_m for each m (the t=1 poly for that parent,
i.e. the Hamming generator = minpoly of the primitive element alpha).

Consistency checks performed (fails loudly if violated):
  - every poly id in polys.txt appears in finds.txt with exactly one
    (parent, t); deg == t*m where m = log2(parent+1)
  - the t=1 poly for each m is irreducible+primitive (checked by
    verifying x has order N mod P, using the known factorisation of
    2^m-1 for m<=22, which is small enough to factor by trial division)
  - the generated generator for (m,t) (recomputed orbit-only from P_m)
    matches the polys.txt hex, for every poly (independent check that
    the embedded bytes are the narrow-sense generators for P_m)
"""
import os
import re
import sys

RS = "/home/hatch/workspace/rssearch"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bch_polys.h")

# ---------- GF(2) polynomial helpers (ints) ----------
def pmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
    return r

def pmod(a, P):
    dm = P.bit_length() - 1
    while a.bit_length() - 1 >= dm:
        a ^= P << (a.bit_length() - 1 - dm)
    return a

def pmodmul(a, b, P):
    return pmod(pmul(a, b), P)

def pmodpow(a, e, P):
    r = 1
    while e:
        if e & 1:
            r = pmodmul(r, a, P)
        a = pmodmul(a, a, P)
        e >>= 1
    return r

def pgcd(a, b):
    while b:
        a, b = b, pmod(a, b)
    return a

def prime_factors(n):
    f = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            f.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        f.append(n)
    return f

def is_primitive_poly(P, m):
    """P degree m. True iff irreducible and x has order 2^m-1 mod P."""
    N = (1 << m) - 1
    x = 2
    if pmodpow(x, 1 << m, P) != x:
        return False
    # irreducibility: gcd(x^(2^(m/q)) - x, P) == 1 for prime q|m
    for q in prime_factors(m):
        if pgcd(pmodpow(x, 1 << (m // q), P) ^ x, P) != 1:
            return False
    for p in prime_factors(N):
        if pmodpow(x, N // p, P) == 1:
            return False
    return True

# ---------- narrow-sense generator (orbit-only), independent check ----------
def gf_mul(a, b, P):
    return pmodmul(a, b, P)

def gf_pow(a, e, P):
    return pmodpow(a, e, P)

def narrow_g(N, t, P):
    m = (N + 1).bit_length() - 1
    # distinct cosets of odd residues 1,3,...,2t-1 under *2 mod N
    cosets = []
    seen = set()
    for a in range(1, 2 * t, 2):
        orb = []
        x = a
        while True:
            orb.append(x)
            x = (2 * x) % N
            if x == a:
                break
        rep = min(orb)
        if rep in seen:
            continue
        seen.add(rep)
        cosets.append(orb)

    def minpoly(orb):
        s = min(orb)
        betas = []
        e = s
        for _ in range(len(orb)):
            betas.append(gf_pow(2, e, P))
            e = (e * 2) % N
        poly = [1]
        for b in betas:
            new = [0] * (len(poly) + 1)
            for i, c in enumerate(poly):
                new[i] ^= gf_mul(c, b, P)
                new[i + 1] ^= c
            poly = new
        assert all(c in (0, 1) for c in poly), "non-binary minpoly coeff"
        v = 0
        for i, c in enumerate(poly):
            if c:
                v |= 1 << i
        return v

    def gf2_mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            b >>= 1
            a <<= 1
        return r

    g = 1
    for orb in cosets:
        g = gf2_mul(g, minpoly(orb))
    return g

def hex_to_int_lsb(h):
    b = bytes.fromhex(h)
    v = 0
    for i, byte in enumerate(b):
        v |= byte << (8 * i)
    return v

def int_to_hex_lsb(v):
    nb = (v.bit_length() + 7) // 8
    return bytes((v >> (8 * i)) & 0xff for i in range(nb)).hex()

# ---------- read the data ----------
polys = {}   # id -> (deg, nbytes, hex)
for line in open(os.path.join(RS, "polys.txt")):
    m = re.match(r"POLY id=([0-9a-f]+) deg=(\d+) nbytes=(\d+) hex=([0-9a-f]+)", line.strip())
    if not m:
        continue
    pid = int(m.group(1), 16)
    polys[pid] = (int(m.group(2)), int(m.group(3)), m.group(4))

# (parent, t) -> poly_id, from finds.txt
pt = {}
for line in open(os.path.join(RS, "finds.txt")):
    m = re.match(r"FIND L=\d+ t=(\d+) n=\d+ r=\d+ d=\d+ fam=\w+ parent=(\d+) poly=([0-9a-f]+) rsp=\d+ save=\d+ hex=[0-9a-f]+", line.strip())
    if not m:
        continue
    t, parent, pid = int(m.group(1)), int(m.group(2)), int(m.group(3), 16)
    key = (parent, t)
    if key in pt and pt[key] != pid:
        print(f"FAIL: (parent={parent},t={t}) maps to both {pt[key]:04x} and {pid:04x}")
        sys.exit(1)
    pt[key] = pid

# invert: poly_id -> (parent, t); check consistency with deg
info = {}    # pid -> dict(m, t, r, parent, hex)
for (parent, t), pid in pt.items():
    m = (parent + 1).bit_length() - 1
    assert (1 << m) - 1 == parent, f"parent {parent} is not 2^m-1"
    if pid in info:
        assert info[pid]["parent"] == parent and info[pid]["t"] == t, \
            f"poly {pid:04x} has two (parent,t)"
        continue
    deg, nbytes, hx = polys[pid]
    assert deg == t * m, f"poly {pid:04x}: deg {deg} != t*m = {t}*{m}"
    assert nbytes == (deg + 7) // 8 or nbytes == (deg // 8) + 1, \
        f"poly {pid:04x}: nbytes {nbytes} vs deg {deg}"
    info[pid] = dict(m=m, t=t, r=deg, parent=parent, hex=hx)

missing = set(polys) - set(info)
if missing:
    print(f"FAIL: polys with no (parent,t) in finds.txt: {sorted(f'{p:04x}' for p in missing)}")
    sys.exit(1)
print(f"polys: {len(info)} (ids {min(info):04x}..{max(info):04x}), "
      f"m range {min(v['m'] for v in info.values())}..{max(v['m'] for v in info.values())}")

# ---------- verify P_m (t=1 poly) is primitive, and recompute every g ----------
prim = {}   # m -> P (int)
for pid, v in info.items():
    if v["t"] == 1:
        assert v["m"] not in prim, f"two t=1 polys for m={v['m']}"
        prim[v["m"]] = hex_to_int_lsb(v["hex"])
for m in sorted(prim):
    P = prim[m]
    assert P.bit_length() - 1 == m, f"P_m degree wrong for m={m}"
    ok = is_primitive_poly(P, m)
    print(f"  m={m}: P={int_to_hex_lsb(P)} primitive={ok}")
    assert ok, f"t=1 poly for m={m} is not primitive"

for pid in sorted(info):
    v = info[pid]
    g = narrow_g(v["parent"], v["t"], prim[v["m"]])
    got = int_to_hex_lsb(g)
    assert got == v["hex"], \
        f"poly {pid:04x} (m={v['m']},t={v['t']}): recomputed {got} != polys.txt {v['hex']}"
print("all 82 generators recomputed orbit-only from P_m and match polys.txt")

# ---------- emit the header ----------
# (m,t) -> pid lookup, as a static table indexed by m (7..22) and t index
TS = [1, 2, 4, 8, 16, 32]
lookup = {}  # (m, t) -> pid
for pid, v in info.items():
    lookup[(v["m"], v["t"])] = pid

lines = []
lines.append("/* bch_polys.h - embedded BCH generator polynomials for lzply.")
lines.append(" *")
lines.append(" * Generated by gen_bch_polys.py from the rssearch results")
lines.append(" * (polys.txt / finds.txt). DO NOT EDIT BY HAND -- regenerate:")
lines.append(" *   python3 gen_bch_polys.py")
lines.append(" *")
lines.append(" * 82 narrow-sense primitive BCH generators, parents N=2^m-1 for")
lines.append(" * m=7..22, t in {1,2,4,8,16,32}. Generator bytes are LSB-first")
lines.append(" * (byte i holds bits 8i..8i+7), exactly as in polys.txt / finds.h.")
lines.append(" * The t=1 polynomial for each m is the primitive polynomial P_m")
lines.append(" * defining GF(2^m) (verified primitive by the generator).")
lines.append(" *")
lines.append(" * Every polynomial was independently recomputed orbit-only from")
lines.append(" * its P_m and checked byte-identical to polys.txt, so this table")
lines.append(" * is the narrow-sense generator for (m,t) under that P_m.")
lines.append(" */")
lines.append("#ifndef LZPLY_BCH_POLYS_H")
lines.append("#define LZPLY_BCH_POLYS_H")
lines.append("")
lines.append("#include <stdint.h>")
lines.append("")
lines.append("typedef struct {")
lines.append("    uint16_t id;       /* 2-byte polynomial id, e.g. 0x003a */")
lines.append("    uint8_t  m;        /* parent exponent: N = 2^m - 1 */")
lines.append("    uint8_t  t;        /* correctable bit errors */")
lines.append("    uint16_t r;        /* degree = parity bits = t*m */")
lines.append("    uint32_t parent;   /* N = 2^m - 1 */")
lines.append("    uint16_t nbytes;   /* generator length in bytes */")
lines.append("    uint16_t off;      /* offset into bch_poly_bytes[] */")
lines.append("} bch_poly_t;")
lines.append("")
lines.append(f"#define BCH_NPOLYS {len(info)}")
lines.append(f"#define BCH_MIN_M {min(v['m'] for v in info.values())}")
lines.append(f"#define BCH_MAX_M {max(v['m'] for v in info.values())}")
lines.append("")

# concatenated generator bytes
allbytes = bytearray()
offs = {}
for pid in sorted(info):
    hx = info[pid]["hex"]
    b = bytes.fromhex(hx)
    offs[pid] = len(allbytes)
    allbytes += b
lines.append("static const uint8_t bch_poly_bytes[] = {")
for i in range(0, len(allbytes), 16):
    chunk = allbytes[i:i + 16]
    lines.append("    " + ",".join(f"0x{b:02x}" for b in chunk) + ",")
lines.append("};")
lines.append("")

lines.append("static const bch_poly_t bch_polys[] = {")
for pid in sorted(info):
    v = info[pid]
    lines.append(f"    {{ 0x{pid:04x}, {v['m']}, {v['t']}, {v['r']}, "
                 f"{v['parent']}, {len(bytes.fromhex(v['hex']))}, {offs[pid]} }},")
lines.append("};")
lines.append("")

# (m,t) lookup: rows m=7..22, cols t in {1,2,4,8,16,32}; 0 = no poly
lines.append("/* (m,t) -> poly id, rows m=7..22, cols t = 1,2,4,8,16,32; 0 = none. */")
lines.append("static const uint16_t bch_poly_by_mt[16][6] = {")
for m in range(7, 23):
    row = [lookup.get((m, t), 0) for t in TS]
    lines.append("    { " + ", ".join(f"0x{v:04x}" for v in row) + " },  /* m=" + str(m) + " */")
lines.append("};")
lines.append("")

# primitive polynomial per m (t=1 hex), as a uint32
lines.append("/* Primitive polynomial P_m for GF(2^m), as a uint32 (bit i = coeff of x^i).")
lines.append(" * This is the t=1 generator for that parent. */")
lines.append("static const uint32_t bch_prim_poly[23] = {")
for m in range(0, 23):
    if m in prim:
        lines.append(f"    0x{prim[m]:08x}u,  /* m={m} */")
    else:
        lines.append(f"    0u,  /* m={m} (unused) */")
lines.append("};")
lines.append("")
lines.append("#endif /* LZPLY_BCH_POLYS_H */")
lines.append("")

with open(OUT, "w") as f:
    f.write("\n".join(lines))
print(f"wrote {OUT} ({os.path.getsize(OUT)} bytes, "
      f"{len(allbytes)} generator bytes, {len(info)} polys)")
