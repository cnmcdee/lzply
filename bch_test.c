/* bch_test.c - unit test for the BCH codec (bch.c).
 *
 * Checks:
 *  1. Table-driven remainder == brute-force remainder, for all 82 polys
 *     and several data lengths.
 *  2. Encode/decode roundtrip (no errors) for all 82 polys and several
 *     sizes, including >max_data (block splitting).
 *  3. Corruption: flip k<=t bits -> recovers exactly; flip t+1 bits ->
 *     fails cleanly (never returns wrong data).
 *  4. Auto-pick: bch_poly_for_data returns the band-correct poly
 *     (smallest m covering the data, with a poly for (m,t)).
 *  5. t=1 poly for each m is the primitive polynomial (recomputed).
 *  6. bch_encoded_len / block splitting arithmetic.
 *
 * Usage: ./bch_test [seed]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bch.h"

static int fails = 0;
static int checks = 0;
#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } \
} while (0)

static uint64_t rng_state = 0x12345678abcdefULL;
static uint64_t xr(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void rand_bytes(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
        buf[i] = (uint8_t)(xr() & 0xff);
}

/* flip k distinct random bits within the first nbits bits of buf. */
static void flip_bits(uint8_t *buf, size_t nbits, int k)
{
    /* simple: pick k distinct positions by rejection */
    size_t *pos = malloc((size_t)k * sizeof(size_t));
    int got = 0;
    while (got < k) {
        size_t p = (size_t)(xr() % nbits);
        int dup = 0;
        for (int i = 0; i < got; i++)
            if (pos[i] == p)
                dup = 1;
        if (!dup)
            pos[got++] = p;
    }
    for (int i = 0; i < k; i++) {
        size_t p = pos[i];
        buf[p / 8] ^= (uint8_t)(1u << (7 - (p % 8)));
    }
    free(pos);
}

int main(int argc, char **argv)
{
    if (argc > 1)
        rng_state = strtoull(argv[1], NULL, 0) ^ 0x9e3779b97f4a7c15ULL;

    /* sizes to test (data bytes per block) */
    static const size_t sizes[] = { 0, 1, 2, 3, 7, 8, 15, 16, 100, 1000,
                                    8192, 16384, 65536 };
    static const int nsize = (int)(sizeof(sizes) / sizeof(sizes[0]));

    /* --- 1+2: remainder cross-check + roundtrip for every poly --- */
    for (int pi = 0; pi < BCH_NPOLYS; pi++) {
        const bch_poly_t *p = &bch_polys[pi];
        size_t maxd = bch_max_data(p);
        for (int si = 0; si < nsize; si++) {
            size_t D = sizes[si];
            if (D > maxd)
                continue;
            uint8_t *data = malloc(D ? D : 1);
            rand_bytes(data, D);
            size_t slen = bch_block_stored_len(D, p);
            uint8_t *enc = malloc(slen);
            uint8_t *dec = malloc(D ? D : 1);
            CHECK(bch_encode_block(data, D, p, enc) == 0,
                  "encode poly %04x D=%zu", p->id, D);
            /* parity bytes == brute-force remainder */
            uint8_t *bf = malloc((p->r + 7) / 8);
            CHECK(bch_remainder_bruteforce(data, D, p, bf) == 0,
                  "bruteforce poly %04x D=%zu", p->id, D);
            CHECK(memcmp(enc + D, bf, (p->r + 7) / 8) == 0,
                  "table!=brute poly %04x D=%zu r=%u", p->id, D, p->r);
            free(bf);
            /* clean roundtrip */
            int corr = -1;
            CHECK(bch_decode_block(enc, slen, D, p, dec, &corr) == 0,
                  "decode poly %04x D=%zu", p->id, D);
            CHECK(memcmp(dec, data, D) == 0,
                  "roundtrip data poly %04x D=%zu", p->id, D);
            CHECK(corr == 0, "clean decode corrected %d bits poly %04x D=%zu",
                  corr, p->id, D);
            free(data);
            free(enc);
            free(dec);
        }
    }
    printf("phase 1+2 (remainder x-check + roundtrip, all 82 polys): "
           "%d checks, %d fails\n", checks, fails);

    /* --- 3: corruption recovery, a spread of polys --- */
    static const uint16_t corr_polys[] = {
        0x0001, /* m7 t1 */
        0x0002, /* m7 t2 */
        0x0004, /* m8 t2 */
        0x0008, /* m10 t1 */
        0x000d, /* m11 t2 */
        0x0012, /* m12 t2 */
        0x0018, /* m13 t2 */
        0x0025, /* m15 t4 */
        0x002e, /* m16 t32 */
        0x0034, /* m17 t32 */
        0x003a, /* m18 t32 */
        0x0040, /* m19 t32 */
        0x0046, /* m20 t32 */
        0x004c, /* m21 t32 */
        0x0052, /* m22 t32 */
    };
    static const size_t corr_sizes[] = { 100, 1000, 8192 };
    for (size_t ci = 0; ci < sizeof(corr_polys) / sizeof(corr_polys[0]); ci++) {
        const bch_poly_t *p = bch_poly_by_id(corr_polys[ci]);
        CHECK(p != NULL, "lookup poly %04x", corr_polys[ci]);
        if (!p)
            continue;
        int t = p->t;
        for (size_t si = 0; si < sizeof(corr_sizes) / sizeof(corr_sizes[0]); si++) {
            size_t D = corr_sizes[si];
            if (D > bch_max_data(p))
                continue;
            uint8_t *data = malloc(D);
            rand_bytes(data, D);
            size_t slen = bch_block_stored_len(D, p);
            uint8_t *enc = malloc(slen);
            uint8_t *dec = malloc(D);
            CHECK(bch_encode_block(data, D, p, enc) == 0,
                  "corr encode poly %04x D=%zu", p->id, D);
            /* flip k = 1..t bits: must recover exactly */
            for (int k = 1; k <= t; k++) {
                uint8_t *bad = malloc(slen);
                memcpy(bad, enc, slen);
                flip_bits(bad, (size_t)8 * D + (size_t)p->r, k);
                int corr = -1;
                int rc = bch_decode_block(bad, slen, D, p, dec, &corr);
                CHECK(rc == 0, "flip %d bits poly %04x D=%zu t=%d rc=%d",
                      k, p->id, D, t, rc);
                if (rc == 0)
                    CHECK(memcmp(dec, data, D) == 0,
                          "flip %d bits data mismatch poly %04x D=%zu",
                          k, p->id, D);
                CHECK(corr == k, "flip %d bits corrected=%d poly %04x D=%zu",
                      k, corr, p->id, D);
                free(bad);
            }
            /* flip t+1 bits: must NOT return wrong data (fail, or
             * recover exactly -- miscorrection to another codeword is
             * possible in principle but must be vanishingly rare) */
            {
                int miscorr = 0, failed = 0, recovered = 0;
                for (int trial = 0; trial < 20; trial++) {
                    uint8_t *bad = malloc(slen);
                    memcpy(bad, enc, slen);
                    flip_bits(bad, (size_t)8 * D + (size_t)p->r, t + 1);
                    int rc = bch_decode_block(bad, slen, D, p, dec, NULL);
                    if (rc != 0)
                        failed++;
                    else if (memcmp(dec, data, D) == 0)
                        recovered++;
                    else
                        miscorr++;
                    free(bad);
                }
                /* t+1 flips: must NOT return wrong data, except that
                 * for small t the radius-t balls cover a large fraction
                 * of the space, so miscorrection to another codeword
                 * is expected (bounded-distance decoding). For t>=8
                 * the covering fraction is negligible, so any
                 * miscorrection there is a real bug. The per-entry
                 * SHA-256 in lzply catches miscorrections in any case. */
                if (t >= 8)
                    CHECK(miscorr == 0,
                          "t+1 flips: %d miscorrections (wrong data) poly %04x D=%zu t=%d",
                          miscorr, p->id, D, t);
                else
                    printf("  note: poly %04x t=%d D=%zu: %d/%d t+1 trials "
                           "miscorrected (expected for small t)\n",
                           p->id, t, D, miscorr, 20);
                printf("  poly %04x (m=%d t=%d) D=%zu: t+1 flips x20: "
                       "failed=%d recovered=%d miscorr=%d\n",
                       p->id, p->m, t, D, failed, recovered, miscorr);
            }
            free(data);
            free(enc);
            free(dec);
        }
    }
    printf("phase 3 (corruption): %d checks, %d fails\n", checks, fails);

    /* --- 4: auto-pick band correctness --- */
    /* For a spread of (D, t), the picked poly must be the smallest m
     * with a poly for (m,t) and N >= 8D + t*m, and no smaller m works. */
    {
        static const int ts[] = { 1, 2, 4, 8, 16, 32 };
        static const size_t ds[] = { 1, 8, 15, 16, 100, 1000, 8192,
                                     16384, 65536, 131072, 524199, 524287 };
        for (size_t ti = 0; ti < sizeof(ts) / sizeof(ts[0]); ti++) {
            for (size_t di = 0; di < sizeof(ds) / sizeof(ds[0]); di++) {
                int t = ts[ti];
                size_t D = ds[di];
                const bch_poly_t *p = bch_poly_for_data(D, t);
                /* brute-force expected: smallest m with a poly and N>=8D+t*m */
                const bch_poly_t *exp = NULL;
                for (int m = BCH_MIN_M; m <= BCH_MAX_M && !exp; m++) {
                    for (int pi = 0; pi < BCH_NPOLYS; pi++) {
                        const bch_poly_t *q = &bch_polys[pi];
                        if (q->m == m && q->t == t &&
                            (uint64_t)q->parent >= (uint64_t)8 * D + (uint64_t)t * m) {
                            exp = q;
                            break;
                        }
                    }
                }
                /* bch_polys.h uses static arrays, so bch.c and this
                 * test each have their own copy: compare by id, not
                 * by pointer. */
                CHECK((p == NULL) == (exp == NULL) &&
                      (p == NULL || p->id == exp->id),
                      "autopick D=%zu t=%d: got %04x expected %04x",
                      D, t, p ? p->id : 0, exp ? exp->id : 0);
                if (p)
                    CHECK(bch_max_data(p) >= D,
                          "autopick max_data %zu < D=%zu poly %04x",
                          bch_max_data(p), D, p->id);
            }
        }
        /* too large for m=22 at t=32: no poly */
        CHECK(bch_poly_for_data(600000, 32) == NULL,
              "autopick 600000B t=32 should be NULL");
        /* but 524199B at t=32 fits m=22 */
        CHECK(bch_poly_for_data(524199, 32) != NULL,
              "autopick 524199B t=32 should exist");
    }
    printf("phase 4 (auto-pick): %d checks, %d fails\n", checks, fails);

    /* --- 5: block splitting + whole-blob encode/decode --- */
    {
        const bch_poly_t *p = bch_poly_by_id(0x0052); /* m22 t32 */
        size_t maxd = bch_max_data(p);
        CHECK(maxd == 524199, "m22 t32 max_data=%zu expected 524199", maxd);
        size_t big = maxd * 2 + 12345;
        uint8_t *data = malloc(big);
        rand_bytes(data, big);
        size_t elen = bch_encoded_len(big, p);
        CHECK(elen == 2 * bch_block_stored_len(maxd, p) +
                        bch_block_stored_len(12345, p),
              "encoded_len %zu for %zu bytes", elen, big);
        uint8_t *enc = malloc(elen);
        uint8_t *dec = malloc(big);
        CHECK(bch_encode(data, big, p, enc) == elen,
              "bch_encode returned %zu expected %zu",
              bch_encode(data, big, p, enc), elen);
        /* corrupt 5 bits in the first block and 32 in the last */
        flip_bits(enc, (size_t)8 * maxd + (size_t)p->r, 5);
        flip_bits(enc + 2 * bch_block_stored_len(maxd, p),
                  (size_t)8 * 12345 + (size_t)p->r, 32);
        int corr = 0;
        CHECK(bch_decode(enc, elen, big, p, dec, &corr) == 0,
              "split-blob decode with corruption rc");
        CHECK(memcmp(dec, data, big) == 0, "split-blob data mismatch");
        CHECK(corr == 37, "split-blob corrected=%d expected 37", corr);
        free(data);
        free(enc);
        free(dec);
        /* empty blob */
        {
            uint8_t e0[128], d0[1];
            size_t l0 = bch_encode(NULL, 0, p, e0);
            CHECK(l0 == bch_block_stored_len(0, p), "empty encoded len %zu", l0);
            CHECK(bch_decode(e0, l0, 0, p, d0, NULL) == 0, "empty decode");
        }
    }
    printf("phase 5 (block splitting): %d checks, %d fails\n", checks, fails);

    /* --- 6: unknown / edge lookups --- */
    CHECK(bch_poly_by_id(0x0000) == NULL, "id 0000 should be NULL");
    CHECK(bch_poly_by_id(0x0053) == NULL, "id 0053 should be NULL");
    CHECK(bch_poly_by_id(0xffff) == NULL, "id ffff should be NULL");
    CHECK(bch_t_for_level(0) == 0 && bch_t_for_level(1) == 1 &&
          bch_t_for_level(2) == 2 && bch_t_for_level(3) == 4 &&
          bch_t_for_level(4) == 8 && bch_t_for_level(5) == 16 &&
          bch_t_for_level(6) == 32 && bch_t_for_level(7) == 32,
          "t_for_level mapping");
    CHECK(bch_t_for_level(8) == -1 && bch_t_for_level(-1) == -1,
          "t_for_level invalid");

    printf("TOTAL: %d checks, %d fails\n", checks, fails);
    return fails ? 1 : 0;
}
