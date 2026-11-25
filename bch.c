/* bch.c - binary BCH error correction for lzply.
 *
 * Systematic shortened primitive BCH over GF(2), using the 82
 * narrow-sense generators in bch_polys.h (m=7..22, t=1,2,4,8,16,32).
 *
 * ENCODER (remainder / CRC style). A block is D data bytes (k=8D bits)
 * plus r parity bits. The codeword polynomial C(x) = M(x)*x^r + P(x),
 * P(x) = (M(x)*x^r) mod g(x), so C(x) is divisible by g(x). The
 * remainder is computed by a table-driven LFSR (CRC-style): the register
 * is an r-bit value stored LEFT-ALIGNED in a byte array (top bit =
 * bit 7 of rem[0]); for each data byte b,
 *   rem = byteshift(rem) XOR T[rem[0] XOR b],
 * where T[u] = (u(x)*x^r) mod g(x). Feeding the data bytes alone yields
 * P(x) -- the LFSR inherently multiplies by x^r, so NO augmentation
 * (extra zero bits) is fed. The parity bytes ARE the remainder bytes
 * (the last byte's low bits are the zero padding).
 *
 * DECODER. Feed the received codeword (data bytes + r parity bits;
 * the final partial parity byte is fed bit-by-bit so the padding
 * bits are never fed) into the same LFSR, giving R = (E*x^r) mod g,
 * E = error polynomial. R==0 means no error. Otherwise the syndromes
 * are S_j = R(alpha^j) * alpha^(-j*r) for j=1..2t (valid because
 * g(alpha^j)=0, so R(alpha^j) = E(alpha^j)*alpha^(j*r)).
 * Berlekamp-Massey on S_1..S_2t gives the error-locator
 * Lambda(x) = prod (1 + X_p*x), X_p = alpha^(n-1-p) for an error at
 * bit position p (p=0 is the first stored bit, coefficient of
 * x^(n-1)). Chien search evaluates Lambda(alpha^(p-(n-1))) for
 * p=0..n-1; a zero means an error at p, and that bit is flipped.
 * After flipping, the LFSR remainder must be 0 again, else the block
 * is declared uncorrectable. The per-entry SHA-256 in lzply is the
 * final guard against any miscorrection.
 *
 * GF(2^m) arithmetic: elements are uint32_t (< 2^m). The primitive
 * polynomial P_m is the t=1 generator for that m (bch_prim_poly).
 * Multiply-by-alpha is a shift + conditional XOR with the low m bits
 * of P_m. General multiplication is shift-and-xor (used for the
 * syndrome/BM, which need few mults). Chien search needs many mults,
 * so it uses log/exp tables built on demand and cached per m.
 */
#include <stdlib.h>
#include <string.h>
#include "bch.h"

/* ------------------------------------------------------------------ */
/* polynomial lookup                                                   */
/* ------------------------------------------------------------------ */

const bch_poly_t *bch_poly_by_id(uint16_t id)
{
    for (int i = 0; i < BCH_NPOLYS; i++)
        if (bch_polys[i].id == id)
            return &bch_polys[i];
    return NULL;
}

static int t_index(int t)
{
    switch (t) {
    case 1:  return 0;
    case 2:  return 1;
    case 4:  return 2;
    case 8:  return 3;
    case 16: return 4;
    case 32: return 5;
    default: return -1;
    }
}

const bch_poly_t *bch_poly_for_data(size_t data_bytes, int t)
{
    int ti = t_index(t);
    if (ti < 0)
        return NULL;
    /* smallest m with a poly for (m,t) whose codeword can hold the data:
     * N >= 8*data_bytes + t*m. */
    for (int m = BCH_MIN_M; m <= BCH_MAX_M; m++) {
        uint16_t id = bch_poly_by_mt[m - BCH_MIN_M][ti];
        if (!id)
            continue;
        const bch_poly_t *p = bch_poly_by_id(id);
        uint64_t need = (uint64_t)8 * data_bytes + (uint64_t)t * m;
        if ((uint64_t)p->parent >= need)
            return p;
    }
    return NULL;
}

size_t bch_max_data(const bch_poly_t *p)
{
    /* floor((N - r)/8) data bytes fit in one codeword of this parent. */
    return (size_t)((p->parent - p->r) / 8);
}

size_t bch_block_stored_len(size_t data_len, const bch_poly_t *p)
{
    return data_len + (size_t)((p->r + 7) / 8);
}

size_t bch_encoded_len(size_t len, const bch_poly_t *p)
{
    size_t maxd = bch_max_data(p);
    if (len == 0)
        return bch_block_stored_len(0, p);
    size_t blocks = (len + maxd - 1) / maxd;
    size_t full = blocks - 1;
    size_t last = len - full * maxd;
    return full * bch_block_stored_len(maxd, p) + bch_block_stored_len(last, p);
}

int bch_t_for_level(int level)
{
    switch (level) {
    case 0: return 0;
    case 1: return 1;
    case 2: return 2;
    case 3: return 4;
    case 4: return 8;
    case 5: return 16;
    case 6: return 32;
    case 7: return 32;
    default: return -1;
    }
}

/* ------------------------------------------------------------------ */
/* remainder (table-driven LFSR)                                       */
/*                                                                     */
/* The remainder is an r-bit value stored LEFT-ALIGNED in rem[0..nb-1]:
 * bit (r-1) (coefficient of x^(r-1)) is bit 7 of rem[0]; bit i is at
 * byte (r-1-i)/8, bit 7-((r-1-i)%8). The low (nb*8-r) bits of the
 * last byte are always zero.                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    const bch_poly_t *p;
    int r;              /* parity bits */
    int nb;             /* remainder bytes = (r+7)/8 */
    uint8_t glow[89];   /* low r bits of g(x), left-aligned */
    uint8_t *table;     /* 256 * nb bytes: T[u] = (u(x)*x^r) mod g(x) */
} bch_ctx_t;

static void rem_set_bit(uint8_t *rem, int r, int i)
{
    int byte = (r - 1 - i) / 8;
    int bit = 7 - ((r - 1 - i) % 8);
    rem[byte] |= (uint8_t)(1u << bit);
}

/* (rem_get_bit removed: rem_eval iterates the bytes directly.) */

/* shift the left-aligned remainder left by one bit (top bit dropped). */
static void rem_shl1(uint8_t *rem, int nb)
{
    for (int i = 0; i < nb; i++)
        rem[i] = (uint8_t)((rem[i] << 1) | (i + 1 < nb ? (rem[i + 1] >> 7) : 0));
}

/* one bit-step of the LFSR: feed input bit m. */
static void rem_bitstep(uint8_t *rem, int m, const uint8_t *glow, int nb)
{
    int fb = ((rem[0] >> 7) & 1) ^ (m & 1);
    rem_shl1(rem, nb);
    if (fb)
        for (int i = 0; i < nb; i++)
            rem[i] ^= glow[i];
}

static bch_ctx_t *bch_ctx_new(const bch_poly_t *p)
{
    bch_ctx_t *c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->p = p;
    c->r = p->r;
    c->nb = (p->r + 7) / 8;
    c->table = malloc((size_t)256 * c->nb);
    if (!c->table) {
        free(c);
        return NULL;
    }
    /* glow: low r bits of g(x). Generator bytes are LSB-first:
     * gen[j] holds bits 8j..8j+7, so g_i = (gen[i/8] >> (i%8)) & 1. */
    const uint8_t *gen = bch_poly_bytes + p->off;
    for (int i = 0; i < p->r; i++) {
        if ((gen[i / 8] >> (i % 8)) & 1)
            rem_set_bit(c->glow, p->r, i);
    }
    /* T[u]: feed u's 8 bits (MSB first) into the LFSR from rem=0. */
    for (int u = 0; u < 256; u++) {
        uint8_t *t = c->table + (size_t)u * c->nb;
        memset(t, 0, c->nb);
        for (int b = 7; b >= 0; b--)
            rem_bitstep(t, (u >> b) & 1, c->glow, c->nb);
    }
    return c;
}

static void bch_ctx_free(bch_ctx_t *c)
{
    if (!c)
        return;
    free(c->table);
    free(c);
}

/* table-driven update: feed one whole byte into the remainder. */
static void rem_feed_byte(uint8_t *rem, uint8_t b, const bch_ctx_t *c)
{
    int idx = rem[0] ^ b;
    /* shift left by 8 bits (one byte) */
    for (int i = 0; i < c->nb - 1; i++)
        rem[i] = rem[i + 1];
    rem[c->nb - 1] = 0;
    const uint8_t *t = c->table + (size_t)idx * c->nb;
    for (int i = 0; i < c->nb; i++)
        rem[i] ^= t[i];
}

/* remainder of the data bytes alone (== parity P(x)). */
static void rem_of_data(const uint8_t *data, size_t len, const bch_ctx_t *c,
                        uint8_t *rem)
{
    memset(rem, 0, c->nb);
    for (size_t i = 0; i < len; i++)
        rem_feed_byte(rem, data[i], c);
}

/* remainder of a codeword: data bytes (whole) + parity bits (r bits).
 * The parity bits are the first r bits of the parity bytes (MSB first);
 * the padding bits in the final byte are never fed. */
static void rem_of_codeword(const uint8_t *data, size_t data_len,
                            const uint8_t *par, const bch_ctx_t *c,
                            uint8_t *rem)
{
    memset(rem, 0, c->nb);
    for (size_t i = 0; i < data_len; i++)
        rem_feed_byte(rem, data[i], c);
    int r = c->r;
    int whole = r / 8;
    for (int i = 0; i < whole; i++)
        rem_feed_byte(rem, par[i], c);
    for (int b = 7; b >= 8 - (r % 8) && (r % 8); b--)
        rem_bitstep(rem, (par[whole] >> b) & 1, c->glow, c->nb);
}

static int rem_is_zero(const uint8_t *rem, int nb)
{
    for (int i = 0; i < nb; i++)
        if (rem[i])
            return 0;
    return 1;
}

/* brute-force remainder: bit-by-bit long division of the data polynomial
 * (MSB first) by g(x). Used by the unit test to cross-check the table. */
int bch_remainder_bruteforce(const uint8_t *data, size_t data_len,
                             const bch_poly_t *p, uint8_t *rem_out)
{
    bch_ctx_t *c = bch_ctx_new(p);
    if (!c)
        return -1;
    uint8_t *rem = calloc(1, c->nb);
    if (!rem) {
        bch_ctx_free(c);
        return -1;
    }
    for (size_t i = 0; i < data_len; i++)
        for (int b = 7; b >= 0; b--)
            rem_bitstep(rem, (data[i] >> b) & 1, c->glow, c->nb);
    memcpy(rem_out, rem, c->nb);
    free(rem);
    bch_ctx_free(c);
    return 0;
}

/* ------------------------------------------------------------------ */
/* GF(2^m) arithmetic                                                  */
/* ------------------------------------------------------------------ */

static uint32_t gf_mul_slow(uint32_t a, uint32_t b, uint32_t P, int m)
{
    uint32_t mask = (m >= 32) ? 0xffffffffu : ((1u << m) - 1);
    uint32_t plow = P & mask;
    uint32_t r = 0;
    while (b) {
        if (b & 1)
            r ^= a;
        b >>= 1;
        uint32_t top = (a >> (m - 1)) & 1u;
        a = (a << 1) & mask;
        if (top)
            a ^= plow;
    }
    return r;
}

static uint32_t gf_mul_alpha(uint32_t a, uint32_t P, int m)
{
    uint32_t mask = (m >= 32) ? 0xffffffffu : ((1u << m) - 1);
    uint32_t top = (a >> (m - 1)) & 1u;
    a = (a << 1) & mask;
    if (top)
        a ^= (P & mask);
    return a;
}

static uint32_t gf_pow_slow(uint32_t a, uint32_t e, uint32_t P, int m)
{
    uint32_t r = 1;
    while (e) {
        if (e & 1)
            r = gf_mul_slow(r, a, P, m);
        a = gf_mul_slow(a, a, P, m);
        e >>= 1;
    }
    return r;
}

/* (gf_inv via the log/exp tables is used instead; see gf_div_tab.) */

/* log/exp tables, cached per m (single slot; lzply is single-threaded). */
typedef struct {
    int m;
    uint32_t N;         /* 2^m - 1 */
    uint32_t *exp;      /* exp[i] = alpha^i, i = 0..N-1 */
    uint32_t *log;      /* log[v] = i with alpha^i = v, v = 1..N-1 */
} gf_tables_t;

static gf_tables_t gf_cache = { 0, 0, NULL, NULL };

static const gf_tables_t *gf_tables_for(int m)
{
    if (gf_cache.m == m && gf_cache.exp)
        return &gf_cache;
    free(gf_cache.exp);
    free(gf_cache.log);
    gf_cache.m = 0;
    gf_cache.exp = NULL;
    gf_cache.log = NULL;
    uint32_t P = bch_prim_poly[m];
    uint32_t N = (1u << m) - 1;
    size_t sz = (size_t)1 << m;
    uint32_t *exp = malloc(sz * sizeof(uint32_t));
    uint32_t *log = malloc(sz * sizeof(uint32_t));
    if (!exp || !log) {
        free(exp);
        free(log);
        return NULL;
    }
    uint32_t x = 1;
    for (uint32_t i = 0; i < N; i++) {
        exp[i] = x;
        log[x] = i;
        x = gf_mul_alpha(x, P, m);
    }
    exp[N] = 1;
    log[0] = 0;
    gf_cache.m = m;
    gf_cache.N = N;
    gf_cache.exp = exp;
    gf_cache.log = log;
    return &gf_cache;
}

static uint32_t gf_mul_tab(uint32_t a, uint32_t b, const gf_tables_t *t)
{
    if (!a || !b)
        return 0;
    uint32_t s = t->log[a] + t->log[b];
    if (s >= t->N)
        s -= t->N;
    return t->exp[s];
}

static uint32_t gf_div_tab(uint32_t a, uint32_t b, const gf_tables_t *t)
{
    if (!a)
        return 0;
    int d = (int)t->log[a] - (int)t->log[b];
    if (d < 0)
        d += (int)t->N;
    return t->exp[d];
}

/* evaluate the remainder polynomial R(x) (left-aligned bytes, r bits)
 * at x = a, by Horner from the top coefficient down. */
static uint32_t rem_eval(const uint8_t *rem, int r, uint32_t a,
                         uint32_t P, int m)
{
    uint32_t res = 0;
    int seen = 0;
    for (int by = 0; by < (r + 7) / 8 && seen < r; by++) {
        for (int bi = 7; bi >= 0 && seen < r; bi--, seen++) {
            int coeff = (rem[by] >> bi) & 1;
            res = gf_mul_slow(res, a, P, m) ^ (uint32_t)coeff;
        }
    }
    return res;
}

/* ------------------------------------------------------------------ */
/* decoder                                                             */
/* ------------------------------------------------------------------ */

/* Berlekamp-Massey on S_1..S_2t. Returns the degree L and fills
 * lambda[0..L] (lambda[0]=1). Uses slow GF arithmetic. */
static int berlekamp_massey(const uint32_t *S, int t, uint32_t P, int m,
                            uint32_t *lambda)
{
    uint32_t C[33], B[33], T[33];
    for (int i = 0; i <= 32; i++)
        C[i] = B[i] = 0;
    C[0] = B[0] = 1;
    int L = 0, shift = 1;
    uint32_t b = 1;
    for (int n = 0; n < 2 * t; n++) {
        /* discrepancy d = S_{n+1} + sum_{i=1..L} C_i * S_{n+1-i} */
        uint32_t d = S[n];
        for (int i = 1; i <= L; i++) {
            if (C[i] && n - i >= 0)
                d ^= gf_mul_slow(C[i], S[n - i], P, m);
        }
        if (d == 0) {
            shift++;
            continue;
        }
        memcpy(T, C, sizeof(T));
        uint32_t coef = gf_div_tab(d, b, gf_tables_for(m));
        /* C = C + coef * x^shift * B */
        for (int i = 0; i <= 32 - shift; i++) {
            if (B[i])
                C[i + shift] ^= gf_mul_slow(coef, B[i], P, m);
        }
        if (2 * L <= n) {
            L = n + 1 - L;
            memcpy(B, T, sizeof(B));
            b = d;
            shift = 1;
        } else {
            shift++;
        }
    }
    for (int i = 0; i <= L; i++)
        lambda[i] = C[i];
    return L;
}

int bch_encode_block(const uint8_t *data, size_t data_len,
                     const bch_poly_t *p, uint8_t *out)
{
    bch_ctx_t *c = bch_ctx_new(p);
    if (!c)
        return -1;
    uint8_t *rem = malloc(c->nb);
    if (!rem) {
        bch_ctx_free(c);
        return -1;
    }
    rem_of_data(data, data_len, c, rem);
    memcpy(out, data, data_len);
    memcpy(out + data_len, rem, c->nb);
    free(rem);
    bch_ctx_free(c);
    return 0;
}

int bch_decode_block(const uint8_t *in, size_t in_len, size_t data_len,
                     const bch_poly_t *p, uint8_t *out, int *corrected)
{
    if (corrected)
        *corrected = 0;
    size_t stored = bch_block_stored_len(data_len, p);
    if (in_len != stored)
        return -1;
    int r = p->r, m = p->m, t = p->t;
    uint32_t P = bch_prim_poly[m];
    uint32_t N = (1u << m) - 1;
    size_t nbits = (size_t)8 * data_len + (size_t)r;
    int nb = (r + 7) / 8;

    bch_ctx_t *c = bch_ctx_new(p);
    if (!c)
        return -1;
    uint8_t *rem = malloc(nb);
    uint8_t *work = malloc(in_len);
    if (!rem || !work) {
        free(rem);
        free(work);
        bch_ctx_free(c);
        return -1;
    }
    memcpy(work, in, in_len);
    rem_of_codeword(work, data_len, work + data_len, c, rem);
    if (rem_is_zero(rem, nb)) {
        /* no errors */
        memcpy(out, work, data_len);
        free(rem);
        free(work);
        bch_ctx_free(c);
        return 0;
    }

    /* syndromes S_j = R(alpha^j) * alpha^(-j*r), j = 1..2t */
    const gf_tables_t *tab = gf_tables_for(m);
    if (!tab) {
        free(rem);
        free(work);
        bch_ctx_free(c);
        return -1;
    }
    uint32_t S[64];
    for (int j = 1; j <= 2 * t; j++) {
        uint32_t aj = tab->exp[j % N];
        uint32_t v = rem_eval(rem, r, aj, P, m);
        /* multiply by alpha^(-j*r) */
        uint32_t e = (uint32_t)(((uint64_t)j * (uint64_t)r) % N);
        uint32_t inv = (e == 0) ? 1 : tab->exp[N - e];
        S[j - 1] = gf_mul_tab(v, inv, tab);
    }

    uint32_t lambda[33];
    int L = berlekamp_massey(S, t, P, m, lambda);
    if (L <= 0 || L > t) {
        free(rem);
        free(work);
        bch_ctx_free(c);
        return -1;
    }

    /* Chien search, incremental: x_p = alpha^(p-(n-1)), p = 0..n-1.
     * Maintain v[j] = lambda[j] * x_p^j; lambda(x_p) = sum v[j].
     * Stop once L roots are found. */
    uint32_t x0 = tab->exp[(N - (nbits - 1) % N) % N]; /* alpha^-(n-1) */
    uint32_t v[33];
    for (int j = 0; j <= L; j++) {
        /* v[j] = lambda[j] * x0^j */
        v[j] = lambda[j] ? gf_mul_tab(lambda[j], gf_pow_slow(x0, (uint32_t)j, P, m), tab) : 0;
    }
    /* alpha^j for the per-step update */
    uint32_t ajpow[33];
    for (int j = 0; j <= L; j++)
        ajpow[j] = tab->exp[j % N];

    int found = 0;
    for (size_t p = 0; p < nbits && found < L; p++) {
        uint32_t sum = 0;
        for (int j = 0; j <= L; j++)
            sum ^= v[j];
        if (sum == 0) {
            /* error at bit position p: flip it in work */
            size_t byte = p / 8;
            int bit = 7 - (int)(p % 8);
            work[byte] ^= (uint8_t)(1u << bit);
            found++;
        }
        /* advance to p+1: v[j] *= alpha^j */
        for (int j = 1; j <= L; j++)
            if (v[j])
                v[j] = gf_mul_tab(v[j], ajpow[j], tab);
    }
    if (found != L) {
        free(rem);
        free(work);
        bch_ctx_free(c);
        return -1;
    }
    if (corrected)
        *corrected = found;

    /* verify: the corrected codeword must have zero remainder */
    rem_of_codeword(work, data_len, work + data_len, c, rem);
    if (!rem_is_zero(rem, nb)) {
        free(rem);
        free(work);
        bch_ctx_free(c);
        return -1;
    }
    memcpy(out, work, data_len);
    free(rem);
    free(work);
    bch_ctx_free(c);
    return 0;
}

/* ------------------------------------------------------------------ */
/* whole-blob encode / decode                                          */
/* ------------------------------------------------------------------ */

size_t bch_encode(const uint8_t *data, size_t len, const bch_poly_t *p,
                  uint8_t *out)
{
    size_t maxd = bch_max_data(p);
    size_t off = 0, woff = 0;
    if (len == 0) {
        bch_encode_block(data, 0, p, out);
        return bch_block_stored_len(0, p);
    }
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > maxd)
            chunk = maxd;
        bch_encode_block(data + off, chunk, p, out + woff);
        woff += bch_block_stored_len(chunk, p);
        off += chunk;
    }
    return woff;
}

int bch_decode(const uint8_t *in, size_t len, size_t orig_len,
               const bch_poly_t *p, uint8_t *out, int *corrected)
{
    if (corrected)
        *corrected = 0;
    size_t maxd = bch_max_data(p);
    size_t off = 0, roff = 0;
    int total = 0;
    if (orig_len == 0) {
        if (len != bch_block_stored_len(0, p))
            return -1;
        int c1 = 0;
        if (bch_decode_block(in, len, 0, p, out, &c1) != 0)
            return -1;
        if (corrected)
            *corrected = c1;
        return 0;
    }
    while (off < orig_len) {
        size_t chunk = orig_len - off;
        if (chunk > maxd)
            chunk = maxd;
        size_t slen = bch_block_stored_len(chunk, p);
        if (roff + slen > len)
            return -1;
        int c1 = 0;
        if (bch_decode_block(in + roff, slen, chunk, p, out + off, &c1) != 0)
            return -1;
        total += c1;
        roff += slen;
        off += chunk;
    }
    if (roff != len)
        return -1;
    if (corrected)
        *corrected = total;
    return 0;
}
