/* lzply_hyper.c - striped volume with bit-plane striping and multi-stripe-loss recovery.
 *
 * A user-space striped volume, RAID-0 style but recoverable:
 *   - 8 data stripes, bit-plane: byte i splits into its 8 bits, bit j
 *     goes to stripe j. Stripe j holds one bit of every byte, packed.
 *     No compression anywhere. Write speed is not a constraint;
 *     read speed is the priority.
 *   - Stripe-loss layer (required): independent parity stripes P, Q, R.
 *     P = XOR across the 8 data stripes (recovers 1 lost stripe).
 *     Q = GF(256) weighted parity (recovers a 2nd lost stripe, RAID-6 style).
 *     R = GF(256) weighted parity with different coefficients (recovers
 *     a 3rd lost stripe). 1 parity -> 1 loss, 2 parities -> 2 losses,
 *     3 parities -> 3 losses. The parities are INDEPENDENT, not mirrors.
 *   - Bit-rot layer: BCH parity over the whole file, using the config's
 *     poly + error level (reuses bch.c). SHA-256 over the file for
 *     verification (reuses sha256.c).
 *
 * Config file (-c config.txt), one entry per line:
 *   stripe:<label>:<file>:<rw>:<size>
 *   parity:<label>:<file>:<rw>:<poly>:<error_level>
 *   rw = read-write, ro = read-only. size = capacity, K/M/G suffixes.
 *   poly is authoritative; error_level must agree with it
 *   (bch_t_for_level). 8 data stripes (bit-plane fixes the count),
 *   1..3 parity stripes.
 *
 * Commands (lzply_hyper -c config.txt <command>):
 *   -init [--force]   create the stripe/parity files (checks dirs,
 *                     writability, free space; refuses to overwrite
 *                     existing files without --force)
 *   write <file> [name]  stripe a file into the volume
 *   read <name> <out>    read a file back (fast path; rebuilds a dead
 *                     stripe via parity if needed; verifies SHA-256)
 *   list              list files in the volume
 *   check <name>      verify a file (XOR + BCH + SHA-256, no output)
 *   -rebuild          rebuild lost/corrupt stripes from parity
 *
 * Exit codes: 0 ok, 1 usage, 2 I/O error, 3 corrupt/unrecoverable.
 * (Matches the lzply family convention.)
 */
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include "bch.h"
#include "sha256.h"

#define HYPER_NSTRIPES 8
#define HYPER_MAXPAR 3
#define HYPER_BURST (64u * 1024u)   /* I/O burst size */
#define HYPER_MAXNAME 255

#define EXIT_OK 0
#define EXIT_USAGE 1
#define EXIT_IO 2
#define EXIT_CORRUPT 3

static const char *prog = "lzply_hyper";

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", prog);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(EXIT_IO);
}

static void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        die("out of memory");
    return p;
}

static void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p)
        die("out of memory");
    return p;
}

static void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q)
        die("out of memory");
    return q;
}

static char *xstrdup(const char *s)
{
    char *p = strdup(s);
    if (!p)
        die("out of memory");
    return p;
}

/* CRC-32 (IEEE, poly 0xEDB88320), table built on first use. */
static uint32_t crc32_table[256];
static int crc32_ready = 0;

static void crc32_init(void)
{
    if (crc32_ready)
        return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_ready = 1;
}

static uint32_t hyper_crc32(const uint8_t *buf, size_t len)
{
    crc32_init();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = crc32_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* little-endian helpers */
static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)((v >> (8 * i)) & 0xFF);
}

static uint16_t get_u16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* Parse a size with optional K/M/G suffix (1024-based). Returns 0 on error. */
static int parse_size(const char *s, uint64_t *out)
{
    if (!s || !*s)
        return 0;
    char *end;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s)
        return 0;
    uint64_t mult = 1;
    if (*end) {
        char c = (char)toupper((unsigned char)*end);
        if (c == 'K')
            mult = 1024ULL;
        else if (c == 'M')
            mult = 1024ULL * 1024ULL;
        else if (c == 'G')
            mult = 1024ULL * 1024ULL * 1024ULL;
        else
            return 0;
        end++;
        if (*end == 'B' || *end == 'b')
            end++;
        if (*end)
            return 0;
    }
    if (v > UINT64_MAX / mult)
        return 0;
    *out = v * mult;
    return *out > 0;
}

/* Parse a poly id like lzply's poly= : hex if it has a-f digits or a
 * 0x prefix, else decimal. Returns 0 on error. */
/* Poly ids in the config are hex, as written in the design and the
 * polynomial tables (0044 = m=20, t=8; 003a = m=18, t=32). An
 * optional 0x prefix is accepted. */
static int parse_poly_id(const char *s, uint16_t *out)
{
    if (!s || !*s)
        return 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    if (!*s)
        return 0;
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 16);
    if (errno || end == s || *end || v > 0xFFFF)
        return 0;
    *out = (uint16_t)v;
    return 1;
}

static void hex32(const uint8_t *b, char *out)
{
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i] = h[b[i] >> 4];
        out[2 * i + 1] = h[b[i] & 0xF];
    }
    out[64] = '\0';
}

/* ------------------------------------------------------------------ */
/* GF(256) arithmetic (primitive poly 0x11d, generator 2)               */
/* ------------------------------------------------------------------ */

static uint8_t gf256_exp[512];
static uint8_t gf256_log[256];
static int gf256_ready = 0;

static void gf256_init(void)
{
    if (gf256_ready)
        return;
    int x = 1;
    for (int i = 0; i < 255; i++) {
        gf256_exp[i] = (uint8_t)x;
        gf256_log[x] = (uint8_t)i;
        x <<= 1;
        if (x & 0x100)
            x ^= 0x11D;
    }
    for (int i = 255; i < 512; i++)
        gf256_exp[i] = gf256_exp[i - 255];
    gf256_ready = 1;
}

static uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    if (a == 0 || b == 0)
        return 0;
    gf256_init();
    return gf256_exp[gf256_log[a] + gf256_log[b]];
}

static uint8_t gf256_inv(uint8_t a)
{
    if (a == 0)
        return 0;
    gf256_init();
    return gf256_exp[255 - gf256_log[a]];
}

/* g^e in GF(256), e any integer (reduced mod 255). */
static uint8_t gf256_pow2(int e)
{
    gf256_init();
    e %= 255;
    if (e < 0)
        e += 255;
    return gf256_exp[e];
}

/* ------------------------------------------------------------------ */
/* 8x8 bit-matrix transpose (SWAR).                                    */
/*                                                                     */
/* Input: 8 bytes a[0..7] packed little-endian into a uint64 (a[0] in */
/* the lowest byte). Output: 8 bytes b[0..7] where b[j] bit p =       */
/* a[p] bit j. The transpose is an involution, so the same function    */
/* converts file bytes -> stripe bytes (write) and stripe bytes ->     */
/* file bytes (read). The test suite checks the on-disk layout      */
/* against hand-computed values (tests/run_hyper_tests.sh).           */
/* ------------------------------------------------------------------ */

static uint64_t transpose8x8(uint64_t x)
{
    uint64_t t;
    t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AAULL;
    x = x ^ t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCCULL;
    x = x ^ t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0ULL;
    x = x ^ t ^ (t << 28);
    return x;
}

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */

typedef struct {
    char label[64];
    char path[1024];
    int rw; /* 1 = rw, 0 = ro */
    uint64_t size; /* capacity bytes (stripes only) */
} hyper_stripe_t;

typedef struct {
    char label[64];
    char path[1024];
    int rw; /* 1 = rw, 0 = ro */
    uint16_t poly_id;
    int level; /* error_level 0..7 */
    const bch_poly_t *poly;
} hyper_parity_t;

typedef struct {
    hyper_stripe_t stripes[HYPER_NSTRIPES];
    int nstripes;
    hyper_parity_t parities[HYPER_MAXPAR];
    int nparities;
    const bch_poly_t *poly; /* from the first parity line */
    int t;
    char path[1024]; /* config file path (for messages) */
} hyper_cfg_t;

static void cfg_error(hyper_cfg_t *cfg, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: %s: ", prog, cfg->path);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(EXIT_USAGE);
}

/* Split a line on ':' into fields. Returns field count, or -1 on error.
 * fields[] gets pointers into a copy of the line. */
static int split_fields(char *line, char **fields, int maxf)
{
    int n = 0;
    char *p = line;
    while (1) {
        if (n >= maxf)
            return -1;
        fields[n++] = p;
        char *c = strchr(p, ':');
        if (!c)
            break;
        *c = '\0';
        p = c + 1;
    }
    return n;
}

static int parse_cfg(const char *path, hyper_cfg_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->path, sizeof(cfg->path), "%s", path);
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "%s: cannot open config %s: %s\n", prog, path,
                strerror(errno));
        return -1;
    }
    char line[4096];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        /* strip trailing newline / CR */
        size_t L = strlen(line);
        while (L && (line[L - 1] == '\n' || line[L - 1] == '\r'))
            line[--L] = '\0';
        /* skip blank lines and comments */
        char *s = line;
        while (*s == ' ' || *s == '\t')
            s++;
        if (!*s || *s == '#')
            continue;
        char *fields[8];
        int nf = split_fields(s, fields, 8);
        if (nf < 0) {
            fclose(f);
            cfg_error(cfg, "line %d: too many fields", lineno);
        }
        if (strcmp(fields[0], "stripe") == 0) {
            if (nf != 5) {
                fclose(f);
                cfg_error(cfg, "line %d: stripe needs 5 fields "
                               "(stripe:label:file:rw:size)", lineno);
            }
            if (cfg->nstripes >= HYPER_NSTRIPES) {
                fclose(f);
                cfg_error(cfg, "line %d: too many data stripes "
                               "(bit-plane layout fixes the count at 8)",
                          lineno);
            }
            hyper_stripe_t *st = &cfg->stripes[cfg->nstripes];
            if (strlen(fields[1]) == 0 || strlen(fields[1]) >= sizeof(st->label)) {
                fclose(f);
                cfg_error(cfg, "line %d: bad stripe label", lineno);
            }
            snprintf(st->label, sizeof(st->label), "%s", fields[1]);
            if (strlen(fields[2]) == 0 || strlen(fields[2]) >= sizeof(st->path)) {
                fclose(f);
                cfg_error(cfg, "line %d: bad stripe file path", lineno);
            }
            snprintf(st->path, sizeof(st->path), "%s", fields[2]);
            if (strcmp(fields[3], "rw") == 0)
                st->rw = 1;
            else if (strcmp(fields[3], "ro") == 0)
                st->rw = 0;
            else {
                fclose(f);
                cfg_error(cfg, "line %d: rw field must be rw or ro", lineno);
            }
            if (!parse_size(fields[4], &st->size)) {
                fclose(f);
                cfg_error(cfg, "line %d: bad stripe size '%s'", lineno, fields[4]);
            }
            cfg->nstripes++;
        } else if (strcmp(fields[0], "parity") == 0) {
            if (nf != 6) {
                fclose(f);
                cfg_error(cfg, "line %d: parity needs 6 fields "
                               "(parity:label:file:rw:poly:error_level)", lineno);
            }
            if (cfg->nparities >= HYPER_MAXPAR) {
                fclose(f);
                cfg_error(cfg, "line %d: too many parity stripes "
                               "(v1 supports at most 3)", lineno);
            }
            hyper_parity_t *pa = &cfg->parities[cfg->nparities];
            if (strlen(fields[1]) == 0 || strlen(fields[1]) >= sizeof(pa->label)) {
                fclose(f);
                cfg_error(cfg, "line %d: bad parity label", lineno);
            }
            snprintf(pa->label, sizeof(pa->label), "%s", fields[1]);
            if (strlen(fields[2]) == 0 || strlen(fields[2]) >= sizeof(pa->path)) {
                fclose(f);
                cfg_error(cfg, "line %d: bad parity file path", lineno);
            }
            snprintf(pa->path, sizeof(pa->path), "%s", fields[2]);
            if (strcmp(fields[3], "rw") == 0)
                pa->rw = 1;
            else if (strcmp(fields[3], "ro") == 0)
                pa->rw = 0;
            else {
                fclose(f);
                cfg_error(cfg, "line %d: rw field must be rw or ro", lineno);
            }
            uint16_t pid;
            if (!parse_poly_id(fields[4], &pid)) {
                fclose(f);
                cfg_error(cfg, "line %d: bad polynomial id '%s'", lineno, fields[4]);
            }
            const bch_poly_t *poly = bch_poly_by_id(pid);
            if (!poly) {
                fclose(f);
                cfg_error(cfg, "line %d: unknown polynomial id 0x%04x", lineno, pid);
            }
            char *end;
            errno = 0;
            long lvl = strtol(fields[5], &end, 10);
            if (errno || end == fields[5] || *end || lvl < 0 || lvl > 7) {
                fclose(f);
                cfg_error(cfg, "line %d: bad error_level '%s' (0..7)", lineno, fields[5]);
            }
            int t = bch_t_for_level((int)lvl);
            if (t < 0 || t != poly->t) {
                fclose(f);
                cfg_error(cfg, "line %d: error_level %ld (t=%d) does not "
                               "agree with poly 0x%04x (t=%d)", lineno, lvl, t,
                          pid, poly->t);
            }
            pa->poly_id = pid;
            pa->level = (int)lvl;
            pa->poly = poly;
            cfg->nparities++;
        } else {
            fclose(f);
            cfg_error(cfg, "line %d: unknown entry type '%s' (stripe or parity)",
                      lineno, fields[0]);
        }
    }
    fclose(f);
    if (cfg->nstripes != HYPER_NSTRIPES) {
        cfg_error(cfg, "need exactly 8 data stripes (bit-plane layout), "
                       "config has %d", cfg->nstripes);
    }
    if (cfg->nparities < 1) {
        cfg_error(cfg, "need at least 1 parity stripe");
    }
    /* labels must be unique across all entries */
    for (int i = 0; i < cfg->nstripes; i++) {
        for (int j = i + 1; j < cfg->nstripes; j++) {
            if (strcmp(cfg->stripes[i].label, cfg->stripes[j].label) == 0)
                cfg_error(cfg, "duplicate label '%s'", cfg->stripes[i].label);
        }
        for (int j = 0; j < cfg->nparities; j++) {
            if (strcmp(cfg->stripes[i].label, cfg->parities[j].label) == 0)
                cfg_error(cfg, "duplicate label '%s'", cfg->stripes[i].label);
        }
    }
    for (int i = 0; i < cfg->nparities; i++) {
        for (int j = i + 1; j < cfg->nparities; j++) {
            if (strcmp(cfg->parities[i].label, cfg->parities[j].label) == 0)
                cfg_error(cfg, "duplicate label '%s'", cfg->parities[i].label);
        }
    }
    /* all parity lines must agree on poly + error level; the first
     * parity line is authoritative */
    cfg->poly = cfg->parities[0].poly;
    cfg->t = cfg->parities[0].poly->t;
    for (int i = 1; i < cfg->nparities; i++) {
        if (cfg->parities[i].poly_id != cfg->parities[0].poly_id ||
            cfg->parities[i].level != cfg->parities[0].level) {
            cfg_error(cfg, "parity lines disagree on poly/error_level "
                           "(%s has 0x%04x:%d, %s has 0x%04x:%d)",
                      cfg->parities[0].label, cfg->parities[0].poly_id,
                      cfg->parities[0].level, cfg->parities[i].label,
                      cfg->parities[i].poly_id, cfg->parities[i].level);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Parity record format                                                */
/*                                                                     */
/* Each parity stripe file is a sequence of records, one per file in  */
/* the volume, appended in write order. Each record holds: a fixed    */
/* 96-byte header, the file name, that parity stripe's parity bytes   */
/* (P, Q or R for this record), and the BCH parity bytes (same on    */
/* every parity stripe). The header carries everything needed to     */
/* find and verify the file: name, original length, stripe offset    */
/* and length, poly, t, parity lengths, SHA-256 of the original.     */
/*                                                                     */
/* Header (96 bytes, little-endian):                                   */
/*   0  magic[4] "HYPR"                                               */
/*   4  version u8 = 1                                                */
/*   5  parity_idx u8 (0=P, 1=Q, 2=R)                                 */
/*   6  flags u8 (0)                                                  */
/*   7  reserved u8                                                   */
/*   8  name_len u16                                                  */
/*  10  poly_id u16                                                   */
/*  12  t u8                                                          */
/*  13  npar u8 (parity stripes in the volume)                        */
/*  14  reserved u16                                                  */
/*  16  orig_len u64                                                  */
/*  24  stripe_off u64 (offset in stripe files)                       */
/*  32  stripe_len u64 (bytes per stripe = ceil(orig_len/8))          */
/*  40  parity_len u64 (= stripe_len)                                 */
/*  48  bch_len u64                                                   */
/*  56  sha256[32]                                                    */
/*  88  header_crc32 u32 (covers bytes 0..87)                         */
/*  92  reserved u32                                                  */
/* Then: name[name_len], parity[parity_len], bch[bch_len].             */
/* ------------------------------------------------------------------ */

#define HYPER_HDR_LEN 96
#define HYPER_MAGIC "HYPR"

typedef struct {
    uint8_t parity_idx;
    uint16_t name_len;
    uint16_t poly_id;
    uint8_t t;
    uint8_t npar;
    uint64_t orig_len;
    uint64_t stripe_off;
    uint64_t stripe_len;
    uint64_t parity_len;
    uint64_t bch_len;
    uint8_t sha256[32];
    char name[HYPER_MAXNAME + 1];
    uint64_t rec_off; /* file offset of this record in its parity stripe */
} hyper_rec_t;

static void hyper_rec_pack(const hyper_rec_t *r, uint8_t *h)
{
    memset(h, 0, HYPER_HDR_LEN);
    memcpy(h, HYPER_MAGIC, 4);
    h[4] = 1;
    h[5] = r->parity_idx;
    h[6] = 0;
    h[7] = 0;
    put_u16(h + 8, r->name_len);
    put_u16(h + 10, r->poly_id);
    h[12] = r->t;
    h[13] = r->npar;
    put_u16(h + 14, 0);
    put_u64(h + 16, r->orig_len);
    put_u64(h + 24, r->stripe_off);
    put_u64(h + 32, r->stripe_len);
    put_u64(h + 40, r->parity_len);
    put_u64(h + 48, r->bch_len);
    memcpy(h + 56, r->sha256, 32);
    put_u32(h + 88, hyper_crc32(h, 88));
    put_u32(h + 92, 0);
}

/* Returns 0 ok, -1 bad magic/version/CRC. */
static int hyper_rec_unpack(const uint8_t *h, hyper_rec_t *r)
{
    if (memcmp(h, HYPER_MAGIC, 4) != 0)
        return -1;
    if (h[4] != 1)
        return -1;
    if (get_u32(h + 88) != hyper_crc32(h, 88))
        return -1;
    memset(r, 0, sizeof(*r));
    r->parity_idx = h[5];
    r->name_len = get_u16(h + 8);
    r->poly_id = get_u16(h + 10);
    r->t = h[12];
    r->npar = h[13];
    r->orig_len = get_u64(h + 16);
    r->stripe_off = get_u64(h + 24);
    r->stripe_len = get_u64(h + 32);
    r->parity_len = get_u64(h + 40);
    r->bch_len = get_u64(h + 48);
    memcpy(r->sha256, h + 56, 32);
    if (r->parity_idx > 2 || r->name_len == 0 || r->name_len > HYPER_MAXNAME)
        return -1;
    if (r->parity_len != r->stripe_len)
        return -1;
    return 0;
}

/* Stripe bytes for a file of orig_len bytes. */
static uint64_t hyper_stripe_len(uint64_t orig_len)
{
    return (orig_len + 7) / 8;
}

/* ------------------------------------------------------------------ */
/* BCH parity helpers (block API: parity bytes extracted per block)    */
/* ------------------------------------------------------------------ */

/* Total BCH parity bytes for a file of len bytes with poly p. */
static size_t hyper_bch_parity_len(size_t len, const bch_poly_t *p)
{
    if (len == 0)
        return 0;
    return bch_encoded_len(len, p) - len;
}

/* Extract the BCH parity bytes for data[0..len) into out
 * (must hold hyper_bch_parity_len(len, p) bytes). */
static void hyper_bch_parity(const uint8_t *data, size_t len,
                             const bch_poly_t *p, uint8_t *out)
{
    size_t maxd = bch_max_data(p);
    size_t off = 0, ooff = 0;
    while (off < len) {
        size_t d = len - off;
        if (d > maxd)
            d = maxd;
        size_t slen = bch_block_stored_len(d, p);
        uint8_t *stored = xmalloc(slen);
        bch_encode_block(data + off, d, p, stored);
        size_t plen = slen - d;
        if (plen)
            memcpy(out + ooff, stored + d, plen);
        ooff += plen;
        free(stored);
        off += d;
    }
}

/* Correct data[0..len) in place using parity[0..hyper_bch_parity_len).
 * Returns 0 ok, -1 uncorrectable. *corrected (if non-NULL) = bits fixed. */
static int hyper_bch_correct(uint8_t *data, size_t len, const uint8_t *parity,
                             const bch_poly_t *p, int *corrected)
{
    if (corrected)
        *corrected = 0;
    if (len == 0)
        return 0;
    size_t maxd = bch_max_data(p);
    size_t off = 0, poff = 0;
    int total = 0;
    while (off < len) {
        size_t d = len - off;
        if (d > maxd)
            d = maxd;
        size_t slen = bch_block_stored_len(d, p);
        size_t plen = slen - d;
        uint8_t *stored = xmalloc(slen);
        uint8_t *outb = xmalloc(d);
        memcpy(stored, data + off, d);
        if (plen)
            memcpy(stored + d, parity + poff, plen);
        int c = 0;
        int rc = bch_decode_block(stored, slen, d, p, outb, &c);
        free(stored);
        if (rc != 0) {
            free(outb);
            return -1;
        }
        memcpy(data + off, outb, d);
        free(outb);
        total += c;
        poff += plen;
        off += d;
    }
    if (corrected)
        *corrected = total;
    return 0;
}

/* ------------------------------------------------------------------ */
/* File I/O helpers                                                    */
/* ------------------------------------------------------------------ */

/* Read a whole file into memory. Returns buffer (caller frees) and
 * sets *len. Dies on error. */
static uint8_t *read_whole_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        die("cannot open %s: %s", path, strerror(errno));
    if (fseek(f, 0, SEEK_END) != 0)
        die("cannot seek %s: %s", path, strerror(errno));
    long sz = ftell(f);
    if (sz < 0)
        die("cannot stat %s: %s", path, strerror(errno));
    if (fseek(f, 0, SEEK_SET) != 0)
        die("cannot seek %s: %s", path, strerror(errno));
    uint8_t *buf = xmalloc((size_t)sz);
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz)
        die("cannot read %s: %s", path, strerror(errno));
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

/* Write len bytes from buf to path (truncate/create). Dies on error. */
static void write_whole_file(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        die("cannot open %s for writing: %s", path, strerror(errno));
    if (len > 0 && fwrite(buf, 1, len, f) != len)
        die("cannot write %s: %s", path, strerror(errno));
    if (fclose(f) != 0)
        die("cannot close %s: %s", path, strerror(errno));
}

/* File size, or -1 if it does not exist / cannot be statted. */
static int64_t file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;
    return (int64_t)st.st_size;
}

/* Parent directory of path (everything before the last '/'), or "."
 * if there is none. Returns a malloc'd string. */
static char *parent_dir(const char *path)
{
    const char *slash = strrchr(path, '/');
    if (!slash)
        return xstrdup(".");
    if (slash == path)
        return xstrdup("/");
    return strndup(path, (size_t)(slash - path));
}

/* ------------------------------------------------------------------ */
/* Index: scan a parity stripe file into an in-memory list of records  */
/* ------------------------------------------------------------------ */

typedef struct {
    hyper_rec_t *recs;
    size_t n, cap;
    int bad; /* set if scanning stopped on a bad record */
} hyper_index_t;

static void index_add(hyper_index_t *idx, const hyper_rec_t *r)
{
    if (idx->n == idx->cap) {
        idx->cap = idx->cap ? idx->cap * 2 : 16;
        idx->recs = xrealloc(idx->recs, idx->cap * sizeof(hyper_rec_t));
    }
    idx->recs[idx->n++] = *r;
}

/* Scan parity stripe file `path` for records. Returns 0 on success
 * (even if the file is empty), -1 if the file cannot be opened.
 * Records are appended to idx in file order. Stops (sets idx->bad)
 * at the first bad record. */
static int index_scan(const char *path, hyper_index_t *idx)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    uint64_t off = 0;
    while (1) {
        uint8_t h[HYPER_HDR_LEN];
        if (fseek(f, (long)off, SEEK_SET) != 0)
            break;
        size_t n = fread(h, 1, HYPER_HDR_LEN, f);
        if (n == 0)
            break; /* clean EOF */
        if (n < HYPER_HDR_LEN) {
            idx->bad = 1;
            break;
        }
        hyper_rec_t r;
        if (hyper_rec_unpack(h, &r) != 0) {
            idx->bad = 1;
            break;
        }
        /* read the name */
        if (fseek(f, (long)(off + HYPER_HDR_LEN), SEEK_SET) != 0) {
            idx->bad = 1;
            break;
        }
        if (fread(r.name, 1, r.name_len, f) != r.name_len) {
            idx->bad = 1;
            break;
        }
        r.name[r.name_len] = '\0';
        r.rec_off = off;
        index_add(idx, &r);
        uint64_t recsize = HYPER_HDR_LEN + r.name_len + r.parity_len + r.bch_len;
        off += recsize;
    }
    fclose(f);
    return 0;
}

static const hyper_rec_t *index_find(const hyper_index_t *idx, const char *name)
{
    for (size_t i = 0; i < idx->n; i++) {
        if (strcmp(idx->recs[i].name, name) == 0)
            return &idx->recs[i];
    }
    return NULL;
}

/* Build the index from the best surviving parity stripe. Scans all
 * parity stripes and keeps the one with the most records: a truncated
 * parity stripe yields a short index, and a crashed write may leave
 * one parity stripe one record ahead (that record's stripe data is
 * already on disk, so the longest index is the right one). Ties break
 * to the first (lowest parity index). Returns 0 on success, -1 if no
 * parity stripe can be read. Sets *used to the stripe used. */
static int index_build(hyper_cfg_t *cfg, hyper_index_t *idx, int *used)
{
    hyper_index_t best;
    memset(&best, 0, sizeof(best));
    int best_pi = -1;
    for (int i = 0; i < cfg->nparities; i++) {
        hyper_index_t cur;
        memset(&cur, 0, sizeof(cur));
        if (index_scan(cfg->parities[i].path, &cur) != 0) {
            free(cur.recs);
            continue;
        }
        if (cur.n == 0 && cur.bad) {
            free(cur.recs);
            continue;
        }
        if (best_pi < 0 || cur.n > best.n) {
            free(best.recs);
            best = cur;
            best_pi = i;
        } else {
            free(cur.recs);
        }
    }
    if (best_pi < 0) {
        free(best.recs);
        return -1;
    }
    *idx = best;
    *used = best_pi;
    return 0;
}

/* Read one record's parity + BCH bytes from parity stripe `pi` at
 * rec_off. The caller provides buffers of parity_len and bch_len.
 * Either buffer may be NULL, in which case those bytes are skipped
 * (seeked past) rather than read. Returns 0 ok, -1 on error. */
static int rec_read_parity(hyper_cfg_t *cfg, int pi, const hyper_rec_t *r,
                           uint8_t *parity, uint8_t *bch)
{
    FILE *f = fopen(cfg->parities[pi].path, "rb");
    if (!f)
        return -1;
    uint64_t base = r->rec_off + HYPER_HDR_LEN + r->name_len;
    if (fseek(f, (long)base, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    if (r->parity_len > 0) {
        if (parity) {
            if (fread(parity, 1, r->parity_len, f) != r->parity_len) {
                fclose(f);
                return -1;
            }
        } else if (fseek(f, (long)r->parity_len, SEEK_CUR) != 0) {
            fclose(f);
            return -1;
        }
    }
    if (r->bch_len > 0) {
        if (bch) {
            if (fread(bch, 1, r->bch_len, f) != r->bch_len) {
                fclose(f);
                return -1;
            }
        } else if (fseek(f, (long)r->bch_len, SEEK_CUR) != 0) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Stripe engine: bit-plane split / merge                              */
/*                                                                     */
/* File bytes d[0..F) -> 8 stripe buffers s_j[0..ceil(F/8)), where    */
/* s_j[k] bit p = d[8k+p] bit j. The 8 bytes of one group are one     */
/* 8x8 bit-matrix transpose. Write uses the same transpose as read    */
/* (it is an involution). Work is done in 64 KiB bursts.               */
/* ------------------------------------------------------------------ */

/* Split file data[0..len) into 8 stripe buffers (each stripe_len
 * bytes, zero-padded). stripes[j] must hold stripe_len bytes. */
static void hyper_split(const uint8_t *data, size_t len,
                        uint8_t *stripes[HYPER_NSTRIPES])
{
    size_t slen = (len + 7) / 8;
    size_t groups = len / 8;
    size_t rem = len % 8;
    /* full groups of 8 bytes -> 8 stripe bytes each */
    for (size_t g = 0; g < groups; g++) {
        uint64_t x;
        memcpy(&x, data + 8 * g, 8);
        x = transpose8x8(x);
        for (int j = 0; j < HYPER_NSTRIPES; j++)
            stripes[j][g] = (uint8_t)((x >> (8 * j)) & 0xFF);
    }
    /* partial last group: pad with zero bytes, transpose, keep only
     * the stripe bytes that exist (slen may be groups or groups+1) */
    if (rem) {
        uint8_t tmp[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        memcpy(tmp, data + 8 * groups, rem);
        uint64_t x;
        memcpy(&x, tmp, 8);
        x = transpose8x8(x);
        for (int j = 0; j < HYPER_NSTRIPES; j++)
            stripes[j][groups] = (uint8_t)((x >> (8 * j)) & 0xFF);
    }
    (void)slen;
}

/* Merge 8 stripe buffers back into file data[0..len). The inverse of
 * hyper_split (same transpose). */
static void hyper_merge(uint8_t *stripes[HYPER_NSTRIPES], size_t len,
                        uint8_t *data)
{
    size_t groups = len / 8;
    size_t rem = len % 8;
    for (size_t g = 0; g < groups; g++) {
        uint64_t x = 0;
        for (int j = 0; j < HYPER_NSTRIPES; j++)
            x |= (uint64_t)stripes[j][g] << (8 * j);
        x = transpose8x8(x);
        memcpy(data + 8 * g, &x, 8);
    }
    if (rem) {
        uint64_t x = 0;
        for (int j = 0; j < HYPER_NSTRIPES; j++)
            x |= (uint64_t)stripes[j][groups] << (8 * j);
        x = transpose8x8(x);
        uint8_t tmp[8];
        memcpy(tmp, &x, 8);
        memcpy(data + 8 * groups, tmp, rem);
    }
}

/* ------------------------------------------------------------------ */
/* Parity: P = XOR, Q = sum g^j * s_j, R = sum g^(2j) * s_j (GF(256)) */
/* All three are computed over the stripe bytes (length stripe_len).   */
/* ------------------------------------------------------------------ */

/* Compute parity row `idx` (0=P, 1=Q, 2=R) over the 8 stripe buffers
 * into out (stripe_len bytes). */
static void hyper_parity_row(int idx, uint8_t *stripes[HYPER_NSTRIPES],
                             size_t stripe_len, uint8_t *out)
{
    if (idx == 0) {
        for (size_t k = 0; k < stripe_len; k++) {
            uint8_t v = 0;
            for (int j = 0; j < HYPER_NSTRIPES; j++)
                v ^= stripes[j][k];
            out[k] = v;
        }
    } else if (idx == 1) {
        for (size_t k = 0; k < stripe_len; k++) {
            uint8_t v = 0;
            for (int j = 0; j < HYPER_NSTRIPES; j++)
                v ^= gf256_mul(gf256_pow2(j), stripes[j][k]);
            out[k] = v;
        }
    } else {
        for (size_t k = 0; k < stripe_len; k++) {
            uint8_t v = 0;
            for (int j = 0; j < HYPER_NSTRIPES; j++)
                v ^= gf256_mul(gf256_pow2(2 * j), stripes[j][k]);
            out[k] = v;
        }
    }
}

/* Coefficient of parity row idx for data stripe j. */
static uint8_t hyper_coeff(int idx, int j)
{
    if (idx == 0)
        return 1;
    if (idx == 1)
        return gf256_pow2(j);
    return gf256_pow2(2 * j);
}

/* ------------------------------------------------------------------ */
/* Recovery: solve for lost stripes over GF(256)                       */
/*                                                                     */
/* lost[0..k) are the lost stripe indices (sorted, k = 1..3).         */
/* par_bufs[0..2] are the P/Q/R parity buffers for this file          */
/* (stripe_len bytes each), indexed by parity row — NULL where that   */
/* row is unavailable. Recovery uses whichever rows survive (at      */
/* least k of them); e.g. Q alone rebuilds 1 lost stripe if P is     */
/* dead. stripes[j] is NULL for a lost stripe, else a stripe_len     */
/* buffer of that stripe's bytes. On success the lost stripe buffers */
/* are allocated and filled. Returns 0 ok, -1 if fewer than k parity */
/* rows survive or the system is singular (should not happen for the */
/* P/Q/R coefficient scheme).                                         */
/* ------------------------------------------------------------------ */

/* Invert a kxk matrix over GF(256) by Gauss-Jordan. A is row-major
 * k*k; inv gets the inverse. Returns 0 ok, -1 singular. */
static int gf256_invert(const uint8_t *A, int k, uint8_t *inv)
{
    /* augmented matrix [A | I], 2k columns */
    uint8_t m[3][6];
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < k; j++)
            m[i][j] = A[i * k + j];
        for (int j = 0; j < k; j++)
            m[i][k + j] = (i == j) ? 1 : 0;
    }
    for (int col = 0; col < k; col++) {
        int piv = -1;
        for (int r = col; r < k; r++) {
            if (m[r][col] != 0) {
                piv = r;
                break;
            }
        }
        if (piv < 0)
            return -1;
        if (piv != col) {
            for (int j = 0; j < 2 * k; j++) {
                uint8_t t = m[col][j];
                m[col][j] = m[piv][j];
                m[piv][j] = t;
            }
        }
        uint8_t invp = gf256_inv(m[col][col]);
        for (int j = 0; j < 2 * k; j++)
            m[col][j] = gf256_mul(m[col][j], invp);
        for (int r = 0; r < k; r++) {
            if (r == col || m[r][col] == 0)
                continue;
            uint8_t f = m[r][col];
            for (int j = 0; j < 2 * k; j++)
                m[r][j] ^= gf256_mul(f, m[col][j]);
        }
    }
    for (int i = 0; i < k; i++)
        for (int j = 0; j < k; j++)
            inv[i * k + j] = m[i][k + j];
    return 0;
}

static int hyper_recover(const int *lost, int k, uint8_t *par_bufs[3],
                         uint8_t *stripes[HYPER_NSTRIPES],
                         size_t stripe_len)
{
    if (k < 1 || k > HYPER_MAXPAR)
        return -1;
    /* which parity rows survive; need at least k of them */
    int rows[3], nrows = 0;
    for (int i = 0; i < 3; i++)
        if (par_bufs[i])
            rows[nrows++] = i;
    if (nrows < k)
        return -1;
    /* coefficient matrix A[i][m] = coeff of parity rows[i] for stripe lost[m] */
    uint8_t A[9];
    for (int i = 0; i < k; i++)
        for (int m = 0; m < k; m++)
            A[i * k + m] = hyper_coeff(rows[i], lost[m]);
    uint8_t Ainv[9];
    if (gf256_invert(A, k, Ainv) != 0)
        return -1;
    /* Which stripes are lost (the caller leaves their buffers NULL;
     * surviving stripes must already be loaded). */
    int is_lost[HYPER_NSTRIPES] = {0};
    for (int m = 0; m < k; m++)
        is_lost[lost[m]] = 1;
    /* allocate the lost stripe buffers */
    for (int m = 0; m < k; m++)
        stripes[lost[m]] = xcalloc(stripe_len ? stripe_len : 1, 1);
    /* per byte position: syndromes, then x = Ainv * syn */
    for (size_t pos = 0; pos < stripe_len; pos++) {
        uint8_t syn[3] = {0, 0, 0};
        for (int i = 0; i < k; i++) {
            uint8_t v = par_bufs[rows[i]][pos];
            for (int j = 0; j < HYPER_NSTRIPES; j++) {
                if (is_lost[j])
                    continue;
                v ^= gf256_mul(hyper_coeff(rows[i], j), stripes[j][pos]);
            }
            syn[i] = v;
        }
        for (int m = 0; m < k; m++) {
            uint8_t v = 0;
            for (int i = 0; i < k; i++)
                v ^= gf256_mul(Ainv[m * k + i], syn[i]);
            stripes[lost[m]][pos] = v;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Core file operations                                                */
/* ------------------------------------------------------------------ */

/* Write len bytes in 64 KiB bursts. Returns 0 ok, -1 on error. */
static int write_bursts(FILE *f, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > HYPER_BURST)
            n = HYPER_BURST;
        if (fwrite(buf + off, 1, n, f) != n)
            return -1;
        off += n;
    }
    return 0;
}

/* Read a file's stripe data. stripes[j] gets a stripe_len buffer, or
 * NULL if stripe j is dead (missing file, too short, unreadable).
 * Returns the number of dead stripes; lost[] gets their indices. */
static int load_stripes(hyper_cfg_t *cfg, const hyper_rec_t *r,
                        uint8_t *stripes[HYPER_NSTRIPES], int *lost)
{
    int ndead = 0;
    for (int j = 0; j < HYPER_NSTRIPES; j++) {
        stripes[j] = NULL;
        FILE *f = fopen(cfg->stripes[j].path, "rb");
        if (!f) {
            lost[ndead++] = j;
            continue;
        }
        if (fseek(f, (long)r->stripe_off, SEEK_SET) != 0) {
            fclose(f);
            lost[ndead++] = j;
            continue;
        }
        uint8_t *buf = xmalloc(r->stripe_len ? r->stripe_len : 1);
        if (r->stripe_len > 0 &&
            fread(buf, 1, r->stripe_len, f) != r->stripe_len) {
            free(buf);
            fclose(f);
            lost[ndead++] = j;
            continue;
        }
        fclose(f);
        stripes[j] = buf;
    }
    return ndead;
}

/* Append one parity record to parity stripe pi. The record holds
 * parity bytes `parity` (parity_len bytes) and BCH bytes `bch`
 * (bch_len bytes) for file `name`. Returns 0 ok, -1 on error. */
static int append_record(hyper_cfg_t *cfg, int pi, const hyper_rec_t *tmpl,
                         const char *name, const uint8_t *parity,
                         const uint8_t *bch)
{
    FILE *f = fopen(cfg->parities[pi].path, "ab");
    if (!f)
        return -1;
    hyper_rec_t r = *tmpl;
    r.parity_idx = (uint8_t)pi;
    r.name_len = (uint16_t)strlen(name);
    uint8_t h[HYPER_HDR_LEN];
    hyper_rec_pack(&r, h);
    int rc = 0;
    if (fwrite(h, 1, HYPER_HDR_LEN, f) != HYPER_HDR_LEN)
        rc = -1;
    if (rc == 0 && fwrite(name, 1, r.name_len, f) != r.name_len)
        rc = -1;
    if (rc == 0 && r.parity_len > 0 &&
        write_bursts(f, parity, r.parity_len) != 0)
        rc = -1;
    if (rc == 0 && r.bch_len > 0 &&
        write_bursts(f, bch, r.bch_len) != 0)
        rc = -1;
    if (fclose(f) != 0)
        rc = -1;
    return rc;
}

/* Load a file by name from the volume.
 * On success returns a malloc'd buffer of the file data (caller frees),
 * sets *len, *corrected (BCH bits fixed, 0 if clean), *rebuilt (dead
 * stripes rebuilt via parity, 0 if none). On failure returns NULL and
 * writes a message into errmsg. */
static uint8_t *hyper_load_file(hyper_cfg_t *cfg, const char *name,
                                size_t *len, int *corrected, int *rebuilt,
                                char *errmsg, size_t errmsg_len)
{
    *corrected = 0;
    *rebuilt = 0;
    /* indexes, one per parity stripe (a stripe that cannot be read
     * simply has an empty index) */
    hyper_index_t pidx[HYPER_MAXPAR];
    for (int i = 0; i < HYPER_MAXPAR; i++)
        memset(&pidx[i], 0, sizeof(pidx[i]));
    for (int i = 0; i < cfg->nparities; i++)
        index_scan(cfg->parities[i].path, &pidx[i]);
    /* find the record (first parity stripe that has it) */
    const hyper_rec_t *rec = NULL;
    int rec_pi = -1;
    for (int i = 0; i < cfg->nparities; i++) {
        rec = index_find(&pidx[i], name);
        if (rec) {
            rec_pi = i;
            break;
        }
    }
    if (!rec) {
        snprintf(errmsg, errmsg_len, "no such file '%s' in the volume", name);
        goto fail;
    }
    /* the record's poly must be the config's poly */
    if (rec->poly_id != cfg->poly->id || rec->t != (uint8_t)cfg->t) {
        snprintf(errmsg, errmsg_len,
                 "file '%s' uses poly 0x%04x (t=%d), config uses 0x%04x (t=%d)",
                 name, rec->poly_id, rec->t, cfg->poly->id, cfg->t);
        goto fail;
    }
    /* BCH bytes: read from the parity stripe that had the record
     * (parity bytes skipped here; they are read only if a rebuild
     * is needed) */
    uint8_t *bch = NULL;
    if (rec->bch_len > 0) {
        bch = xmalloc(rec->bch_len);
        if (rec_read_parity(cfg, rec_pi, rec, NULL, bch) != 0) {
            snprintf(errmsg, errmsg_len, "cannot read parity record for '%s'",
                     name);
            free(bch);
            goto fail;
        }
    }
    /* load the stripe data */
    uint8_t *stripes[HYPER_NSTRIPES];
    int lost[HYPER_NSTRIPES];
    int ndead = load_stripes(cfg, rec, stripes, lost);
    if (ndead > cfg->nparities) {
        snprintf(errmsg, errmsg_len,
                 "%d data stripes dead for '%s', only %d parity stripes "
                 "can rebuild that many",
                 ndead, name, cfg->nparities);
        goto fail_stripes;
    }
    if (ndead > 0) {
        /* parity bytes for each row, from that row's parity stripe */
        uint8_t *par_bufs[3] = {NULL, NULL, NULL};
        for (int pi = 0; pi < cfg->nparities; pi++) {
            const hyper_rec_t *pr = index_find(&pidx[pi], name);
            if (!pr)
                continue;
            uint8_t *pb = xmalloc(rec->parity_len ? rec->parity_len : 1);
            uint8_t *bb = xmalloc(rec->bch_len ? rec->bch_len : 1);
            if (rec_read_parity(cfg, pi, pr, pb, bb) == 0)
                par_bufs[pi] = pb;
            else
                free(pb);
            free(bb);
        }
        if (hyper_recover(lost, ndead, par_bufs, stripes, rec->stripe_len) != 0) {
            snprintf(errmsg, errmsg_len,
                     "cannot rebuild %d dead stripe(s) for '%s' "
                     "(not enough surviving parity)", ndead, name);
            for (int i = 0; i < 3; i++)
                free(par_bufs[i]);
            goto fail_stripes;
        }
        for (int i = 0; i < 3; i++)
            free(par_bufs[i]);
        *rebuilt = ndead;
    }
    /* reassemble the file */
    uint8_t *data = xmalloc(rec->orig_len ? rec->orig_len : 1);
    hyper_merge(stripes, rec->orig_len, data);
    for (int j = 0; j < HYPER_NSTRIPES; j++)
        free(stripes[j]);
    /* BCH correct (syndrome is cheap when clean; full correction
     * only runs if the syndrome is non-zero) */
    if (rec->orig_len > 0) {
        int corr = 0;
        if (hyper_bch_correct(data, rec->orig_len, bch, cfg->poly, &corr) != 0) {
            snprintf(errmsg, errmsg_len,
                     "file '%s': BCH uncorrectable (too many bit errors)",
                     name);
            free(data);
            free(bch);
            goto fail;
        }
        *corrected = corr;
    }
    free(bch);
    /* SHA-256 verify: the final judge */
    uint8_t digest[32];
    lzply_sha256(data, rec->orig_len, digest);
    if (memcmp(digest, rec->sha256, 32) != 0) {
        snprintf(errmsg, errmsg_len,
                 "file '%s': SHA-256 mismatch (data corrupt)", name);
        free(data);
        goto fail;
    }
    *len = rec->orig_len;
    for (int i = 0; i < HYPER_MAXPAR; i++)
        free(pidx[i].recs);
    return data;

fail_stripes:
    for (int j = 0; j < HYPER_NSTRIPES; j++)
        free(stripes[j]);
    free(bch);
fail:
    for (int i = 0; i < HYPER_MAXPAR; i++)
        free(pidx[i].recs);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

/* Load the parity buffers for a file, one per parity row.
 * pidx[] are the per-parity-stripe indexes (built by the caller).
 * par_bufs[pi] gets a malloc'd parity_len buffer for each parity
 * stripe that has the file's record, else NULL. Returns the number
 * of parity rows loaded. */
static int load_file_parity(hyper_cfg_t *cfg, hyper_index_t *pidx,
                            const char *name, const hyper_rec_t *rec,
                            uint8_t *par_bufs[3])
{
    int n = 0;
    for (int pi = 0; pi < 3; pi++)
        par_bufs[pi] = NULL;
    for (int pi = 0; pi < cfg->nparities; pi++) {
        const hyper_rec_t *pr = index_find(&pidx[pi], name);
        if (!pr)
            continue;
        uint8_t *pb = xmalloc(rec->parity_len ? rec->parity_len : 1);
        uint8_t *bb = xmalloc(rec->bch_len ? rec->bch_len : 1);
        if (rec_read_parity(cfg, pi, pr, pb, bb) == 0) {
            par_bufs[pi] = pb;
            n++;
        } else {
            free(pb);
        }
        free(bb);
    }
    return n;
}

static void free_par_bufs(uint8_t *par_bufs[3])
{
    for (int i = 0; i < 3; i++) {
        free(par_bufs[i]);
        par_bufs[i] = NULL;
    }
}

/* --- -init ------------------------------------------------------- */

static int cmd_init(hyper_cfg_t *cfg, int force)
{
    /* 1. parent dirs exist, are directories, writable for rw files;
     *    ro files must already exist and be readable. */
    for (int j = 0; j < HYPER_NSTRIPES; j++) {
        hyper_stripe_t *st = &cfg->stripes[j];
        char *dir = parent_dir(st->path);
        struct stat dst;
        if (stat(dir, &dst) != 0 || !S_ISDIR(dst.st_mode)) {
            fprintf(stderr, "%s: stripe %s: parent directory %s missing\n",
                    prog, st->label, dir);
            free(dir);
            return EXIT_IO;
        }
        if (st->rw) {
            if (access(dir, W_OK) != 0) {
                fprintf(stderr, "%s: stripe %s: directory %s not writable\n",
                        prog, st->label, dir);
                free(dir);
                return EXIT_IO;
            }
        } else {
            if (access(st->path, R_OK) != 0) {
                fprintf(stderr,
                        "%s: stripe %s: read-only file %s does not exist "
                        "(cannot create a read-only stripe)\n",
                        prog, st->label, st->path);
                free(dir);
                return EXIT_IO;
            }
        }
        free(dir);
    }
    for (int i = 0; i < cfg->nparities; i++) {
        hyper_parity_t *pa = &cfg->parities[i];
        char *dir = parent_dir(pa->path);
        struct stat dst;
        if (stat(dir, &dst) != 0 || !S_ISDIR(dst.st_mode)) {
            fprintf(stderr, "%s: parity %s: parent directory %s missing\n",
                    prog, pa->label, dir);
            free(dir);
            return EXIT_IO;
        }
        if (pa->rw) {
            if (access(dir, W_OK) != 0) {
                fprintf(stderr, "%s: parity %s: directory %s not writable\n",
                        prog, pa->label, dir);
                free(dir);
                return EXIT_IO;
            }
        } else {
            if (access(pa->path, R_OK) != 0) {
                fprintf(stderr,
                        "%s: parity %s: read-only file %s does not exist\n",
                        prog, pa->label, pa->path);
                free(dir);
                return EXIT_IO;
            }
        }
        free(dir);
    }
    /* 2. free-space check, grouped by filesystem (st_dev of the
     *    parent dir). Only rw stripe sizes are reserved; parity
     *    files grow with the file count and have no configured size. */
    {
        struct { dev_t dev; uint64_t need; char *dir; } fs[HYPER_NSTRIPES];
        int nfs = 0;
        for (int j = 0; j < HYPER_NSTRIPES; j++) {
            hyper_stripe_t *st = &cfg->stripes[j];
            if (!st->rw)
                continue;
            char *dir = parent_dir(st->path);
            struct stat dst;
            stat(dir, &dst);
            int k;
            for (k = 0; k < nfs; k++) {
                if (fs[k].dev == dst.st_dev)
                    break;
            }
            if (k == nfs) {
                fs[nfs].dev = dst.st_dev;
                fs[nfs].need = 0;
                fs[nfs].dir = dir;
                nfs++;
            } else {
                free(dir);
            }
            fs[k].need += st->size;
        }
        for (int k = 0; k < nfs; k++) {
            struct statvfs vfs;
            if (statvfs(fs[k].dir, &vfs) != 0) {
                fprintf(stderr, "%s: cannot stat filesystem %s: %s\n",
                        prog, fs[k].dir, strerror(errno));
                for (int m = 0; m < nfs; m++)
                    free(fs[m].dir);
                return EXIT_IO;
            }
            uint64_t freeb = (uint64_t)vfs.f_bavail * (uint64_t)vfs.f_frsize;
            if (freeb < fs[k].need) {
                fprintf(stderr,
                        "%s: filesystem %s has %llu bytes free, needs %llu "
                        "for the configured stripe sizes\n",
                        prog, fs[k].dir,
                        (unsigned long long)freeb,
                        (unsigned long long)fs[k].need);
                for (int m = 0; m < nfs; m++)
                    free(fs[m].dir);
                return EXIT_IO;
            }
            free(fs[k].dir);
        }
    }
    /* 3. create (or verify) the files */
    for (int j = 0; j < HYPER_NSTRIPES; j++) {
        hyper_stripe_t *st = &cfg->stripes[j];
        if (!st->rw) {
            printf("stripe %s: %s (read-only, verified)\n", st->label, st->path);
            continue;
        }
        int64_t sz = file_size(st->path);
        if (sz >= 0 && !force) {
            fprintf(stderr,
                    "%s: stripe %s: %s already exists (%lld bytes); "
                    "refusing to overwrite (use --force)\n",
                    prog, st->label, st->path, (long long)sz);
            return EXIT_IO;
        }
        FILE *f = fopen(st->path, "wb");
        if (!f) {
            fprintf(stderr, "%s: cannot create %s: %s\n", prog, st->path,
                    strerror(errno));
            return EXIT_IO;
        }
        fclose(f);
        printf("stripe %s: %s (%s, capacity %llu bytes)\n", st->label, st->path,
               sz >= 0 ? "replaced" : "created",
               (unsigned long long)st->size);
    }
    for (int i = 0; i < cfg->nparities; i++) {
        hyper_parity_t *pa = &cfg->parities[i];
        if (!pa->rw) {
            printf("parity %s: %s (read-only, verified)\n", pa->label, pa->path);
            continue;
        }
        int64_t sz = file_size(pa->path);
        if (sz >= 0 && !force) {
            fprintf(stderr,
                    "%s: parity %s: %s already exists (%lld bytes); "
                    "refusing to overwrite (use --force)\n",
                    prog, pa->label, pa->path, (long long)sz);
            return EXIT_IO;
        }
        FILE *f = fopen(pa->path, "wb");
        if (!f) {
            fprintf(stderr, "%s: cannot create %s: %s\n", prog, pa->path,
                    strerror(errno));
            return EXIT_IO;
        }
        fclose(f);
        printf("parity %s: %s (%s, poly 0x%04x t=%d)\n", pa->label, pa->path,
               sz >= 0 ? "replaced" : "created", pa->poly_id, pa->poly->t);
    }
    printf("volume initialized: 8 data stripes, %d parity stripe(s), "
           "poly 0x%04x t=%d\n",
           cfg->nparities, cfg->poly->id, cfg->t);
    return EXIT_OK;
}

/* --- write -------------------------------------------------------- */

static int cmd_write(hyper_cfg_t *cfg, const char *srcpath, const char *name)
{
    /* name defaults to the basename of the source file */
    char defname[HYPER_MAXNAME + 1];
    if (!name) {
        const char *base = strrchr(srcpath, '/');
        base = base ? base + 1 : srcpath;
        if (!*base || strlen(base) > HYPER_MAXNAME) {
            fprintf(stderr, "%s: bad file name '%s'\n", prog, base);
            return EXIT_USAGE;
        }
        snprintf(defname, sizeof(defname), "%s", base);
        name = defname;
    }
    if (!*name || strlen(name) > HYPER_MAXNAME || strchr(name, '/') ||
        strchr(name, ':')) {
        fprintf(stderr, "%s: bad file name '%s' (1..%d chars, no '/' or ':')\n",
                prog, name, HYPER_MAXNAME);
        return EXIT_USAGE;
    }
    /* all stripes and parities must be writable for a write */
    for (int j = 0; j < HYPER_NSTRIPES; j++) {
        if (!cfg->stripes[j].rw) {
            fprintf(stderr, "%s: stripe %s is read-only; cannot write\n",
                    prog, cfg->stripes[j].label);
            return EXIT_IO;
        }
    }
    for (int i = 0; i < cfg->nparities; i++) {
        if (!cfg->parities[i].rw) {
            fprintf(stderr, "%s: parity %s is read-only; cannot write\n",
                    prog, cfg->parities[i].label);
            return EXIT_IO;
        }
    }
    /* refuse to overwrite an existing file (no overwrite in v1) */
    {
        hyper_index_t idx;
        memset(&idx, 0, sizeof(idx));
        int used = -1;
        if (index_build(cfg, &idx, &used) == 0) {
            if (index_find(&idx, name)) {
                fprintf(stderr, "%s: file '%s' already exists in the volume "
                                "(no overwrite in v1)\n", prog, name);
                free(idx.recs);
                return EXIT_IO;
            }
            free(idx.recs);
        }
    }
    size_t len;
    uint8_t *data = read_whole_file(srcpath, &len);
    uint64_t slen = hyper_stripe_len(len);
    /* stripe files must all exist and be the same size; that size is
     * where this file's data goes */
    int64_t base_off = -1;
    for (int j = 0; j < HYPER_NSTRIPES; j++) {
        int64_t sz = file_size(cfg->stripes[j].path);
        if (sz < 0) {
            fprintf(stderr, "%s: stripe %s: %s missing (run -init or -rebuild)\n",
                    prog, cfg->stripes[j].label, cfg->stripes[j].path);
            free(data);
            return EXIT_IO;
        }
        if (base_off < 0)
            base_off = sz;
        else if (sz != base_off) {
            fprintf(stderr,
                    "%s: stripe files out of sync (%s is %lld bytes, %s is %lld); "
                    "run -rebuild\n",
                    prog, cfg->stripes[0].label, (long long)base_off,
                    cfg->stripes[j].label, (long long)sz);
            free(data);
            return EXIT_IO;
        }
        if ((uint64_t)base_off + slen > cfg->stripes[j].size) {
            fprintf(stderr,
                    "%s: stripe %s would exceed capacity (%llu + %llu > %llu)\n",
                    prog, cfg->stripes[j].label,
                    (unsigned long long)base_off,
                    (unsigned long long)slen,
                    (unsigned long long)cfg->stripes[j].size);
            free(data);
            return EXIT_IO;
        }
    }
    /* SHA-256 of the original */
    uint8_t digest[32];
    lzply_sha256(data, len, digest);
    /* BCH parity */
    size_t bch_len = hyper_bch_parity_len(len, cfg->poly);
    uint8_t *bch = xmalloc(bch_len ? bch_len : 1);
    if (bch_len > 0)
        hyper_bch_parity(data, len, cfg->poly, bch);
    /* bit-plane split */
    uint8_t *stripes[HYPER_NSTRIPES];
    for (int j = 0; j < HYPER_NSTRIPES; j++)
        stripes[j] = xmalloc(slen ? slen : 1);
    hyper_split(data, len, stripes);
    /* parity rows */
    uint8_t *par[HYPER_MAXPAR];
    for (int i = 0; i < cfg->nparities; i++) {
        par[i] = xmalloc(slen ? slen : 1);
        hyper_parity_row(i, stripes, slen, par[i]);
    }
    /* append stripe data (64 KiB bursts) */
    for (int j = 0; j < HYPER_NSTRIPES; j++) {
        FILE *f = fopen(cfg->stripes[j].path, "ab");
        if (!f) {
            fprintf(stderr, "%s: cannot append to %s: %s\n", prog,
                    cfg->stripes[j].path, strerror(errno));
            goto fail_write;
        }
        if (slen > 0 && write_bursts(f, stripes[j], slen) != 0) {
            fprintf(stderr, "%s: cannot write %s: %s\n", prog,
                    cfg->stripes[j].path, strerror(errno));
            fclose(f);
            goto fail_write;
        }
        if (fclose(f) != 0) {
            fprintf(stderr, "%s: cannot close %s: %s\n", prog,
                    cfg->stripes[j].path, strerror(errno));
            goto fail_write;
        }
    }
    /* append a parity record to each parity stripe */
    {
        hyper_rec_t tmpl;
        memset(&tmpl, 0, sizeof(tmpl));
        tmpl.name_len = (uint16_t)strlen(name);
        tmpl.poly_id = cfg->poly->id;
        tmpl.t = (uint8_t)cfg->t;
        tmpl.npar = (uint8_t)cfg->nparities;
        tmpl.orig_len = len;
        tmpl.stripe_off = (uint64_t)base_off;
        tmpl.stripe_len = slen;
        tmpl.parity_len = slen;
        tmpl.bch_len = bch_len;
        memcpy(tmpl.sha256, digest, 32);
        for (int i = 0; i < cfg->nparities; i++) {
            if (append_record(cfg, i, &tmpl, name, par[i], bch) != 0) {
                fprintf(stderr, "%s: cannot append parity record to %s: %s\n",
                        prog, cfg->parities[i].path, strerror(errno));
                goto fail_write;
            }
        }
    }
    {
        char hex[65];
        hex32(digest, hex);
        printf("wrote '%s': %zu bytes, stripe_off %lld, stripe_len %llu, "
               "bch %zu bytes, sha256 %s\n",
               name, len, (long long)base_off,
               (unsigned long long)slen, bch_len, hex);
    }
    for (int j = 0; j < HYPER_NSTRIPES; j++)
        free(stripes[j]);
    for (int i = 0; i < cfg->nparities; i++)
        free(par[i]);
    free(bch);
    free(data);
    return EXIT_OK;

fail_write:
    for (int j = 0; j < HYPER_NSTRIPES; j++)
        free(stripes[j]);
    for (int i = 0; i < cfg->nparities; i++)
        free(par[i]);
    free(bch);
    free(data);
    return EXIT_IO;
}

/* --- read --------------------------------------------------------- */

static int cmd_read(hyper_cfg_t *cfg, const char *name, const char *outpath)
{
    char errmsg[256];
    size_t len;
    int corrected, rebuilt;
    uint8_t *data = hyper_load_file(cfg, name, &len, &corrected, &rebuilt,
                                    errmsg, sizeof(errmsg));
    if (!data) {
        fprintf(stderr, "%s: %s\n", prog, errmsg);
        return EXIT_CORRUPT;
    }
    write_whole_file(outpath, data, len); /* dies on error */
    printf("read '%s': %zu bytes -> %s", name, len, outpath);
    if (rebuilt > 0)
        printf(" (rebuilt %d dead stripe%s)", rebuilt, rebuilt == 1 ? "" : "s");
    if (corrected > 0)
        printf(" (BCH corrected %d bit%s)", corrected, corrected == 1 ? "" : "s");
    printf("\n");
    free(data);
    return EXIT_OK;
}

/* --- list --------------------------------------------------------- */

static int cmd_list(hyper_cfg_t *cfg)
{
    hyper_index_t idx;
    memset(&idx, 0, sizeof(idx));
    int used;
    if (index_build(cfg, &idx, &used) != 0) {
        fprintf(stderr, "%s: no readable parity stripe; cannot list "
                        "(index lives in the parity stripes)\n", prog);
        return EXIT_CORRUPT;
    }
    printf("index from parity stripe %d (%s): %zu file(s)\n", used,
           cfg->parities[used].label, idx.n);
    if (idx.bad)
        fprintf(stderr, "%s: warning: index ends in a bad record\n", prog);
    uint64_t total = 0;
    for (size_t i = 0; i < idx.n; i++) {
        hyper_rec_t *r = &idx.recs[i];
        total += r->orig_len;
        printf("  %-24s %10llu bytes  poly 0x%04x t=%-2d  stripe_off %lld  "
               "stripe_len %llu\n",
               r->name, (unsigned long long)r->orig_len, r->poly_id, r->t,
               (long long)r->stripe_off, (unsigned long long)r->stripe_len);
    }
    printf("%zu file(s), %llu bytes total\n", idx.n,
           (unsigned long long)total);
    free(idx.recs);
    return EXIT_OK;
}

/* --- check -------------------------------------------------------- */

static int cmd_check(hyper_cfg_t *cfg, const char *name)
{
    char errmsg[256];
    size_t len;
    int corrected, rebuilt;
    uint8_t *data = hyper_load_file(cfg, name, &len, &corrected, &rebuilt,
                                    errmsg, sizeof(errmsg));
    if (!data) {
        fprintf(stderr, "%s: check '%s' FAILED: %s\n", prog, name, errmsg);
        return EXIT_CORRUPT;
    }
    printf("check '%s': OK (%zu bytes, sha256 verified)", name, len);
    if (rebuilt > 0)
        printf(", rebuilt %d dead stripe%s", rebuilt, rebuilt == 1 ? "" : "s");
    if (corrected > 0)
        printf(", BCH corrected %d bit%s", corrected, corrected == 1 ? "" : "s");
    printf("\n");
    free(data);
    return EXIT_OK;
}

/* --- -rebuild ----------------------------------------------------- */

/* Expected total size of the data stripes for this index. */
static uint64_t index_total_stripe_len(const hyper_index_t *idx)
{
    uint64_t total = 0;
    for (size_t i = 0; i < idx->n; i++)
        total += idx->recs[i].stripe_len;
    return total;
}

/* Expected size of a parity stripe holding exactly this index. */
static uint64_t index_parity_size(const hyper_index_t *idx)
{
    uint64_t total = 0;
    for (size_t i = 0; i < idx->n; i++) {
        hyper_rec_t *r = &idx->recs[i];
        total += HYPER_HDR_LEN + r->name_len + r->parity_len + r->bch_len;
    }
    return total;
}

static int cmd_rebuild(hyper_cfg_t *cfg)
{
    hyper_index_t idx;
    memset(&idx, 0, sizeof(idx));
    int used;
    if (index_build(cfg, &idx, &used) != 0) {
        fprintf(stderr,
                "%s: no readable parity stripe; cannot rebuild without the "
                "index (if every parity stripe is dead but the data stripes "
                "are intact, the files are still readable via read, just "
                "unverifiable and unrecoverable)\n", prog);
        return EXIT_CORRUPT;
    }
    if (idx.bad)
        fprintf(stderr, "%s: warning: index ends in a bad record\n", prog);
    uint64_t exp_stripe = index_total_stripe_len(&idx);
    uint64_t exp_parity = index_parity_size(&idx);
    /* which data stripes are damaged (missing or wrong size) */
    int damaged_data[HYPER_NSTRIPES];
    int lost[HYPER_NSTRIPES];
    int k = 0;
    for (int j = 0; j < HYPER_NSTRIPES; j++) {
        int64_t sz = file_size(cfg->stripes[j].path);
        damaged_data[j] = (sz < 0 || (uint64_t)sz != exp_stripe);
        if (damaged_data[j])
            lost[k++] = j;
    }
    /* which parity stripes are damaged */
    int damaged_par[HYPER_MAXPAR];
    int npar_ok = 0;
    for (int i = 0; i < cfg->nparities; i++) {
        int64_t sz = file_size(cfg->parities[i].path);
        damaged_par[i] = (sz < 0 || (uint64_t)sz != exp_parity);
        if (!damaged_par[i])
            npar_ok++;
    }
    if (k == 0) {
        int any_par = 0;
        for (int i = 0; i < cfg->nparities; i++)
            if (damaged_par[i])
                any_par++;
        if (!any_par) {
            printf("rebuild: nothing to rebuild (all stripes intact)\n");
            free(idx.recs);
            return EXIT_OK;
        }
    }
    /* data-stripe rebuild needs at least k surviving parity rows */
    if (k > 0 && k > npar_ok) {
        fprintf(stderr,
                "%s: rebuild FAILED: %d data stripe(s) lost (%s) but only %d "
                "parity stripe(s) survive; %d parity row(s) can rebuild at most "
                "%d lost stripe(s)\n",
                prog, k, k == 1 ? "" : "", npar_ok, npar_ok, npar_ok);
        fprintf(stderr, "%s: damaged stripes are left as they are; "
                        "no data was silently returned\n", prog);
        for (int j = 0; j < HYPER_NSTRIPES; j++)
            if (damaged_data[j])
                fprintf(stderr, "  lost data stripe: %s (%s)\n",
                        cfg->stripes[j].label, cfg->stripes[j].path);
        free(idx.recs);
        return EXIT_CORRUPT;
    }
    /* phase A: rebuild the damaged data stripes. Rebuilt data goes
     * to temp files first and is renamed into place only on success,
     * so a failed rebuild leaves the damaged files untouched. */
    FILE *dout[HYPER_NSTRIPES];
    char *tmpath[HYPER_NSTRIPES];
    for (int j = 0; j < HYPER_NSTRIPES; j++) {
        dout[j] = NULL;
        tmpath[j] = NULL;
    }
    if (k > 0) {
        for (int m = 0; m < k; m++) {
            int j = lost[m];
            if (!cfg->stripes[j].rw) {
                fprintf(stderr, "%s: rebuild FAILED: data stripe %s is "
                                "read-only and damaged; cannot rebuild it\n",
                        prog, cfg->stripes[j].label);
                for (int mm = 0; mm < m; mm++) {
                    fclose(dout[lost[mm]]);
                    remove(tmpath[lost[mm]]);
                    free(tmpath[lost[mm]]);
                }
                free(idx.recs);
                return EXIT_CORRUPT;
            }
            tmpath[j] = xmalloc(strlen(cfg->stripes[j].path) + 16);
            sprintf(tmpath[j], "%s.rebuild-tmp", cfg->stripes[j].path);
            dout[j] = fopen(tmpath[j], "wb");
            if (!dout[j]) {
                fprintf(stderr, "%s: cannot create %s: %s\n", prog,
                        tmpath[j], strerror(errno));
                for (int mm = 0; mm < m; mm++) {
                    fclose(dout[lost[mm]]);
                    remove(tmpath[lost[mm]]);
                    free(tmpath[lost[mm]]);
                }
                free(tmpath[j]);
                free(idx.recs);
                return EXIT_IO;
            }
        }
        /* per-file recovery: load the surviving stripes + parity
         * rows, recover the dead ones, and append each damaged
         * stripe's data (read or recovered) to its rebuilt file.
         * Every damaged stripe gets exactly stripe_len bytes per
         * file, in index order, so the rebuilt files stay aligned
         * even when a damaged stripe happens to read fine for a
         * file near the front of a truncated stripe file. */
        hyper_index_t pidx[HYPER_MAXPAR];
        memset(pidx, 0, sizeof(pidx));
        for (int i = 0; i < cfg->nparities; i++)
            index_scan(cfg->parities[i].path, &pidx[i]);
        int ok = 1;
        for (int fi = 0; fi < (int)idx.n && ok; fi++) {
            hyper_rec_t *rec = &idx.recs[fi];
            uint8_t *stripes[HYPER_NSTRIPES];
            int dlost[HYPER_NSTRIPES];
            int ndead = load_stripes(cfg, rec, stripes, dlost);
            /* Force every damaged stripe dead for this file, even if
             * the old file still has bytes at this offset: a stripe
             * whose file is missing or the wrong size is rebuilt
             * purely from parity, never from its old (possibly
             * corrupt) bytes. */
            for (int m = 0; m < k; m++) {
                int j = lost[m];
                int already = 0;
                for (int d = 0; d < ndead; d++)
                    if (dlost[d] == j) {
                        already = 1;
                        break;
                    }
                if (!already) {
                    free(stripes[j]);
                    stripes[j] = NULL;
                    dlost[ndead++] = j;
                }
            }
            if (ndead > 0) {
                uint8_t *par_bufs[3];
                load_file_parity(cfg, pidx, rec->name, rec, par_bufs);
                if (hyper_recover(dlost, ndead, par_bufs, stripes,
                                  (size_t)rec->stripe_len) != 0) {
                    fprintf(stderr, "%s: rebuild FAILED: file '%s' could not "
                                    "be recovered (%d dead stripe(s))\n",
                            prog, rec->name, ndead);
                    ok = 0;
                }
                free_par_bufs(par_bufs);
            }
            if (ok) {
                for (int m = 0; m < k; m++) {
                    int j = lost[m];
                    if (rec->stripe_len > 0 &&
                        fwrite(stripes[j], 1, rec->stripe_len, dout[j]) !=
                            rec->stripe_len) {
                        fprintf(stderr, "%s: cannot write %s: %s\n", prog,
                                cfg->stripes[j].path, strerror(errno));
                        ok = 0;
                        break;
                    }
                }
            }
            for (int j = 0; j < HYPER_NSTRIPES; j++)
                free(stripes[j]);
        }
        for (int i = 0; i < cfg->nparities; i++)
            free(pidx[i].recs);
        for (int m = 0; m < k; m++)
            fclose(dout[lost[m]]);
        if (!ok) {
            for (int m = 0; m < k; m++) {
                remove(tmpath[lost[m]]);
                free(tmpath[lost[m]]);
            }
            free(idx.recs);
            return EXIT_CORRUPT;
        }
        for (int m = 0; m < k; m++) {
            int j = lost[m];
            if (rename(tmpath[j], cfg->stripes[j].path) != 0) {
                fprintf(stderr, "%s: cannot install rebuilt %s: %s\n", prog,
                        cfg->stripes[j].path, strerror(errno));
                for (int mm = m; mm < k; mm++) {
                    remove(tmpath[lost[mm]]);
                    free(tmpath[lost[mm]]);
                }
                free(idx.recs);
                return EXIT_IO;
            }
            free(tmpath[j]);
        }
        for (int m = 0; m < k; m++)
            printf("rebuilt data stripe %s (%s)\n", cfg->stripes[lost[m]].label,
                   cfg->stripes[lost[m]].path);
    }
    /* phase B: rebuild the damaged parity stripes from the (now
     * complete) data stripes. Each damaged parity file is truncated
     * first, then rebuilt record by record with append_record. */
    {
        hyper_index_t pidx[HYPER_MAXPAR];
        memset(pidx, 0, sizeof(pidx));
        for (int i = 0; i < cfg->nparities; i++)
            index_scan(cfg->parities[i].path, &pidx[i]);
        int src_pi = used; /* a surviving parity stripe to copy BCH from */
        for (int i = 0; i < cfg->nparities; i++) {
            if (!damaged_par[i])
                continue;
            if (!cfg->parities[i].rw) {
                fprintf(stderr, "%s: parity stripe %s is read-only and "
                                "damaged; cannot rebuild it\n",
                        prog, cfg->parities[i].label);
                for (int m = 0; m < cfg->nparities; m++)
                    free(pidx[m].recs);
                free(idx.recs);
                return EXIT_CORRUPT;
            }
            FILE *pf = fopen(cfg->parities[i].path, "wb");
            if (!pf) {
                fprintf(stderr, "%s: cannot rewrite %s: %s\n", prog,
                        cfg->parities[i].path, strerror(errno));
                for (int m = 0; m < cfg->nparities; m++)
                    free(pidx[m].recs);
                free(idx.recs);
                return EXIT_IO;
            }
            fclose(pf); /* truncate; append_record reopens to append */
            int ok = 1;
            for (int fi = 0; fi < (int)idx.n && ok; fi++) {
                hyper_rec_t *rec = &idx.recs[fi];
                uint8_t *stripes[HYPER_NSTRIPES];
                int dlost[HYPER_NSTRIPES];
                int ndead = load_stripes(cfg, rec, stripes, dlost);
                if (ndead > 0) {
                    fprintf(stderr, "%s: rebuild FAILED: file '%s' still has "
                                    "%d dead stripe(s); cannot recompute parity\n",
                            prog, rec->name, ndead);
                    ok = 0;
                } else {
                    uint8_t *prow = xmalloc(rec->parity_len ? rec->parity_len : 1);
                    hyper_parity_row(i, stripes, (size_t)rec->stripe_len, prow);
                    /* BCH bytes are identical on every parity stripe;
                     * copy them from the surviving index stripe */
                    const hyper_rec_t *sr = index_find(&pidx[src_pi], rec->name);
                    uint8_t *bch = xmalloc(rec->bch_len ? rec->bch_len : 1);
                    if (!sr || rec_read_parity(cfg, src_pi, sr, NULL, bch) != 0) {
                        fprintf(stderr, "%s: rebuild FAILED: cannot read BCH "
                                        "for '%s' from parity stripe %d\n",
                                prog, rec->name, src_pi);
                        free(prow);
                        free(bch);
                        ok = 0;
                    } else if (append_record(cfg, i, rec, rec->name, prow,
                                             bch) != 0) {
                        fprintf(stderr, "%s: cannot write parity record to %s: %s\n",
                                prog, cfg->parities[i].path, strerror(errno));
                        free(prow);
                        free(bch);
                        ok = 0;
                    } else {
                        free(prow);
                        free(bch);
                    }
                }
                for (int j = 0; j < HYPER_NSTRIPES; j++)
                    free(stripes[j]);
            }
            if (!ok) {
                for (int m = 0; m < cfg->nparities; m++)
                    free(pidx[m].recs);
                free(idx.recs);
                return EXIT_CORRUPT;
            }
            printf("rebuilt parity stripe %s (%s)\n", cfg->parities[i].label,
                   cfg->parities[i].path);
        }
        for (int m = 0; m < cfg->nparities; m++)
            free(pidx[m].recs);
    }
    free(idx.recs);
    printf("rebuild complete\n");
    return EXIT_OK;
}

/* --- usage / main ------------------------------------------------- */

static void usage(FILE *f)
{
    fprintf(f,
            "usage: %s -c config.txt <command> [args]\n"
            "\n"
            "commands:\n"
            "  -init [--force]     initialize the volume (create stripe and\n"
            "                      parity files; --force replaces existing files)\n"
            "  write <file> [name] write a file into the volume (name defaults\n"
            "                      to the file's basename)\n"
            "  read <name> <out>   read a file back out (rebuilds a dead stripe\n"
            "                      via parity if needed; verifies sha256)\n"
            "  list                list the files in the volume\n"
            "  check <name>        verify a file (stripe parity + BCH + sha256)\n"
            "  -rebuild            rebuild lost/corrupt stripes from parity\n"
            "\n"
            "config lines:\n"
            "  stripe:<label>:<file>:<rw|ro>:<size>   (8 required, size K/M/G)\n"
            "  parity:<label>:<file>:<rw|ro>:<poly>:<error_level>\n"
            "                      (1-3 required; poly + error level must agree\n"
            "                      and match across all parity lines)\n",
            prog);
}

int main(int argc, char **argv)
{
    prog = argv[0];
    const char *cfgpath = NULL;
    int argi = 1;
    /* -c config.txt may come before or after the command */
    if (argi < argc && strcmp(argv[argi], "-c") == 0) {
        if (argi + 1 >= argc) {
            usage(stderr);
            return EXIT_USAGE;
        }
        cfgpath = argv[argi + 1];
        argi += 2;
    }
    if (argi >= argc) {
        usage(stderr);
        return EXIT_USAGE;
    }
    const char *cmd = argv[argi++];
    if (argi < argc && strcmp(argv[argi], "-c") == 0) {
        if (argi + 1 >= argc) {
            usage(stderr);
            return EXIT_USAGE;
        }
        cfgpath = argv[argi + 1];
        argi += 2;
    }
    if (!cfgpath) {
        fprintf(stderr, "%s: no config file given (use -c config.txt)\n", prog);
        usage(stderr);
        return EXIT_USAGE;
    }
    hyper_cfg_t cfg;
    parse_cfg(cfgpath, &cfg); /* exits with a message on bad config */
    int rc;
    if (strcmp(cmd, "-init") == 0) {
        int force = 0;
        if (argi < argc && strcmp(argv[argi], "--force") == 0) {
            force = 1;
            argi++;
        }
        if (argi < argc) {
            fprintf(stderr, "%s: -init takes no further arguments\n", prog);
            return EXIT_USAGE;
        }
        rc = cmd_init(&cfg, force);
    } else if (strcmp(cmd, "write") == 0) {
        if (argi >= argc) {
            fprintf(stderr, "%s: write needs a file\n", prog);
            return EXIT_USAGE;
        }
        const char *name = (argi + 1 < argc) ? argv[argi + 1] : NULL;
        rc = cmd_write(&cfg, argv[argi], name);
    } else if (strcmp(cmd, "read") == 0) {
        if (argi + 1 >= argc) {
            fprintf(stderr, "%s: read needs <name> <out>\n", prog);
            return EXIT_USAGE;
        }
        rc = cmd_read(&cfg, argv[argi], argv[argi + 1]);
    } else if (strcmp(cmd, "list") == 0) {
        rc = cmd_list(&cfg);
    } else if (strcmp(cmd, "check") == 0) {
        if (argi >= argc) {
            fprintf(stderr, "%s: check needs <name>\n", prog);
            return EXIT_USAGE;
        }
        rc = cmd_check(&cfg, argv[argi]);
    } else if (strcmp(cmd, "-rebuild") == 0) {
        rc = cmd_rebuild(&cfg);
    } else {
        fprintf(stderr, "%s: unknown command '%s'\n", prog, cmd);
        usage(stderr);
        return EXIT_USAGE;
    }
    return rc;
}
