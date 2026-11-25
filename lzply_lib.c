/* lzply_lib.c - shared core of the lzply archiver and lzply_mount.
 *
 * Everything both programs need: the v4 archive format, the per-entry
 * pipeline (lzip compress -> BCH encode, and the reverse), the header
 * I/O, the archive scan, and the date / selector filters. The
 * command-line tool (lzply.c) and the FUSE filesystem (lzply_mount.c)
 * both link this file. There is no legacy support: v4 is the only
 * format. (v3 archives are rejected outright; the format changed
 * in v4.)
 *
 * Archive format v4 (all integers little-endian):
 *   global header (16 bytes):
 *     magic "LZPL", version u8 (=4), flags u8, entry_count u32,
 *     reserved u64
 *   entries, each:
 *     u16 path_len, u8 level, u8 rs_level, u8 flags, u8 reserved,
 *     u64 orig_size, u64 stored_size, u64 blob_size, u8 sha256[32],
 *     u32 mode, u64 mtime, u32 header_crc32,
 *     path[path_len], data[stored_size]
 *     (header_crc32 covers the 74 bytes before it; blob_size is the
 *     length of the compressed stream before error-correction parity
 *     was added; mtime is the source file's modification time,
 *     seconds since the epoch, UTC)
 *   end marker: u16 path_len == 0
 * Flags: bit 0 is unused (it was used by v3), bit 1 =
 * directory, bit 2 = BCH mode.
 * For a BCH entry, poly_id = rs_level | (reserved << 8).
 */
#define _FILE_OFFSET_BITS 64
#define _DEFAULT_SOURCE

#include "lzply_lib.h"

#include <errno.h>
#include <limits.h>
#include <lzlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "bch.h"
#include "sha256.h"

/* Program name used in error messages; lzply_mount sets it to "lzply_mount". */
const char *lzply_progname = "lzply";

void lzply_set_progname(const char *name)
{
    lzply_progname = name;
}

static void die_oom(void)
{
    fprintf(stderr, "%s: out of memory\n", lzply_progname);
    exit(EXIT_IO);
}

void *xmalloc(size_t n){
    void *p = malloc(n ? n : 1);
    if (!p)
        die_oom();
    return p;
}

void *xrealloc(void *p, size_t n){
    void *q = realloc(p, n ? n : 1);
    if (!q)
        die_oom();
    return q;
}

char *xstrdup(const char *s){
    char *p = strdup(s);
    if (!p)
        die_oom();
    return p;
}


void buf_init(buf_t *b){
    b->data = NULL;
    b->len = b->cap = 0;
}

void buf_free(buf_t *b){
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static void buf_reserve(buf_t *b, size_t extra){
    if (b->len + extra > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->len + extra)
            nc *= 2;
        b->data = xrealloc(b->data, nc);
        b->cap = nc;
    }
}

void buf_append(buf_t *b, const void *p, size_t n){
    buf_reserve(b, n);
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

/* Little-endian integer access (archive format is LE). */
void put16le(uint8_t *p, uint16_t v) { p[0] = v & 0xff; p[1] = (v >> 8) & 0xff; }

void put32le(uint8_t *p, uint32_t v){
    p[0] = v & 0xff; p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff; p[3] = (v >> 24) & 0xff;
}

void put64le(uint8_t *p, uint64_t v){
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (v >> (8 * i)) & 0xff;
}

uint16_t get16le(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

uint32_t get32le(const uint8_t *p){
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint64_t get64le(const uint8_t *p){
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

/* CRC-32 (IEEE, polynomial 0xEDB88320). */
static uint32_t crc32_table[256];

static int crc32_ready = 0;

void crc32_init(void)
{
    uint32_t i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_ready = 1;
}

uint32_t crc32_of(const uint8_t *p, size_t n){
    uint32_t c = 0xFFFFFFFFu;
    size_t i;
    if (!crc32_ready)
        crc32_init();
    for (i = 0; i < n; i++)
        c = crc32_table[(c ^ p[i]) & 0xff] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* Dictionary size / match-length limit per level, matching the lzip
 * command-line tool's own table (verified by comparing output with
 * `lzip -N` on the same input). */
static const int lz_dict_size[10] =
    { 65535, 1 << 20, 3 << 19, 1 << 21, 3 << 20,
      1 << 22, 1 << 23, 1 << 24, 3 << 23, 1 << 25 };

static const int lz_match_len[10] =
    { 16, 16, 20, 24, 32, 32, 32, 32, 32, 32 };

int lz_compress_mem(const uint8_t *in, size_t in_len, int level,                           uint8_t **out, size_t *out_len)
{
    struct LZ_Encoder *enc;
    buf_t b;
    uint8_t tmp[65536];
    size_t pos = 0;
    int finished = 0;
    buf_init(&b);
    /* member_size must be >= LZ_min_dictionary_size() (4096); 0 is
     * rejected as a bad argument in lzlib 1.13. ULLONG_MAX means a
     * single member of effectively unlimited size. */
    enc = LZ_compress_open(lz_dict_size[level], lz_match_len[level],
                           (unsigned long long)-1);
    if (!enc) {
        buf_free(&b);
        return -1;
    }
    while (pos < in_len) {
        int ws = LZ_compress_write_size(enc);
        if (ws <= 0) {
            int rd = LZ_compress_read(enc, tmp, sizeof tmp);
            if (rd < 0)
                goto fail;
            if (rd == 0)
                goto fail;      /* encoder stuck: should not happen */
            buf_append(&b, tmp, (size_t)rd);
            continue;
        }
        {
            size_t n = in_len - pos;
            int wr;
            int rd;
            if (n > (size_t)ws)
                n = (size_t)ws;
            wr = LZ_compress_write(enc, in + pos, (int)n);
            if (wr < 0)
                goto fail;
            pos += (size_t)wr;
            while ((rd = LZ_compress_read(enc, tmp, sizeof tmp)) > 0)
                buf_append(&b, tmp, (size_t)rd);
            if (rd < 0)
                goto fail;
        }
    }
    if (LZ_compress_finish(enc) < 0)
        goto fail;
    while (!finished) {
        int rd = LZ_compress_read(enc, tmp, sizeof tmp);
        if (rd < 0)
            goto fail;
        if (rd > 0)
            buf_append(&b, tmp, (size_t)rd);
        finished = LZ_compress_finished(enc);
        if (!finished && rd == 0)
            goto fail;          /* no progress after finish */
    }
    LZ_compress_close(enc);
    *out = b.data;
    *out_len = b.len;
    return 0;
fail:
    LZ_compress_close(enc);
    buf_free(&b);
    return -1;
}

int lz_decompress_mem(const uint8_t *in, size_t in_len,                             uint8_t **out, size_t *out_len)
{
    struct LZ_Decoder *dec;
    buf_t b;
    uint8_t tmp[65536];
    size_t pos = 0;
    int finished = 0;
    buf_init(&b);
    dec = LZ_decompress_open();
    if (!dec) {
        buf_free(&b);
        return -1;
    }
    while (pos < in_len) {
        int ws = LZ_decompress_write_size(dec);
        if (ws <= 0) {
            int rd = LZ_decompress_read(dec, tmp, sizeof tmp);
            if (rd < 0)
                goto fail;
            if (rd == 0)
                goto fail;
            buf_append(&b, tmp, (size_t)rd);
            continue;
        }
        {
            size_t n = in_len - pos;
            int wr;
            int rd;
            if (n > (size_t)ws)
                n = (size_t)ws;
            wr = LZ_decompress_write(dec, in + pos, (int)n);
            if (wr < 0)
                goto fail;
            pos += (size_t)wr;
            while ((rd = LZ_decompress_read(dec, tmp, sizeof tmp)) > 0)
                buf_append(&b, tmp, (size_t)rd);
            if (rd < 0)
                goto fail;
        }
    }
    if (LZ_decompress_finish(dec) < 0)
        goto fail;
    while (!finished) {
        int rd = LZ_decompress_read(dec, tmp, sizeof tmp);
        if (rd < 0)
            goto fail;
        if (rd > 0)
            buf_append(&b, tmp, (size_t)rd);
        finished = LZ_decompress_finished(dec);
        if (!finished && rd == 0)
            goto fail;
    }
    if (LZ_decompress_errno(dec) != LZ_ok)
        goto fail;
    LZ_decompress_close(dec);
    *out = b.data;
    *out_len = b.len;
    return 0;
fail:
    LZ_decompress_close(dec);
    buf_free(&b);
    return -1;
}

/* Largest parent's poly for a t (m=22 has all six t values). Used as
 * the auto-pick fallback when a blob is larger than the largest
 * single block, so it is split into blocks of that poly. */
static const bch_poly_t *bch_poly_largest(int t)
{
    static const int t_idx[33] = {
        -1, 0, 1, -1, 2, -1, -1, -1, 3, -1, -1, -1, -1, -1, -1, -1,
        4, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        5
    };
    if (t < 1 || t > 32 || t_idx[t] < 0)
        return NULL;
    return bch_poly_by_id(bch_poly_by_mt[BCH_MAX_M - BCH_MIN_M][t_idx[t]]);
}

/* Entry encode: raw file bytes -> stored bytes.
 * Fills sha_out with SHA-256 of the raw bytes. *poly_id_out /
 * *is_bch_out describe the error correction actually used, for the
 * entry header. *level_out is the level actually stored: the
 * requested level, or 0 when the entry is stored uncompressed
 * (level 0 requested, or the compressed blob was no smaller than
 * the original). BCH applies to the stored blob either way.
 * Returns 0 on success. */
int entry_encode(const uint8_t *raw, size_t raw_len, int level,
                 const ecc_opt_t *ecc,
                 uint8_t **stored, size_t *stored_len,
                 size_t *blob_len_out, uint16_t *poly_id_out,
                 int *is_bch_out, int *level_out,
                 uint8_t sha_out[32])
{
    uint8_t *comp = NULL, *blob = NULL, *ecout = NULL;
    size_t comp_len = 0, blob_len = 0, ec_len = 0;
    const bch_poly_t *poly = NULL;
    *poly_id_out = 0;
    *is_bch_out = 0;
    *level_out = level;
    lzply_sha256(raw, raw_len, sha_out);
    if (level == 0) {
        /* Explicit store: no compression at all. */
        blob = xmalloc(raw_len ? raw_len : 1);
        memcpy(blob, raw, raw_len);
        blob_len = raw_len;
        *level_out = 0;
    } else {
        if (lz_compress_mem(raw, raw_len, level, &comp, &comp_len) != 0)
            return -1;
        if (comp_len >= raw_len) {
            /* Incompressible: storing the raw bytes is no larger
             * (and for an empty file, smaller). BCH still applies
             * to the stored blob below, exactly as for compressed
             * entries. */
            free(comp);
            comp = NULL;
            blob = xmalloc(raw_len ? raw_len : 1);
            memcpy(blob, raw, raw_len);
            blob_len = raw_len;
            *level_out = 0;
        } else {
            blob = comp;
            blob_len = comp_len;
            comp = NULL;
        }
    }
    if (ecc->pinned) {
        poly = ecc->pinned;     /* pinned poly: its own t, any blob size */
    } else if (ecc->t > 0) {
        poly = bch_poly_for_data(blob_len, ecc->t);
        if (!poly)              /* blob bigger than one m=22 block: split */
            poly = bch_poly_largest(ecc->t);
        if (!poly) {
            free(blob);
            return -1;
        }
    }
    if (poly) {
        ec_len = bch_encoded_len(blob_len, poly);
        ecout = xmalloc(ec_len ? ec_len : 1);
        if (bch_encode(blob, blob_len, poly, ecout) != ec_len) {
            free(blob);
            free(ecout);
            return -1;
        }
        free(blob);
        *stored = ecout;
        *stored_len = ec_len;
        *poly_id_out = poly->id;
        *is_bch_out = 1;
    } else {
        *stored = blob;
        *stored_len = blob_len;
    }
    *blob_len_out = blob_len;
    return 0;
}

/* Entry decode: stored bytes -> raw file bytes.
 * Return values: 0 ok, -1 corrupt (BCH uncorrectable, lzip error,
 * SHA-256 mismatch). `corrected` receives the number of bit errors
 * corrected (BCH). `is_bch` / `poly_id` come from the entry header;
 * a non-BCH entry has no error correction. A level-0 entry is stored
 * uncompressed: the blob is copied verbatim, no lzip decode.
 */
int entry_decode(const uint8_t *stored, size_t stored_len, int level,
                 int is_bch, uint16_t poly_id,
                 const uint8_t want_sha[32], size_t blob_size,
                 uint8_t **raw, size_t *raw_len, int *corrected)
{
    uint8_t *blob = NULL, *plain = NULL, *out = NULL;
    size_t blob_len = 0, plain_len = 0, out_len = 0;
    int corr = 0;
    uint8_t sha[32];
    *corrected = 0;
    blob = xmalloc(blob_size ? blob_size : 1);
    if (is_bch) {
        const bch_poly_t *poly = bch_poly_by_id(poly_id);
        if (!poly || stored_len != bch_encoded_len(blob_size, poly)) {
            free(blob);
            return -1;
        }
        if (bch_decode(stored, stored_len, blob_size, poly, blob, &corr) != 0) {
            free(blob);
            return -1;
        }
        blob_len = blob_size;
    } else {
        /* No error correction: the stored data is the blob itself. */
        if (stored_len != blob_size) {
            free(blob);
            return -1;
        }
        memcpy(blob, stored, stored_len);
        blob_len = stored_len;
    }
    *corrected = corr;
    plain = blob;
    plain_len = blob_len;
    blob = NULL;
    if (level == 0) {
        /* Stored uncompressed: the blob is the raw file bytes. */
        out = xmalloc(plain_len ? plain_len : 1);
        memcpy(out, plain, plain_len);
        out_len = plain_len;
        free(plain);
    } else if (lz_decompress_mem(plain, plain_len, &out, &out_len) != 0) {
        free(plain);
        return -1;
    } else {
        free(plain);
    }
    lzply_sha256(out, out_len, sha);
    if (memcmp(sha, want_sha, 32) != 0) {
        free(out);
        return -1;              /* BCH miscorrection or other corruption */
    }
    *raw = out;
    *raw_len = out_len;
    return 0;
}

/* Parent directory of path (everything before the last '/'; "." if none). */
char *parent_dir(const char *path){
    const char *slash = strrchr(path, '/');
    char *r;
    if (!slash)
        return xstrdup(".");
    if (slash == path)
        return xstrdup("/");
    r = xmalloc((size_t)(slash - path) + 1);
    memcpy(r, path, (size_t)(slash - path));
    r[slash - path] = '\0';
    return r;
}


/* rs_level + reserved: for a BCH entry (flags & FLAG_BCH) this is the
 * poly id, poly_id = rs_level | (reserved << 8). For an entry with
 * no error correction both are 0. */

int write_entry_header(FILE *f, const ehdr_t *h){
    uint8_t buf[LZPLY_EHDR_SIZE];
    size_t plen = strlen(h->path);
    if (plen > 65535)
        return -1;
    memset(buf, 0, sizeof buf);
    put16le(buf + 0, (uint16_t)plen);
    buf[2] = h->level;
    buf[3] = h->rs_level;
    buf[4] = h->flags;
    buf[5] = h->reserved;
    put64le(buf + 6, h->orig_size);
    put64le(buf + 14, h->stored_size);
    put64le(buf + 22, h->blob_size);
    memcpy(buf + 30, h->sha, 32);
    put32le(buf + 62, h->mode);
    put64le(buf + 66, h->mtime);
    put32le(buf + 74, crc32_of(buf, 74));
    if (fwrite(buf, 1, sizeof buf, f) != sizeof buf)
        return -1;
    if (plen > 0 && fwrite(h->path, 1, plen, f) != plen)
        return -1;
    return 0;
}

/* Returns 0 = entry read, 1 = end marker, -1 = error/truncated. */
int read_entry_header(FILE *f, ehdr_t *h){
    uint8_t buf[LZPLY_EHDR_SIZE];
    uint16_t plen;
    uint32_t want_crc, got_crc;
    memset(h, 0, sizeof *h);
    if (fread(buf, 1, 2, f) != 2)
        return -1;
    plen = get16le(buf);
    if (plen == 0)
        return 1;
    if (fread(buf + 2, 1, LZPLY_EHDR_SIZE - 2, f) != LZPLY_EHDR_SIZE - 2)
        return -1;
    want_crc = get32le(buf + 74);
    put32le(buf + 74, 0);
    got_crc = crc32_of(buf, 74);
    put32le(buf + 74, want_crc);
    if (got_crc != want_crc)
        return -1;
    h->level = buf[2];
    h->rs_level = buf[3];
    h->flags = buf[4];
    h->reserved = buf[5];
    h->orig_size = get64le(buf + 6);
    h->stored_size = get64le(buf + 14);
    h->blob_size = get64le(buf + 22);
    memcpy(h->sha, buf + 30, 32);
    h->mode = get32le(buf + 62);
    h->mtime = get64le(buf + 66);
    if (h->level > 9)
        return -1;
    if (h->flags & FLAG_BCH) {
        /* rs_level is the low byte of the poly id, reserved the high
         * byte; the id must be in the embedded table. */
        uint16_t pid = (uint16_t)(h->rs_level | ((uint16_t)h->reserved << 8));
        if (!bch_poly_by_id(pid))
            return -1;
    }
    h->path = xmalloc((size_t)plen + 1);
    if (fread(h->path, 1, plen, f) != plen) {
        free(h->path);
        h->path = NULL;
        return -1;
    }
    h->path[plen] = '\0';
    /* Reject paths that would escape the destination directory. */
    if (h->path[0] == '/' || strstr(h->path, "/../") != NULL ||
        strcmp(h->path, "..") == 0 ||
        (plen >= 3 && strcmp(h->path + plen - 3, "/..") == 0)) {
        free(h->path);
        h->path = NULL;
        return -1;
    }
    return 0;
}

int read_global_header(FILE *f, uint32_t *count_out){
    uint8_t buf[LZPLY_HDR_SIZE];
    if (fread(buf, 1, sizeof buf, f) != sizeof buf)
        return -1;
    if (memcmp(buf, LZPLY_MAGIC, 4) != 0 || buf[4] != LZPLY_VERSION)
        return -1;
    *count_out = get32le(buf + 6);
    return 0;
}

void write_global_header(FILE *f, uint32_t count, int version){
    uint8_t buf[LZPLY_HDR_SIZE];
    memset(buf, 0, sizeof buf);
    memcpy(buf, LZPLY_MAGIC, 4);
    buf[4] = (uint8_t)version;
    buf[5] = 0;
    put32le(buf + 6, count);
    fwrite(buf, 1, sizeof buf, f);
}

/* Does selector sel match stored path? True if sel equals path, or
 * sel (with trailing '/' stripped) is a prefix of path and the next
 * character after the prefix is '/'. A selector that is only slashes
 * matches everything. So "photos" matches "photos/a.jpg" and the
 * "photos/" dir entry, but not "photos2/a.jpg"; "photos/" matches
 * everything under photos/. */
int selector_matches(const char *sel, const char *path){
    size_t n = strlen(sel);
    while (n > 0 && sel[n - 1] == '/')
        n--;
    if (n == 0)
        return 1;
    if (strncmp(path, sel, n) != 0)
        return 0;
    return path[n] == '\0' || path[n] == '/';
}

int path_matches_selectors(const char *path,                                  const char **sels, int nsels)
{
    int i;
    if (nsels == 0)
        return 1;
    for (i = 0; i < nsels; i++)
        if (selector_matches(sels[i], path))
            return 1;
    return 0;
}


int date_filter_active(const date_filter_t *f){
    return f && (f->start >= 0 || f->end >= 0 || f->year != 0);
}

/* Does an entry with this mtime pass the filter? */
int date_filter_matches(const date_filter_t *f, uint64_t mtime){
    if (!f)
        return 1;
    if (f->start >= 0 && (int64_t)mtime < f->start)
        return 0;
    if (f->end >= 0 && (int64_t)mtime > f->end)
        return 0;
    if (f->year != 0) {
        time_t t = (time_t)mtime;
        struct tm tmv;
        if (!gmtime_r(&t, &tmv))
            return 0;
        if (tmv.tm_year + 1900 != f->year)
            return 0;
    }
    return 1;
}

/* Parse a date: "YYYY-MM-DD" (midnight at the start of that day, or
 * 23:59:59 at the end of it when is_end is set) or
 * "YYYY-MM-DDTHH:MM:SS" (exact; a space may replace the 'T').
 * Returns 0 on success, -1 on a bad format or an impossible date.
 * All times are UTC. */
int parse_date(const char *s, int is_end, int64_t *out){
    struct tm tmv;
    time_t t;
    struct tm check;
    int y, mo, d, hh = 0, mm = 0, ss = 0;
    size_t n = strlen(s);
    int i;
    if (n != 10 && n != 19)
        return -1;
    for (i = 0; i < 10; i++) {
        if (i == 4 || i == 7) {
            if (s[i] != '-')
                return -1;
        } else if (s[i] < '0' || s[i] > '9') {
            return -1;
        }
    }
    if (n == 19) {
        if (s[10] != 'T' && s[10] != ' ')
            return -1;
        if (s[13] != ':' || s[16] != ':')
            return -1;
        for (i = 11; i < 19; i++) {
            if (i == 13 || i == 16)
                continue;
            if (s[i] < '0' || s[i] > '9')
                return -1;
        }
    }
    y = atoi(s);
    mo = atoi(s + 5);
    d = atoi(s + 8);
    if (n == 19) {
        hh = atoi(s + 11);
        mm = atoi(s + 14);
        ss = atoi(s + 17);
    }
    if (y < 1970 || y > 9999 || mo < 1 || mo > 12 || d < 1 || d > 31 ||
        hh < 0 || hh > 23 || mm < 0 || mm > 59 || ss < 0 || ss > 59)
        return -1;
    memset(&tmv, 0, sizeof tmv);
    tmv.tm_year = y - 1900;
    tmv.tm_mon = mo - 1;
    tmv.tm_mday = d;
    tmv.tm_hour = hh;
    tmv.tm_min = mm;
    tmv.tm_sec = ss;
    t = timegm(&tmv);
    if (t == (time_t)-1)
        return -1;
    /* Reject impossible dates (e.g. Feb 30): timegm normalises them
     * (and may normalise tmv in place), so round-trip through gmtime
     * and compare against the parsed values, not tmv. */
    if (!gmtime_r(&t, &check))
        return -1;
    if (check.tm_year != y - 1900 || check.tm_mon != mo - 1 ||
        check.tm_mday != d || check.tm_hour != hh ||
        check.tm_min != mm || check.tm_sec != ss)
        return -1;
    if (n == 10 && is_end)
        t += 86399;             /* through 23:59:59 of that date */
    *out = (int64_t)t;
    return 0;
}

/* Format an mtime as "YYYY-MM-DD HH:MM:SS UTC" into buf. */
void fmt_mtime(uint64_t mtime, char *buf, size_t bufsz){
    time_t t = (time_t)mtime;
    struct tm tmv;
    if (!gmtime_r(&t, &tmv)) {
        snprintf(buf, bufsz, "-");
        return;
    }
    strftime(buf, bufsz, "%Y-%m-%d %H:%M:%S UTC", &tmv);
}

/* Format permissions as a 10-character string, e.g. "drwxr-xr-x"
 * or "-rw-r--r--". The stored mode holds only the low 12 bits, so
 * the type letter comes from is_dir. */
void fmt_perm(int is_dir, uint32_t mode, char *buf){
    static const char *rwx = "rwxrwxrwx";
    int i;
    buf[0] = is_dir ? 'd' : '-';
    for (i = 0; i < 9; i++)
        buf[1 + i] = (mode & (1u << (8 - i))) ? rwx[i] : '-';
    buf[10] = '\0';
}



void scan_list_free(scan_list_t *l){
    size_t i;
    for (i = 0; i < l->len; i++)
        free(l->v[i].path);
    free(l->v);
    l->v = NULL;
    l->len = l->cap = 0;
}

/* Read the 16-byte global header, returning version and count.
 * Returns 0 on success, -1 if the file is not an lzply archive. */
int read_global_header_full(FILE *f, int *version_out,                                   uint32_t *count_out)
{
    uint8_t buf[LZPLY_HDR_SIZE];
    if (fread(buf, 1, sizeof buf, f) != sizeof buf)
        return -1;
    if (memcmp(buf, LZPLY_MAGIC, 4) != 0 || buf[4] != LZPLY_VERSION)
        return -1;
    *version_out = buf[4];
    *count_out = get32le(buf + 6);
    return 0;
}

/* Scan an archive and record every entry. Returns 0 on success.
 * On success *end_off_out is the file offset of the 2-byte end
 * marker (which must be the last 2 bytes of the file), and the
 * scanned entry count is in *nentries_out (the header's stored
 * count is returned in *count_out but the scanned count is the
 * ground truth). Returns -1 (with a message) if the file is not a
 * valid archive, an entry header is corrupt, or there are trailing
 * bytes after the end marker. */
int scan_archive(const char *path, int *version_out,                        uint32_t *count_out, off_t *size_out,
                        scan_list_t *entries, off_t *end_off_out)
{
    struct stat st;
    FILE *f = fopen(path, "rb");
    off_t end_off;
    if (!f) {
        fprintf(stderr, "%s: cannot open %s: %s\n", lzply_progname, path,
                strerror(errno));
        return -1;
    }
    if (fstat(fileno(f), &st) != 0) {
        fclose(f);
        return -1;
    }
    if (read_global_header_full(f, version_out, count_out) != 0) {
        fprintf(stderr, "%s: %s is not an lzply archive (bad magic/version)\n",
                lzply_progname, path);
        fclose(f);
        return -1;
    }
    memset(entries, 0, sizeof *entries);
    for (;;) {
        off_t off = ftello(f);
        ehdr_t h;
        int r = read_entry_header(f, &h);
        if (r == 1) {           /* end marker */
            end_off = off;
            break;
        }
        if (r < 0) {
            fprintf(stderr, "%s: %s is truncated or has a corrupt entry header\n",
                    lzply_progname, path);
            scan_list_free(entries);
            fclose(f);
            return -1;
        }
        if (entries->len == entries->cap) {
            entries->cap = entries->cap ? entries->cap * 2 : 64;
            entries->v = xrealloc(entries->v,
                                  entries->cap * sizeof(scan_entry_t));
        }
        entries->v[entries->len].path = h.path;   /* take ownership */
        entries->v[entries->len].offset = off;
        entries->v[entries->len].total_len =
            LZPLY_EHDR_SIZE + (uint64_t)strlen(h.path) + h.stored_size;
        entries->v[entries->len].is_dir = (h.flags & FLAG_ISDIR) != 0;
        entries->len++;
        if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
            fprintf(stderr, "%s: %s is truncated\n", lzply_progname, path);
            scan_list_free(entries);
            fclose(f);
            return -1;
        }
    }
    if (end_off != (off_t)st.st_size - 2 || ftello(f) != st.st_size) {
        fprintf(stderr, "%s: %s has trailing bytes after the end marker\n",
                lzply_progname, path);
        scan_list_free(entries);
        fclose(f);
        return -1;
    }
    *size_out = st.st_size;
    *end_off_out = end_off;
    fclose(f);
    return 0;
}

/* Copy n bytes from src (positioned at the start) to dst, streaming.
 * Returns 0 on success, -1 on a short read/write. */
int copy_bytes(FILE *src, FILE *dst, uint64_t n){
    uint8_t buf[65536];
    while (n > 0) {
        size_t want = n > sizeof buf ? sizeof buf : (size_t)n;
        size_t got = fread(buf, 1, want, src);
        if (got == 0)
            return -1;
        if (fwrite(buf, 1, got, dst) != got)
            return -1;
        n -= got;
    }
    return 0;
}

/* Create a temp file in the same directory as path (so rename() can
 * replace path atomically), returning the FILE* and the temp pathname
 * in *tmp_out (caller frees it). Returns NULL on failure. */
FILE *temp_in_same_dir(const char *path, char **tmp_out){
    char *dir = parent_dir(path);
    char *tmpl = xmalloc(strlen(dir) + 20);
    int fd;
    FILE *f;
    sprintf(tmpl, "%s/.lzply-tmp-XXXXXX", dir);
    free(dir);
    fd = mkstemp(tmpl);
    if (fd < 0) {
        fprintf(stderr, "%s: cannot create temp file %s: %s\n",
                lzply_progname, tmpl, strerror(errno));
        free(tmpl);
        return NULL;
    }
    f = fdopen(fd, "w+b");
    if (!f) {
        close(fd);
        unlink(tmpl);
        free(tmpl);
        return NULL;
    }
    *tmp_out = tmpl;
    return f;
}
