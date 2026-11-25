/* lzply_lib.h - shared core of the lzply archiver and lzply_mount.
 *
 * Everything both programs need: the v4 archive format, the per-entry
 * pipeline (lzip compress -> BCH encode, and the reverse), the header
 * I/O, the archive scan, and the date / selector filters. The
 * command-line tool (lzply.c) and the FUSE filesystem (lzply_mount.c)
 * both link lzply_lib.c. There is no legacy support: v4 is the only
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
 * Level is the lzip level (1..9) of the blob, or 0 for a stored
 * (uncompressed) entry: when the compressed blob would be no smaller
 * than the original (already-compressed data, random data, empty
 * files), or when -0 forces it, the raw bytes are stored instead and
 * BCH still applies to them exactly as before.
 * Flags: bit 0 is unused (it was used by v3), bit 1 =
 * directory, bit 2 = BCH mode. Bit 0 is deliberately not renumbered.
 * For a BCH entry, poly_id = rs_level | (reserved << 8).
 */
#ifndef LZPLY_LIB_H
#define LZPLY_LIB_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "bch.h"
#include "sha256.h"

#define LZPLY_MAGIC "LZPL"
#define LZPLY_VERSION 4          /* the only format version */
#define LZPLY_HDR_SIZE 16
#define LZPLY_EHDR_SIZE 78
#define LZPLY_END_MARKER 0

#define FLAG_ISDIR 0x02
#define FLAG_BCH 0x04           /* entry uses BCH; poly_id in rs_level+reserved */

#define EXIT_USAGE 1
#define EXIT_IO 2
#define EXIT_CORRUPT 3

/* Program name used in error messages (default "lzply").
 * lzply_mount sets it to "lzply_mount" at startup. */
extern const char *lzply_progname;
void lzply_set_progname(const char *name);

/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */

/* These die (exit) on allocation failure, like the original lzply. */
void *xmalloc(size_t n);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);

/* Growable byte buffer. */
typedef struct {
    uint8_t *data;
    size_t len, cap;
} buf_t;

void buf_init(buf_t *b);
void buf_free(buf_t *b);
void buf_append(buf_t *b, const void *p, size_t n);

/* Little-endian integer access (archive format is LE). */
void put16le(uint8_t *p, uint16_t v);
void put32le(uint8_t *p, uint32_t v);
void put64le(uint8_t *p, uint64_t v);
uint16_t get16le(const uint8_t *p);
uint32_t get32le(const uint8_t *p);
uint64_t get64le(const uint8_t *p);

/* CRC-32 (IEEE, polynomial 0xEDB88320). */
void crc32_init(void);
uint32_t crc32_of(const uint8_t *p, size_t n);

/* Parent directory of path (everything before the last '/'; "." if
 * none). */
char *parent_dir(const char *path);

/* ------------------------------------------------------------------ */
/* lzip (liblz) in-memory compression                                  */
/* ------------------------------------------------------------------ */

int lz_compress_mem(const uint8_t *in, size_t in_len, int level,
                    uint8_t **out, size_t *out_len);
int lz_decompress_mem(const uint8_t *in, size_t in_len,
                      uint8_t **out, size_t *out_len);

/* ------------------------------------------------------------------ */
/* Per-entry encode / decode                                           */
/* ------------------------------------------------------------------ */

/* Error-correction options for one -c invocation. t is the BCH
 * correction level for auto-pick (0 = no ECC); pinned overrides t. */
typedef struct {
    int t;
    const bch_poly_t *pinned;
} ecc_opt_t;

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
                 uint8_t sha_out[32]);

/* Entry decode: stored bytes -> raw file bytes.
 * Return values: 0 ok, -1 corrupt (BCH uncorrectable, lzip error,
 * SHA-256 mismatch). `corrected` receives the number of bit errors
 * corrected (BCH). `is_bch` / `poly_id` come from the entry header;
 * a non-BCH entry has no error correction. A level-0 entry is stored
 * uncompressed: the blob is copied verbatim, no lzip decode. */
int entry_decode(const uint8_t *stored, size_t stored_len, int level,
                 int is_bch, uint16_t poly_id,
                 const uint8_t want_sha[32], size_t blob_size,
                 uint8_t **raw, size_t *raw_len, int *corrected);

/* ------------------------------------------------------------------ */
/* Archive header I/O                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    char *path;
    uint8_t level, rs_level, flags, reserved;
    uint64_t orig_size, stored_size, blob_size;
    uint8_t sha[32];
    uint32_t mode;
    uint64_t mtime;             /* source mtime, seconds since epoch (UTC) */
} ehdr_t;
/* rs_level + reserved: for a BCH entry (flags & FLAG_BCH) this is the
 * poly id, poly_id = rs_level | (reserved << 8). For an entry with
 * no error correction both are 0. */

int write_entry_header(FILE *f, const ehdr_t *h);
/* Returns 0 = entry read, 1 = end marker, -1 = error/truncated. */
int read_entry_header(FILE *f, ehdr_t *h);
int read_global_header(FILE *f, uint32_t *count_out);
void write_global_header(FILE *f, uint32_t count, int version);
/* Read the 16-byte global header, returning version and count.
 * Returns 0 on success, -1 if the file is not an lzply archive. */
int read_global_header_full(FILE *f, int *version_out,
                            uint32_t *count_out);

/* ------------------------------------------------------------------ */
/* Selectors (for -d / -t / -l)                                        */
/* ------------------------------------------------------------------ */

/* Does selector sel match stored path? True if sel equals path, or
 * sel (with trailing '/' stripped) is a prefix of path and the next
 * character after the prefix is '/'. A selector that is only slashes
 * matches everything. */
int selector_matches(const char *sel, const char *path);
int path_matches_selectors(const char *path,
                           const char **sels, int nsels);

/* ------------------------------------------------------------------ */
/* Date filters (-datestart / -dateend / -year)                        */
/* ------------------------------------------------------------------ */

/* A date filter: an entry matches only if its mtime is in range and
 * (when given) in the given year. Unset bounds are -1 (start/end)
 * and 0 (year). All bounds are UTC, seconds since the epoch. */
typedef struct {
    int64_t start;              /* -1: no lower bound */
    int64_t end;                /* -1: no upper bound (inclusive) */
    int year;                   /* 0: no year filter */
} date_filter_t;

int date_filter_active(const date_filter_t *f);
/* Does an entry with this mtime pass the filter? */
int date_filter_matches(const date_filter_t *f, uint64_t mtime);
/* Parse a date: "YYYY-MM-DD" (midnight at the start of that day, or
 * 23:59:59 at the end of it when is_end is set) or
 * "YYYY-MM-DDTHH:MM:SS" (exact; a space may replace the 'T').
 * Returns 0 on success, -1 on a bad format or an impossible date.
 * All times are UTC. */
int parse_date(const char *s, int is_end, int64_t *out);

/* Format an mtime as "YYYY-MM-DD HH:MM:SS UTC" into buf. */
void fmt_mtime(uint64_t mtime, char *buf, size_t bufsz);
/* Format permissions as a 10-character string, e.g. "drwxr-xr-x"
 * or "-rw-r--r--". The stored mode holds only the low 12 bits, so
 * the type letter comes from is_dir. */
void fmt_perm(int is_dir, uint32_t mode, char *buf);

/* ------------------------------------------------------------------ */
/* Archive scan                                                        */
/* ------------------------------------------------------------------ */

/* One entry found by scanning an archive: its stored path, its file
 * offset (start of the 78-byte header), and its total on-disk length
 * (78 + path_len + stored_size). */
typedef struct {
    char *path;
    off_t offset;
    uint64_t total_len;
    int is_dir;
} scan_entry_t;

typedef struct {
    scan_entry_t *v;
    size_t len, cap;
} scan_list_t;

void scan_list_free(scan_list_t *l);

/* Scan an archive and record every entry. Returns 0 on success.
 * On success *end_off_out is the file offset of the 2-byte end
 * marker (which must be the last 2 bytes of the file), and the
 * scanned entry count is in *nentries_out (the header's stored
 * count is returned in *count_out but the scanned count is the
 * ground truth). Returns -1 (with a message) if the file is not a
 * valid archive, an entry header is corrupt, or there are trailing
 * bytes after the end marker. */
int scan_archive(const char *path, int *version_out,
                 uint32_t *count_out, off_t *size_out,
                 scan_list_t *entries, off_t *end_off_out);

/* Copy n bytes from src (positioned at the start) to dst, streaming.
 * Returns 0 on success, -1 on a short read/write. */
int copy_bytes(FILE *src, FILE *dst, uint64_t n);

/* Create a temp file in the same directory as path (so rename() can
 * replace path atomically), returning the FILE* and the temp pathname
 * in *tmp_out (caller frees it). Returns NULL on failure. */
FILE *temp_in_same_dir(const char *path, char **tmp_out);

#endif /* LZPLY_LIB_H */
