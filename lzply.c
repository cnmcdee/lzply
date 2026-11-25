/* lzply.c - lzip + BCH archive tool.
 *
 * One archive file (like zip) holding many entries. Every entry is an
 * independent byte stream: lzip-compressed, optionally
 * error-correction protected. Pipeline per entry:
 *
 *   compress -> BCH-encode     (on write)
 *   BCH-decode -> decompress   (on read)
 *
 * The parity protects the bytes actually stored on disk, so a damaged
 * block is corrected before decompression is attempted. Every entry
 * carries a SHA-256 of its original data, which catches any
 * BCH miscorrection (a bounded-distance decoder can land on a
 * different valid codeword when damage exceeds the level's limit).
 * Every entry also carries the source file's modification time
 * (mtime, seconds since the epoch, UTC), so entries can be found,
 * listed, and extracted by date.
 *
 * Error correction: binary BCH over GF(2), using the 82 narrow-sense
 * primitive generator polynomials embedded in bch_polys.h (rssearch,
 * m=7..22, t=1,2,4,8,16,32). BCH corrects bit errors and needs
 * 39-42% less parity than Reed-Solomon for the same t. The -e level
 * selects the BCH correction level t (0=none, 1->1, 2->2, 3->4, 4->8,
 * 5->16, 6->32, 7->32; default -e 4, i.e. t=8), and `poly=NN` pins one
 * polynomial by id (hex or decimal) instead of auto-picking. With no
 * poly given, the most efficient poly for each entry's blob length
 * is picked automatically (smallest parent covering the blob).
 * A blob longer than one block's capacity is split into blocks of
 * the poly's max payload; the decoder rebuilds the boundaries from
 * blob_size + the poly.
 *
 * Appending (-a): new files/dirs are added to an existing archive
 * without rewriting it — entries are staged to a temp file, then
 * appended just before the end marker, and the global entry_count
 * is updated in place. If a stored path being added already exists,
 * the archive is rewritten via a temp file (kept entries copied
 * byte-for-byte, replaced entries dropped, new entries appended),
 * then renamed over the original, so a duplicate always leaves
 * exactly one entry per path and the new content wins. Appending to
 * a missing archive creates it, like -c.
 *
 * Selective extract (-d / -t, and -l): selectors after the dest dir
 * (or after the archive for -t / -l) restrict the operation to
 * entries whose stored path matches a selector — exactly, or as a
 * directory prefix (the next character after the prefix must be
 * '/'; a selector ending in '/' matches everything under it).
 * A selector matching nothing prints a message and exits 0.
 * Note: -a used to mean "ask before overwriting"; it is now the
 * append mode, and ask-overwrite is --ask only (it is the default).
 *
 * Inspect (-i): prints every entry's path, type, permissions,
 * mtime, sizes, and error correction by reading the entry headers
 * only — it never reads entry data, never decompresses, and never
 * opens the archived files, so it is fast even on large archives.
 *
 * Tree (-tr): prints the archive contents as a tree, like the
 * Linux `tree` command, with a directory/file count at the end.
 *
 * Date filters (-datestart / -dateend / -year): restrict -d, -i,
 * -tr (and -t / -l) to entries whose mtime falls in the given range
 * or year. They AND with each other and with any path selector.
 *
 * Archive format v4 (the only format; there is no legacy support —
 * this tool has not been used anywhere yet, so old versions are not
 * kept readable). All integers little-endian:
 *   global header (16 bytes):
 *     magic "LZPL", version u8 (=4), flags u8, entry_count u32,
 *     reserved u64
 *   entries, each:
 *     u16 path_len, u8 level, u8 rs_level, u8 flags, u8 reserved,
 *     u64 orig_size, u64 stored_size, u64 blob_size, u8 sha256[32],
 *     u32 mode, u64 mtime, u32 header_crc32,
 *     path[path_len], data[stored_size]
 *     (header_crc32 covers the 74 bytes before it; blob_size is the
 *     length of the compressed stream before error-correction
 *     parity was added, so the decoder knows how much data to recover;
 *     mtime is the source file's modification time, seconds since
 *     the epoch, UTC)
 *   end marker: u16 path_len == 0
 * Flags: bit 0 is unused (it was used by v3), bit 1 = directory,
 * bit 2 = BCH mode.
 * For a BCH entry, poly_id = rs_level | (reserved << 8). For an
 * entry with no error correction, rs_level and reserved are 0.
 */
#define _FILE_OFFSET_BITS 64
#define _DEFAULT_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <lzlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "bch.h"
#include "lzply_lib.h"



/* ------------------------------------------------------------------ */
/* Small utilities                                                     */
/* ------------------------------------------------------------------ */














/* ------------------------------------------------------------------ */
/* lzip (liblz) in-memory compression                                  */
/* ------------------------------------------------------------------ */





/* ------------------------------------------------------------------ */
/* Per-entry encode / decode                                           */
/* ------------------------------------------------------------------ */





/* ------------------------------------------------------------------ */
/* Filesystem helpers                                                  */
/* ------------------------------------------------------------------ */

static int read_file(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    buf_t b;
    uint8_t tmp[65536];
    size_t n;
    if (!f)
        return -1;
    buf_init(&b);
    while ((n = fread(tmp, 1, sizeof tmp, f)) > 0)
        buf_append(&b, tmp, n);
    if (ferror(f)) {
        fclose(f);
        buf_free(&b);
        return -1;
    }
    fclose(f);
    *out = b.data;
    *out_len = b.len;
    return 0;
}

static int write_file(const char *path, const uint8_t *data, size_t len,
                      uint32_t mode)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    if (len > 0 && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0)
        return -1;
    chmod(path, (mode_t)(mode & 07777));
    return 0;
}

/* mkdir -p: create every component of path (which must be a directory). */
static int mkdir_p(const char *path, uint32_t mode)
{
    char *tmp = xstrdup(path);
    char *p;
    int rc = 0;
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, (mode_t)(mode & 07777)) != 0 && errno != EEXIST)
                rc = -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, (mode_t)(mode & 07777)) != 0 && errno != EEXIST)
        rc = -1;
    free(tmp);
    return rc;
}


/* Absolute path (lexical only; does not resolve symlinks). */
static char *abs_path(const char *path)
{
    char cwd[PATH_MAX];
    char *r;
    if (path[0] == '/')
        return xstrdup(path);
    if (!getcwd(cwd, sizeof cwd))
        return xstrdup(path);
    r = xmalloc(strlen(cwd) + strlen(path) + 2);
    sprintf(r, "%s/%s", cwd, path);
    return r;
}

/* Overwrite modes. */
enum { OW_ASK, OW_YES, OW_NO };

/* Returns 1 to proceed, 0 to skip. */
static int ask_overwrite(const char *path, int mode)
{
    struct stat st;
    char line[64];
    if (stat(path, &st) != 0)
        return 1;               /* does not exist: proceed */
    if (mode == OW_YES)
        return 1;
    if (mode == OW_NO) {
        fprintf(stderr, "%s: %s exists, skipping (--no-clobber)\n",
                lzply_progname, path);
        return 0;
    }
    fprintf(stderr, "%s: %s exists. Overwrite? [y/N] ", lzply_progname, path);
    fflush(stderr);
    if (!fgets(line, sizeof line, stdin))
        return 0;
    return (line[0] == 'y' || line[0] == 'Y') ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Entry list + recursive directory walk                               */
/* ------------------------------------------------------------------ */

typedef struct {
    char *full;                 /* absolute source path */
    char *stored;               /* path stored in the archive */
    int is_dir;
    uint32_t mode;
    uint64_t size;
    uint64_t mtime;             /* source mtime, seconds since epoch (UTC) */
} entry_t;

typedef struct {
    entry_t *v;
    size_t len, cap;
} entry_list_t;

static void entry_list_add(entry_list_t *l, const char *full,
                           const char *stored, int is_dir, uint32_t mode,
                           uint64_t size, uint64_t mtime)
{
    if (l->len == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 64;
        l->v = xrealloc(l->v, l->cap * sizeof(entry_t));
    }
    l->v[l->len].full = xstrdup(full);
    l->v[l->len].stored = xstrdup(stored);
    l->v[l->len].is_dir = is_dir;
    l->v[l->len].mode = mode;
    l->v[l->len].size = size;
    l->v[l->len].mtime = mtime;
    l->len++;
}

static void entry_list_free(entry_list_t *l)
{
    size_t i;
    for (i = 0; i < l->len; i++) {
        free(l->v[i].full);
        free(l->v[i].stored);
    }
    free(l->v);
    l->v = NULL;
    l->len = l->cap = 0;
}

static int cmp_entry(const void *a, const void *b)
{
    return strcmp(((const entry_t *)a)->stored, ((const entry_t *)b)->stored);
}

static void walk_dir(const char *full, const char *stored, entry_list_t *l)
{
    DIR *d = opendir(full);
    struct dirent *de;
    if (!d) {
        fprintf(stderr, "%s: cannot open directory %s: %s\n",
                lzply_progname, full, strerror(errno));
        return;
    }
    while ((de = readdir(d)) != NULL) {
        char *child_full, *child_stored;
        struct stat st;
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        child_full = xmalloc(strlen(full) + strlen(de->d_name) + 2);
        sprintf(child_full, "%s/%s", full, de->d_name);
        child_stored = xmalloc(strlen(stored) + strlen(de->d_name) + 2);
        sprintf(child_stored, "%s/%s", stored, de->d_name);
        if (lstat(child_full, &st) != 0) {
            fprintf(stderr, "%s: cannot stat %s: %s\n",
                    lzply_progname, child_full, strerror(errno));
            free(child_full);
            free(child_stored);
            continue;
        }
        if (S_ISLNK(st.st_mode)) {
            fprintf(stderr, "%s: skipping symlink %s (not stored)\n",
                    lzply_progname, child_full);
        } else if (S_ISDIR(st.st_mode)) {
            char *dstored = xmalloc(strlen(child_stored) + 2);
            sprintf(dstored, "%s/", child_stored);
            entry_list_add(l, child_full, dstored, 1,
                           (uint32_t)(st.st_mode & 07777), 0,
                           (uint64_t)st.st_mtime);
            free(dstored);
            walk_dir(child_full, child_stored, l);
        } else if (S_ISREG(st.st_mode)) {
            entry_list_add(l, child_full, child_stored, 0,
                           (uint32_t)(st.st_mode & 07777),
                           (uint64_t)st.st_size,
                           (uint64_t)st.st_mtime);
        } else {
            fprintf(stderr, "%s: skipping special file %s\n",
                    lzply_progname, child_full);
        }
        free(child_full);
        free(child_stored);
    }
    closedir(d);
}

/* ------------------------------------------------------------------ */
/* Archive header I/O                                                  */
/* ------------------------------------------------------------------ */





/* ------------------------------------------------------------------ */
/* Commands                                                            */
/* ------------------------------------------------------------------ */

static const char *human_size(uint64_t n, char *buf, size_t bufsz)
{
    static const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = (double)n;
    int u = 0;
    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        u++;
    }
    if (u == 0)
        snprintf(buf, bufsz, "%" PRIu64 " B", n);
    else
        snprintf(buf, bufsz, "%.1f %s", v, units[u]);
    return buf;
}

/* ------------------------------------------------------------------ */
/* Entry collection + writing (shared by -c and -a)                    */
/* ------------------------------------------------------------------ */

/* Collect stored entries for the given inputs. exclude_abs (may be
 * NULL) is an absolute path to skip (the archive/output file itself);
 * exclude_why names it in the skip message ("the output file" for
 * -c, "the archive" for -a). Unreadable files are dropped with a
 * warning. Returns 0 on success, -1 on error (stat failure, or an
 * input that is not a file or directory). *skipped_out counts the
 * dropped files. */
static int collect_inputs(const char **inputs, int ninputs,
                          const char *exclude_abs, const char *exclude_why,
                          entry_list_t *list, int *skipped_out)
{
    int skipped = 0;
    int i;
    size_t j;
    for (i = 0; i < ninputs; i++) {
        struct stat st;
        char *root;
        if (stat(inputs[i], &st) != 0) {
            fprintf(stderr, "%s: cannot stat %s: %s\n", lzply_progname, inputs[i],
                    strerror(errno));
            return -1;
        }
        root = realpath(inputs[i], NULL);
        if (!root) {
            fprintf(stderr, "%s: cannot resolve %s: %s\n", lzply_progname, inputs[i],
                    strerror(errno));
            return -1;
        }
        if (S_ISDIR(st.st_mode)) {
            const char *base = strrchr(root, '/');
            char *dstored;
            base = base ? base + 1 : root;
            dstored = xmalloc(strlen(base) + 2);
            sprintf(dstored, "%s/", base);
            entry_list_add(list, root, dstored, 1,
                           (uint32_t)(st.st_mode & 07777), 0,
                           (uint64_t)st.st_mtime);
            free(dstored);
            walk_dir(root, base, list);
        } else if (S_ISREG(st.st_mode)) {
            const char *base = strrchr(root, '/');
            base = base ? base + 1 : root;
            entry_list_add(list, root, base, 0,
                           (uint32_t)(st.st_mode & 07777),
                           (uint64_t)st.st_size,
                           (uint64_t)st.st_mtime);
        } else {
            fprintf(stderr, "%s: %s is not a regular file or directory\n",
                    lzply_progname, inputs[i]);
            free(root);
            return -1;
        }
        free(root);
    }
    qsort(list->v, list->len, sizeof(entry_t), cmp_entry);
    /* Drop unreadable files and the excluded file now, so the entry
     * count stays truthful. */
    for (j = 0; j < list->len; j++) {
        if (list->v[j].is_dir)
            continue;
        if (exclude_abs && strcmp(list->v[j].full, exclude_abs) == 0) {
            fprintf(stderr, "%s: skipping %s (it is %s)\n",
                    lzply_progname, list->v[j].full, exclude_why);
            skipped++;
            free(list->v[j].full);
            free(list->v[j].stored);
            memmove(&list->v[j], &list->v[j + 1],
                    (list->len - j - 1) * sizeof(entry_t));
            list->len--;
            j--;
            continue;
        }
        {
            FILE *t = fopen(list->v[j].full, "rb");
            if (!t) {
                fprintf(stderr, "%s: skipping unreadable %s: %s\n",
                        lzply_progname, list->v[j].full, strerror(errno));
                skipped++;
                free(list->v[j].full);
                free(list->v[j].stored);
                memmove(&list->v[j], &list->v[j + 1],
                        (list->len - j - 1) * sizeof(entry_t));
                list->len--;
                j--;
            } else {
                fclose(t);
            }
        }
    }
    *skipped_out = skipped;
    return 0;
}

/* Write all entries in list to the open file f (positioned where the
 * entries go). Directories are written as dir entries; files are
 * read, encoded and written. Prints one line per entry, like -c.
 * Returns 0 on success, -1 on failure (read/encode/write error).
 * On failure the caller must discard f's contents. *any_bch_out is
 * set if any file entry used BCH; totals accumulate into
 * *total_in_out / *total_out_out. */
static int write_entries(FILE *f, entry_list_t *list, int level,
                         const ecc_opt_t *ecc,
                         int *any_bch_out, uint64_t *total_in_out,
                         uint64_t *total_out_out)
{
    size_t i;
    int any_bch = 0;
    uint64_t total_in = 0, total_out = 0;
    for (i = 0; i < list->len; i++) {
        entry_t *e = &list->v[i];
        ehdr_t h;
        uint8_t *raw = NULL, *stored = NULL;
        size_t raw_len = 0, stored_len = 0, blob_len = 0;
        uint16_t poly_id = 0;
        int is_bch = 0;
        int eff_level = level;
        memset(&h, 0, sizeof h);
        h.path = e->stored;
        h.level = (uint8_t)level;
        h.mode = e->mode;
        h.mtime = e->mtime;
        if (e->is_dir) {
            h.flags = FLAG_ISDIR;
            h.orig_size = 0;
            h.stored_size = 0;
            h.blob_size = 0;
            lzply_sha256((const uint8_t *)"", 0, h.sha);
            if (write_entry_header(f, &h) != 0)
                return -1;
            printf("  %s/ (dir)\n", e->stored);
            continue;
        }
        if (read_file(e->full, &raw, &raw_len) != 0) {
            fprintf(stderr, "%s: cannot read %s, aborting\n",
                    lzply_progname, e->full);
            return -1;
        }
        if (entry_encode(raw, raw_len, level, ecc,
                         &stored, &stored_len, &blob_len, &poly_id, &is_bch,
                         &eff_level, h.sha) != 0) {
            fprintf(stderr, "%s: failed to encode %s\n", lzply_progname, e->full);
            free(raw);
            return -1;
        }
        free(raw);
        h.level = (uint8_t)eff_level;   /* 0 when stored uncompressed */
        h.flags = 0;
        if (is_bch) {
            h.flags |= FLAG_BCH;
            h.rs_level = (uint8_t)(poly_id & 0xff);
            h.reserved = (uint8_t)(poly_id >> 8);
            any_bch = 1;
        }
        h.orig_size = raw_len;
        h.stored_size = stored_len;
        h.blob_size = blob_len;
        if (write_entry_header(f, &h) != 0 ||
            (stored_len > 0 &&
             fwrite(stored, 1, stored_len, f) != stored_len)) {
            free(stored);
            return -1;
        }
        {
            char b1[32], b2[32];
            double ratio = raw_len ? 100.0 * (double)stored_len / (double)raw_len : 0.0;
            printf("  %s  %s -> %s (%.1f%%)\n", e->stored,
                   human_size(raw_len, b1, sizeof b1),
                   human_size(stored_len, b2, sizeof b2), ratio);
        }
        total_in += raw_len;
        total_out += stored_len;
        free(stored);
    }
    *any_bch_out = any_bch;
    *total_in_out = total_in;
    *total_out_out = total_out;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Selectors (for -d / -t / -l)                                        */
/* ------------------------------------------------------------------ */



/* ------------------------------------------------------------------ */
/* Date filters (-datestart / -dateend / -year)                        */
/* ------------------------------------------------------------------ */







/* ------------------------------------------------------------------ */
/* Archive scan (for -a)                                               */
/* ------------------------------------------------------------------ */








/* Create a fresh archive from the given inputs (files and/or
 * directories). output_arg may be NULL, in which case the output is
 * inputs[0] with trailing slashes stripped + ".lzply" (the -c
 * default). Stored paths are relative to each input's parent, as
 * before. */
static int cmd_create(const char **inputs, int ninputs, const char *output_arg,
                      int level, const ecc_opt_t *ecc,
                      int ow_mode)
{
    char *out_path = NULL, *out_abs = NULL;
    char *stripped = NULL;
    entry_list_t list;
    FILE *f = NULL;
    int skipped = 0, rc = 0;
    int any_bch = 0;
    uint64_t total_in = 0, total_out = 0;

    memset(&list, 0, sizeof list);
    /* Default output: first input path with trailing slashes stripped
     * + ".lzply". */
    stripped = xstrdup(inputs[0]);
    {
        size_t n = strlen(stripped);
        while (n > 1 && stripped[n - 1] == '/')
            stripped[--n] = '\0';
    }
    if (output_arg) {
        out_path = xstrdup(output_arg);
    } else {
        out_path = xmalloc(strlen(stripped) + 6);
        sprintf(out_path, "%s.lzply", stripped);
    }
    out_abs = abs_path(out_path);
    if (ninputs == 1) {
        /* -c with a single input: refuse to overwrite the input itself. */
        char *root = realpath(inputs[0], NULL);
        if (root) {
            if (strcmp(out_abs, root) == 0) {
                fprintf(stderr, "%s: output would overwrite the input\n",
                        lzply_progname);
                free(root);
                rc = EXIT_USAGE;
                goto done;
            }
            free(root);
        }
    }
    if (!ask_overwrite(out_path, ow_mode)) {
        rc = 0;
        goto done;
    }
    if (collect_inputs(inputs, ninputs, out_abs, "the output file",
                       &list, &skipped) != 0) {
        rc = EXIT_IO;
        goto done;
    }
    /* The format is v4, always. */
    f = fopen(out_path, "wb");
    if (!f) {
        fprintf(stderr, "%s: cannot create %s: %s\n", lzply_progname, out_path,
                strerror(errno));
        rc = EXIT_IO;
        goto done;
    }
    write_global_header(f, (uint32_t)list.len, LZPLY_VERSION);
    if (write_entries(f, &list, level, ecc, &any_bch,
                      &total_in, &total_out) != 0) {
        fclose(f);
        unlink(out_path);
        rc = EXIT_IO;
        goto done;
    }
    (void)any_bch;
    {
        uint8_t end[2] = {0, 0};
        if (fwrite(end, 1, 2, f) != 2)
            goto write_fail;
    }
    if (fclose(f) != 0) {
        fprintf(stderr, "%s: error closing %s: %s\n", lzply_progname, out_path,
                strerror(errno));
        rc = EXIT_IO;
        goto done;
    }
    f = NULL;
    {
        char b1[32], b2[32];
        printf("%s: wrote %s (%zu entries, %s -> %s)%s\n", lzply_progname,
               out_path, list.len, human_size(total_in, b1, sizeof b1),
               human_size(total_out, b2, sizeof b2),
               skipped ? " [some files skipped]" : "");
    }
    rc = skipped ? EXIT_IO : 0;
    goto done;
write_fail:
    fprintf(stderr, "%s: write failed on %s: %s\n", lzply_progname, out_path,
            strerror(errno));
    if (f)
        fclose(f);
    unlink(out_path);
    rc = EXIT_IO;
done:
    entry_list_free(&list);
    free(out_path);
    free(out_abs);
    free(stripped);
    return rc;
}

/* Append files/dirs to an existing archive (or create it if it does
 * not exist). inputs[0..ninputs) are the files/dirs to add; stored
 * paths are relative to each input's parent, exactly as -c does.
 * New entries use the same -e / poly= options as -c.
 * Without duplicates this is a true incremental append: the new
 * entries are staged to a temp file, appended just before the end
 * marker, and entry_count (and the version byte, if any new entry
 * uses BCH) is updated in place. With duplicates the archive is
 * rewritten via a temp file (kept entries copied byte-for-byte,
 * replaced entries dropped, new entries appended) and renamed over
 * the original, so exactly one entry per path remains and the new
 * content wins. Returns an exit code. */
static int cmd_append(const char *archive, const char **inputs, int ninputs,
                      int level, const ecc_opt_t *ecc)
{
    struct stat st;
    char *arch_abs = NULL;
    char *replaced = NULL;      /* per old entry: 1 if replaced by a new file */
    int old_version = LZPLY_VERSION;
    uint32_t old_count = 0;
    off_t size = 0, end_off = 0;
    scan_list_t old;
    entry_list_t list;
    int skipped = 0;
    int rc = 0;
    uint32_t new_count;
    size_t i, j, nrep = 0;
    int has_dup = 0;

    memset(&list, 0, sizeof list);
    memset(&old, 0, sizeof old);
    if (stat(archive, &st) != 0) {
        if (errno == ENOENT) {
            /* No archive yet: create it, like -c. */
            return cmd_create(inputs, ninputs, archive, level, ecc,
                              OW_YES);
        }
        fprintf(stderr, "%s: cannot stat %s: %s\n", lzply_progname, archive,
                strerror(errno));
        return EXIT_IO;
    }
    if (scan_archive(archive, &old_version, &old_count, &size, &old,
                     &end_off) != 0)
        return EXIT_CORRUPT;
    arch_abs = abs_path(archive);
    if (collect_inputs(inputs, ninputs, arch_abs, "the archive",
                       &list, &skipped) != 0) {
        scan_list_free(&old);
        free(arch_abs);
        return EXIT_IO;
    }
    /* Drop new directory entries that already exist in the archive:
     * a dir entry is only a marker, so there is nothing to replace. */
    for (i = 0; i < list.len; i++) {
        if (!list.v[i].is_dir)
            continue;
        for (j = 0; j < old.len; j++) {
            if (strcmp(list.v[i].stored, old.v[j].path) == 0) {
                free(list.v[i].full);
                free(list.v[i].stored);
                memmove(&list.v[i], &list.v[i + 1],
                        (list.len - i - 1) * sizeof(entry_t));
                list.len--;
                i--;
                break;
            }
        }
    }
    if (list.len == 0) {
        printf("%s: nothing to add to %s\n", lzply_progname, archive);
        scan_list_free(&old);
        entry_list_free(&list);
        free(arch_abs);
        return 0;
    }
    replaced = xmalloc(old.len ? old.len : 1);
    memset(replaced, 0, old.len ? old.len : 1);
    for (i = 0; i < list.len; i++) {
        for (j = 0; j < old.len; j++) {
            if (strcmp(list.v[i].stored, old.v[j].path) == 0) {
                replaced[j] = 1;
                has_dup = 1;
                break;
            }
        }
    }
    for (j = 0; j < old.len; j++)
        if (replaced[j])
            nrep++;
    (void)old_version;          /* the format is v4, always */
    new_count = (uint32_t)(old.len - nrep + list.len);
    if (!has_dup) {
        /* True incremental append: stage the new entries to a temp
         * file, append them just before the end marker, then update
         * the global header in place. The archive is only touched
         * once every new entry has encoded successfully. */
        char *tmp_path = NULL;
        FILE *tmp = temp_in_same_dir(archive, &tmp_path);
        FILE *af = NULL;
        int any_bch = 0;
        uint64_t total_in = 0, total_out = 0;
        uint8_t vbuf[4];
        off_t tmp_size;
        if (!tmp) {
            rc = EXIT_IO;
            goto append_done;
        }
        if (write_entries(tmp, &list, level, ecc, &any_bch,
                          &total_in, &total_out) != 0) {
            fclose(tmp);
            unlink(tmp_path);
            free(tmp_path);
            rc = EXIT_IO;
            goto append_done;
        }
        (void)any_bch;
        (void)total_in;
        (void)total_out;
        if (fflush(tmp) != 0 || fseeko(tmp, 0, SEEK_END) != 0) {
            fclose(tmp);
            unlink(tmp_path);
            free(tmp_path);
            rc = EXIT_IO;
            goto append_done;
        }
        tmp_size = ftello(tmp);
        af = fopen(archive, "r+b");
        if (!af) {
            fprintf(stderr, "%s: cannot open %s: %s\n", lzply_progname,
                    archive, strerror(errno));
            fclose(tmp);
            unlink(tmp_path);
            free(tmp_path);
            rc = EXIT_IO;
            goto append_done;
        }
        if (fseeko(tmp, 0, SEEK_SET) != 0 ||
            fseeko(af, end_off, SEEK_SET) != 0 ||
            copy_bytes(tmp, af, (uint64_t)tmp_size) != 0) {
            fprintf(stderr, "%s: failed appending to %s: %s\n",
                    lzply_progname, archive, strerror(errno));
            fclose(tmp);
            fclose(af);
            unlink(tmp_path);
            free(tmp_path);
            rc = EXIT_IO;
            goto append_done;
        }
        fclose(tmp);
        unlink(tmp_path);
        free(tmp_path);
        tmp = NULL;
        tmp_path = NULL;
        {
            uint8_t end[2] = {0, 0};
            if (fwrite(end, 1, 2, af) != 2) {
                fprintf(stderr, "%s: failed appending to %s: %s\n",
                        lzply_progname, archive, strerror(errno));
                fclose(af);
                rc = EXIT_IO;
                goto append_done;
            }
        }
        /* Update version (offset 4) and entry count (offset 6). */
        if (fseeko(af, 4, SEEK_SET) != 0 ||
            fputc(LZPLY_VERSION, af) == EOF ||
            fseeko(af, 6, SEEK_SET) != 0) {
            fprintf(stderr, "%s: failed updating header of %s: %s\n",
                    lzply_progname, archive, strerror(errno));
            fclose(af);
            rc = EXIT_IO;
            goto append_done;
        }
        put32le(vbuf, new_count);
        if (fwrite(vbuf, 1, 4, af) != 4) {
            fprintf(stderr, "%s: failed updating header of %s: %s\n",
                    lzply_progname, archive, strerror(errno));
            fclose(af);
            rc = EXIT_IO;
            goto append_done;
        }
        if (fflush(af) != 0 || fsync(fileno(af)) != 0) {
            fprintf(stderr, "%s: failed writing %s: %s\n",
                    lzply_progname, archive, strerror(errno));
            fclose(af);
            rc = EXIT_IO;
            goto append_done;
        }
        fclose(af);
        printf("%s: added %zu entries to %s (%u entries total)%s\n",
               lzply_progname, list.len, archive, new_count,
               skipped ? " [some files skipped]" : "");
        rc = skipped ? EXIT_IO : 0;
        goto append_done;
    }
    /* Duplicates: rewrite via a temp file, then rename over the
     * original. Kept entries are copied byte-for-byte; replaced
     * entries are dropped; new entries are appended. The original
     * is untouched until the rename, so a failure leaves it intact. */
    {
        char *tmp_path = NULL;
        FILE *tmp = temp_in_same_dir(archive, &tmp_path);
        FILE *src = NULL;
        int any_bch = 0;
        uint64_t total_in = 0, total_out = 0;
        struct stat ost;
        if (!tmp) {
            rc = EXIT_IO;
            goto append_done;
        }
        write_global_header(tmp, new_count, LZPLY_VERSION);
        src = fopen(archive, "rb");
        if (!src) {
            fprintf(stderr, "%s: cannot open %s: %s\n", lzply_progname,
                    archive, strerror(errno));
            fclose(tmp);
            unlink(tmp_path);
            free(tmp_path);
            rc = EXIT_IO;
            goto append_done;
        }
        for (j = 0; j < old.len; j++) {
            if (replaced[j])
                continue;
            if (fseeko(src, old.v[j].offset, SEEK_SET) != 0 ||
                copy_bytes(src, tmp, old.v[j].total_len) != 0) {
                fprintf(stderr, "%s: failed rewriting %s: %s\n",
                        lzply_progname, archive, strerror(errno));
                fclose(src);
                fclose(tmp);
                unlink(tmp_path);
                free(tmp_path);
                rc = EXIT_IO;
                goto append_done;
            }
        }
        fclose(src);
        src = NULL;
        if (write_entries(tmp, &list, level, ecc, &any_bch,
                          &total_in, &total_out) != 0) {
            fclose(tmp);
            unlink(tmp_path);
            free(tmp_path);
            rc = EXIT_IO;
            goto append_done;
        }
        (void)any_bch;
        (void)total_in;
        (void)total_out;
        {
            uint8_t end[2] = {0, 0};
            if (fwrite(end, 1, 2, tmp) != 2) {
                fprintf(stderr, "%s: failed writing %s: %s\n",
                        lzply_progname, archive, strerror(errno));
                fclose(tmp);
                unlink(tmp_path);
                free(tmp_path);
                rc = EXIT_IO;
                goto append_done;
            }
        }
        /* Keep the original's permissions on the rewritten archive. */
        if (stat(archive, &ost) == 0)
            fchmod(fileno(tmp), ost.st_mode & 07777);
        if (fflush(tmp) != 0 || fsync(fileno(tmp)) != 0) {
            fprintf(stderr, "%s: failed writing %s: %s\n",
                    lzply_progname, archive, strerror(errno));
            fclose(tmp);
            unlink(tmp_path);
            free(tmp_path);
            rc = EXIT_IO;
            goto append_done;
        }
        if (fclose(tmp) != 0) {
            fprintf(stderr, "%s: failed writing %s: %s\n",
                    lzply_progname, archive, strerror(errno));
            unlink(tmp_path);
            free(tmp_path);
            rc = EXIT_IO;
            goto append_done;
        }
        tmp = NULL;
        if (rename(tmp_path, archive) != 0) {
            fprintf(stderr, "%s: cannot replace %s: %s\n",
                    lzply_progname, archive, strerror(errno));
            unlink(tmp_path);
            free(tmp_path);
            rc = EXIT_IO;
            goto append_done;
        }
        free(tmp_path);
        printf("%s: added %zu entries to %s (%u entries total, %zu replaced)%s\n",
               lzply_progname, list.len, archive, new_count, nrep,
               skipped ? " [some files skipped]" : "");
        rc = skipped ? EXIT_IO : 0;
        goto append_done;
    }
append_done:
    scan_list_free(&old);
    entry_list_free(&list);
    free(arch_abs);
    free(replaced);
    return rc;
}
static int open_archive(const char *path, FILE **f_out, uint32_t *count_out,
                        off_t *size_out)
{
    struct stat st;
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "%s: cannot open %s: %s\n", lzply_progname, path,
                strerror(errno));
        return EXIT_IO;
    }
    if (fstat(fileno(f), &st) != 0) {
        fclose(f);
        return EXIT_IO;
    }
    if (read_global_header(f, count_out) != 0) {
        fprintf(stderr, "%s: %s is not an lzply archive (bad magic/version)\n",
                lzply_progname, path);
        fclose(f);
        return EXIT_CORRUPT;
    }
    *f_out = f;
    *size_out = st.st_size;
    return 0;
}

/* List an archive's contents. If selectors are given, only entries
 * matching a selector are listed; the date filter (if any) applies
 * on top of the selectors. */
static int cmd_list(const char *archive, const char **selectors, int nselectors,
                    const date_filter_t *dfilter)
{
    FILE *f = NULL;
    uint32_t count = 0;
    off_t size = 0;
    int rc = open_archive(archive, &f, &count, &size);
    uint32_t seen = 0;
    if (rc != 0)
        return rc;
    printf("%-40s %12s %12s  lvl ecc\n", "path", "original", "stored");
    for (;;) {
        ehdr_t h;
        int r = read_entry_header(f, &h);
        char b1[32], b2[32], ecc[16];
        if (r == 1)
            break;
        if (r < 0) {
            fprintf(stderr, "%s: truncated or corrupt entry header\n",
                    lzply_progname);
            fclose(f);
            return EXIT_CORRUPT;
        }
        if (!path_matches_selectors(h.path, selectors, nselectors) ||
            !date_filter_matches(dfilter, h.mtime)) {
            if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
                fprintf(stderr, "%s: truncated archive\n", lzply_progname);
                free(h.path);
                fclose(f);
                return EXIT_CORRUPT;
            }
            free(h.path);
            continue;
        }
        if (h.flags & FLAG_BCH)
            snprintf(ecc, sizeof ecc, "BCH %04x",
                     (unsigned)(h.rs_level | ((unsigned)h.reserved << 8)));
        else
            snprintf(ecc, sizeof ecc, "-");
        printf("%-40s %12s %12s  %d   %-8s\n", h.path,
               human_size(h.orig_size, b1, sizeof b1),
               human_size(h.stored_size, b2, sizeof b2),
               h.level, ecc);
        if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
            fprintf(stderr, "%s: truncated archive\n", lzply_progname);
            free(h.path);
            fclose(f);
            return EXIT_CORRUPT;
        }
        free(h.path);
        seen++;
    }
    if (seen == 0 && (nselectors > 0 || date_filter_active(dfilter))) {
        if (nselectors > 0 && date_filter_active(dfilter))
            printf("no entries match the given selector(s) and date filter(s)\n");
        else if (nselectors > 0)
            printf("no entries match the given selector(s)\n");
        else
            printf("no entries match the given date filter(s)\n");
        fclose(f);
        return 0;
    }
    printf("%u entries\n", seen);
    fclose(f);
    return 0;
}

/* Shared by -d and -t. When extract==0, data is decoded and verified
 * but not written. If selectors are given, only entries matching a
 * selector are extracted/tested; the date filter (if any) applies on
 * top of the selectors; the rest are skipped unread.
 * Returns the worst exit code seen. A selector/filter matching nothing
 * prints a message and returns 0. */
static int cmd_extract(const char *archive, const char *dest_arg,
                       int ow_mode, int extract,
                       const char **selectors, int nselectors,
                       const date_filter_t *dfilter)
{
    FILE *f = NULL;
    uint32_t count = 0;
    off_t size = 0;
    int rc = open_archive(archive, &f, &count, &size);
    int worst = 0;
    uint32_t matched = 0;
    const char *dest = dest_arg ? dest_arg : ".";
    if (rc != 0)
        return rc;
    for (;;) {
        ehdr_t h;
        int r = read_entry_header(f, &h);
        uint8_t *stored = NULL;
        if (r == 1)
            break;
        if (r < 0) {
            fprintf(stderr, "%s: truncated or corrupt entry header\n",
                    lzply_progname);
            worst = EXIT_CORRUPT;
            break;
        }
        if (h.stored_size > (uint64_t)(size - ftello(f))) {
            fprintf(stderr, "%s: entry %s claims more data than the file holds\n",
                    lzply_progname, h.path);
            free(h.path);
            worst = EXIT_CORRUPT;
            break;
        }
        if (!path_matches_selectors(h.path, selectors, nselectors) ||
            !date_filter_matches(dfilter, h.mtime)) {
            /* Skip this entry unread. */
            if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
                fprintf(stderr, "%s: truncated archive\n", lzply_progname);
                free(h.path);
                worst = EXIT_CORRUPT;
                break;
            }
            free(h.path);
            continue;
        }
        matched++;
        stored = xmalloc(h.stored_size ? (size_t)h.stored_size : 1);
        if (h.stored_size > 0 &&
            fread(stored, 1, (size_t)h.stored_size, f) != (size_t)h.stored_size) {
            fprintf(stderr, "%s: truncated data for %s\n", lzply_progname, h.path);
            free(stored);
            free(h.path);
            worst = EXIT_CORRUPT;
            break;
        }
        if (h.flags & FLAG_ISDIR) {
            if (extract) {
                char *dp = xmalloc(strlen(dest) + strlen(h.path) + 2);
                sprintf(dp, "%s/%s", dest, h.path);
                if (mkdir_p(dp, h.mode ? h.mode : 0755) != 0)
                    fprintf(stderr, "%s: cannot create directory %s: %s\n",
                            lzply_progname, dp, strerror(errno));
                free(dp);
            }
            printf("  %s/ (dir)\n", h.path);
            free(stored);
            free(h.path);
            continue;
        }
                {
            uint8_t *raw = NULL;
            size_t raw_len = 0;
            int corrected = 0;
            int is_bch = (h.flags & FLAG_BCH) != 0;
            uint16_t poly_id = (uint16_t)(h.rs_level |
                                          ((uint16_t)h.reserved << 8));
                        int dr = entry_decode(stored, (size_t)h.stored_size, h.level,
                                  is_bch, poly_id,
                                  h.sha, (size_t)h.blob_size,
                                  &raw, &raw_len, &corrected);
            free(stored);
                        if (dr != 0) {
                fprintf(stderr, "%s: %s: corrupt or unrecoverable data\n",
                        lzply_progname, h.path);
                if (EXIT_CORRUPT > worst)
                    worst = EXIT_CORRUPT;
                free(h.path);
                continue;
            }
            if (raw_len != h.orig_size) {
                fprintf(stderr, "%s: %s: size mismatch after decode\n",
                        lzply_progname, h.path);
                free(raw);
                if (EXIT_CORRUPT > worst)
                    worst = EXIT_CORRUPT;
                free(h.path);
                continue;
            }
            if (!extract) {
                printf("  %s OK%s\n", h.path,
                       corrected ? " (BCH corrected bit errors)" : "");
                free(raw);
                free(h.path);
                continue;
            }
            {
                char *dp = xmalloc(strlen(dest) + strlen(h.path) + 2);
                char *pd;
                sprintf(dp, "%s/%s", dest, h.path);
                pd = parent_dir(dp);
                if (mkdir_p(pd, 0755) != 0)
                    fprintf(stderr, "%s: cannot create %s: %s\n",
                            lzply_progname, pd, strerror(errno));
                free(pd);
                if (!ask_overwrite(dp, ow_mode)) {
                    printf("  %s skipped\n", h.path);
                    free(dp);
                    free(raw);
                    free(h.path);
                    continue;
                }
                if (write_file(dp, raw, raw_len, h.mode ? h.mode : 0644) != 0) {
                    fprintf(stderr, "%s: cannot write %s: %s\n",
                            lzply_progname, dp, strerror(errno));
                    if (EXIT_IO > worst)
                        worst = EXIT_IO;
                } else {
                    printf("  %s OK%s\n", h.path,
                           corrected ? " (BCH corrected bit errors)" : "");
                }
                free(dp);
                free(raw);
                free(h.path);
            }
        }
    }
    if (matched == 0 && (nselectors > 0 || date_filter_active(dfilter))) {
        if (nselectors > 0 && date_filter_active(dfilter))
            printf("no entries match the given selector(s) and date filter(s)\n");
        else if (nselectors > 0)
            printf("no entries match the given selector(s)\n");
        else
            printf("no entries match the given date filter(s)\n");
    }
    fclose(f);
    return worst;
}

/* Inspect an archive (-i): print every entry's path, type,
 * permissions, mtime, sizes, and error correction, reading the entry
 * headers only. Entry data is never read, never decompressed, and
 * the archived files are never opened, so this is fast even on large
 * archives — and it works on an archive whose data is corrupt, as
 * long as the headers are intact. Selectors and the date filter
 * restrict which entries are printed. Returns 0 on success. */
static int cmd_inspect(const char *archive, const char **selectors,
                       int nselectors, const date_filter_t *dfilter)
{
    FILE *f = NULL;
    uint32_t count = 0;
    off_t size = 0;
    int rc = open_archive(archive, &f, &count, &size);
    uint32_t seen = 0, ndirs = 0, nfiles = 0;
    if (rc != 0)
        return rc;
    printf("%-40s %-10s %-4s %-11s %-20s %12s %12s  %3s %-8s\n",
           "path", "type", "perm", "symbolic", "mtime (UTC)",
           "original", "stored", "lvl", "ecc");
    for (;;) {
        ehdr_t h;
        int r = read_entry_header(f, &h);
        char b1[32], b2[32], mt[32], perm[11], ecc[16];
        int is_dir;
        if (r == 1)
            break;
        if (r < 0) {
            fprintf(stderr, "%s: truncated or corrupt entry header\n",
                    lzply_progname);
            fclose(f);
            return EXIT_CORRUPT;
        }
        if (!path_matches_selectors(h.path, selectors, nselectors) ||
            !date_filter_matches(dfilter, h.mtime)) {
            if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
                fprintf(stderr, "%s: truncated archive\n", lzply_progname);
                free(h.path);
                fclose(f);
                return EXIT_CORRUPT;
            }
            free(h.path);
            continue;
        }
        is_dir = (h.flags & FLAG_ISDIR) != 0;
        fmt_mtime(h.mtime, mt, sizeof mt);
        fmt_perm(is_dir, h.mode, perm);
        if (h.flags & FLAG_BCH)
            snprintf(ecc, sizeof ecc, "BCH %04x",
                     (unsigned)(h.rs_level | ((unsigned)h.reserved << 8)));
        else
            snprintf(ecc, sizeof ecc, "-");
        printf("%-40s %-10s %04o %-11s %-20s %12s %12s  %3u %-8s\n",
               h.path, is_dir ? "directory" : "file",
               (unsigned)(h.mode & 07777), perm, mt,
               human_size(h.orig_size, b1, sizeof b1),
               human_size(h.stored_size, b2, sizeof b2),
               (unsigned)h.level,
               ecc);
        if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
            fprintf(stderr, "%s: truncated archive\n", lzply_progname);
            free(h.path);
            fclose(f);
            return EXIT_CORRUPT;
        }
        free(h.path);
        seen++;
        if (is_dir)
            ndirs++;
        else
            nfiles++;
    }
    if (seen == 0 && (nselectors > 0 || date_filter_active(dfilter))) {
        if (nselectors > 0 && date_filter_active(dfilter))
            printf("no entries match the given selector(s) and date filter(s)\n");
        else if (nselectors > 0)
            printf("no entries match the given selector(s)\n");
        else
            printf("no entries match the given date filter(s)\n");
        fclose(f);
        return 0;
    }
    printf("%u entries (%u directories, %u files)\n", seen, ndirs, nfiles);
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tree (-tr)                                                          */
/* ------------------------------------------------------------------ */

/* One node of the reconstructed directory tree. Entries are stored
 * flat (one path per entry), so the hierarchy is rebuilt from the
 * path components. A directory node with no explicit entry (its
 * files are present but the directory itself was not stored, or was
 * filtered out) is an implied node, shown for structure. */
typedef struct tree_node {
    char *name;                 /* one path component, no '/' */
    int is_dir;
    int implied;                /* dir node with no explicit entry */
    uint64_t size;              /* file orig_size (0 for directories) */
    struct tree_node **children;
    size_t nchildren, cap;
} tree_node_t;

static tree_node_t *tree_node_new(const char *name, int is_dir, int implied,
                                  uint64_t size)
{
    tree_node_t *n = xmalloc(sizeof *n);
    n->name = xstrdup(name);
    n->is_dir = is_dir;
    n->implied = implied;
    n->size = size;
    n->children = NULL;
    n->nchildren = n->cap = 0;
    return n;
}

static void tree_node_free(tree_node_t *n)
{
    size_t i;
    for (i = 0; i < n->nchildren; i++)
        tree_node_free(n->children[i]);
    free(n->children);
    free(n->name);
    free(n);
}

static int cmp_tree_node(const void *a, const void *b)
{
    return strcmp((*(tree_node_t *const *)a)->name,
                  (*(tree_node_t *const *)b)->name);
}

/* Find a child by name, or create it (as a directory unless it is
 * the last component of a file path). Returns the child. */
static tree_node_t *tree_child(tree_node_t *parent, const char *name,
                               int is_dir, int implied, uint64_t size)
{
    size_t i;
    for (i = 0; i < parent->nchildren; i++) {
        if (strcmp(parent->children[i]->name, name) == 0) {
            tree_node_t *c = parent->children[i];
            /* A node first seen as an implied directory may turn out
             * to have an explicit entry; a node first seen as a file
             * cannot also be a directory in a valid archive. */
            if (is_dir && !c->is_dir) {
                c->is_dir = 1;
                c->implied = implied;
                c->size = 0;
            } else if (is_dir && c->implied && !implied) {
                c->implied = 0;
            }
            return c;
        }
    }
    if (parent->nchildren == parent->cap) {
        parent->cap = parent->cap ? parent->cap * 2 : 8;
        parent->children = xrealloc(parent->children,
                                    parent->cap * sizeof(tree_node_t *));
    }
    parent->children[parent->nchildren] =
        tree_node_new(name, is_dir, implied, size);
    return parent->children[parent->nchildren++];
}

/* Insert one stored path into the tree. A directory entry's path
 * ends in '/'; a file entry's path does not. Intermediate components
 * are directories (implied unless an explicit entry exists). */
static void tree_insert(tree_node_t *root, const char *path, int is_dir,
                        uint64_t size)
{
    char *copy = xstrdup(path);
    char *save = NULL;
    char *comp = strtok_r(copy, "/", &save);
    tree_node_t *cur = root;
    while (comp) {
        char *next = strtok_r(NULL, "/", &save);
        int last = (next == NULL);
        if (last) {
            tree_child(cur, comp, is_dir, 0, is_dir ? 0 : size);
        } else {
            cur = tree_child(cur, comp, 1, 1, 0);
        }
        comp = next;
    }
    free(copy);
}

/* Count directories and files in the tree (excluding the root). */
static void tree_count(tree_node_t *n, uint32_t *ndirs, uint32_t *nfiles)
{
    size_t i;
    for (i = 0; i < n->nchildren; i++) {
        if (n->children[i]->is_dir)
            (*ndirs)++;
        else
            (*nfiles)++;
        tree_count(n->children[i], ndirs, nfiles);
    }
}

/* Print a node's children, each on its own line with the tree
 * connectors, recursing into directories. prefix is the indentation
 * built up from the ancestors. */
static void tree_print_children(tree_node_t *dir, const char *prefix)
{
    size_t i;
    if (dir->nchildren > 1)
        qsort(dir->children, dir->nchildren, sizeof(tree_node_t *),
              cmp_tree_node);
    for (i = 0; i < dir->nchildren; i++) {
        tree_node_t *c = dir->children[i];
        int last = (i + 1 == dir->nchildren);
        char b1[32];
        if (c->is_dir) {
            printf("%s%s%s/\n", prefix, last ? "└── " : "├── ", c->name);
        } else {
            printf("%s%s%s (%s)\n", prefix, last ? "└── " : "├── ",
                   c->name, human_size(c->size, b1, sizeof b1));
        }
        if (c->is_dir) {
            char next[4096];
            snprintf(next, sizeof next, "%s%s", prefix,
                     last ? "    " : "│   ");
            tree_print_children(c, next);
        }
    }
}

/* Print an archive as a tree, like the Linux `tree` command.
 * Headers only — entry data is never read. Selectors and the date
 * filter restrict which entries appear; a filtered-out directory
 * still appears as an implied node if one of its files is shown.
 * Returns 0 on success. */
static int cmd_tree(const char *archive, const char **selectors,
                    int nselectors, const date_filter_t *dfilter)
{
    FILE *f = NULL;
    uint32_t count = 0;
    off_t size = 0;
    int rc = open_archive(archive, &f, &count, &size);
    tree_node_t *root;
    uint32_t seen = 0, ndirs = 0, nfiles = 0;
    if (rc != 0)
        return rc;
    root = tree_node_new("", 1, 0, 0);
    for (;;) {
        ehdr_t h;
        int r = read_entry_header(f, &h);
        if (r == 1)
            break;
        if (r < 0) {
            fprintf(stderr, "%s: truncated or corrupt entry header\n",
                    lzply_progname);
            tree_node_free(root);
            fclose(f);
            return EXIT_CORRUPT;
        }
        if (!path_matches_selectors(h.path, selectors, nselectors) ||
            !date_filter_matches(dfilter, h.mtime)) {
            if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
                fprintf(stderr, "%s: truncated archive\n", lzply_progname);
                free(h.path);
                tree_node_free(root);
                fclose(f);
                return EXIT_CORRUPT;
            }
            free(h.path);
            continue;
        }
        tree_insert(root, h.path, (h.flags & FLAG_ISDIR) != 0,
                    h.orig_size);
        if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
            fprintf(stderr, "%s: truncated archive\n", lzply_progname);
            free(h.path);
            tree_node_free(root);
            fclose(f);
            return EXIT_CORRUPT;
        }
        free(h.path);
        seen++;
    }
    if (seen == 0 && (nselectors > 0 || date_filter_active(dfilter))) {
        if (nselectors > 0 && date_filter_active(dfilter))
            printf("no entries match the given selector(s) and date filter(s)\n");
        else if (nselectors > 0)
            printf("no entries match the given selector(s)\n");
        else
            printf("no entries match the given date filter(s)\n");
        tree_node_free(root);
        fclose(f);
        return 0;
    }
    printf("%s\n", archive);
    tree_print_children(root, "");
    tree_count(root, &ndirs, &nfiles);
    printf("\n%u directories, %u files\n", ndirs, nfiles);
    tree_node_free(root);
    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/* CLI                                                                 */
/* ------------------------------------------------------------------ */

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: %s -c|-d|-l|-t|-a|-i|-tr [options] <input> [output] [selectors...]\n"
        "\n"
        "  -c            compress a file or directory into one .lzply archive\n"
        "  -a            append files/dirs to an archive (creates it if\n"
        "                missing): -a <archive.lzply> <file|dir> [...]\n"
        "                New entries use the same -e / poly=\n"
        "                options as -c. A stored path that already exists\n"
        "                is replaced (exactly one entry per path remains).\n"
        "                Without duplicates the append is incremental\n"
        "                (no rewrite of the existing archive).\n"
        "  -d            decompress an archive (extracts into [output] dir, default .)\n"
        "                With selectors after the dest dir, extracts only\n"
        "                matching entries: -d <arc> <dest> <selector> [...]\n"
        "  -l            list an archive's contents (selectors filter it)\n"
        "  -t            test an archive (decode and verify, write nothing)\n"
        "                Selectors go right after the archive: -t <arc> <selector> [...]\n"
        "  -i            inspect an archive: path, type, permissions,\n"
        "                mtime, sizes, level, and error correction for every\n"
        "                entry, from the headers only — no data is read,\n"
        "                nothing is decompressed. Selectors filter it.\n"
        "  -tr           print an archive as a tree, like the Linux\n"
        "                `tree` command, with a directory/file count.\n"
        "                Selectors filter it.\n"
        "  -datestart <date>  only entries with mtime on or after this date\n"
        "  -dateend <date>    only entries with mtime on or before this date\n"
        "                Dates are YYYY-MM-DD (whole day, inclusive) or\n"
        "                YYYY-MM-DDTHH:MM:SS (exact). Filters -d, -i, -tr\n"
        "                (and -t, -l); they AND with each other and with\n"
        "                any path selector.\n"
        "  -year <YYYY>  only entries whose mtime falls in that year\n"
        "                (same as that year's Jan 1 - Dec 31). Combines\n"
        "                with -datestart / -dateend; both must match.\n"
        "  -0 .. -9      compression level, like lzip (default -6). -0\n"
        "                stores entries uncompressed; BCH still applies.\n"
        "                Without -0, an entry whose compressed blob would\n"
        "                be no smaller than the original is stored\n"
        "                uncompressed automatically (level 0).\n"
        "  -e <0..7>     BCH correction level t: 0 = none, 1 -> t=1,\n"
        "                2 -> t=2, 3 -> t=4, 4 -> t=8, 5 -> t=16,\n"
        "                6 -> t=32, 7 -> t=32 (default -e 4, t=8).\n"
        "                -e 0 writes no error correction.\n"
        "  poly=NN       pin one BCH polynomial by id, hex (poly=003a)\n"
        "                or decimal (poly=58); overrides -e. The id must\n"
        "                be one of the 82 embedded polys (0001..0052).\n"
        "                Without poly=, the most efficient poly for each\n"
        "                file's blob length is picked automatically.\n"
        "  -y            overwrite without asking\n"
        "  -n            never overwrite (skip existing files)\n"
        "  --ask         ask before overwriting (default). -a used to mean\n"
        "                this; it is now the append mode.\n"
        "  -h, --help    this help\n"
        "\n"
        "Selectors: a selector matches an entry if it equals the entry's\n"
        "stored path exactly, or is a prefix of it and the next character\n"
        "is '/' (so 'photos' matches 'photos/a.jpg' but not 'photos2/a.jpg').\n"
        "A selector ending in '/' matches everything under it. For -d the\n"
        "dest dir must be given explicitly when selectors are used.\n"
        "A selector matching nothing prints a message and exits 0.\n"
        "\n"
        "Examples:\n"
        "  %s -c photos/                 photos/ -> photos.lzply\n"
        "  %s -c -9 -e 5 docs/ backup.lzply\n"
        "  %s -c poly=003a src/          pin BCH poly 0x003a (m=18, t=32)\n"
        "  %s -c -e 0 docs/ no-ecc.lzply\n"
        "  %s -c -0 raw/                 store raw data uncompressed\n"
        "  %s -a backup.lzply more/       append a directory to backup.lzply\n"
        "  %s -a backup.lzply a.txt b.txt append two files\n"
        "  %s -d backup.lzply             extract into .\n"
        "  %s -d -y backup.lzply out/\n"
        "  %s -d backup.lzply out/ photos/   extract only photos/ from backup.lzply\n"
        "  %s -t backup.lzply photos/a.jpg   test only that one file\n"
        "  %s -i backup.lzply            inspect: headers only, no decompress\n"
        "  %s -tr backup.lzply           print the archive as a tree\n"
        "  %s -d backup.lzply out/ -year 2024   extract only 2024 files\n"
        "  %s -i backup.lzply -datestart 2024-01-01 -dateend 2024-06-30\n"
        "                               inspect only Jan-Jun 2024 entries\n"
        "  %s -tr backup.lzply photos/ -year 2025   tree of 2025 photos only\n"
        "\n"
        "Exit codes: 0 ok, 1 usage, 2 I/O error, 3 corrupt/unrecoverable.\n",
        lzply_progname, lzply_progname, lzply_progname, lzply_progname, lzply_progname, lzply_progname,
        lzply_progname, lzply_progname, lzply_progname, lzply_progname, lzply_progname, lzply_progname,
        lzply_progname, lzply_progname, lzply_progname, lzply_progname,
        lzply_progname);
}

enum { MODE_NONE, MODE_COMPRESS, MODE_DECOMPRESS, MODE_LIST, MODE_TEST,
       MODE_APPEND, MODE_INSPECT, MODE_TREE };

/* Parse a poly=NN value: hex if it has a 0x prefix or any a-f/A-F
 * letter, else decimal. Returns the poly, or NULL if it is not a
 * number or not one of the 82 embedded polys. */
static const bch_poly_t *parse_poly_id(const char *s)
{
    int is_hex = 0;
    const char *p = s;
    long v;
    char *end;
    if (!*s)
        return NULL;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        is_hex = 1;
        p += 2;
    } else {
        for (const char *q = s; *q; q++) {
            if ((*q >= 'a' && *q <= 'f') || (*q >= 'A' && *q <= 'F')) {
                is_hex = 1;
                break;
            }
        }
    }
    if (!*p)
        return NULL;
    v = strtol(p, &end, is_hex ? 16 : 10);
    if (*end != '\0' || v < 0 || v > 0xffff)
        return NULL;
    return bch_poly_by_id((uint16_t)v);
}

int main(int argc, char **argv)
{
    int mode = MODE_NONE;
    int level = 6;
    int ecc_level = 4;          /* default -e 4 -> BCH t=8 */
    const bch_poly_t *pinned_poly = NULL;
    int ow_mode = OW_ASK;
    date_filter_t dfilter;
    const char **args = NULL;   /* positional arguments after the options */
    int nargs = 0;
    int i;
    int rc;

    lzply_progname = argv[0];
    {
        const char *slash = strrchr(lzply_progname, '/');
        if (slash)
            lzply_progname = slash + 1;
    }
    memset(&dfilter, 0, sizeof dfilter);
    dfilter.start = -1;
    dfilter.end = -1;
    dfilter.year = 0;
    crc32_init();

    /* Positional arguments are collected here, and options are
     * recognised anywhere on the command line — even after the
     * positionals — so `lzply -d arc out/ -year 2024` works. */
    args = xmalloc(sizeof(char *) * (size_t)(argc > 0 ? argc : 1));
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--") == 0) {
            for (i++; i < argc; i++)
                args[nargs++] = argv[i];
            break;
        }
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage(stdout);
            free(args);
            return 0;
        }
        if (strcmp(a, "-c") == 0 || strcmp(a, "--compress") == 0) {
            mode = MODE_COMPRESS;
        } else if (strcmp(a, "-a") == 0 || strcmp(a, "--append") == 0) {
            mode = MODE_APPEND;
        } else if (strcmp(a, "-d") == 0 || strcmp(a, "--decompress") == 0) {
            mode = MODE_DECOMPRESS;
        } else if (strcmp(a, "-l") == 0 || strcmp(a, "--list") == 0) {
            mode = MODE_LIST;
        } else if (strcmp(a, "-t") == 0 || strcmp(a, "--test") == 0) {
            mode = MODE_TEST;
        } else if (strcmp(a, "-i") == 0 || strcmp(a, "--inspect") == 0) {
            mode = MODE_INSPECT;
        } else if (strcmp(a, "-tr") == 0 || strcmp(a, "--tree") == 0) {
            mode = MODE_TREE;
        } else if (strcmp(a, "-datestart") == 0 ||
                   strcmp(a, "--datestart") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: -datestart needs a date (YYYY-MM-DD)\n",
                        lzply_progname);
                return EXIT_USAGE;
            }
            if (parse_date(argv[++i], 0, &dfilter.start) != 0) {
                fprintf(stderr,
                        "%s: bad -datestart '%s' (want YYYY-MM-DD or "
                        "YYYY-MM-DDTHH:MM:SS)\n", lzply_progname, argv[i]);
                return EXIT_USAGE;
            }
        } else if (strncmp(a, "-datestart=", 11) == 0 ||
                   strncmp(a, "--datestart=", 12) == 0) {
            const char *eq = strchr(a, '=');
            if (parse_date(eq + 1, 0, &dfilter.start) != 0) {
                fprintf(stderr,
                        "%s: bad -datestart '%s' (want YYYY-MM-DD or "
                        "YYYY-MM-DDTHH:MM:SS)\n", lzply_progname, eq + 1);
                return EXIT_USAGE;
            }
        } else if (strcmp(a, "-dateend") == 0 ||
                   strcmp(a, "--dateend") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: -dateend needs a date (YYYY-MM-DD)\n",
                        lzply_progname);
                return EXIT_USAGE;
            }
            if (parse_date(argv[++i], 1, &dfilter.end) != 0) {
                fprintf(stderr,
                        "%s: bad -dateend '%s' (want YYYY-MM-DD or "
                        "YYYY-MM-DDTHH:MM:SS)\n", lzply_progname, argv[i]);
                return EXIT_USAGE;
            }
        } else if (strncmp(a, "-dateend=", 9) == 0 ||
                   strncmp(a, "--dateend=", 10) == 0) {
            const char *eq = strchr(a, '=');
            if (parse_date(eq + 1, 1, &dfilter.end) != 0) {
                fprintf(stderr,
                        "%s: bad -dateend '%s' (want YYYY-MM-DD or "
                        "YYYY-MM-DDTHH:MM:SS)\n", lzply_progname, eq + 1);
                return EXIT_USAGE;
            }
        } else if (strcmp(a, "-year") == 0 || strcmp(a, "--year") == 0) {
            char *end;
            long y;
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: -year needs a year (YYYY)\n", lzply_progname);
                return EXIT_USAGE;
            }
            y = strtol(argv[++i], &end, 10);
            if (*end != '\0' || y < 1970 || y > 9999) {
                fprintf(stderr, "%s: bad -year '%s' (want a year, e.g. 2024)\n",
                        lzply_progname, argv[i]);
                return EXIT_USAGE;
            }
            dfilter.year = (int)y;
        } else if (strncmp(a, "-year=", 6) == 0 ||
                   strncmp(a, "--year=", 7) == 0) {
            const char *eq = strchr(a, '=');
            char *end;
            long y = strtol(eq + 1, &end, 10);
            if (*end != '\0' || y < 1970 || y > 9999) {
                fprintf(stderr, "%s: bad -year '%s' (want a year, e.g. 2024)\n",
                        lzply_progname, eq + 1);
                return EXIT_USAGE;
            }
            dfilter.year = (int)y;
        } else if (strcmp(a, "-y") == 0 || strcmp(a, "--force") == 0) {
            ow_mode = OW_YES;
        } else if (strcmp(a, "-n") == 0 || strcmp(a, "--no-clobber") == 0) {
            ow_mode = OW_NO;
        } else if (strcmp(a, "--ask") == 0) {
            /* -a used to mean this; it is now the append mode. */
            ow_mode = OW_ASK;
        } else if (a[0] == '-' && a[1] >= '0' && a[1] <= '9' && a[2] == '\0') {
            level = a[1] - '0';
        } else if (strcmp(a, "-e") == 0 || strcmp(a, "--rs") == 0 ||
                   strcmp(a, "--ecc") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s: -e needs a level 0..7\n", lzply_progname);
                return EXIT_USAGE;
            }
            ecc_level = atoi(argv[++i]);
            if (ecc_level < 0 || ecc_level > 7) {
                fprintf(stderr, "%s: BCH level must be 0..7\n", lzply_progname);
                return EXIT_USAGE;
            }
        } else if (a[0] == '-' && a[1] == 'e' && a[2] != '\0') {
            ecc_level = atoi(a + 2);
            if (ecc_level < 0 || ecc_level > 7) {
                fprintf(stderr, "%s: BCH level must be 0..7\n", lzply_progname);
                return EXIT_USAGE;
            }
        } else if (strncmp(a, "poly=", 5) == 0 ||
                   strncmp(a, "-poly=", 6) == 0 ||
                   strncmp(a, "--poly=", 7) == 0) {
            const char *eq = strchr(a, '=');
            pinned_poly = parse_poly_id(eq + 1);
            if (!pinned_poly) {
                fprintf(stderr,
                        "%s: unknown BCH polynomial '%s' "
                        "(want an id 0001..0052, hex or decimal)\n",
                        lzply_progname, eq + 1);
                return EXIT_USAGE;
            }
        } else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "%s: unknown option %s\n", lzply_progname, a);
            usage(stderr);
            free(args);
            return EXIT_USAGE;
        } else {
            /* Positional argument: collect it and keep scanning, so
             * options may follow positionals. */
            args[nargs++] = a;
        }
    }
    if (mode == MODE_NONE || nargs == 0) {
        usage(stderr);
        free(args);
        return EXIT_USAGE;
    }
        {
        ecc_opt_t ecc;
        ecc.t = bch_t_for_level(ecc_level);
        ecc.pinned = pinned_poly;
        switch (mode) {
        case MODE_COMPRESS:
            if (nargs > 2) {
                fprintf(stderr, "%s: too many arguments\n", lzply_progname);
                usage(stderr);
                rc = EXIT_USAGE;
                break;
            }
            rc = cmd_create(args, 1, nargs == 2 ? args[1] : NULL,
                            level, &ecc, ow_mode);
            break;
        case MODE_APPEND:
            if (nargs < 2) {
                fprintf(stderr,
                        "%s: -a needs an archive and at least one file or directory\n",
                        lzply_progname);
                usage(stderr);
                rc = EXIT_USAGE;
                break;
            }
            rc = cmd_append(args[0], args + 1, nargs - 1,
                            level, &ecc);
            break;
        case MODE_DECOMPRESS:
            /* archive, optional dest, then selectors. */
            rc = cmd_extract(args[0], nargs >= 2 ? args[1] : NULL,
                             ow_mode, 1,
                             nargs >= 3 ? args + 2 : NULL,
                             nargs >= 3 ? nargs - 2 : 0,
                             &dfilter);
            break;
        case MODE_LIST:
            /* archive, then selectors. */
            rc = cmd_list(args[0],
                          nargs >= 2 ? args + 1 : NULL,
                          nargs >= 2 ? nargs - 1 : 0,
                          &dfilter);
            break;
        case MODE_TEST:
            /* archive, then selectors (no dest dir for -t). */
            rc = cmd_extract(args[0], NULL,
                             ow_mode, 0,
                             nargs >= 2 ? args + 1 : NULL,
                             nargs >= 2 ? nargs - 1 : 0,
                             &dfilter);
            break;
        case MODE_INSPECT:
            /* archive, then selectors. */
            rc = cmd_inspect(args[0],
                             nargs >= 2 ? args + 1 : NULL,
                             nargs >= 2 ? nargs - 1 : 0,
                             &dfilter);
            break;
        case MODE_TREE:
            /* archive, then selectors. */
            rc = cmd_tree(args[0],
                          nargs >= 2 ? args + 1 : NULL,
                          nargs >= 2 ? nargs - 1 : 0,
                          &dfilter);
            break;
        default:
            rc = EXIT_USAGE;
            break;
        }
    }
    free(args);
        return rc;
}
