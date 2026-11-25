/* lzply_mount.c - mount an .lzply archive as a writable filesystem (FUSE).
 *
 *   lzply_mount [options] <archive.lzply> <mountpoint>
 *
 * At mount the archive's entry headers are scanned once (like `lzply -i`)
 * into an in-memory index; directories are reconstructed from the stored
 * paths (like `lzply -tr`). File contents are decoded on demand
 * (decode-on-open, cached). Writes go to an in-memory working copy and
 * are written back by repacking the archive on clean unmount:
 * unmodified entries are copied verbatim, modified/new entries are
 * encoded fresh. A killed daemon loses unflushed changes but never
 * corrupts the on-disk archive (the repack is temp-file + rename).
 *
 * Single-threaded (FUSE -s): all operations run on one thread, so no
 * locking is needed.
 *
 * There is no legacy support: v4 is the only archive format.
 *
 * Build stages (one FUSE command at a time):
 *   v0.1 browse: getattr, readdir            (this file, stage 1)
 *   v0.2 read:   open, read, release         (stage 2)
 *   v0.3 write:  write, truncate, flush, fsync (stage 3)
 *   v0.4 create/delete: create, mknod, mkdir, rmdir, unlink (stage 4)
 *   v0.5 rename                              (stage 5)
 *   v0.6 metadata: chmod, chown, utimens     (stage 6)
 *   v0.7 mount.lzply helper + polish          (stage 7)
 */
#define FUSE_USE_VERSION 31
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <getopt.h>
#include <limits.h>
#include "sha256.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "lzply_lib.h"
#include "bch.h"

/* renameat2 flags (linux/fs.h); defined here so lzply_mount does not need
 * that header. */
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

/* ------------------------------------------------------------------ */
/* In-memory filesystem state                                          */
/* ------------------------------------------------------------------ */

typedef struct fs_node {
    char *path;                 /* archive-relative, no leading/trailing
                                 * slash; "" is the root */
    uint32_t mode;              /* permission bits (low 12 bits) */
    uint64_t mtime;             /* seconds since epoch (UTC) */
    int is_dir;
    int is_implied;             /* synthesized dir, no archive entry */
    /* On-disk entry (valid when has_entry, i.e. the node came from the
     * archive and has not been replaced). */
    int has_entry;
    ehdr_t hdr;                 /* full entry header from the archive */
    off_t data_off;             /* offset of the stored data in the archive */
    /* Content (stages 2+): decoded file bytes, or the working copy for
     * a file being written. */
    uint8_t *content;
    size_t content_len;
    int content_loaded;         /* content holds the current file data */
    int dirty;                  /* content differs from the on-disk entry */
    int meta_dirty;             /* mode/mtime differ (header-only change) */
    int is_new;                 /* created in this session, no on-disk entry */
    int deleted;                /* removed in this session, pending repack */
    uint64_t ino;
    uint64_t load_seq;          /* load order (read-cache eviction) */
} fs_node_t;

typedef struct {
    char *archive_path;
    int level;                  /* compression level for re-encoding */
    ecc_opt_t ecc;              /* BCH options for re-encoding */
    FILE *archive;              /* open FILE* to the archive (read) */
    fs_node_t *nodes;
    size_t nnodes, cap;
    uint64_t next_ino;
    int dirty;                  /* any change pending repack */
    size_t cache_bytes;         /* bytes held in decoded content buffers */
    size_t cache_cap;           /* soft cap for the read cache (256 MiB) */
    uint64_t load_clock;        /* monotonically increasing load sequence */
} lzply_mount_state_t;

/* ------------------------------------------------------------------ */
/* Node table                                                          */
/* ------------------------------------------------------------------ */

static fs_node_t *node_find(lzply_mount_state_t *st, const char *path)
{
    size_t i;
    for (i = 0; i < st->nnodes; i++) {
        fs_node_t *n = &st->nodes[i];
        if (!n->deleted && strcmp(n->path, path) == 0)
            return n;
    }
    return NULL;
}

/* Current size of a file node: the working content when loaded,
 * otherwise the archived original size. */
static uint64_t node_size(fs_node_t *n)
{
    if (n->content_loaded)
        return (uint64_t)n->content_len;
    return n->hdr.orig_size;
}

static fs_node_t *node_add(lzply_mount_state_t *st, const char *path,
                           uint32_t mode, uint64_t mtime, int is_dir)
{
    fs_node_t *n;
    if (st->nnodes == st->cap) {
        st->cap = st->cap ? st->cap * 2 : 64;
        st->nodes = xrealloc(st->nodes, st->cap * sizeof *st->nodes);
    }
    n = &st->nodes[st->nnodes++];
    memset(n, 0, sizeof *n);
    n->path = xstrdup(path);
    n->mode = mode & 07777;
    n->mtime = mtime;
    n->is_dir = is_dir;
    n->ino = st->next_ino++;
    return n;
}

/* True if node_path is an immediate child of dir_path ("" = root). */
static int is_child_of(const char *node_path, const char *dir_path)
{
    char *p = parent_dir(node_path);
    int r;
    if (dir_path[0] == '\0')
        r = (strcmp(p, ".") == 0);
    else
        r = (strcmp(p, dir_path) == 0);
    free(p);
    return r;
}

/* Basename of an archive-relative path. */
static const char *base_name(const char *path)
{
    const char *s = strrchr(path, '/');
    return s ? s + 1 : path;
}

/* Ensure implied directory nodes exist for every parent of path.
 * Implied dirs get mode 0755 and the child's mtime. */
static void ensure_implied_dirs(lzply_mount_state_t *st, const char *path,
                                uint64_t mtime)
{
    char *tmp = xstrdup(path);
    char *slash = tmp;
    while ((slash = strchr(slash, '/')) != NULL) {
        *slash = '\0';
        if (tmp[0] != '\0' && node_find(st, tmp) == NULL)
            node_add(st, tmp, 0755, mtime, 1)->is_implied = 1;
        *slash = '/';
        slash++;
    }
    free(tmp);
}

/* Number of immediate subdirectories of dir (for st_nlink). */
static int count_subdirs(lzply_mount_state_t *st, const char *dir_path)
{
    size_t i;
    int n = 0;
    for (i = 0; i < st->nnodes; i++) {
        fs_node_t *c = &st->nodes[i];
        if (c->deleted || strcmp(c->path, dir_path) == 0)
            continue;
        if (c->is_dir && is_child_of(c->path, dir_path))
            n++;
    }
    return n;
}

/* Take the exclusive non-blocking mount lock on the open archive
 * FILE*. Two daemons on the same archive would build from the same
 * snapshot and the second one's repack would silently discard the
 * first one's changes, so a second mount is refused. The lock is
 * held for the daemon's lifetime and released by the kernel even on
 * kill -9. Returns 0 on success, -1 on failure (errno is set). */
static int lock_archive_file(FILE *f)
{
    return flock(fileno(f), LOCK_EX | LOCK_NB);
}

/* ------------------------------------------------------------------ */
/* Index build (mount)                                                 */
/* ------------------------------------------------------------------ */

static int build_index(lzply_mount_state_t *st)
{
    scan_list_t scan = {0};
    int version;
    uint32_t count;
    off_t size, end_off;
    size_t i;

    if (scan_archive(st->archive_path, &version, &count, &size,
                     &scan, &end_off) != 0) {
        fprintf(stderr, "lzply_mount: %s: not a valid lzply archive\n",
                st->archive_path);
        return -1;
    }
    st->archive = fopen(st->archive_path, "rb");
    if (!st->archive) {
        fprintf(stderr, "lzply_mount: %s: %s\n", st->archive_path,
                strerror(errno));
        scan_list_free(&scan);
        return -1;
    }
    if (lock_archive_file(st->archive) != 0) {
        if (errno == EWOULDBLOCK)
            fprintf(stderr, "lzply_mount: %s: already mounted by another lzply_mount\n",
                    st->archive_path);
        else
            fprintf(stderr, "lzply_mount: %s: cannot lock: %s\n",
                    st->archive_path, strerror(errno));
        fclose(st->archive);
        st->archive = NULL;
        scan_list_free(&scan);
        return -1;
    }
    st->next_ino = 1;
    node_add(st, "", 0755, (uint64_t)time(NULL), 1);

    for (i = 0; i < scan.len; i++) {
        scan_entry_t *e = &scan.v[i];
        ehdr_t h;
        char *rel;
        size_t len;
        off_t data_off;
        fs_node_t *n;

        if (fseeko(st->archive, e->offset, SEEK_SET) != 0 ||
            read_entry_header(st->archive, &h) != 0) {
            fprintf(stderr, "lzply_mount: %s: corrupt entry header at %lld\n",
                    st->archive_path, (long long)e->offset);
            scan_list_free(&scan);
            return -1;
        }
        rel = xstrdup(h.path);
        len = strlen(rel);
        if (len > 0 && rel[len - 1] == '/')
            rel[len - 1] = '\0';
        ensure_implied_dirs(st, rel, h.mtime);
        data_off = e->offset + LZPLY_EHDR_SIZE + (off_t)strlen(h.path);

        n = node_find(st, rel);
        if (n != NULL) {
            if (!n->is_implied || !n->is_dir || !(h.flags & FLAG_ISDIR)) {
                fprintf(stderr,
                        "lzply_mount: %s: duplicate entry for path '%s'\n",
                        st->archive_path, rel);
                free(h.path);
                free(rel);
                scan_list_free(&scan);
                return -1;
            }
            /* An implied dir turns out to have a real entry: upgrade it. */
            n->is_implied = 0;
        } else {
            n = node_add(st, rel, h.mode, h.mtime,
                         (h.flags & FLAG_ISDIR) != 0);
        }
        n->has_entry = 1;
        n->hdr = h;
        n->hdr.path = NULL;     /* hdr.path is never owned here; the
                                 * node's path is n->path (see free_state) */
        n->data_off = data_off;
        n->mode = h.mode & 07777;
        n->mtime = h.mtime;
        free(h.path);
        free(rel);
    }
    scan_list_free(&scan);
    return 0;
}

static void free_state(lzply_mount_state_t *st)
{
    size_t i;
    if (!st)
        return;
    for (i = 0; i < st->nnodes; i++) {
        free(st->nodes[i].path);
        free(st->nodes[i].content);
        free(st->nodes[i].hdr.path);
    }
    free(st->nodes);
    if (st->archive)
        fclose(st->archive);
    free(st->archive_path);
    free(st);
}

/* ------------------------------------------------------------------ */
/* FUSE helpers                                                        */
/* ------------------------------------------------------------------ */

static lzply_mount_state_t *fs_state(void)
{
    return (lzply_mount_state_t *)fuse_get_context()->private_data;
}

/* Archive-relative path for a FUSE path ("/photos/a.txt" -> "photos/a.txt"). */
static const char *rel_path(const char *path)
{
    return path[0] == '/' ? path + 1 : path;
}

static void fill_stat(lzply_mount_state_t *st, fs_node_t *n, struct stat *sb)
{
    memset(sb, 0, sizeof *sb);
    /* st_ino is deliberately 0: libfuse's high-level API manages inode
     * numbers itself (it assigns nodeids in first-access order), and
     * it only honours the st_ino passed to the readdir filler, not the
     * one from getattr. Supplying our own numbers makes the same file
     * show two different inodes depending on whether stat or ls found
     * it first, and can collide with libfuse's lookup-assigned ids.
     * With st_ino 0 libfuse assigns nodeids consistently in both
     * paths; the kernel shows those (unique and stable within a
     * mount). n->ino stays as an internal id only. */
    sb->st_ino = 0;
    sb->st_mode = (n->is_dir ? S_IFDIR : S_IFREG) | (n->mode & 07777);
    sb->st_nlink = n->is_dir ? 2 + count_subdirs(st, n->path) : 1;
    sb->st_uid = getuid();
    sb->st_gid = getgid();
    sb->st_size = n->is_dir ? 4096 : (off_t)node_size(n);
    sb->st_blksize = 4096;
    sb->st_blocks = n->is_dir ? 0 : ((off_t)node_size(n) + 511) / 512;
    sb->st_mtime = sb->st_atime = sb->st_ctime = (time_t)n->mtime;
}

/* ------------------------------------------------------------------ */
/* Content decode + bounded read cache (stage 2)                       */
/* ------------------------------------------------------------------ */

/* Free the decoded content of clean (non-dirty) nodes, oldest first,
 * until cache_bytes + need <= cache_cap (or nothing clean is left).
 * A single entry larger than the cap still loads (a file must be
 * readable); the cap is a soft target. Dirty nodes are never evicted:
 * their content is the only copy of unflushed changes. */
static void cache_evict(lzply_mount_state_t *st, size_t need, fs_node_t *except)
{
    while (st->cache_bytes + need > st->cache_cap) {
        fs_node_t *victim = NULL;
        size_t i;
        for (i = 0; i < st->nnodes; i++) {
            fs_node_t *n = &st->nodes[i];
            if (n == except || !n->content_loaded || n->dirty || n->is_dir)
                continue;
            if (!victim || n->load_seq < victim->load_seq)
                victim = n;
        }
        if (!victim)
            break;
        st->cache_bytes -= victim->content_len;
        free(victim->content);
        victim->content = NULL;
        victim->content_len = 0;
        victim->content_loaded = 0;
    }
}

/* Decode a file node's entry into its content buffer (decode-on-open).
 * Returns 0 on success, -EIO on corruption (BCH uncorrectable, lzip
 * error, SHA-256 mismatch). */
static int load_content(lzply_mount_state_t *st, fs_node_t *n)
{
    uint8_t *stored = NULL, *raw = NULL;
    size_t raw_len = 0;
    int corrected = 0, rc, is_bch;
    uint16_t poly_id;

    if (n->content_loaded)
        return 0;
    if (!n->has_entry) {
        /* A file created in this session (stage 4+): its content is
         * the working buffer, initialised at creation. */
        return 0;
    }
    stored = xmalloc(n->hdr.stored_size ? (size_t)n->hdr.stored_size : 1);
    if (fseeko(st->archive, n->data_off, SEEK_SET) != 0 ||
        fread(stored, 1, (size_t)n->hdr.stored_size, st->archive) !=
            (size_t)n->hdr.stored_size) {
        free(stored);
        return -EIO;
    }
    is_bch = (n->hdr.flags & FLAG_BCH) != 0;
    poly_id = (uint16_t)(n->hdr.rs_level | ((uint16_t)n->hdr.reserved << 8));
    rc = entry_decode(stored, (size_t)n->hdr.stored_size, n->hdr.level,
                      is_bch, poly_id, n->hdr.sha,
                      (size_t)n->hdr.blob_size, &raw, &raw_len, &corrected);
    free(stored);
    if (rc != 0)
        return -EIO;            /* corrupt: BCH uncorrectable / SHA mismatch */
    if (raw_len != n->hdr.orig_size) {
        /* Should not happen (SHA-256 already verified), but be safe. */
        free(raw);
        return -EIO;
    }
    cache_evict(st, raw_len, n);
    n->content = raw;
    n->content_len = raw_len;
    n->content_loaded = 1;
    n->load_seq = ++st->load_clock;
    st->cache_bytes += raw_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* FUSE operations — stage 1: getattr, readdir (+ open/read stub)      */
/* ------------------------------------------------------------------ */

static int lzply_mount_getattr(const char *path, struct stat *sb,
                          struct fuse_file_info *fi)
{
    lzply_mount_state_t *st = fs_state();
    fs_node_t *n;
    (void)fi;
    n = node_find(st, rel_path(path));
    if (!n)
        return -ENOENT;
    fill_stat(st, n, sb);
    return 0;
}

static int lzply_mount_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                          off_t offset, struct fuse_file_info *fi,
                          enum fuse_readdir_flags flags)
{
    lzply_mount_state_t *st = fs_state();
    const char *rel = rel_path(path);
    fs_node_t *dir;
    size_t i;
    (void)offset;
    (void)fi;
    (void)flags;

    dir = node_find(st, rel);
    if (!dir)
        return -ENOENT;
    if (!dir->is_dir)
        return -ENOTDIR;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    for (i = 0; i < st->nnodes; i++) {
        fs_node_t *c = &st->nodes[i];
        struct stat sb;
        if (c->deleted || c == dir)
            continue;
        if (!is_child_of(c->path, rel))
            continue;
        fill_stat(st, c, &sb);
        filler(buf, base_name(c->path), &sb, 0, 0);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Repack (stage 3): write the in-memory state as a new archive        */
/* ------------------------------------------------------------------ */

/* Write the current in-memory state as a new archive, replacing the
 * old one. Unmodified entries are copied verbatim; modified/new
 * entries are encoded fresh. Directories
 * are written as dir entries; implied dirs get no entry. On success
 * the archive FILE* is reopened on the new file, every node's
 * data_off/hdr is updated, dirty flags are cleared, and st->dirty
 * is 0. Returns 0 on success, -1 on failure (the original archive
 * is left untouched, and the in-memory state is unmodified — new
 * offsets/headers are staged in side arrays and applied only after
 * the rename succeeds). */
static int repack_archive(lzply_mount_state_t *st)
{
    FILE *out = NULL;
    char *tmp = NULL;
    uint32_t count = 0;
    size_t i;
    off_t *new_off = NULL;
    ehdr_t *new_hdr = NULL;
    uint8_t *written = NULL;
    int rc = -1;

    new_off = xmalloc(st->nnodes * sizeof(off_t));
    new_hdr = xmalloc(st->nnodes * sizeof(ehdr_t));
    written = xmalloc(st->nnodes ? st->nnodes : 1);
    memset(written, 0, st->nnodes);
    memset(new_hdr, 0, st->nnodes * sizeof(ehdr_t));

    out = temp_in_same_dir(st->archive_path, &tmp);
    if (!out) {
        fprintf(stderr, "lzply_mount: cannot create temp file for repack: %s\n",
                strerror(errno));
        goto out;
    }
    write_global_header(out, 0, LZPLY_VERSION);
    for (i = 0; i < st->nnodes; i++) {
        fs_node_t *n = &st->nodes[i];
        ehdr_t h;
        off_t entry_off;
        if (n->deleted || n->path[0] == '\0')
            continue;   /* deleted, or the synthetic mount root */
        if (n->is_dir) {
            char *dpath;
            if (!n->has_entry && n->is_implied)
                continue;   /* implied dirs get no entry */
            dpath = xmalloc(strlen(n->path) + 2);
            sprintf(dpath, "%s/", n->path);
            memset(&h, 0, sizeof h);
            h.path = dpath;
            h.level = (uint8_t)st->level;
            h.mode = n->mode;
            h.mtime = n->mtime;
            h.flags = FLAG_ISDIR;
            h.orig_size = 0;
            h.stored_size = 0;
            h.blob_size = 0;
            lzply_sha256((const uint8_t *)"", 0, h.sha);
            entry_off = ftello(out);
            if (write_entry_header(out, &h) != 0) {
                free(dpath);
                goto fail;
            }
            free(dpath);
            new_off[i] = entry_off + LZPLY_EHDR_SIZE +
                         (off_t)(strlen(n->path) + 1);
            new_hdr[i] = h;
            new_hdr[i].path = NULL;
            written[i] = 1;
            count++;
            continue;
        }
        if (n->dirty || n->is_new) {
            /* Re-encode from the working content. */
            uint8_t *stored = NULL;
            size_t stored_len = 0, blob_len = 0;
            uint16_t poly_id = 0;
            int is_bch = 0, lrc;
            if (!n->content_loaded) {
                lrc = load_content(st, n);
                if (lrc != 0)
                    goto fail;
            }
            if (!n->content_loaded) {
                /* New file with no working buffer yet: empty content. */
                n->content = xmalloc(1);
                n->content_len = 0;
                n->content_loaded = 1;
            }
            memset(&h, 0, sizeof h);
            h.path = n->path;
            h.level = (uint8_t)st->level;
            h.mode = n->mode;
            h.mtime = n->mtime;
            {
                int eff_level = st->level;
                if (entry_encode(n->content, n->content_len, st->level,
                                 &st->ecc,
                                 &stored, &stored_len, &blob_len, &poly_id,
                                 &is_bch, &eff_level, h.sha) != 0)
                    goto fail;
                h.level = (uint8_t)eff_level;   /* 0 when stored uncompressed */
            }
            h.flags = 0;
            if (is_bch) {
                h.flags |= FLAG_BCH;
                h.rs_level = (uint8_t)(poly_id & 0xff);
                h.reserved = (uint8_t)(poly_id >> 8);
            }
            h.orig_size = n->content_len;
            h.stored_size = stored_len;
            h.blob_size = blob_len;
            entry_off = ftello(out);
            if (write_entry_header(out, &h) != 0 ||
                (stored_len > 0 &&
                 fwrite(stored, 1, stored_len, out) != stored_len)) {
                free(stored);
                goto fail;
            }
            free(stored);
            new_off[i] = entry_off + LZPLY_EHDR_SIZE +
                         (off_t)strlen(n->path);
            new_hdr[i] = h;
            new_hdr[i].path = NULL;
            written[i] = 1;
            count++;
        } else {
            /* Clean: copy the stored bytes verbatim, header with the
             * current mode/mtime (a metadata-only change). */
            h = n->hdr;
            h.mode = n->mode;
            h.mtime = n->mtime;
            h.path = n->path;
            entry_off = ftello(out);
            if (write_entry_header(out, &h) != 0)
                goto fail;
            if (fseeko(st->archive, n->data_off, SEEK_SET) != 0 ||
                copy_bytes(st->archive, out, n->hdr.stored_size) != 0)
                goto fail;
            new_off[i] = entry_off + LZPLY_EHDR_SIZE +
                         (off_t)strlen(n->path);
            new_hdr[i] = h;
            new_hdr[i].path = NULL;
            written[i] = 1;
            count++;
        }
    }
    /* End marker. */
    {
        uint8_t end[2] = {0, 0};
        if (fwrite(end, 1, 2, out) != 2)
            goto fail;
    }
    /* Patch the entry count into the global header. */
    {
        uint8_t cbuf[4];
        put32le(cbuf, count);
        if (fseeko(out, 6, SEEK_SET) != 0 ||
            fwrite(cbuf, 1, 4, out) != 4)
            goto fail;
    }
    if (fflush(out) != 0 || fsync(fileno(out)) != 0)
        goto fail;
    if (fclose(out) != 0) {
        out = NULL;
        goto fail;
    }
    out = NULL;
    if (rename(tmp, st->archive_path) != 0) {
        fprintf(stderr, "lzply_mount: repack rename failed: %s\n",
                strerror(errno));
        goto fail;
    }
    /* Reopen the archive on the new file and apply the staged state.
     * The new file is opened and locked before the old one is closed,
     * so a failed reopen leaves the daemon working (old fd still
     * valid, nodes untouched, dirty flags still set for a later
     * repack). */
    {
        FILE *newarch = fopen(st->archive_path, "rb");
        if (!newarch) {
            fprintf(stderr,
                    "lzply_mount: repack succeeded but cannot reopen %s: %s\n",
                    st->archive_path, strerror(errno));
            goto out;
        }
        if (lock_archive_file(newarch) != 0)
            fprintf(stderr,
                    "lzply_mount: WARNING: repacked %s but could not re-lock "
                    "it (%s); another lzply_mount may have mounted it\n",
                    st->archive_path, strerror(errno));
        fclose(st->archive);
        st->archive = newarch;
    }
    for (i = 0; i < st->nnodes; i++) {
        fs_node_t *n = &st->nodes[i];
        if (!written[i])
            continue;
        n->data_off = new_off[i];
        n->hdr = new_hdr[i];
        n->hdr.path = NULL;
        n->dirty = 0;
        n->meta_dirty = 0;
        n->is_new = 0;
        n->has_entry = 1;
    }
    st->dirty = 0;
    rc = 0;
    goto out;
fail:
    if (out)
        fclose(out);
    if (tmp)
        unlink(tmp);
out:
    free(tmp);
    free(new_off);
    free(new_hdr);
    free(written);
    return rc;
}

/* Resize a file node's content to length (zero-filling on growth).
 * Loads (decodes) the content first if needed. Marks the node dirty
 * (and the filesystem dirty) and updates its mtime. */
static int truncate_node(lzply_mount_state_t *st, fs_node_t *n, off_t length)
{
    int rc;
    if (length < 0)
        return -EINVAL;
    rc = load_content(st, n);
    if (rc != 0)
        return rc;
    if (!n->content_loaded) {
        n->content = xmalloc(1);
        n->content_len = 0;
        n->content_loaded = 1;
    }
    if ((uint64_t)length != n->content_len) {
        if ((uint64_t)length > n->content_len) {
            size_t old = n->content_len;
            size_t newlen = (size_t)length;
            uint8_t *nb;
            cache_evict(st, newlen - old, n);
            nb = realloc(n->content, newlen ? newlen : 1);
            if (!nb)
                return -ENOMEM;
            n->content = nb;
            memset(n->content + old, 0, newlen - old);
            st->cache_bytes += (newlen - old);
            n->content_len = newlen;
        } else {
            st->cache_bytes -= (n->content_len - (size_t)length);
            n->content_len = (size_t)length;
        }
        n->dirty = 1;
        n->meta_dirty = 1;
        st->dirty = 1;
        n->mtime = (uint64_t)time(NULL);
    }
    return 0;
}

/* Find the parent directory node of rel ("" = root). Returns 0 on
 * success, -ENOENT if the parent does not exist, -ENOTDIR if it is
 * not a directory. */
static int find_parent(lzply_mount_state_t *st, const char *rel,
                       fs_node_t **parent_out)
{
    char *p = parent_dir(rel);
    fs_node_t *par;
    if (strcmp(p, ".") == 0)
        par = node_find(st, "");
    else
        par = node_find(st, p);
    free(p);
    if (!par)
        return -ENOENT;
    if (!par->is_dir)
        return -ENOTDIR;
    *parent_out = par;
    return 0;
}

/* Does dir (by path) have any non-deleted children? */
static int dir_has_children(lzply_mount_state_t *st, const char *dir_path)
{
    size_t i;
    for (i = 0; i < st->nnodes; i++) {
        fs_node_t *c = &st->nodes[i];
        if (!c->deleted && is_child_of(c->path, dir_path))
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* FUSE operations — stage 3: write, truncate, flush, fsync            */
/* ------------------------------------------------------------------ */

/* Decode-on-open: the content is decoded here and cached in the node,
 * so read() and write() just serve from memory. Corruption
 * surfaces at open time. */
static int lzply_mount_open(const char *path, struct fuse_file_info *fi)
{
    lzply_mount_state_t *st = fs_state();
    fs_node_t *n = node_find(st, rel_path(path));
    int rc;
    if (!n)
        return -ENOENT;
    if (n->is_dir)
        return -EISDIR;
    rc = load_content(st, n);
    if (rc != 0)
        return rc;
    if (!n->content_loaded) {
        n->content = xmalloc(1);
        n->content_len = 0;
        n->content_loaded = 1;
    }
    if ((fi->flags & O_TRUNC) && (fi->flags & O_ACCMODE) != O_RDONLY) {
        rc = truncate_node(st, n, 0);
        if (rc != 0)
            return rc;
    }
    return 0;
}

static int lzply_mount_read(const char *path, char *buf, size_t size, off_t offset,
                       struct fuse_file_info *fi)
{
    lzply_mount_state_t *st = fs_state();
    fs_node_t *n = node_find(st, rel_path(path));
    size_t avail;
    int rc;
    (void)fi;
    if (!n)
        return -ENOENT;
    if (n->is_dir)
        return -EISDIR;
    /* Defensive: open() normally decodes, but read must not trust that. */
    rc = load_content(st, n);
    if (rc != 0)
        return rc;
    if (offset < 0)
        return -EINVAL;
    if (size > (size_t)INT_MAX)
        size = (size_t)INT_MAX;
    if ((uint64_t)offset >= n->content_len)
        return 0;               /* EOF */
    avail = n->content_len - (size_t)offset;
    if (size > avail)
        size = avail;
    memcpy(buf, n->content + offset, size);
    return (int)size;
}

static int lzply_mount_release(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;
    /* The decoded content stays cached in the node (bounded cache). */
    return 0;
}

/* Write into the in-memory working copy (zero-filling any gap when
 * writing past EOF). The file is re-encoded and the archive repacked
 * on fsync / clean unmount. */
static int lzply_mount_write(const char *path, const char *buf, size_t size,
                        off_t offset, struct fuse_file_info *fi)
{
    lzply_mount_state_t *st = fs_state();
    fs_node_t *n = node_find(st, rel_path(path));
    size_t end;
    int rc;
    (void)fi;
    if (!n)
        return -ENOENT;
    if (n->is_dir)
        return -EISDIR;
    if (offset < 0)
        return -EINVAL;
    if (size > (size_t)INT_MAX)
        size = (size_t)INT_MAX;
    if ((uint64_t)offset > (uint64_t)SIZE_MAX - size)
        return -EFBIG;
    rc = load_content(st, n);
    if (rc != 0)
        return rc;
    if (!n->content_loaded) {
        n->content = xmalloc(1);
        n->content_len = 0;
        n->content_loaded = 1;
    }
    end = (size_t)offset + size;
    if (end > n->content_len) {
        size_t old = n->content_len;
        uint8_t *nb;
        cache_evict(st, end - old, n);
        nb = realloc(n->content, end ? end : 1);
        if (!nb)
            return -ENOMEM;
        n->content = nb;
        memset(n->content + old, 0, end - old);
        st->cache_bytes += (end - old);
        n->content_len = end;
    }
    memcpy(n->content + offset, buf, size);
    n->dirty = 1;
    n->meta_dirty = 1;          /* mtime changes on write */
    st->dirty = 1;
    n->mtime = (uint64_t)time(NULL);
    return (int)size;
}

static int lzply_mount_truncate(const char *path, off_t length,
                           struct fuse_file_info *fi)
{
    lzply_mount_state_t *st = fs_state();
    fs_node_t *n = node_find(st, rel_path(path));
    (void)fi;
    if (!n)
        return -ENOENT;
    if (n->is_dir)
        return -EISDIR;
    return truncate_node(st, n, length);
}

static int lzply_mount_flush(const char *path, struct fuse_file_info *fi)
{
    (void)path;
    (void)fi;
    /* Writes go straight to the in-memory working copy, so there is
     * nothing to flush at close. Durability is via fsync / unmount. */
    return 0;
}

static int lzply_mount_fsync(const char *path, int isdatasync,
                        struct fuse_file_info *fi)
{
    lzply_mount_state_t *st = fs_state();
    (void)path;
    (void)isdatasync;
    (void)fi;
    /* fsync means "make it durable": repack the archive now when
     * anything is dirty. A no-op when nothing changed. */
    if (!st->dirty)
        return 0;
    if (repack_archive(st) != 0)
        return -EIO;
    return 0;
}

/* ------------------------------------------------------------------ */
/* FUSE operations — stage 4: create, mknod, mkdir, rmdir, unlink      */
/* ------------------------------------------------------------------ */

static int lzply_mount_create(const char *path, mode_t mode,
                         struct fuse_file_info *fi)
{
    lzply_mount_state_t *st = fs_state();
    const char *rel = rel_path(path);
    fs_node_t *par, *n;
    int rc;
    (void)fi;
    if (node_find(st, rel) != NULL)
        return -EEXIST;
    rc = find_parent(st, rel, &par);
    if (rc != 0)
        return rc;
    n = node_add(st, rel, mode & 07777, (uint64_t)time(NULL), 0);
    n->is_new = 1;
    n->content = xmalloc(1);
    n->content_len = 0;
    n->content_loaded = 1;
    st->dirty = 1;
    return 0;
}

static int lzply_mount_mknod(const char *path, mode_t mode, dev_t rdev)
{
    lzply_mount_state_t *st = fs_state();
    const char *rel = rel_path(path);
    fs_node_t *par, *n;
    int rc;
    (void)rdev;
    /* Only regular files make sense in an archive; device nodes,
     * fifos and sockets are not supported. */
    if (!S_ISREG(mode))
        return -ENOSYS;
    if (node_find(st, rel) != NULL)
        return -EEXIST;
    rc = find_parent(st, rel, &par);
    if (rc != 0)
        return rc;
    n = node_add(st, rel, mode & 07777, (uint64_t)time(NULL), 0);
    n->is_new = 1;
    n->content = xmalloc(1);
    n->content_len = 0;
    n->content_loaded = 1;
    st->dirty = 1;
    return 0;
}

static int lzply_mount_mkdir(const char *path, mode_t mode)
{
    lzply_mount_state_t *st = fs_state();
    const char *rel = rel_path(path);
    fs_node_t *par, *n;
    int rc;
    if (node_find(st, rel) != NULL)
        return -EEXIST;
    rc = find_parent(st, rel, &par);
    if (rc != 0)
        return rc;
    n = node_add(st, rel, mode & 07777, (uint64_t)time(NULL), 1);
    n->is_new = 1;
    st->dirty = 1;
    return 0;
}

static int lzply_mount_rmdir(const char *path)
{
    lzply_mount_state_t *st = fs_state();
    const char *rel = rel_path(path);
    fs_node_t *n = node_find(st, rel);
    if (!n)
        return -ENOENT;
    if (!n->is_dir)
        return -ENOTDIR;
    if (rel[0] == '\0')
        return -EBUSY;          /* the mount root cannot be removed */
    if (dir_has_children(st, rel))
        return -ENOTEMPTY;
    if (n->content_loaded) {
        st->cache_bytes -= n->content_len;
        free(n->content);
        n->content = NULL;
        n->content_len = 0;
        n->content_loaded = 0;
    }
    n->deleted = 1;
    st->dirty = 1;
    return 0;
}

static int lzply_mount_unlink(const char *path)
{
    lzply_mount_state_t *st = fs_state();
    const char *rel = rel_path(path);
    fs_node_t *n = node_find(st, rel);
    if (!n)
        return -ENOENT;
    if (n->is_dir)
        return -EISDIR;
    if (n->content_loaded) {
        st->cache_bytes -= n->content_len;
        free(n->content);
        n->content = NULL;
        n->content_len = 0;
        n->content_loaded = 0;
    }
    n->deleted = 1;
    st->dirty = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* FUSE operations — stage 5: rename                                   */
/* ------------------------------------------------------------------ */

/* Rewrite the path of node n from old_prefix to new_prefix (for a
 * directory rename: all descendants move with it). */
static void repath_node(fs_node_t *n, const char *old_prefix,
                        const char *new_prefix)
{
    size_t olen = strlen(old_prefix);
    char *np;
    if (strcmp(n->path, old_prefix) == 0) {
        np = xstrdup(new_prefix);
    } else {
        /* old_prefix + "/" + rest */
        np = xmalloc(strlen(new_prefix) + 1 + (strlen(n->path) - olen) + 1);
        sprintf(np, "%s/%s", new_prefix, n->path + olen + 1);
    }
    free(n->path);
    n->path = np;
}

static int lzply_mount_rename(const char *from, const char *to, unsigned int flags)
{
    lzply_mount_state_t *st = fs_state();
    const char *frel = rel_path(from);
    const char *trel = rel_path(to);
    fs_node_t *src, *dst, *tpar;
    int rc;
    size_t i;

    if (flags & RENAME_EXCHANGE)
        return -EINVAL;         /* exchange is not supported */
    src = node_find(st, frel);
    if (!src)
        return -ENOENT;
    if (strcmp(frel, trel) == 0)
        return 0;               /* renaming onto itself: no-op */
    if (src->is_dir) {
        /* Cannot move a directory into itself. */
        size_t flen = strlen(frel);
        if (strncmp(trel, frel, flen) == 0 && trel[flen] == '/')
            return -EINVAL;
    }
    rc = find_parent(st, trel, &tpar);
    if (rc != 0)
        return rc;
    if ((flags & RENAME_NOREPLACE) && node_find(st, trel) != NULL)
        return -EEXIST;
    dst = node_find(st, trel);
    if (dst != NULL) {
        if (src->is_dir != dst->is_dir)
            return src->is_dir ? -ENOTDIR : -EISDIR;
        if (dst->is_dir && dir_has_children(st, trel))
            return -ENOTEMPTY;
        /* Replace the target: mark it deleted (the repack drops it). */
        if (dst->content_loaded) {
            st->cache_bytes -= dst->content_len;
            free(dst->content);
            dst->content = NULL;
            dst->content_len = 0;
            dst->content_loaded = 0;
        }
        dst->deleted = 1;
    }
    if (src->is_dir) {
        /* Move descendants first (matched on the old prefix). */
        size_t flen = strlen(frel);
        for (i = 0; i < st->nnodes; i++) {
            fs_node_t *c = &st->nodes[i];
            if (c->deleted || c == src)
                continue;
            if (strncmp(c->path, frel, flen) == 0 && c->path[flen] == '/')
                repath_node(c, frel, trel);
        }
    }
    repath_node(src, frel, trel);
    st->dirty = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* FUSE operations — stage 6: chmod, chown, utimens                    */
/* ------------------------------------------------------------------ */

static int lzply_mount_chmod(const char *path, mode_t mode,
                        struct fuse_file_info *fi)
{
    lzply_mount_state_t *st = fs_state();
    fs_node_t *n = node_find(st, rel_path(path));
    (void)fi;
    if (!n)
        return -ENOENT;
    n->mode = mode & 07777;
    n->meta_dirty = 1;
    st->dirty = 1;
    return 0;
}

static int lzply_mount_chown(const char *path, uid_t uid, gid_t gid,
                        struct fuse_file_info *fi)
{
    lzply_mount_state_t *st = fs_state();
    (void)uid;
    (void)gid;
    (void)fi;
    /* The archive stores a mode, not an owner: every entry appears
     * owned by the mounting user. chown is a no-op that succeeds, so
     * tools that preserve ownership do not fail. */
    if (!node_find(st, rel_path(path)))
        return -ENOENT;
    return 0;
}

static int lzply_mount_utimens(const char *path, const struct timespec tv[2],
                          struct fuse_file_info *fi)
{
    lzply_mount_state_t *st = fs_state();
    fs_node_t *n = node_find(st, rel_path(path));
    (void)fi;
    if (!n)
        return -ENOENT;
    /* Only mtime is stored in the archive (atime is reported as
     * mtime by getattr). tv[1] is mtime; tv may be NULL (use now). */
    if (tv == NULL) {
        n->mtime = (uint64_t)time(NULL);
    } else if (tv[1].tv_nsec == UTIME_OMIT) {
        return 0;               /* mtime explicitly left unchanged */
    } else if (tv[1].tv_nsec == UTIME_NOW) {
        n->mtime = (uint64_t)time(NULL);
    } else {
        n->mtime = (uint64_t)tv[1].tv_sec;
    }
    n->meta_dirty = 1;
    st->dirty = 1;
    return 0;
}

/* Set by lzply_mount_destroy(): fuse_main can return non-zero after a
 * signal-triggered shutdown (e.g. SIGTERM) even though destroy()
 * already ran and freed the state. main() must not free the state
 * a second time in that case (double-free). */
static int g_destroy_ran = 0;

static void lzply_mount_destroy(void *data)
{
    lzply_mount_state_t *st = (lzply_mount_state_t *)data;
    g_destroy_ran = 1;
    if (st->dirty) {
        if (repack_archive(st) != 0)
            fprintf(stderr,
                    "lzply_mount: WARNING: repack on unmount failed; "
                    "changes lost\n");
    }
    free_state(st);
}

static const struct fuse_operations lzply_mount_ops = {
    .getattr = lzply_mount_getattr,
    .readdir = lzply_mount_readdir,
    .open = lzply_mount_open,
    .read = lzply_mount_read,
    .release = lzply_mount_release,
    .write = lzply_mount_write,
    .truncate = lzply_mount_truncate,
    .flush = lzply_mount_flush,
    .fsync = lzply_mount_fsync,
    .create = lzply_mount_create,
    .mknod = lzply_mount_mknod,
    .mkdir = lzply_mount_mkdir,
    .rmdir = lzply_mount_rmdir,
    .unlink = lzply_mount_unlink,
    .rename = lzply_mount_rename,
    .chmod = lzply_mount_chmod,
    .chown = lzply_mount_chown,
    .utimens = lzply_mount_utimens,
    .destroy = lzply_mount_destroy,
};

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s [-f] [-d] [-s] [-o opt] [-e N] [poly=NN] [-0] "
            "[-cache N] <archive.lzply> <mountpoint>\n"
            "  -f            run in the foreground (FUSE option)\n"
            "  -d            debug output (FUSE option)\n"
            "  -s            single-threaded (FUSE option; always on)\n"
            "  -o opt        FUSE mount option (passed through); lzply_mount\n"
            "                consumes cache= from it\n"
            "  -e N          BCH level for re-encoded entries (0-7, default 4)\n"
            "  -0            store re-encoded entries uncompressed\n"
            "  poly=NN       pin a BCH polynomial by id for re-encoding\n"
            "  -cache N      read-cache cap in MiB (default 256)\n"
            "Unmount with: fusermount3 -u <mountpoint>\n"
            "Or: mount -t lzply <archive.lzply> <mountpoint> "
            "[-o cache=N]\n",
            prog);
}

/* Set the read-cache cap from a decimal MiB value. Returns 0 or -1. */
static int set_cache_cap(lzply_mount_state_t *st, const char *s)
{
    char *end;
    long n = strtol(s, &end, 10);
    if (*end != '\0' || n < 1) {
        fprintf(stderr, "lzply_mount: cache size must be a positive integer (MiB)\n");
        return -1;
    }
    st->cache_cap = (size_t)n * 1024u * 1024u;
    return 0;
}

/* Parse a comma-separated -o value. The lzply_mount option cache=
 * is consumed here; anything else is returned (malloced, comma-joined)
 * for FUSE, or NULL if nothing remains. Returns 0 or -1 on bad input. */
static int parse_fuse_opts(lzply_mount_state_t *st, const char *value,
                           char **out_rest)
{
    char *copy = xstrdup(value);
    char *save = NULL, *tok;
    char *rest = NULL;
    size_t rest_len = 0;
    int rc = 0;

    *out_rest = NULL;
    for (tok = strtok_r(copy, ",", &save); tok != NULL;
         tok = strtok_r(NULL, ",", &save)) {
        if (strncmp(tok, "cache=", 6) == 0) {
            if (set_cache_cap(st, tok + 6) != 0) {
                rc = -1;
                break;
            }
        } else {
            size_t tl = strlen(tok);
            rest = xrealloc(rest, rest_len + tl + 2);
            if (rest_len > 0)
                rest[rest_len++] = ',';
            memcpy(rest + rest_len, tok, tl + 1);
            rest_len += tl;
        }
    }
    free(copy);
    if (rc != 0) {
        free(rest);
        return -1;
    }
    *out_rest = rest;
    return 0;
}

int main(int argc, char *argv[])
{
    lzply_mount_state_t *st;
    char *archive = NULL, *mountpoint = NULL;
    char **fuse_argv;
    int fuse_argc = 0, i;
    int rc;

    lzply_set_progname("lzply_mount");
    crc32_init();

    st = xmalloc(sizeof *st);
    memset(st, 0, sizeof *st);
    st->level = 6;              /* same default as lzply -c */
    st->ecc.t = 8;              /* -e 4 -> t=8, same default as lzply */
    st->cache_cap = 256u * 1024u * 1024u;   /* 256 MiB read cache */

    fuse_argv = xmalloc(sizeof(char *) * (size_t)(argc + 4));
    fuse_argv[fuse_argc++] = argv[0];

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-e") == 0) {
            int t;
            if (i + 1 >= argc) {
                fprintf(stderr, "lzply_mount: -e needs a value\n");
                return 1;
            }
            t = atoi(argv[++i]);
            if (t < 0 || t > 7) {
                fprintf(stderr, "lzply_mount: -e must be 0..7\n");
                return 1;
            }
            /* Same mapping as lzply -e: 0=none, 1->1, 2->2, 3->4, 4->8,
             * 5->16, 6->32, 7->32. */
            static const int e_to_t[8] = {0, 1, 2, 4, 8, 16, 32, 32};
            st->ecc.t = e_to_t[t];
            st->ecc.pinned = NULL;
        } else if (strcmp(a, "-0") == 0) {
            /* Store re-encoded entries uncompressed (level 0). */
            st->level = 0;
        } else if (strncmp(a, "poly=", 5) == 0) {
            const char *s = a + 5;
            char *end;
            long v;
            const bch_poly_t *p;
            /* Hex with 0x prefix or a-f digits, else decimal. */
            if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
                v = strtol(s + 2, &end, 16);
            else if (strpbrk(s, "abcdefABCDEF") != NULL)
                v = strtol(s, &end, 16);
            else
                v = strtol(s, &end, 10);
            if (*end != '\0' || v <= 0 || v > 0xffff ||
                (p = bch_poly_by_id((uint16_t)v)) == NULL) {
                fprintf(stderr, "lzply_mount: unknown poly id '%s'\n", s);
                return 1;
            }
            st->ecc.pinned = p;
        } else if (a[0] != '-') {
            if (!archive)
                archive = (char *)a;
            else if (!mountpoint)
                mountpoint = (char *)a;
            else {
                fprintf(stderr, "lzply_mount: unexpected argument '%s'\n", a);
                usage(argv[0]);
                return 1;
            }
        } else if (strcmp(a, "-cache") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "lzply_mount: -cache needs a value\n");
                return 1;
            }
            if (set_cache_cap(st, argv[++i]) != 0)
                return 1;
        } else if (strcmp(a, "-o") == 0) {
            /* -o takes a value; lzply_mount consumes cache= from it
             * and passes the rest through to FUSE. */
            char *rest = NULL;
            if (i + 1 >= argc) {
                fprintf(stderr, "lzply_mount: -o needs a value\n");
                return 1;
            }
            if (parse_fuse_opts(st, argv[++i], &rest) != 0)
                return 1;
            if (rest != NULL) {
                fuse_argv[fuse_argc++] = "-o";
                fuse_argv[fuse_argc++] = rest;
            }
        } else {
            /* Any other dash option is a FUSE option: pass through. */
            fuse_argv[fuse_argc++] = argv[i];
        }
    }
    /* Single-threaded: all operations on one thread, no locking. */
    fuse_argv[fuse_argc++] = "-s";
    if (!archive || !mountpoint) {
        usage(argv[0]);
        return 1;
    }
    /* libfuse changes the daemon's working directory to "/" while
     * mounting, so a relative archive or mountpoint path would
     * resolve against "/" later: the repack would write the new
     * archive to /<basename> instead of the real archive (and the
     * original would silently keep its old contents). Canonicalise
     * both to absolute paths up front, while the caller's cwd is
     * still in effect. */
    {
        char *abs = realpath(archive, NULL);
        if (!abs) {
            fprintf(stderr, "lzply_mount: %s: %s\n", archive, strerror(errno));
            return 1;
        }
        archive = abs;
    }
    {
        char *abs = realpath(mountpoint, NULL);
        if (!abs) {
            fprintf(stderr, "lzply_mount: %s: %s\n", mountpoint, strerror(errno));
            return 1;
        }
        mountpoint = abs;
    }
    fuse_argv[fuse_argc++] = mountpoint;
    fuse_argv[fuse_argc] = NULL;

    st->archive_path = xstrdup(archive);
    if (build_index(st) != 0) {
        free_state(st);
        return 1;
    }
    fprintf(stderr, "lzply_mount: mounted %s (%zu entries) on %s\n",
            st->archive_path, st->nnodes - 1, mountpoint);

    rc = fuse_main(fuse_argc, fuse_argv, &lzply_mount_ops, st);
    free(fuse_argv);
    /* On a clean unmount destroy() (called by FUSE) frees st. On a
     * signal shutdown fuse_main can return non-zero after destroy()
     * already ran, so only free the state here if destroy() did not. */
    if (rc != 0 && !g_destroy_ran)
        free_state(st);
    return rc;
}
