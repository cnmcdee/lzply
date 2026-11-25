/* lzply_stat.c - statistics for an lzply archive or a mounted
 * lzply_mount filesystem.
 *
 *   lzply_stat <path> [selector...]
 *
 * The path may be an .lzply archive, an lzply_mount mount point, or a file
 * or directory inside an lzply_mount mount. For a mount path the backing
 * archive is found via /proc/mounts + a scan for the lzply_mount daemon
 * (see lzply_util.c). Per entry it shows the uncompressed size,
 * the compressed size (blob, pre-ECC), the stored size (on disk,
 * including ECC), compression as stored/original, the BCH poly id
 * and t, the parity bits and the ECC overhead, and the mtime —
 * plus a totals footer for archive/mount views.
 *
 * Like `lzply -i`, it reads headers only: nothing is decompressed,
 * so it works on an archive whose data is corrupted. When the archive is currently mounted,
 * the figures are the on-disk (committed) state; unflushed changes
 * in the mount are not included. A file created in the mount but
 * not yet repacked has no on-disk entry, and is reported as such
 * instead of showing stale numbers. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "lzply_lib.h"
#include "lzply_util.h"

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <path> [selector...]\n"
            "  <path> may be an .lzply archive, an lzply_mount mount point, or a\n"
            "  file or directory inside an lzply_mount mount.\n"
            "  Selectors use lzply selector semantics (exact path, or a\n"
            "  directory prefix where the next char must be '/').\n"
            "  Statistics come from the entry headers only: nothing is\n"
            "  decompressed.\n",
            prog);
}

enum { VIEW_ARCHIVE, VIEW_MOUNT_ALL, VIEW_MOUNT_DIR, VIEW_MOUNT_FILE };

static void print_header(void)
{
    printf("%-40s %-4s %10s %10s %10s %7s %4s %5s %3s %8s %7s %s\n",
           "path", "type", "original", "compressed", "stored",
           "comp%", "lvl", "poly", "t", "parity", "ecc%",
           "mtime (UTC)");
}

static void print_row(const ehdr_t *h, int is_dir)
{
    char b1[32], b2[32], b3[32], mt[32];
    char comp[16], poly[8], t[8], parity[24], ecc[16];
    const bch_poly_t *p = NULL;

    if ((h->flags & FLAG_BCH) != 0) {
        uint16_t pid = (uint16_t)(h->rs_level |
                                  ((unsigned)h->reserved << 8));
        p = bch_poly_by_id(pid);
        snprintf(poly, sizeof poly, "%04x", (unsigned)pid);
        snprintf(t, sizeof t, "%u", (unsigned)p->t);
        /* Parity bits = blocks * r, blocks = ceil(blob / max_data).
         * stored_size must equal bch_encoded_len(blob, poly); a
         * mismatch is reported on stderr, never silently trusted.
         * A zero-length blob is one parity-only block. */
        size_t maxd = bch_max_data(p);
        uint64_t blocks = (h->blob_size == 0) ? 1 :
                          (h->blob_size + maxd - 1) / maxd;
        uint64_t par = blocks * (uint64_t)p->r;
        size_t want = bch_encoded_len((size_t)h->blob_size, p);
        snprintf(parity, sizeof parity, "%" PRIu64, par);
        if (h->blob_size > 0)
            snprintf(ecc, sizeof ecc, "%.3f%%",
                     (double)par / (8.0 * (double)h->blob_size) * 100.0);
        else
            snprintf(ecc, sizeof ecc, "-");
        if (h->stored_size != want) {
            fprintf(stderr,
                    "%s: warning: %s: stored size %" PRIu64
                    " != %" PRIu64
                    " expected for BCH poly %04x (blob %" PRIu64
                    "); parity figures use the formula\n",
                    lzply_progname, h->path, h->stored_size,
                    (uint64_t)want, (unsigned)pid, h->blob_size);
        }
    } else {
        snprintf(poly, sizeof poly, "-");
        snprintf(t, sizeof t, "-");
        snprintf(parity, sizeof parity, "-");
        snprintf(ecc, sizeof ecc, "-");
    }
    if (h->orig_size > 0)
        snprintf(comp, sizeof comp, "%.1f%%",
                 (double)h->stored_size / (double)h->orig_size * 100.0);
    else
        snprintf(comp, sizeof comp, "-");
    fmt_mtime(h->mtime, mt, sizeof mt);
    printf("%-40s %-4s %10s %10s %10s %7s %4u %5s %3s %8s %7s %s\n",
           h->path, is_dir ? "dir" : "file",
           human_size(h->orig_size, b1, sizeof b1),
           human_size(h->blob_size, b2, sizeof b2),
           human_size(h->stored_size, b3, sizeof b3),
           comp, (unsigned)h->level, poly, t, parity, ecc, mt);
}

int main(int argc, char *argv[])
{
    const char *path;
    const char **selectors = NULL;
    int nselectors = 0;
    struct stat st;
    int is_archive = 0;
    char *archive = NULL, *mountpoint = NULL, *rel = NULL;
    int view = VIEW_ARCHIVE;
    FILE *f = NULL;
    uint32_t count = 0;
    uint32_t seen = 0, ndirs = 0, nfiles = 0;
    uint64_t tot_orig = 0, tot_blob = 0, tot_stored = 0, tot_parity = 0;
    int rc = 0;

    lzply_set_progname("lzply_stat");
    crc32_init();

    if (argc < 2) {
        usage(argv[0]);
        return EXIT_USAGE;
    }
    path = argv[1];
    selectors = (const char **)(argv + 2);
    nselectors = argc - 2;

    if (stat(path, &st) != 0) {
        fprintf(stderr, "%s: %s: no such file or directory\n",
                lzply_progname, path);
        return EXIT_IO;
    }
    if (S_ISREG(st.st_mode)) {
        /* Archive, or a file inside a mount? The magic decides. */
        FILE *probe = fopen(path, "rb");
        char magic[4];
        if (probe) {
            if (fread(magic, 1, 4, probe) == 4 &&
                memcmp(magic, LZPLY_MAGIC, 4) == 0)
                is_archive = 1;
            fclose(probe);
        }
    }
    if (is_archive) {
        archive = canon_path(path);
        mountpoint = NULL;
        if (archive_is_mounted(archive, &mountpoint) == 1) {
            printf("note: %s is mounted on %s; figures below are the "
                   "on-disk (committed) state — unflushed changes in "
                   "the mount are not included.\n",
                   archive, mountpoint);
        }
        view = VIEW_ARCHIVE;
    } else {
        if (mount_resolve(path, &archive, &mountpoint, &rel) != 0) {
            fprintf(stderr,
                    "%s: %s: not an .lzply archive and not inside an "
                    "lzply_mount mount\n",
                    lzply_progname, path);
            return EXIT_IO;
        }
        printf("note: showing the on-disk (committed) state of %s "
               "(mounted on %s); unflushed changes in the mount are "
               "not included.\n",
               archive, mountpoint);
        if (rel[0] == '\0') {
            view = VIEW_MOUNT_ALL;
        } else if (S_ISDIR(st.st_mode)) {
            view = VIEW_MOUNT_DIR;
        } else {
            view = VIEW_MOUNT_FILE;
        }
    }

    f = fopen(archive, "rb");
    if (!f) {
        fprintf(stderr, "%s: cannot open %s\n", lzply_progname, archive);
        return EXIT_IO;
    }
    if (read_global_header(f, &count) != 0) {
        fprintf(stderr, "%s: %s is not an lzply archive "
                "(bad magic/version)\n",
                lzply_progname, archive);
        fclose(f);
        return EXIT_CORRUPT;
    }
    print_header();
    for (;;) {
        ehdr_t h;
        int r = read_entry_header(f, &h);
        int is_dir, match = 0;
        if (r == 1)
            break;
        if (r < 0) {
            fprintf(stderr, "%s: truncated or corrupt entry header\n",
                    lzply_progname);
            fclose(f);
            return EXIT_CORRUPT;
        }
        is_dir = (h.flags & FLAG_ISDIR) != 0;
        switch (view) {
        case VIEW_ARCHIVE:
        case VIEW_MOUNT_ALL:
            match = path_matches_selectors(h.path, selectors, nselectors);
            break;
        case VIEW_MOUNT_DIR:
            /* Must be under the directory AND match any extra
             * selector (if given). */
            match = selector_matches(rel, h.path) &&
                    path_matches_selectors(h.path, selectors, nselectors);
            break;
        case VIEW_MOUNT_FILE:
            match = strcmp(h.path, rel) == 0 &&
                    path_matches_selectors(h.path, selectors, nselectors);
            break;
        }
        if (match) {
            print_row(&h, is_dir);
            seen++;
            if (is_dir)
                ndirs++;
            else
                nfiles++;
            tot_orig += h.orig_size;
            tot_blob += h.blob_size;
            tot_stored += h.stored_size;
            if ((h.flags & FLAG_BCH) != 0) {
                const bch_poly_t *p = bch_poly_by_id(
                    (uint16_t)(h.rs_level |
                               ((unsigned)h.reserved << 8)));
                size_t maxd = bch_max_data(p);
                /* A zero-length blob is one parity-only block. */
                uint64_t blocks = (h.blob_size == 0) ? 1 :
                                  (h.blob_size + maxd - 1) / maxd;
                tot_parity += blocks * (uint64_t)p->r;
            }
        }
        if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
            fprintf(stderr, "%s: truncated archive\n", lzply_progname);
            free(h.path);
            fclose(f);
            return EXIT_CORRUPT;
        }
        free(h.path);
    }
    fclose(f);
    if (seen == 0) {
        if (view == VIEW_MOUNT_FILE) {
            printf("note: %s exists in the mount on %s but is not in "
                   "the on-disk archive yet — it was created in the "
                   "mount and is committed only on unmount or fsync, "
                   "so there are no committed statistics to show.\n",
                   rel, mountpoint);
            return 0;
        }
        if (nselectors > 0 || view == VIEW_MOUNT_DIR)
            printf("no entries match the given selector(s)\n");
        else
            printf("no entries in this archive\n");
        return 0;
    }
    if (view != VIEW_MOUNT_FILE) {
        char b1[32], b2[32], b3[32];
        printf("%u entries (%u directories, %u files)\n",
               seen, ndirs, nfiles);
        printf("total uncompressed: %s, total compressed (blob): %s, "
               "total stored: %s\n",
               human_size(tot_orig, b1, sizeof b1),
               human_size(tot_blob, b2, sizeof b2),
               human_size(tot_stored, b3, sizeof b3));
        if (tot_orig > 0)
            printf("overall compression: %.1f%% (stored/original)\n",
                   (double)tot_stored / (double)tot_orig * 100.0);
        if (tot_blob > 0)
            printf("total parity bits: %" PRIu64
                   ", overall ECC overhead: %.3f%%\n",
                   tot_parity,
                   (double)tot_parity / (8.0 * (double)tot_blob) * 100.0);
        else
            printf("total parity bits: %" PRIu64 "\n", tot_parity);
    }
    free(archive);
    free(mountpoint);
    free(rel);
    return rc;
}
