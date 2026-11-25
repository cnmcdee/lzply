/* lzply_check.c - bit error rate (BER) detector for an lzply archive or
 * a mounted lzply_mount filesystem.
 *
 *   lzply_check <path> [selector...] [--json] [--warn-ber <value>] [--fail-ber <value>]
 *
 * The path may be an .lzply archive, an lzply_mount mount point, or a file
 * or directory inside an lzply_mount mount (same mount resolution as
 * lzply_stat: /proc/mounts + a scan for the lzply_mount daemon).
 *
 * Read-only: it never modifies the archive. For each BCH entry it runs
 * bch_decode() on the stored bytes in memory and counts the bit errors
 * the decoder corrects. This operates on the stored codeword below
 * the compression layer, so it does NOT decompress anything.
 *
 * BER per entry = corrected bit errors / total stored bits
 * (8 * stored_size), as seen by the BCH decoder. Entries with no BCH
 * (t=0) cannot be measured and are reported as "no-ecc". Uncorrectable
 * entries are reported separately and are NOT folded into the BER
 * number. The overall BER is total corrected / total stored bits
 * across the BCH entries that decoded successfully.
 *
 * Exit codes: 0 = OK (no errors, or only correctable errors and the
 * overall BER is below --fail-ber). 3 = any uncorrectable entry, or
 * the overall BER is above --fail-ber. --warn-ber prints a warning
 * but still exits 0. With no thresholds given, only uncorrectable
 * entries fail.
 *
 * Caveat: the BER is as seen by the BCH decoder. For small t, if the
 * true error count exceeds t the decoder may miscorrect and the
 * reported BER is unreliable — so a high BER or any uncorrectable
 * entry means: run lzply_heal, then lzply -t to fully verify. */
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "lzply_lib.h"
#include "lzply_util.h"

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <path> [selector...] [--json] [--warn-ber <value>] [--fail-ber <value>]\n"
            "  <path> may be an .lzply archive, an lzply_mount mount point, or a\n"
            "  file or directory inside an lzply_mount mount.\n"
            "  Selectors use lzply selector semantics (exact path, or a\n"
            "  directory prefix where the next char must be '/').\n"
            "  For each BCH entry the stored bytes are decoded in memory and\n"
            "  the corrected bit errors counted; BER = corrected / (8 * stored\n"
            "  size). Nothing is decompressed, and the archive is never\n"
            "  modified.\n"
            "  Entries with no BCH cannot be measured (reported as no-ecc).\n"
            "  --warn-ber prints a warning when the overall BER exceeds it\n"
            "  (still exits 0); --fail-ber exits 3 when the overall BER\n"
            "  exceeds it. Without thresholds, only uncorrectable entries\n"
            "  fail (exit 3).\n",
            prog);
}

enum { VIEW_ARCHIVE, VIEW_MOUNT_ALL, VIEW_MOUNT_DIR, VIEW_MOUNT_FILE };

/* One checked entry. kept in a list for the totals and for --json. */
typedef struct {
    char *path;
    uint16_t poly_id;           /* 0 when no BCH */
    int t;                      /* 0 when no BCH */
    uint64_t stored_bits;       /* 8 * stored_size */
    int has_ber;                /* 1 when ber/corrected are meaningful */
    int64_t corrected;          /* -1 when uncorrectable */
    double ber;                 /* corrected / stored_bits */
    const char *status;         /* "clean", "correctable", "uncorrectable", "no-ecc" */
} check_entry_t;

static void fmt_ber(double ber, char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, "%.3g", ber);
}

/* Minimal JSON string escaping: " \ and control chars. */
static void json_escape(FILE *f, const char *s)
{
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (c < 0x20)
                fprintf(f, "\\u%04x", c);
            else
                fputc(c, f);
        }
    }
    fputc('"', f);
}

static void print_json(const char *archive, check_entry_t *v, size_t n,
                       uint64_t tot_corrected, uint64_t tot_bits,
                       double overall_ber, int has_overall,
                       const char *worst_path, double worst_ber,
                       size_t n_bch, size_t n_noecc, size_t n_err,
                       size_t n_uncorr, const char *status)
{
    size_t i;
    printf("{\n  \"archive\": ");
    json_escape(stdout, archive);
    printf(",\n  \"entries\": [");
    for (i = 0; i < n; i++) {
        check_entry_t *e = &v[i];
        printf("%s\n    {\"path\": ", i ? "," : "");
        json_escape(stdout, e->path);
        if (e->t > 0)
            printf(", \"poly\": \"%04x\", \"t\": %d", (unsigned)e->poly_id, e->t);
        else
            printf(", \"poly\": null, \"t\": 0");
        printf(", \"stored_bits\": %" PRIu64, e->stored_bits);
        if (e->has_ber)
            printf(", \"corrected\": %" PRId64 ", \"ber\": %.17g",
                   e->corrected, e->ber);
        else
            printf(", \"corrected\": null, \"ber\": null");
        printf(", \"status\": ");
        json_escape(stdout, e->status);
        printf("}");
    }
    printf("%s],\n  \"totals\": {\n", n ? "\n  " : "");
    printf("    \"entries\": %" PRIu64 ", \"bch_entries\": %" PRIu64
           ", \"no_ecc\": %" PRIu64 ", \"with_errors\": %" PRIu64
           ", \"uncorrectable\": %" PRIu64 ",\n",
           (uint64_t)n, (uint64_t)n_bch, (uint64_t)n_noecc,
           (uint64_t)n_err, (uint64_t)n_uncorr);
    printf("    \"total_corrected\": %" PRIu64
           ", \"total_bits\": %" PRIu64 ", ",
           tot_corrected, tot_bits);
    if (has_overall)
        printf("\"overall_ber\": %.17g, ", overall_ber);
    else
        printf("\"overall_ber\": null, ");
    if (worst_path) {
        printf("\"worst_entry\": ");
        json_escape(stdout, worst_path);
        printf(", \"worst_ber\": %.17g\n", worst_ber);
    } else {
        printf("\"worst_entry\": null, \"worst_ber\": null\n");
    }
    printf("  },\n  \"status\": ");
    json_escape(stdout, status);
    printf("\n}\n");
}

static int parse_ber(const char *s, double *out)
{
    char *end = NULL;
    double v = strtod(s, &end);
    if (!end || *end != '\0' || !isfinite(v) || v < 0)
        return -1;
    *out = v;
    return 0;
}

int main(int argc, char *argv[])
{
    const char *path = NULL;
    const char **selectors = NULL;
    int nselectors = 0;
    int json = 0, have_warn = 0, have_fail = 0;
    double warn_ber = 0, fail_ber = 0;
    struct stat st;
    int is_archive = 0;
    char *archive = NULL, *mountpoint = NULL, *rel = NULL;
    int view = VIEW_ARCHIVE;
    FILE *f = NULL;
    uint32_t count = 0;
    check_entry_t *entries = NULL;
    size_t nentries = 0, cap = 0;
    size_t n_bch = 0, n_noecc = 0, n_err = 0, n_uncorr = 0;
    uint64_t tot_corrected = 0, tot_bits = 0;
    double worst_ber = 0;
    const char *worst_path = NULL;
    int rc = 0, i;

    lzply_set_progname("lzply_check");
    crc32_init();

    /* Options may appear before or after the positionals. The first
     * positional is the path; the rest are selectors. */
    selectors = (const char **)xmalloc(sizeof(char *) * (size_t)(argc > 0 ? argc : 1));
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--json") == 0) {
            json = 1;
        } else if (strncmp(a, "--warn-ber=", 11) == 0) {
            if (parse_ber(a + 11, &warn_ber) != 0) {
                fprintf(stderr, "%s: bad --warn-ber value '%s'\n",
                        lzply_progname, a + 11);
                return EXIT_USAGE;
            }
            have_warn = 1;
        } else if (strcmp(a, "--warn-ber") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: --warn-ber needs a value\n",
                        lzply_progname);
                return EXIT_USAGE;
            }
            if (parse_ber(argv[i], &warn_ber) != 0) {
                fprintf(stderr, "%s: bad --warn-ber value '%s'\n",
                        lzply_progname, argv[i]);
                return EXIT_USAGE;
            }
            have_warn = 1;
        } else if (strncmp(a, "--fail-ber=", 11) == 0) {
            if (parse_ber(a + 11, &fail_ber) != 0) {
                fprintf(stderr, "%s: bad --fail-ber value '%s'\n",
                        lzply_progname, a + 11);
                return EXIT_USAGE;
            }
            have_fail = 1;
        } else if (strcmp(a, "--fail-ber") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "%s: --fail-ber needs a value\n",
                        lzply_progname);
                return EXIT_USAGE;
            }
            if (parse_ber(argv[i], &fail_ber) != 0) {
                fprintf(stderr, "%s: bad --fail-ber value '%s'\n",
                        lzply_progname, argv[i]);
                return EXIT_USAGE;
            }
            have_fail = 1;
        } else if (a[0] == '-') {
            fprintf(stderr, "%s: unknown option '%s'\n", lzply_progname, a);
            usage(argv[0]);
            return EXIT_USAGE;
        } else if (!path) {
            path = a;
        } else {
            selectors[nselectors++] = a;
        }
    }
    if (!path) {
        usage(argv[0]);
        return EXIT_USAGE;
    }

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
        if (archive_is_mounted(archive, &mountpoint) == 1 && !json) {
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
        if (!json)
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
            match = selector_matches(rel, h.path) &&
                    path_matches_selectors(h.path, selectors, nselectors);
            break;
        case VIEW_MOUNT_FILE:
            match = strcmp(h.path, rel) == 0 &&
                    path_matches_selectors(h.path, selectors, nselectors);
            break;
        }
        if (match && !is_dir) {
            /* Read the stored bytes (the file position is at the
             * start of the entry data) and decode them in memory.
             * Directories have no data and are not checked. */
            uint8_t *stored = NULL, *blob = NULL;
            check_entry_t e;
            memset(&e, 0, sizeof e);
            e.path = xstrdup(h.path);
            e.stored_bits = 8 * h.stored_size;
            e.corrected = -1;
            if ((h.flags & FLAG_BCH) == 0) {
                e.poly_id = 0;
                e.t = 0;
                e.has_ber = 0;
                e.status = "no-ecc";
                n_noecc++;
                /* No decode for a no-ECC entry, but the stored data
                 * must still be skipped so the next header reads
                 * from the right offset. */
                if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
                    fprintf(stderr, "%s: truncated archive\n",
                            lzply_progname);
                    free(e.path);
                    free(h.path);
                    fclose(f);
                    return EXIT_CORRUPT;
                }
            } else {
                uint16_t pid = (uint16_t)(h.rs_level |
                                          ((unsigned)h.reserved << 8));
                const bch_poly_t *p = bch_poly_by_id(pid);
                e.poly_id = pid;
                e.t = p ? (int)p->t : 0;
                e.has_ber = 0;
                e.status = "uncorrectable";
                n_bch++;
                if (h.stored_size > 0) {
                    stored = xmalloc(h.stored_size);
                    if (fread(stored, 1, h.stored_size, f) != h.stored_size) {
                        fprintf(stderr, "%s: truncated data for %s\n",
                                lzply_progname, h.path);
                        free(stored);
                        free(e.path);
                        free(h.path);
                        fclose(f);
                        return EXIT_CORRUPT;
                    }
                }
                if (!p) {
                    fprintf(stderr,
                            "%s: warning: %s: unknown BCH poly %04x; "
                            "cannot measure BER\n",
                            lzply_progname, h.path, (unsigned)pid);
                    n_uncorr++;
                } else if (h.stored_size == 0 ||
                           h.stored_size != bch_encoded_len(
                               (size_t)h.blob_size, p)) {
                    fprintf(stderr,
                            "%s: warning: %s: stored size %" PRIu64
                            " != %" PRIu64
                            " expected for BCH poly %04x; cannot measure BER\n",
                            lzply_progname, h.path, h.stored_size,
                            (uint64_t)bch_encoded_len((size_t)h.blob_size, p),
                            (unsigned)pid);
                    n_uncorr++;
                } else {
                    int corrected = 0;
                    blob = xmalloc(h.blob_size ? h.blob_size : 1);
                    if (bch_decode(stored, h.stored_size, h.blob_size,
                                   p, blob, &corrected) != 0) {
                        n_uncorr++;
                    } else {
                        e.corrected = corrected;
                        e.has_ber = 1;
                        e.ber = h.stored_size > 0
                            ? (double)corrected / (double)e.stored_bits
                            : 0.0;
                        e.status = corrected > 0 ? "correctable" : "clean";
                        if (corrected > 0)
                            n_err++;
                        tot_corrected += (uint64_t)corrected;
                        tot_bits += e.stored_bits;
                        if (!worst_path || e.ber > worst_ber) {
                            worst_ber = e.ber;
                            worst_path = e.path;
                        }
                    }
                    free(blob);
                }
                free(stored);
            }
            if (nentries == cap) {
                cap = cap ? cap * 2 : 16;
                entries = xrealloc(entries, cap * sizeof *entries);
            }
            entries[nentries++] = e;
        } else {
            /* Not checked: skip the stored data. */
            if (fseeko(f, (off_t)h.stored_size, SEEK_CUR) != 0) {
                fprintf(stderr, "%s: truncated archive\n", lzply_progname);
                free(h.path);
                fclose(f);
                return EXIT_CORRUPT;
            }
        }
        free(h.path);
    }
    fclose(f);

    /* Overall BER across the BCH entries that decoded. */
    int has_overall = tot_bits > 0;
    double overall_ber = has_overall
        ? (double)tot_corrected / (double)tot_bits : 0.0;

    if (n_uncorr > 0)
        rc = EXIT_CORRUPT;
    else if (have_fail && has_overall && overall_ber > fail_ber)
        rc = EXIT_CORRUPT;
    int warned = have_warn && has_overall && overall_ber > warn_ber;
    const char *status = rc != 0 ? "fail" : warned ? "warning" : "ok";

    if (nentries == 0) {
        if (view == VIEW_MOUNT_FILE) {
            printf("note: %s exists in the mount on %s but is not in "
                   "the on-disk archive yet — it was created in the "
                   "mount and is committed only on unmount or fsync, "
                   "so there is nothing committed to check.\n",
                   rel, mountpoint);
            return 0;
        }
        if (json) {
            print_json(archive, entries, 0, 0, 0, 0.0, 0, NULL, 0.0,
                       0, 0, 0, 0, "ok");
            return 0;
        }
        if (nselectors > 0 || view == VIEW_MOUNT_DIR)
            printf("no entries match the given selector(s)\n");
        else
            printf("no entries in this archive\n");
        return 0;
    }

    if (json) {
        print_json(archive, entries, nentries, tot_corrected, tot_bits,
                   overall_ber, has_overall, worst_path, worst_ber,
                   n_bch, n_noecc, n_err, n_uncorr, status);
        if (rc != 0)
            fprintf(stderr, "%s: FAIL: %s\n", lzply_progname,
                    n_uncorr > 0
                        ? "uncorrectable entries present"
                        : "overall BER above --fail-ber");
        else if (warned)
            fprintf(stderr, "%s: warning: overall BER %.3g exceeds "
                    "--warn-ber %.3g\n",
                    lzply_progname, overall_ber, warn_ber);
    } else {
        size_t i;
        char berbuf[32];
        printf("%-40s %5s %3s %10s %12s %12s %s\n",
               "path", "poly", "t", "corrected", "total_bits", "ber",
               "status");
        for (i = 0; i < nentries; i++) {
            check_entry_t *e = &entries[i];
            char poly[8], t[8], corr[16], bits[16];
            if (e->t > 0) {
                snprintf(poly, sizeof poly, "%04x", (unsigned)e->poly_id);
                snprintf(t, sizeof t, "%d", e->t);
            } else {
                snprintf(poly, sizeof poly, "-");
                snprintf(t, sizeof t, "-");
            }
            if (e->has_ber) {
                snprintf(corr, sizeof corr, "%" PRId64, e->corrected);
                fmt_ber(e->ber, berbuf, sizeof berbuf);
            } else {
                snprintf(corr, sizeof corr, "-");
                snprintf(berbuf, sizeof berbuf, "-");
            }
            snprintf(bits, sizeof bits, "%" PRIu64, e->stored_bits);
            printf("%-40s %5s %3s %10s %12s %12s %s\n",
                   e->path, poly, t, corr, bits, berbuf, e->status);
        }
        printf("%" PRIu64 " entries checked (%" PRIu64 " BCH, %" PRIu64
               " no-ECC)\n",
               (uint64_t)nentries, (uint64_t)n_bch, (uint64_t)n_noecc);
        printf("with errors: %" PRIu64 ", uncorrectable: %" PRIu64 "\n",
               (uint64_t)n_err, (uint64_t)n_uncorr);
        printf("total corrected: %" PRIu64 " bits over %" PRIu64
               " total stored bits\n",
               tot_corrected, tot_bits);
        if (has_overall) {
            fmt_ber(overall_ber, berbuf, sizeof berbuf);
            printf("overall BER: %s", berbuf);
            if (worst_path) {
                fmt_ber(worst_ber, berbuf, sizeof berbuf);
                printf(" (worst: %s %s)", worst_path, berbuf);
            }
            printf("\n");
        } else {
            printf("overall BER: n/a (no decodable BCH entries)\n");
        }
        if (warned)
            printf("warning: overall BER %.3g exceeds --warn-ber %.3g\n",
                   overall_ber, warn_ber);
        if (rc != 0) {
            if (n_uncorr > 0)
                printf("FAIL: %" PRIu64
                       " uncorrectable entr%s — data-loss risk. Run "
                       "lzply_heal, then lzply -t to fully verify.\n",
                       (uint64_t)n_uncorr, n_uncorr == 1 ? "y" : "ies");
            else
                printf("FAIL: overall BER %.3g exceeds --fail-ber %.3g. "
                       "Run lzply_heal, then lzply -t to fully verify.\n",
                       overall_ber, fail_ber);
        }
        printf("BER = corrected bit errors / total stored bits (8 x "
               "stored size), as seen by the BCH decoder on the stored "
               "codeword. No-ECC entries cannot be measured.\n");
    }
    for (i = 0; (size_t)i < nentries; i++)
        free(entries[i].path);
    free(entries);
    free(archive);
    free(mountpoint);
    free(rel);
    return rc;
}
