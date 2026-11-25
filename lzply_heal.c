/* lzply_heal.c - strip and reapply BCH error correction on an lzply archive.
 *
 *   lzply_heal <archive.lzply> [-e <level>] [poly=<id>] [-o <output.lzply>] [selector...]
 *
 * For each entry (matching selectors): strip the BCH parity with
 * bch_decode — which corrects bit errors up to t, that is the heal —
 * then re-encode with the new error correction. The compressed /
 * then re-encode with the new error correction. The compressed
 * blob is never touched: no recompression, and it is preserved
 * byte-for-byte. Only the poly id, the stored size and the
 * header CRC change; orig_size, blob_size, SHA-256, mode
 * and mtime are unchanged, so the per-entry SHA-256 still verifies
 * the original data.
 *
 * New error correction:
 *   poly=NN   pin one polynomial for every entry (its t is fixed by
 *             the poly; any blob size works — the encoder splits into
 *             blocks, so no blob is ever too large for a poly).
 *   -e N      set the level (0=none, 1->t=1, 2->t=2, 3->t=4, 4->t=8,
 *             5->t=16, 6->t=32, 7->t=32); the most efficient poly per
 *             blob is auto-picked, as in `lzply -c`.
 *   neither   re-encode with the same poly and t the entry already
 *             has — a pure heal pass that corrects bit errors.
 *   -e 0      strip the error correction entirely (no parity).
 * poly= overrides -e when both are given.
 *
 * An entry whose BCH decode fails (uncorrectable) is kept byte-for-byte
 * unchanged, reported, and the program exits non-zero at the end; the
 * other entries are still healed. Directories have no data and are
 * copied verbatim. The archive is rewritten via a temp file and
 * renamed over the original (or over -o), so a failure leaves the
 * original intact. The archive must not be mounted: heal takes the
 * same exclusive flock the mount daemon holds, so a mounted archive
 * is refused and a mount cannot start mid-heal. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lzply_lib.h"
#include "lzply_util.h"

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <archive.lzply> [-e <level>] [poly=<id>] [-o <output.lzply>] [selector...]\n"
            "  Strip the BCH error correction from each entry and reapply a\n"
            "  new one. The compressed blob is never touched, so the\n"
            "  data is unchanged.\n"
            "  -e <level>  new BCH level: 0=none, 1->t=1, 2->t=2, 3->t=4,\n"
            "              4->t=8 (default for new archives), 5->t=16,\n"
            "              6->t=32, 7->t=32. Auto-picks the most efficient\n"
            "              poly per blob. -e 0 strips the ECC entirely.\n"
            "  poly=<id>   pin one BCH polynomial by id, hex (poly=003a)\n"
            "              or decimal (poly=58); overrides -e.\n"
            "  -o <file>   write the healed archive to <file> instead of\n"
            "              healing in place (the original is untouched).\n"
            "  With neither -e nor poly=, each entry is re-encoded with\n"
            "  the same poly and t it already has — a pure heal pass that\n"
            "  corrects bit errors up to t. The archive must not be\n"
            "  mounted while healing.\n",
            prog);
}

/* Parse a poly=NN value: hex if it has a 0x prefix or any a-f/A-F
 * letter, else decimal. Returns the poly, or NULL if it is not a
 * number or not one of the 82 embedded polys. (Same rule as lzply.) */
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

/* Largest parent's poly for a t (m=22 has all six t values). The
 * auto-pick fallback when a blob is larger than the largest single
 * block, so it is split into blocks of that poly. Scans the embedded
 * table for the largest m with the given t. */
static const bch_poly_t *largest_poly_for_t(int t)
{
    const bch_poly_t *best = NULL;
    uint16_t id;
    if (t < 1 || t > 32)
        return NULL;
    for (id = 0x0001; id <= 0x0052; id++) {
        const bch_poly_t *p = bch_poly_by_id(id);
        if (p && p->t == t && (!best || p->m > best->m))
            best = p;
    }
    return best;
}

/* Describe a poly for a report line: "003a (m=18, t=32)" or "none". */
static void fmt_poly(const bch_poly_t *p, char *buf, size_t bufsz)
{
    if (!p)
        snprintf(buf, bufsz, "none");
    else
        snprintf(buf, bufsz, "%04x (m=%u, t=%u)",
                 (unsigned)p->id, (unsigned)p->m, (unsigned)p->t);
}

int main(int argc, char *argv[])
{
    const char *archive = NULL, *output = NULL;
    const char **selectors = NULL;
    int nselectors = 0;
    int ecc_level = -1;         /* -1: no -e given */
    const bch_poly_t *pinned = NULL;
    char *carch = NULL;
    FILE *src = NULL, *tmp = NULL;
    char *tmp_path = NULL;
    const char *dest = NULL;
    uint32_t count = 0;
    int version = 0;
    off_t size_out = 0, end_off = 0;
    scan_list_t entries;
    size_t i;
    int rc = 0, fail = 0;
    uint32_t nhealed = 0, nunchanged = 0, nskipped = 0, nfailed = 0;
    uint64_t tot_corrected = 0;

    lzply_set_progname("lzply_heal");
    crc32_init();

    /* Options may appear before or after the positionals, as in lzply. */
    for (i = 1; i < (size_t)argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-e") == 0 || strcmp(a, "--ecc") == 0 ||
            strcmp(a, "--rs") == 0) {
            if (i + 1 >= (size_t)argc) {
                fprintf(stderr, "%s: -e needs a level 0..7\n",
                        lzply_progname);
                return EXIT_USAGE;
            }
            ecc_level = atoi(argv[++i]);
            if (ecc_level < 0 || ecc_level > 7) {
                fprintf(stderr, "%s: BCH level must be 0..7\n",
                        lzply_progname);
                return EXIT_USAGE;
            }
        } else if (a[0] == '-' && a[1] == 'e' && a[2] != '\0') {
            ecc_level = atoi(a + 2);
            if (ecc_level < 0 || ecc_level > 7) {
                fprintf(stderr, "%s: BCH level must be 0..7\n",
                        lzply_progname);
                return EXIT_USAGE;
            }
        } else if (strncmp(a, "poly=", 5) == 0 ||
                   strncmp(a, "-poly=", 6) == 0 ||
                   strncmp(a, "--poly=", 7) == 0) {
            const char *eq = strchr(a, '=');
            pinned = parse_poly_id(eq + 1);
            if (!pinned) {
                fprintf(stderr,
                        "%s: unknown BCH polynomial '%s' "
                        "(want an id 0001..0052, hex or decimal)\n",
                        lzply_progname, eq + 1);
                return EXIT_USAGE;
            }
        } else if (strcmp(a, "-o") == 0) {
            if (i + 1 >= (size_t)argc) {
                fprintf(stderr, "%s: -o needs an output file\n",
                        lzply_progname);
                return EXIT_USAGE;
            }
            output = argv[++i];
        } else if (strncmp(a, "-o=", 3) == 0) {
            output = a + 3;
            if (!*output) {
                fprintf(stderr, "%s: -o needs an output file\n",
                        lzply_progname);
                return EXIT_USAGE;
            }
        } else if (a[0] == '-' && a[1] == 'o' && a[2] != '\0') {
            output = a + 2;
        } else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "%s: unknown option %s\n", lzply_progname, a);
            usage(argv[0]);
            return EXIT_USAGE;
        } else if (!archive) {
            archive = a;
        } else {
            /* Extra positionals are selectors. */
            selectors = (const char **)(argv + i);
            nselectors = argc - (int)i;
            break;
        }
    }
    if (!archive) {
        usage(argv[0]);
        return EXIT_USAGE;
    }

    carch = canon_path(archive);
    if (!carch) {
        fprintf(stderr, "%s: cannot resolve %s\n", lzply_progname, archive);
        return EXIT_IO;
    }

    /* Open the archive and take the mount lock (the same exclusive
     * flock the lzply_mount daemon holds). If it is held, the archive
     * is mounted: refuse, change nothing. The lock is held for the
     * whole run, so a mount cannot start mid-heal either. */
    src = fopen(carch, "rb");
    if (!src) {
        fprintf(stderr, "%s: cannot open %s: %s\n", lzply_progname,
                carch, strerror(errno));
        free(carch);
        return EXIT_IO;
    }
    if (flock(fileno(src), LOCK_EX | LOCK_NB) != 0) {
        if (errno == EWOULDBLOCK) {
            char *mp = NULL;
            if (archive_is_mounted(carch, &mp) == 1) {
                fprintf(stderr,
                        "%s: %s is mounted on %s; unmount it before "
                        "healing (healing under a live mount would "
                        "corrupt the daemon's in-memory index)\n",
                        lzply_progname, carch, mp);
                free(mp);
            } else {
                fprintf(stderr,
                        "%s: %s is locked by another process; "
                        "healing refused\n",
                        lzply_progname, carch);
            }
        } else {
            fprintf(stderr, "%s: cannot lock %s: %s\n", lzply_progname,
                    carch, strerror(errno));
        }
        fclose(src);
        free(carch);
        return EXIT_IO;
    }

    if (scan_archive(carch, &version, &count, &size_out, &entries,
                     &end_off) != 0) {
        fclose(src);
        free(carch);
        return EXIT_CORRUPT;
    }

    dest = output ? output : carch;
    tmp = temp_in_same_dir(dest, &tmp_path);
    if (!tmp) {
        fprintf(stderr, "%s: cannot create temp file for %s: %s\n",
                lzply_progname, dest, strerror(errno));
        scan_list_free(&entries);
        fclose(src);
        free(carch);
        return EXIT_IO;
    }
    write_global_header(tmp, count, LZPLY_VERSION);
    if (ferror(tmp)) {
        fprintf(stderr, "%s: cannot write %s\n", lzply_progname, dest);
        fclose(tmp);
        unlink(tmp_path);
        free(tmp_path);
        scan_list_free(&entries);
        fclose(src);
        free(carch);
        return EXIT_IO;
    }

    for (i = 0; i < entries.len; i++) {
        scan_entry_t *e = &entries.v[i];
        ehdr_t h;
        uint8_t *stored = NULL, *blob = NULL, *new_stored = NULL;
        size_t new_stored_len = 0;
        const bch_poly_t *p_old = NULL, *p_new = NULL;
        int corrected = 0, is_dir, matched;
        uint16_t old_id = 0;

        if (fseeko(src, e->offset, SEEK_SET) != 0 ||
            read_entry_header(src, &h) != 0) {
            fprintf(stderr, "%s: cannot read entry header at %lld\n",
                    lzply_progname, (long long)e->offset);
            rc = EXIT_CORRUPT;
            goto heal_done;
        }
        is_dir = (h.flags & FLAG_ISDIR) != 0;
        matched = path_matches_selectors(h.path, selectors, nselectors);

        if (h.stored_size > 0) {
            stored = xmalloc(h.stored_size ? h.stored_size : 1);
            if (fread(stored, 1, h.stored_size, src) != h.stored_size) {
                fprintf(stderr, "%s: truncated data for %s\n",
                        lzply_progname, h.path);
                free(stored);
                free(h.path);
                rc = EXIT_CORRUPT;
                goto heal_done;
            }
        }

        if (is_dir || !matched) {
            /* Directories have no data; non-matching entries are
             * left alone. Re-emit byte-for-byte (the header CRC is
             * deterministic and the archive was validated on scan). */
            if (write_entry_header(tmp, &h) != 0 ||
                (h.stored_size > 0 &&
                 fwrite(stored, 1, h.stored_size, tmp) != h.stored_size)) {
                fprintf(stderr, "%s: cannot write %s\n",
                        lzply_progname, dest);
                free(stored);
                free(h.path);
                rc = EXIT_IO;
                goto heal_done;
            }
            if (is_dir)
                nunchanged++;
            else
                nskipped++;
            free(stored);
            free(h.path);
            continue;
        }

        /* A file entry to heal. Strip the BCH parity (correcting bit
         * errors up to t); without BCH the blob is the stored data. */
        if ((h.flags & FLAG_BCH) != 0) {
            old_id = (uint16_t)(h.rs_level |
                                ((unsigned)h.reserved << 8));
            p_old = bch_poly_by_id(old_id);
            blob = xmalloc(h.blob_size ? h.blob_size : 1);
            if (bch_decode(stored, h.stored_size, h.blob_size, p_old,
                           blob, &corrected) != 0) {
                /* Uncorrectable: keep byte-for-byte, report, continue. */
                fprintf(stderr,
                        "%s: %s: BCH decode failed (more than t=%u bit "
                        "errors for poly %04x); entry kept unchanged\n",
                        lzply_progname, h.path, (unsigned)p_old->t,
                        (unsigned)old_id);
                if (write_entry_header(tmp, &h) != 0 ||
                    (h.stored_size > 0 &&
                     fwrite(stored, 1, h.stored_size, tmp) !=
                         h.stored_size)) {
                    fprintf(stderr, "%s: cannot write %s\n",
                            lzply_progname, dest);
                    free(blob);
                    free(stored);
                    free(h.path);
                    rc = EXIT_IO;
                    goto heal_done;
                }
                nfailed++;
                fail = 1;
                free(blob);
                free(stored);
                free(h.path);
                continue;
            }
        } else {
            blob = xmalloc(h.blob_size ? h.blob_size : 1);
            if (h.blob_size > 0)
                memcpy(blob, stored, h.blob_size);
        }

        /* Pick the new error correction. */
        if (pinned) {
            p_new = pinned;
        } else if (ecc_level >= 0) {
            int t = bch_t_for_level(ecc_level);
            if (t == 0) {
                p_new = NULL;
            } else {
                p_new = bch_poly_for_data(h.blob_size, t);
                if (!p_new)
                    p_new = largest_poly_for_t(t);
            }
        } else {
            p_new = p_old;      /* pure heal: same poly and t */
        }

        if ((p_old ? p_old->id : 0) == (p_new ? p_new->id : 0) &&
            corrected == 0) {
            /* Same ECC and no errors corrected: re-encoding would
             * produce identical bytes, so copy verbatim. */
            if (write_entry_header(tmp, &h) != 0 ||
                (h.stored_size > 0 &&
                 fwrite(stored, 1, h.stored_size, tmp) != h.stored_size)) {
                fprintf(stderr, "%s: cannot write %s\n",
                        lzply_progname, dest);
                free(blob);
                free(stored);
                free(h.path);
                rc = EXIT_IO;
                goto heal_done;
            }
            nunchanged++;
            free(blob);
            free(stored);
            free(h.path);
            continue;
        }

        /* Verify the stripped blob before re-encoding (all
         * entries): decompress and check the SHA-256. This
         * catches a BCH miscorrection, which is possible when the
         * errors exceed t (notably at small t: t=1 with 2-bit errors
         * miscorrects about half the time). A miscorrected blob
         * would decompress to the wrong data, and must not be
         * re-encoded. A level-0 entry is stored uncompressed, so
         * its blob is the raw data: check the SHA-256 directly. */
        {
            uint8_t *raw = NULL;
            size_t raw_len = 0;
            uint8_t sha[32];
            int vok = 0;
            if (h.level == 0) {
                if (h.blob_size == h.orig_size) {
                    lzply_sha256(blob, h.blob_size, sha);
                    vok = (memcmp(sha, h.sha, 32) == 0);
                }
            } else if (lz_decompress_mem(blob, h.blob_size, &raw, &raw_len) == 0 &&
                raw_len == h.orig_size) {
                lzply_sha256(raw, raw_len, sha);
                vok = (memcmp(sha, h.sha, 32) == 0);
            }
            free(raw);
            if (!vok) {
                fprintf(stderr,
                        "%s: %s: stripped blob does not verify "
                        "(SHA-256 mismatch after decompress); entry "
                        "kept unchanged\n",
                        lzply_progname, h.path);
                if (write_entry_header(tmp, &h) != 0 ||
                    (h.stored_size > 0 &&
                     fwrite(stored, 1, h.stored_size, tmp) !=
                         h.stored_size)) {
                    fprintf(stderr, "%s: cannot write %s\n",
                            lzply_progname, dest);
                    free(blob);
                    free(stored);
                    free(h.path);
                    rc = EXIT_IO;
                    goto heal_done;
                }
                nfailed++;
                fail = 1;
                free(blob);
                free(stored);
                free(h.path);
                continue;
            }
        }

        /* Re-encode with the new ECC. */
        if (p_new) {
            new_stored_len = bch_encoded_len(h.blob_size, p_new);
            new_stored = xmalloc(new_stored_len ? new_stored_len : 1);
            if (bch_encode(blob, h.blob_size, p_new, new_stored) !=
                    new_stored_len) {
                fprintf(stderr, "%s: %s: BCH encode failed\n",
                        lzply_progname, h.path);
                free(new_stored);
                free(blob);
                free(stored);
                free(h.path);
                rc = EXIT_CORRUPT;
                goto heal_done;
            }
            /* Self-check: the new encoding must decode to the blob. */
            {
                uint8_t *check = xmalloc(h.blob_size ? h.blob_size : 1);
                int c2 = 0;
                if (bch_decode(new_stored, new_stored_len, h.blob_size,
                               p_new, check, &c2) != 0 ||
                    (h.blob_size > 0 &&
                     memcmp(check, blob, h.blob_size) != 0)) {
                    fprintf(stderr,
                            "%s: %s: internal error: re-encoded entry "
                            "does not decode; entry kept unchanged\n",
                            lzply_progname, h.path);
                    free(check);
                    if (write_entry_header(tmp, &h) != 0 ||
                        (h.stored_size > 0 &&
                         fwrite(stored, 1, h.stored_size, tmp) !=
                             h.stored_size)) {
                        fprintf(stderr, "%s: cannot write %s\n",
                                lzply_progname, dest);
                        free(new_stored);
                        free(blob);
                        free(stored);
                        free(h.path);
                        rc = EXIT_IO;
                        goto heal_done;
                    }
                    nfailed++;
                    fail = 1;
                    free(new_stored);
                    free(blob);
                    free(stored);
                    free(h.path);
                    continue;
                }
                free(check);
            }
        } else {
            new_stored = blob;  /* no ECC: the blob is the stored data */
            new_stored_len = h.blob_size;
            blob = NULL;        /* ownership moved to new_stored */
        }

        {
            ehdr_t h2 = h;
            char oldp[32], newp[32];
            h2.stored_size = new_stored_len;
            if (p_new) {
                h2.flags |= FLAG_BCH;
                h2.rs_level = (uint8_t)(p_new->id & 0xff);
                h2.reserved = (uint8_t)((p_new->id >> 8) & 0xff);
            } else {
                h2.flags &= (uint8_t)~FLAG_BCH;
                h2.rs_level = 0;
                h2.reserved = 0;
            }
            if (write_entry_header(tmp, &h2) != 0 ||
                (new_stored_len > 0 &&
                 fwrite(new_stored, 1, new_stored_len, tmp) !=
                     new_stored_len)) {
                fprintf(stderr, "%s: cannot write %s\n",
                        lzply_progname, dest);
                free(new_stored);
                free(blob);
                free(stored);
                free(h.path);
                rc = EXIT_IO;
                goto heal_done;
            }
            fmt_poly(p_old, oldp, sizeof oldp);
            fmt_poly(p_new, newp, sizeof newp);
            printf("%s: %s -> %s, stored %" PRIu64 " -> %" PRIu64
                   " B, %d bit error(s) corrected\n",
                   h.path, oldp, newp, h.stored_size,
                   (uint64_t)new_stored_len, corrected);
            tot_corrected += (uint64_t)corrected;
            nhealed++;
        }
        free(new_stored);
        free(blob);
        free(stored);
        free(h.path);
    }

    /* End marker, then flush + fsync the temp file and rename it over
     * the destination. The original is untouched until the rename. */
    {
        uint8_t end[2] = {0, 0};
        if (fwrite(end, 1, 2, tmp) != 2 || fflush(tmp) != 0 ||
            fsync(fileno(tmp)) != 0) {
            fprintf(stderr, "%s: cannot finish %s: %s\n",
                    lzply_progname, dest, strerror(errno));
            rc = EXIT_IO;
            goto heal_done;
        }
    }
    if (fclose(tmp) != 0) {
        tmp = NULL;
        fprintf(stderr, "%s: cannot close %s: %s\n", lzply_progname,
                dest, strerror(errno));
        unlink(tmp_path);
        rc = EXIT_IO;
        goto heal_done;
    }
    tmp = NULL;
    if (rename(tmp_path, dest) != 0) {
        fprintf(stderr, "%s: cannot replace %s: %s\n", lzply_progname,
                dest, strerror(errno));
        rc = EXIT_IO;
        goto heal_done;
    }
    printf("%s: %s: %u healed, %u unchanged, %u skipped by selector, "
           "%u uncorrectable (kept), %" PRIu64 " bit error(s) corrected\n",
           lzply_progname, dest, nhealed, nunchanged, nskipped, nfailed,
           tot_corrected);
    rc = fail ? EXIT_CORRUPT : 0;

heal_done:
    if (tmp) {
        fclose(tmp);
        if (tmp_path)
            unlink(tmp_path);
    }
    free(tmp_path);
    scan_list_free(&entries);
    if (src)
        fclose(src);
    free(carch);
    return rc;
}
