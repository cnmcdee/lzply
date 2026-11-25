/* lzply_refresh.c - rewrite a file over itself, in place, to refresh
 * the magnetic signal on older spinning disks.
 *
 *   lzply_refresh <path> [n]
 *
 * n = number of rewrite passes, 1-3, default 1. The whole file is
 * read into memory, then each pass opens the file O_WRONLY (same
 * inode — never deleted and recreated), writes the bytes back from
 * offset 0, and fsyncs. The point is to rewrite the same blocks so
 * the magnetic signal on the platter is refreshed.
 *
 * Verification: SHA-256 of the file before the first pass and after
 * the last pass must match; both hashes are reported. If the content
 * changed, that is an error (exit non-zero).
 *
 * The path may be a single file, a directory, or a mount point (an
 * lzply_mount mount, or any directory — directories are refreshed
 * recursively). For a directory, every regular file under it is
 * refreshed with the same pass count; symlinks and special files are
 * skipped, the same rule as `lzply -c`. A mount point is detected
 * via the same mount resolution as lzply_stat (/proc/mounts) and
 * noted in the output.
 *
 * A file inside an lzply_mount mount works: the write goes through
 * FUSE and the entry is re-encoded on repack, which also refreshes
 * the archive. But an .lzply archive file that is currently mounted
 * is refused (same rule as lzply_heal — modifying the archive under
 * a live mount corrupts the daemon's view).
 *
 * Caveats: on copy-on-write filesystems (btrfs, ZFS) an overwrite
 * may allocate new blocks rather than rewriting the same sectors,
 * so the platter refresh may not happen — this tool is aimed at
 * traditional overwrite filesystems (ext4) and older spinning
 * disks. On SSDs wear-levelling means a rewrite does not hit the
 * same cells, so it is specifically for older physical (magnetic)
 * drives. The whole file is buffered in memory, like the rest of
 * the lzply family. */
#define _XOPEN_SOURCE 500
#define _DEFAULT_SOURCE
#include <errno.h>
#include <ftw.h>
#include <fcntl.h>
#include "sha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lzply_lib.h"
#include "lzply_util.h"

static void usage(const char *prog)
{
    fprintf(stderr,
            "usage: %s <path> [n]\n"
            "  <path> may be a file, a directory, or a mount point.\n"
            "  n = rewrite passes, 1-3, default 1. n outside 1..3 is a\n"
            "  usage error.\n"
            "  The file is read into memory, then each pass rewrites it\n"
            "  in place (same inode: O_WRONLY, write from offset 0,\n"
            "  fsync). SHA-256 before the first pass and after the last\n"
            "  pass must match; both hashes are reported.\n"
            "  A directory (or mount point) is refreshed recursively:\n"
            "  every regular file under it, symlinks and special files\n"
            "  skipped. An .lzply archive file that is currently\n"
            "  mounted is refused.\n"
            "  Caveats: copy-on-write filesystems (btrfs, ZFS) may\n"
            "  allocate new blocks instead of rewriting the same\n"
            "  sectors, and SSD wear-levelling means a rewrite does\n"
            "  not hit the same cells — this is for ext4-style\n"
            "  overwrite filesystems on older spinning disks.\n",
            prog);
}

static void sha256_hex(const unsigned char *data, size_t len,
                       char out[65])
{
    unsigned char md[32];
    static const char hexd[] = "0123456789abcdef";
    unsigned int i;

    lzply_sha256(data, len, md);
    for (i = 0; i < 32; i++) {
        out[2 * i] = hexd[md[i] >> 4];
        out[2 * i + 1] = hexd[md[i] & 0xf];
    }
    out[64] = '\0';
}

/* Refresh one regular file. Returns 0 on success (content verified
 * unchanged), -1 on any failure. Prints a per-file report line. */
static int refresh_file(const char *path, int passes)
{
    struct stat st;
    unsigned char *buf = NULL;
    char before[65], after[65];
    int fd, pass;
    size_t done = 0;

    if (lstat(path, &st) != 0) {
        fprintf(stderr, "%s: cannot stat %s: %s\n", lzply_progname,
                path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "%s: skipping %s (not a regular file)\n",
                lzply_progname, path);
        return -1;
    }
    if (st.st_size < 0) {
        fprintf(stderr, "%s: %s has a negative size; refusing\n",
                lzply_progname, path);
        return -1;
    }

    buf = malloc(st.st_size > 0 ? (size_t)st.st_size : 1);
    if (!buf) {
        fprintf(stderr, "%s: out of memory reading %s\n",
                lzply_progname, path);
        return -1;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: cannot open %s: %s\n", lzply_progname,
                path, strerror(errno));
        free(buf);
        return -1;
    }
    done = 0;
    while (done < (size_t)st.st_size) {
        ssize_t r = read(fd, buf + done, (size_t)st.st_size - done);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "%s: cannot read %s: %s\n", lzply_progname,
                    path, strerror(errno));
            close(fd);
            free(buf);
            return -1;
        }
        if (r == 0)
            break; /* file shrank mid-read; caught by the size check below */
        done += (size_t)r;
    }
    close(fd);
    if (done != (size_t)st.st_size) {
        fprintf(stderr,
                "%s: %s changed size while reading (%zu of %lld bytes); "
                "refusing to refresh a moving target\n",
                lzply_progname, path, done, (long long)st.st_size);
        free(buf);
        return -1;
    }
    sha256_hex(buf, (size_t)st.st_size, before);

    for (pass = 0; pass < passes; pass++) {
        size_t off = 0;
        fd = open(path, O_WRONLY); /* same inode, no O_TRUNC */
        if (fd < 0) {
            fprintf(stderr, "%s: cannot open %s for writing: %s\n",
                    lzply_progname, path, strerror(errno));
            free(buf);
            return -1;
        }
        while (off < (size_t)st.st_size) {
            ssize_t w = pwrite(fd, buf + off,
                               (size_t)st.st_size - off, (off_t)off);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                fprintf(stderr, "%s: cannot write %s: %s\n",
                        lzply_progname, path, strerror(errno));
                close(fd);
                free(buf);
                return -1;
            }
            off += (size_t)w;
        }
        if (fsync(fd) != 0) {
            fprintf(stderr, "%s: fsync failed on %s: %s\n",
                    lzply_progname, path, strerror(errno));
            close(fd);
            free(buf);
            return -1;
        }
        if (close(fd) != 0) {
            fprintf(stderr, "%s: close failed on %s: %s\n",
                    lzply_progname, path, strerror(errno));
            free(buf);
            return -1;
        }
        /* The file must not have changed size under us. */
        if (stat(path, &st) != 0 || st.st_size < 0 ||
            (size_t)st.st_size != done) {
            fprintf(stderr,
                    "%s: %s changed size during refresh; refusing\n",
                    lzply_progname, path);
            free(buf);
            return -1;
        }
    }

    /* Re-read and verify the content is byte-identical. */
    {
        unsigned char *back = malloc(done > 0 ? done : 1);
        size_t rdone = 0;
        if (!back) {
            fprintf(stderr, "%s: out of memory verifying %s\n",
                    lzply_progname, path);
            free(buf);
            return -1;
        }
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "%s: cannot re-open %s: %s\n",
                    lzply_progname, path, strerror(errno));
            free(back);
            free(buf);
            return -1;
        }
        while (rdone < done) {
            ssize_t r = read(fd, back + rdone, done - rdone);
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                fprintf(stderr, "%s: cannot re-read %s: %s\n",
                        lzply_progname, path, strerror(errno));
                close(fd);
                free(back);
                free(buf);
                return -1;
            }
            if (r == 0)
                break;
            rdone += (size_t)r;
        }
        close(fd);
        if (rdone != done) {
            fprintf(stderr,
                    "%s: %s changed size during verification; refusing\n",
                    lzply_progname, path);
            free(back);
            free(buf);
            return -1;
        }
        sha256_hex(back, done, after);
        free(back);
    }
    free(buf);

    if (strcmp(before, after) != 0) {
        fprintf(stderr,
                "%s: %s CONTENT CHANGED during refresh!\n"
                "  sha256 before: %s\n"
                "  sha256 after:  %s\n",
                lzply_progname, path, before, after);
        return -1;
    }
    printf("%s: %lld bytes, %d pass%s, sha256 %s, verified unchanged\n",
           path, (long long)done, passes, passes == 1 ? "" : "es",
           before);
    return 0;
}

/* Recursive (directory / mount point) state for the nftw callback. */
static int g_passes;
static size_t g_refreshed, g_skipped, g_failed;

static int refresh_nftw_cb(const char *fpath, const struct stat *sb,
                           int typeflag, struct FTW *ftwbuf)
{
    (void)ftwbuf;
    switch (typeflag) {
    case FTW_F:
        if (!S_ISREG(sb->st_mode)) {
            /* FTW_F should be a regular file; be safe anyway. */
            g_skipped++;
            printf("skipped (not a regular file): %s\n", fpath);
            return 0;
        }
        if (refresh_file(fpath, g_passes) == 0)
            g_refreshed++;
        else
            g_failed++;
        return 0;
    case FTW_SL:
    case FTW_SLN:
        g_skipped++;
        printf("skipped (symlink): %s\n", fpath);
        return 0;
    case FTW_D:
    case FTW_DP:
        return 0;
    case FTW_NS:
    case FTW_DNR:
    default:
        g_skipped++;
        fprintf(stderr, "%s: cannot access %s; skipped\n",
                lzply_progname, fpath);
        return 0;
    }
}

int main(int argc, char **argv)
{
    const char *path;
    int passes = 1;
    struct stat st;
    char *canon = NULL;

    lzply_set_progname(argv[0]);
    if (argc < 2 || argc > 3) {
        usage(lzply_progname);
        return EXIT_USAGE;
    }
    path = argv[1];
    if (argc == 3) {
        char *end = NULL;
        long n = strtol(argv[2], &end, 10);
        if (end == argv[2] || *end != '\0' || n < 1 || n > 3) {
            fprintf(stderr,
                    "%s: invalid pass count '%s' (must be 1, 2 or 3)\n",
                    lzply_progname, argv[2]);
            usage(lzply_progname);
            return EXIT_USAGE;
        }
        passes = (int)n;
    }

    if (lstat(path, &st) != 0) {
        fprintf(stderr, "%s: cannot stat %s: %s\n", lzply_progname,
                path, strerror(errno));
        return EXIT_IO;
    }

    if (S_ISREG(st.st_mode)) {
        /* A mounted archive file must not be refreshed in place:
         * same rule as lzply_heal — modifying the archive under a
         * live mount corrupts the daemon's view. */
        canon = canon_path(path);
        if (canon) {
            char *mp = NULL;
            if (archive_is_mounted(canon, &mp) == 1) {
                fprintf(stderr,
                        "%s: %s is mounted on %s; unmount it before "
                        "refreshing (refreshing under a live mount "
                        "would corrupt the daemon's in-memory index)\n",
                        lzply_progname, path, mp);
                free(mp);
                free(canon);
                return EXIT_IO;
            }
            free(canon);
        }
        /* A file inside a mount: note it, the write goes through FUSE
         * and the entry is re-encoded on repack. */
        {
            char *arch = NULL, *mpoint = NULL, *rel = NULL;
            if (mount_resolve(path, &arch, &mpoint, &rel) == 0) {
                printf("note: %s is inside mount %s (archive %s); "
                       "the write goes through FUSE and the entry is "
                       "re-encoded on repack\n",
                       path, mpoint, arch);
                free(arch);
                free(mpoint);
                free(rel);
            }
        }
        return refresh_file(path, passes) == 0 ? 0 : EXIT_IO;
    }

    if (S_ISDIR(st.st_mode)) {
        char *arch = NULL, *mpoint = NULL, *rel = NULL;
        int in_mount = (mount_resolve(path, &arch, &mpoint, &rel) == 0);
        if (in_mount && rel && rel[0] == '\0')
            printf("refreshing mount at %s: (archive %s)\n",
                   mpoint, arch);
        else if (in_mount)
            printf("refreshing directory %s inside mount %s "
                   "(archive %s)\n", path, mpoint, arch);
        else
            printf("refreshing directory %s:\n", path);
        free(arch);
        free(mpoint);
        free(rel);

        g_passes = passes;
        g_refreshed = g_skipped = g_failed = 0;
        if (nftw(path, refresh_nftw_cb, 20, FTW_PHYS) != 0) {
            fprintf(stderr, "%s: cannot walk %s: %s\n", lzply_progname,
                    path, strerror(errno));
            return EXIT_IO;
        }
        printf("summary: %zu file%s refreshed (%d pass%s each), "
               "%zu skipped, %zu failed\n",
               g_refreshed, g_refreshed == 1 ? "" : "s",
               passes, passes == 1 ? "" : "es",
               g_skipped, g_failed);
        return g_failed == 0 ? 0 : EXIT_IO;
    }

    fprintf(stderr,
            "%s: %s is not a regular file or a directory "
            "(symlinks and special files are skipped)\n",
            lzply_progname, path);
    usage(lzply_progname);
    return EXIT_USAGE;
}
