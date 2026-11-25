/* lzply_util.c - shared helpers for lzply_stat and lzply_mount_heal.
 *
 * Mount resolution works in two steps. /proc/mounts tells us which
 * mount points are fuse.lzply_mount filesystems (the source field is the
 * literal "lzply_mount", so the fstype is the reliable marker). The
 * backing archive is not in /proc/mounts, so the daemon is found by
 * scanning /proc for a process whose argv[0] is lzply_mount and whose
 * positional arguments are <archive> <mountpoint> — the same two
 * arguments lzply_mount takes on the command line. Options between
 * argv[0] and the archive (notably "-o rw" when the mount went
 * through mount -t lzply) are skipped, and relative paths are
 * resolved against the daemon's cwd. */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lzply_lib.h"
#include "lzply_util.h"

const char *human_size(uint64_t n, char *buf, size_t bufsz)
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

char *canon_path(const char *path)
{
    char *r = realpath(path, NULL);
    if (r)
        return r;
    /* Split off the last component and canonicalise the parent. */
    const char *slash = strrchr(path, '/');
    if (!slash)
        return xstrdup(path);   /* bare name; leave as-is */
    if (slash == path)
        return xstrdup(path);   /* "/name": parent is the root */
    size_t dlen = (size_t)(slash - path);
    char *dir = xmalloc(dlen + 1);
    memcpy(dir, path, dlen);
    dir[dlen] = '\0';
    char *cd = canon_path(dir);
    free(dir);
    if (!cd)
        return NULL;
    size_t cl = strlen(cd);
    int need_slash = (cl == 0 || cd[cl - 1] != '/');
    char *out = xmalloc(cl + (size_t)need_slash + strlen(slash + 1) + 1);
    strcpy(out, cd);
    if (need_slash)
        strcat(out, "/");
    strcat(out, slash + 1);
    free(cd);
    return out;
}

/* ------------------------------------------------------------------ */
/* /proc/mounts                                                        */
/* ------------------------------------------------------------------ */

/* Unescape a /proc/mounts field (\040 space, \011 tab, \012 newline,
 * \134 backslash). Returns a malloced string. */
static char *unescape_field(const char *s, size_t len)
{
    char *out = xmalloc(len + 1);
    size_t o = 0, i = 0;
    while (i < len) {
        if (s[i] == '\\' && i + 4 <= len &&
            s[i + 1] >= '0' && s[i + 1] <= '7' &&
            s[i + 2] >= '0' && s[i + 2] <= '7' &&
            s[i + 3] >= '0' && s[i + 3] <= '7') {
            out[o++] = (char)((s[i + 1] - '0') * 64 +
                              (s[i + 2] - '0') * 8 + (s[i + 3] - '0'));
            i += 4;
        } else {
            out[o++] = s[i++];
        }
    }
    out[o] = '\0';
    return out;
}

/* Read /proc/mounts and return the mount points whose fstype is
 * fuse.lzply_mount. Returns 0 on success (*out malloced array of malloced
 * strings, *n_out entries), -1 if /proc/mounts cannot be read. */
static int read_lzply_mount_mounts(char ***out, size_t *n_out)
{
    FILE *f = fopen("/proc/mounts", "r");
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    char **mounts = NULL;
    size_t n = 0, mcap = 0;
    *out = NULL;
    *n_out = 0;
    if (!f)
        return -1;
    while ((len = getline(&line, &cap, f)) >= 0) {
        /* Fields: source, mountpoint, fstype, options, ... */
        char *sp1 = strchr(line, ' ');
        char *sp2, *sp3;
        char *mp, *fstype;
        if (!sp1)
            continue;
        sp2 = strchr(sp1 + 1, ' ');
        if (!sp2)
            continue;
        sp3 = strchr(sp2 + 1, ' ');
        if (!sp3)
            continue;
        mp = unescape_field(sp1 + 1, (size_t)(sp2 - (sp1 + 1)));
        fstype = unescape_field(sp2 + 1, (size_t)(sp3 - (sp2 + 1)));
        if (strcmp(fstype, "fuse.lzply_mount") == 0) {
            if (n == mcap) {
                mcap = mcap ? mcap * 2 : 8;
                mounts = xrealloc(mounts, mcap * sizeof *mounts);
            }
            mounts[n++] = mp;
            mp = NULL;
        }
        free(mp);
        free(fstype);
    }
    free(line);
    fclose(f);
    *out = mounts;
    *n_out = n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* /proc cmdline scan for the lzply_mount daemon                            */
/* ------------------------------------------------------------------ */

/* Resolve a possibly-relative daemon argument against the daemon's
 * cwd. Returns a malloced string. */
static char *resolve_against_cwd(const char *arg, const char *cwd)
{
    if (arg[0] == '/' || !cwd)
        return xstrdup(arg);
    size_t cl = strlen(cwd);
    int need_slash = (cl == 0 || cwd[cl - 1] != '/');
    char *out = xmalloc(cl + (size_t)need_slash + strlen(arg) + 1);
    strcpy(out, cwd);
    if (need_slash)
        strcat(out, "/");
    strcat(out, arg);
    return out;
}

/* Resolve a raw daemon argument against a cwd (empty cwd = leave as-is).
 * libfuse changes the daemon's cwd to "/" at mount time, so a daemon
 * started with a relative path needs its args resolved against the
 * cwd it was started from, not the one it has now. */
static char *resolve_arg(const char *arg, const char *cwd)
{
    if (arg[0] == '/' || !cwd || cwd[0] == '\0')
        return xstrdup(arg);
    return resolve_against_cwd(arg, cwd);
}


static int all_digits(const char *s)
{
    if (!*s)
        return 0;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s))
            return 0;
    return 1;
}

/* Parse /proc/<pid>/cmdline as an lzply_mount invocation. On success
 * returns 0 and mallocs *archive_out and *mountpoint_out (the two
 * positional arguments, as given on the daemon's command line) and
 * *cwd_out (the daemon's cwd, "" if it could not be read). Callers
 * resolve the relative args themselves: the daemon's cwd is "/" after
 * libfuse's mount-time chdir, so it is only one candidate. Returns -1
 * if this pid is not an lzply_mount daemon. */
static int parse_lzply_mount_cmdline(const char *pid, char **archive_out,
                                char **mountpoint_out, char **cwd_out)
{
    char path[64];
    FILE *f;
    uint8_t *buf;
    size_t n;
    char **argv = NULL;
    size_t argc = 0, acap = 0, i;
    const char *base;
    const char *pos[2] = {NULL, NULL};
    int npos = 0;
    char cwd[PATH_MAX];
    char linkpath[64];
    ssize_t cl;

    snprintf(path, sizeof path, "/proc/%s/cmdline", pid);
    f = fopen(path, "rb");
    if (!f)
        return -1;
    buf = xmalloc(65536);
    n = fread(buf, 1, 65535, f);
    fclose(f);
    if (n == 0) {
        free(buf);
        return -1;
    }
    i = 0;
    while (i < n) {
        size_t len = strlen((char *)buf + i);
        if (len == 0)
            break;
        if (argc == acap) {
            acap = acap ? acap * 2 : 16;
            argv = xrealloc(argv, acap * sizeof *argv);
        }
        argv[argc++] = (char *)buf + i;
        i += len + 1;
    }
    if (argc == 0) {
        free(argv);
        free(buf);
        return -1;
    }
    base = strrchr(argv[0], '/');
    base = base ? base + 1 : argv[0];
    if (strcmp(base, "lzply_mount") != 0) {
        free(argv);
        free(buf);
        return -1;
    }
    /* Positional arguments are <archive> <mountpoint>. Skip options:
     * -o/-e/-cache take a value; any other dash option and
     * poly=NN are single tokens. (A mount through mount -t lzply
     * shows up as "lzply_mount -o rw <archive> <mountpoint>".) */
    for (i = 1; i < argc && npos < 2; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-o") == 0 || strcmp(a, "-e") == 0 ||
            strcmp(a, "-cache") == 0) {
            i++;    /* skip the value as well */
            continue;
        }
        if (a[0] == '-')
            continue;
        if (strncmp(a, "poly=", 5) == 0)
            continue;
        pos[npos++] = a;
    }
    if (npos < 2) {
        free(argv);
        free(buf);
        return -1;
    }
    snprintf(linkpath, sizeof linkpath, "/proc/%s/cwd", pid);
    cl = readlink(linkpath, cwd, sizeof cwd - 1);
    if (cl < 0)
        cwd[0] = '\0';
    else
        cwd[cl] = '\0';
    *archive_out = xstrdup(pos[0]);
    *mountpoint_out = xstrdup(pos[1]);
    *cwd_out = xstrdup(cwd);
    free(argv);
    free(buf);
    return 0;
}

/* Find the lzply_mount daemon serving this mount point. On success
 * returns 0 and mallocs *archive_out (canonicalised). */
static int daemon_archive_for_mount(const char *mountpoint,
                                    char **archive_out)
{
    DIR *d = opendir("/proc");
    struct dirent *de;
    char *cmp = canon_path(mountpoint);
    char own[PATH_MAX];
    if (!d) {
        free(cmp);
        return -1;
    }
    if (getcwd(own, sizeof own) == NULL)
        own[0] = '\0';
    while ((de = readdir(d)) != NULL) {
        char *arch = NULL, *mp = NULL, *dcwd = NULL;
        int t;
        if (!all_digits(de->d_name))
            continue;
        if (parse_lzply_mount_cmdline(de->d_name, &arch, &mp, &dcwd) != 0)
            continue;
        /* The daemon's args may be relative. Try them against the
         * daemon's cwd first, then against our own: libfuse changes
         * the daemon's cwd to "/" at mount time, so the daemon-cwd
         * resolution can point at the wrong existing directory
         * (e.g. a relative mountpoint "mnt" resolves to "/mnt"). */
        for (t = 0; t < 2; t++) {
            const char *base = (t == 0) ? dcwd : own;
            char *rmp = resolve_arg(mp, base);
            char *camp = canon_path(rmp);
            free(rmp);
            if (camp && cmp && strcmp(camp, cmp) == 0) {
                char *rarch = resolve_arg(arch, base);
                char *carch = canon_path(rarch);
                free(rarch);
                free(camp);
                free(arch);
                free(mp);
                free(dcwd);
                closedir(d);
                free(cmp);
                *archive_out = carch;
                return 0;
            }
            free(camp);
        }
        free(arch);
        free(mp);
        free(dcwd);
    }
    closedir(d);
    free(cmp);
    return -1;
}

int mount_resolve(const char *path, char **archive_out,
                  char **mountpoint_out, char **rel_out)
{
    char *cpath = canon_path(path);
    char **mounts = NULL;
    size_t nmounts = 0, i;
    const char *best = NULL;
    size_t best_len = 0;
    char *mp, *archive, *rel;

    if (!cpath)
        return -1;
    if (read_lzply_mount_mounts(&mounts, &nmounts) != 0) {
        free(cpath);
        return -1;
    }
    /* Longest mount point that is a prefix of the path (component
     * boundary: equal, or followed by '/'). */
    for (i = 0; i < nmounts; i++) {
        size_t ml = strlen(mounts[i]);
        if ((strcmp(cpath, mounts[i]) == 0 ||
             (strncmp(cpath, mounts[i], ml) == 0 && cpath[ml] == '/')) &&
            ml > best_len) {
            best = mounts[i];
            best_len = ml;
        }
    }
    if (!best) {
        for (i = 0; i < nmounts; i++)
            free(mounts[i]);
        free(mounts);
        free(cpath);
        return -1;
    }
    mp = xstrdup(best);
    for (i = 0; i < nmounts; i++)
        free(mounts[i]);
    free(mounts);
    rel = xstrdup(cpath + best_len);
    free(cpath);
    if (rel[0] == '/')
        memmove(rel, rel + 1, strlen(rel));   /* drop leading '/' */
    if (daemon_archive_for_mount(mp, &archive) != 0) {
        free(mp);
        free(rel);
        return -1;
    }
    *archive_out = archive;
    *mountpoint_out = mp;
    *rel_out = rel;
    return 0;
}

int archive_is_mounted(const char *archive, char **mountpoint_out)
{
    DIR *d = opendir("/proc");
    struct dirent *de;
    char *carch = canon_path(archive);
    char own[PATH_MAX];
    if (!d) {
        free(carch);
        return -1;
    }
    if (getcwd(own, sizeof own) == NULL)
        own[0] = '\0';
    while ((de = readdir(d)) != NULL) {
        char *arch = NULL, *mp = NULL, *dcwd = NULL;
        int t;
        if (!all_digits(de->d_name))
            continue;
        if (parse_lzply_mount_cmdline(de->d_name, &arch, &mp, &dcwd) != 0)
            continue;
        /* Try the daemon's cwd first, then our own (see
         * daemon_archive_for_mount: relative daemon args must not be
         * resolved against the daemon's post-mount cwd "/"). */
        for (t = 0; t < 2; t++) {
            const char *base = (t == 0) ? dcwd : own;
            char *rarch = resolve_arg(arch, base);
            char *ca = canon_path(rarch);
            free(rarch);
            if (ca && carch && strcmp(ca, carch) == 0) {
                char *rmp = resolve_arg(mp, base);
                char *cmp = canon_path(rmp);
                free(rmp);
                free(ca);
                free(arch);
                free(mp);
                free(dcwd);
                closedir(d);
                free(carch);
                *mountpoint_out = cmp;
                return 1;
            }
            free(ca);
        }
        free(arch);
        free(mp);
        free(dcwd);
    }
    closedir(d);
    free(carch);
    return 0;
}
