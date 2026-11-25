/* lzply_util.h - shared helpers for lzply_stat and lzply_mount_heal.
 *
 * Mount resolution (via /proc/mounts plus a /proc cmdline scan for
 * the lzply_mount daemon) and a human-size formatter. No FUSE, no archive
 * writing — these run anywhere; only the mount tests need a live
 * mount. */
#ifndef LZPLY_UTIL_H
#define LZPLY_UTIL_H

#include <stddef.h>
#include <stdint.h>

const char *human_size(uint64_t n, char *buf, size_t bufsz);

/* Canonicalise a path (like realpath, but tolerates a non-existent
 * trailing component by canonicalising the longest existing prefix).
 * Returned string is malloced. */
char *canon_path(const char *path);

/* Resolve a path to the lzply_mount mount it lives in (or is). On success
 * returns 0 and mallocs *archive_out (the backing archive),
 * *mountpoint_out, and *rel_out (the path relative to the mount
 * point: "" for the mount point itself, otherwise no leading '/').
 * Returns -1 if the path is not in (or at) a fuse.lzply_mount mount, or
 * if the mount's daemon cannot be found. */
int mount_resolve(const char *path, char **archive_out,
                  char **mountpoint_out, char **rel_out);

/* Is this archive currently mounted by an lzply_mount daemon? Returns 1
 * and mallocs *mountpoint_out if yes, 0 if no, -1 on error. */
int archive_is_mounted(const char *archive, char **mountpoint_out);

#endif /* LZPLY_UTIL_H */
