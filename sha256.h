/* sha256.h - self-contained SHA-256 (FIPS 180-4); no external crypto library.
 *
 * One-shot: lzply_sha256(data, len, out32). Incremental:
 * lzply_sha256_init / _update / _final. Used by the lzply family
 * for the per-entry SHA-256 (the BCH miscorrection guard) and by
 * lzply_refresh for its before/after verification. */
#ifndef LZPLY_SHA256_H
#define LZPLY_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} lzply_sha256_ctx_t;

void lzply_sha256_init(lzply_sha256_ctx_t *ctx);
void lzply_sha256_update(lzply_sha256_ctx_t *ctx, const uint8_t *data,
                         size_t len);
void lzply_sha256_final(lzply_sha256_ctx_t *ctx, uint8_t out[32]);
void lzply_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

#endif /* LZPLY_SHA256_H */
