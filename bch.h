/* bch.h - binary BCH error correction for lzply.
 *
 * Systematic shortened primitive BCH codes over GF(2), using the
 * 82 narrow-sense generator polynomials embedded in bch_polys.h
 * (parents N = 2^m - 1, m = 7..22, t in {1,2,4,8,16,32}).
 *
 * Bit convention (shared by encoder and decoder):
 *   A block holds D data bytes (k = 8*D data bits) and r parity bits.
 *   The codeword is n = k + r bits, stored data-first then parity,
 *   each byte MSB-first, with zero-bit padding to a byte boundary.
 *   The codeword polynomial c(x) has the first stored bit as the
 *   coefficient of x^(n-1) and the last as the coefficient of x^0.
 *   The encoder makes c(x) divisible by g(x): parity =
 *   (data_poly * x^r) mod g(x), i.e. the standard cyclic (CRC-style)
 *   remainder. The decoder recomputes that remainder (the syndrome);
 *   nonzero means errors, which Berlekamp-Massey + Chien search
 *   locate as bit flips. Binary BCH needs no magnitude step.
 *
 * The data capacity of one block is floor((N - r)/8) bytes; a blob
 * longer than that is split into blocks of that size. The decoder
 * reconstructs block boundaries from blob_size + the poly, so no
 * per-block length is stored.
 */
#ifndef LZPLY_BCH_H
#define LZPLY_BCH_H

#include <stddef.h>
#include <stdint.h>
#include "bch_polys.h"

/* Look up a polynomial by id (0x0001..0x0052). NULL if unknown. */
const bch_poly_t *bch_poly_by_id(uint16_t id);

/* Auto-pick: smallest parent m with a poly for (m,t) whose codeword can
 * hold `data_bytes` of data, i.e. N >= 8*data_bytes + t*m. Returns NULL
 * if no parent covers it (data too large for m=22 at this t). */
const bch_poly_t *bch_poly_for_data(size_t data_bytes, int t);

/* Max data bytes one block of this poly can hold: floor((N - r)/8). */
size_t bch_max_data(const bch_poly_t *p);

/* Stored (codeword) bytes for a block holding data_len data bytes:
 * ceil((8*data_len + r)/8). */
size_t bch_block_stored_len(size_t data_len, const bch_poly_t *p);

/* Total stored bytes for a whole blob of len data bytes (all blocks). */
size_t bch_encoded_len(size_t len, const bch_poly_t *p);

/* -e level -> t. 0 -> 0 (no ECC), 1 -> 1, 2 -> 2, 3 -> 4, 4 -> 8,
 * 5 -> 16, 6 -> 32, 7 -> 32. Returns -1 for an invalid level. */
int bch_t_for_level(int level);

/* Encode one block: data_len <= bch_max_data(p). out must hold
 * bch_block_stored_len(data_len, p) bytes. Returns 0 on success. */
int bch_encode_block(const uint8_t *data, size_t data_len,
                     const bch_poly_t *p, uint8_t *out);

/* Decode one block: in_len must equal bch_block_stored_len(data_len, p).
 * out must hold data_len bytes. Returns 0 on success, -1 if
 * uncorrectable. *corrected (if non-NULL) = number of bits corrected. */
int bch_decode_block(const uint8_t *in, size_t in_len, size_t data_len,
                     const bch_poly_t *p, uint8_t *out, int *corrected);

/* Encode a whole blob (splits into blocks of bch_max_data). out must
 * hold bch_encoded_len(len, p) bytes. Returns the stored length. */
size_t bch_encode(const uint8_t *data, size_t len, const bch_poly_t *p,
                  uint8_t *out);

/* Decode a whole blob: orig_len is the data length (blob_size). Returns
 * 0 on success, -1 if any block is uncorrectable. *corrected (if
 * non-NULL) = total bits corrected across blocks. */
int bch_decode(const uint8_t *in, size_t len, size_t orig_len,
               const bch_poly_t *p, uint8_t *out, int *corrected);

/* Brute-force remainder (bit-by-bit long division), used by the unit
 * test to cross-check the table-driven encoder. rem_out must hold
 * (r+7)/8 bytes; returns 0 on success. */
int bch_remainder_bruteforce(const uint8_t *data, size_t data_len,
                             const bch_poly_t *p, uint8_t *rem_out);

#endif /* LZPLY_BCH_H */
