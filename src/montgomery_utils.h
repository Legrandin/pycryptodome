#ifndef _MONTGOMERY_UTILS_H
#define _MONTGOMERY_UTILS_H

#include "pycrypto_common.h"

/**
 * Convert a number in[], originally encoded as raw bytes (big endian)
 * into words x[] (little endian). The output array x[] must
 * be correctly sized.
 *
 * The length of the array in[] may not be a multiple of 8, in which
 * case the most significant word of x[] gets padded with zeroes.
 */
void bytes_to_words(uint64_t *x, const uint8_t *in, size_t len, size_t words);

/**
 * Convert a number in[], originally encoded in words (little endian)
 * into bytes (big endian). The output array out[] must
 * have appropriate size.
 */
void words_to_bytes(uint8_t *out, const uint64_t *x, size_t len, size_t words);

/**
 * Expand a fixed-size seed
 */
void expand_seed(uint64_t seed_in, uint8_t* seed_out, size_t out_len);

#endif
