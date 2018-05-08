#ifndef _MONTGOMERY_UTILS_H
#define _MONTGOMERY_UTILS_H

#include "common.h"

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

struct BitWindow {
    /** Size of a window, in bits **/
    unsigned window_size;
    
    /** Total number of windows covering the exponent **/
    unsigned nr_windows;

    /** Number of bits we miss for the next digit **/
    unsigned tg;
    
    /** Number of rightmost bits that have not been used yet **/
    unsigned available;
    
    /** Index to the byte in the big-endian exponent currently scanned **/
    unsigned scan_exp;

    /** Exponent where we extract digits from **/
    const uint8_t *exp;
};

/**
 * Initialize the data structure we can use to read groups of bits (windows)
 * from a big endian number.
 */
struct BitWindow init_bit_window(unsigned window_size, const uint8_t *exp, size_t exp_len);

/**
 * Return the next window.
 */
unsigned get_next_digit(struct BitWindow *bw);

#endif
