#ifndef _MONTGOMERY_UTILS_H
#define _MONTGOMERY_UTILS_H

#include "common.h"

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
