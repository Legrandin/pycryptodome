#ifndef _MONTGOMERY_UTILS_H
#define _MONTGOMERY_UTILS_H

#include "common.h"

void expand_seed(uint64_t seed_in, void* seed_out, size_t out_len);

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

typedef struct _ProtMemory {
    void *scattered;
    uint16_t *scramble;
    unsigned nr_arrays;
    unsigned array_len;
} ProtMemory;

int scatter(ProtMemory** pprot, void *arrays[], uint8_t nr_arrays, size_t array_len, uint64_t seed);
void gather(void *out, const ProtMemory *prot, unsigned index);
void free_scattered(ProtMemory *prot);

#endif
