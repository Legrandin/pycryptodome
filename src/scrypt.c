/*
 * SPDX-FileCopyrightText: 2015 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * scrypt ROMix (RFC 7914), with Salsa20/8 as core function.
 *
 * Internally, every 64-byte block is kept as 16 words in native
 * endianess, so data is converted only at the beginning and at the end.
 * The words of each block are stored in the order expected by
 * salsa20_core() (see SALSA20_WORD_POS in salsa20_core.h).
 */

#include "common.h"
#include "endianess.h"
#include "salsa20_core.h"

#if defined(__linux__)
#include <sys/mman.h>
#endif

#ifndef SCRYPT_MODULE
#define SCRYPT_MODULE scrypt
#endif

FAKE_INIT(SCRYPT_MODULE)

/**
 * scrypt BlockMix function, applied to (in xor mask)
 *
 * @in:    input, a sequence of 2r blocks, each 16 words long
 * @mask:  a sequence of 2r blocks to XOR to @in, or NULL
 * @out:   output, a sequence of 2r blocks, each 16 words long
 * @r:     the block size parameter
 *
 * @out may not overlap with @in or @mask.
 */
static inline void scryptBlockMix(const uint32_t *in, const uint32_t *mask, uint32_t *out, size_t r)
{
    uint32_t X[16];
    size_t i, last;

    last = (2*r - 1) * 16;
    memcpy(X, &in[last], sizeof X);
    if (mask != NULL) {
        for (i=0; i<16; i++)
            X[i] ^= mask[last + i];
    }

    /** Even blocks go into the first half of @out, odd blocks into the second **/
    for (i=0; i<r; i++) {
        salsa20_core(8, X, &in[32*i], mask ? &mask[32*i] : NULL);
        memcpy(&out[16*i], X, sizeof X);
        salsa20_core(8, X, &in[32*i + 16], mask ? &mask[32*i + 16] : NULL);
        memcpy(&out[16*(r + i)], X, sizeof X);
    }
}

/**
 * Allocate the memory for the V array (@size bytes).
 *
 * On Linux, a large area is aligned to 2 MiB and marked for transparent
 * huge pages, so it takes much fewer page faults and TLB misses.
 * Free it with align_free().
 */
static void *alloc_v(size_t size)
{
#if defined(__linux__) && defined(MADV_HUGEPAGE)
    const size_t huge_page = 2U*1024*1024;
    void *v;

    if (size >= huge_page) {
        v = align_alloc(size, (unsigned)huge_page);
        if (v != NULL) {
            /* Only a hint: it is not an error if the kernel ignores it */
            (void)madvise(v, size, MADV_HUGEPAGE);
        }
        return v;
    }
#endif
    return align_alloc(size, 64);
}

/**
 * scrypt ROMix for one flow, with the memory @v of (N+2)*words words.
 * @data_in and @data_out may overlap.
 */
static void scryptROMix_one(uint32_t *v, const uint8_t *data_in, uint8_t *data_out,
                            size_t r, size_t words, unsigned N)
{
    uint32_t *x, *y, *t;
    size_t i;

    x = v + (size_t)N * words;
    y = x + words;

    for (i=0; i<words; i++) {
        v[(i & ~(size_t)15) + SALSA20_WORD_POS(i & 15)] = LOAD_U32_LITTLE(&data_in[4*i]);
    }

    /** Create the V array **/
    for (i=0; i<N-1; i++) {
        scryptBlockMix(&v[i*words], NULL, &v[(i+1)*words], r);
    }
    scryptBlockMix(&v[(N-1)*words], NULL, x, r);

    /** Mix via a pseudo random sequence **/
    for (i=0; i<N; i++) {
        uint32_t index;

        /* Extract pseudo random index from first word of the last block
         * (SALSA20_WORD_POS(0) is always 0) */
        index = x[words - 16] & (N - 1);
        scryptBlockMix(x, &v[(size_t)index * words], y, r);
        t = x;
        x = y;
        y = t;
    }

    for (i=0; i<words; i++) {
        STORE_U32_LITTLE(&data_out[4*i], x[(i & ~(size_t)15) + SALSA20_WORD_POS(i & 15)]);
    }
}

/**
 * scrypt ROMix function, for the consecutive flows @first, @first+1, ...,
 * @first+@count-1 (each one @data_len bytes long) of the buffers
 * @data_in and @data_out.
 *
 * Several threads can call this function at the same time, with the same
 * buffers and different flows: they only need the pointers to the buffers,
 * which the calling thread creates once.
 *
 * @data_in:   input, @total_len bytes long
 * @data_out:  output, @total_len bytes long
 * @data_len:  Length in bytes of each flow. It is a multiple of 128.
 * @N:         Memory/CPU cost. It must be a power of 2.
 * @first:     The first flow to compute
 * @count:     The number of flows to compute
 * @total_len: Length in bytes of @data_in and @data_out
 *
 * The memory (N+2)*data_len bytes is allocated once, for all the flows.
 * @data_in and @data_out may overlap.
 */
EXPORT_SYM int scryptROMix(const uint8_t *data_in, uint8_t *data_out,
                           size_t data_len, unsigned N,
                           size_t first, size_t count, size_t total_len)
{
    size_t r, words, k;
    uint32_t *v;

    if (NULL==data_in || NULL==data_out) {
        return ERR_NULL;
    }

    if (data_len == 0 || data_len % 128) {
        return ERR_BLOCK_SIZE;
    }
    r = data_len / 128;
    words = data_len / 4;

    if (N == 0 || (N & (N - 1))) {
        return ERR_VALUE;
    }

    /** The flows must be within the buffers **/
    if (first > total_len / data_len || count > total_len / data_len - first) {
        return ERR_VALUE;
    }
    if (count == 0) {
        return 0;
    }

    /** Allocate a possibly gigantic amount of memory **/
    /* It takes in total (N+2) * (128r) bytes */
    if (N > SIZE_MAX / data_len - 2) {
        return ERR_MEMORY;
    }
    v = (uint32_t*)alloc_v((N + 2) * data_len);
    if (NULL == v) {
        return ERR_MEMORY;
    }

    for (k=first; k<first+count; k++) {
        scryptROMix_one(v, data_in + k*data_len, data_out + k*data_len, r, words, N);
    }

    align_free(v);
    return 0;
}
