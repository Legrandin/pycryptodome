/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"

FAKE_INIT(ghash_pmull)

/**
 * GHASH with the 64-bit carry-less multiplication (PMULL and PMULL2)
 * of the ARMv8 Cryptography Extensions, for AArch64 CPUs.
 *
 * It is the same algorithm as ghash_clmul.c (see there for the details),
 * with the same representation of the polynomials in the 128-bit
 * registers: lane 0 of a uint64x2_t holds the 64 bits that are in
 * the low qword of an XMM register.
 *
 * On other targets (such as the x86-64 half of a macOS universal2 build),
 * the module is empty: the Python code only loads it after checking
 * that the CPU has the extensions.
 */

#if defined(__aarch64__) || defined(_M_ARM64)

#include <arm_neon.h>

/** Number of blocks authenticated with a single reduction **/
#define GROUP 8

struct exp_key {
    /**
     *  Powers of H (already swapped in byte endianness, and pre-multiplied by X)
     *
     *  h[i] is x*H^(i+1) mod p(x), for i = 0..GROUP-1
     */
    uint64x2_t h[GROUP];
};

#if defined(_MSC_VER) && !defined(__clang__)

/*
 * In MSVC, all 64-bit and 128-bit vectors have the same types (__n64 and
 * __n128), and the operands of vmull_p64() are 64-bit vectors,
 * not poly64_t scalars as in the ACLE.
 */

/** Carry-less multiplication of lane 0 of a and lane 0 of b **/
STATIC uint64x2_t pmull_lo(uint64x2_t a, uint64x2_t b)
{
    return vmull_p64(vget_low_u64(a), vget_low_u64(b));
}

/** Carry-less multiplication of lane 1 of a and lane 1 of b **/
STATIC uint64x2_t pmull_hi(uint64x2_t a, uint64x2_t b)
{
    return vmull_high_p64(a, b);
}

#else

/** Carry-less multiplication of lane 0 of a and lane 0 of b **/
STATIC uint64x2_t pmull_lo(uint64x2_t a, uint64x2_t b)
{
    return vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(a, 0),
                                            (poly64_t)vgetq_lane_u64(b, 0)));
}

/** Carry-less multiplication of lane 1 of a and lane 1 of b **/
STATIC uint64x2_t pmull_hi(uint64x2_t a, uint64x2_t b)
{
    return vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(a),
                                                 vreinterpretq_p64_u64(b)));
}

#endif

/** Swap the two 64-bit lanes **/
STATIC uint64x2_t swap_lanes(uint64x2_t a)
{
    return vextq_u64(a, a, 1);
}

/**
 * Perform the Montgomery reduction on a polynomial of degree 255,
 * using basis x^128 and modulus p(x) = x^128 + x^127 + x^126 + x^121 + 1.
 *
 * See the bottom of ghash_clmul.c for an explanation.
 */
STATIC uint64x2_t reduce(uint64x2_t prod_high, uint64x2_t prod_low)
{
    const uint64x2_t c2 = vcombine_u64(vcreate_u64((uint64_t)0xc2 << 56), vcreate_u64(0));
    uint64x2_t t2, t4;

    t2 = pmull_lo(c2, prod_low);                /* A */
    t4 = veorq_u64(swap_lanes(prod_low), t2);   /* B */
    t2 = pmull_lo(c2, t4);                      /* C */
    t4 = veorq_u64(swap_lanes(t4), t2);         /* D */
    return veorq_u64(prod_high, t4);            /* T */
}

/**
 * Add the carry-less product of two polynomials of degree 127 to the
 * three partial sums of a product of degree 255:
 *
 *  acc[0] += A0*B0             (bits 0..127)
 *  acc[1] += A0*B1 + A1*B0     (bits 64..191)
 *  acc[2] += A1*B1             (bits 128..255)
 *
 * The sums of several products are folded and reduced only once,
 * by fold_reduce().
 */
STATIC void clmult_acc(uint64x2_t acc[3], uint64x2_t a, uint64x2_t b)
{
    uint64x2_t b_swapped = swap_lanes(b);

    acc[0] = veorq_u64(acc[0], pmull_lo(a, b));
    acc[1] = veorq_u64(acc[1], veorq_u64(pmull_lo(a, b_swapped), pmull_hi(a, b_swapped)));
    acc[2] = veorq_u64(acc[2], pmull_hi(a, b));
}

/** Fold the three partial sums into a polynomial of degree 255, and reduce it **/
STATIC uint64x2_t fold_reduce(const uint64x2_t acc[3])
{
    uint64x2_t zero = vdupq_n_u64(0);
    uint64x2_t prod_high, prod_low;

    prod_high = veorq_u64(acc[2], vextq_u64(acc[1], zero, 1));  /* 0:Mid1 */
    prod_low  = veorq_u64(acc[0], vextq_u64(zero, acc[1], 1));  /* Mid0:0 */
    return reduce(prod_high, prod_low);
}

/** Multiply and reduce, for a single product (see clmult_acc() and fold_reduce()) **/
STATIC uint64x2_t gf_mult(uint64x2_t a, uint64x2_t b)
{
    uint64x2_t acc[3];

    acc[0] = acc[1] = acc[2] = vdupq_n_u64(0);
    clmult_acc(acc, a, b);
    return fold_reduce(acc);
}

/**
 * Multiply a polynomial of degree 127 by x, modulo p(x) = x^128 + x^127 + x^126 + x^121 + 1
 */
STATIC uint64x2_t multx(uint64x2_t a)
{
    uint64_t lo, hi, mask;

    lo = vgetq_lane_u64(a, 0);
    hi = vgetq_lane_u64(a, 1);
    mask = (uint64_t)0 - (hi >> 63);            /* a[127] is copied into all 64 positions */

    /* Shift value a left by 1 bit */
    hi = (hi << 1) | (lo >> 63);
    lo = lo << 1;

    /* XOR conditional mask */
    lo ^= mask & 1;
    hi ^= mask & ((uint64_t)0xc2 << 56);

    return vcombine_u64(vcreate_u64(lo), vcreate_u64(hi));
}

/** Load 16 bytes, reversing their order **/
STATIC uint64x2_t load_swap(const uint8_t *p)
{
    uint8x16_t x;

    x = vrev64q_u8(vld1q_u8(p));
    return swap_lanes(vreinterpretq_u64_u8(x));
}

/**
 * Load a block of data. A block of GHASH has its bytes reversed (see
 * load_swap()), so a block already in reversed order is just loaded as it is.
 */
STATIC uint64x2_t load_block(const uint8_t *p, int reversed)
{
    return reversed ? vreinterpretq_u64_u8(vld1q_u8(p)) : load_swap(p);
}

/** Store 16 bytes, reversing their order **/
STATIC void store_swap(uint8_t *p, uint64x2_t a)
{
    vst1q_u8(p, vrev64q_u8(vreinterpretq_u8_u64(swap_lanes(a))));
}

EXPORT_SYM int ghash_expand_pmull(const uint8_t h[16], struct exp_key **expanded)
{
    unsigned i;

    if (NULL==h || NULL==expanded)
        return ERR_NULL;

    *expanded = align_alloc(sizeof(struct exp_key), 16);
    if (NULL == *expanded)
        return ERR_MEMORY;

    (*expanded)->h[0] = multx(load_swap(h));    /** x*H **/

    for (i=1; i<GROUP; i++) {
        (*expanded)->h[i] = gf_mult((*expanded)->h[i-1], (*expanded)->h[0]);
    }

    return 0;
}

EXPORT_SYM int ghash_destroy_pmull(struct exp_key *expanded)
{
    align_free(expanded);
    return 0;
}

STATIC int ghash_blocks(
        uint8_t y_out[16],
        const uint8_t block_data[],
        size_t len,
        const uint8_t y_in[16],
        struct exp_key *expanded,
        int reversed
        )
{
    uint64x2_t y;

    if (NULL==y_out || NULL==block_data || NULL==y_in || NULL==expanded)
        return ERR_NULL;

    if (len % 16)
        return ERR_NOT_ENOUGH_DATA;

    y = load_swap(y_in);

    /**
     * Authenticate up to GROUP blocks X_1..X_n at a time, with one reduction:
     *
     *  Y' = (Y + X_1)*H^n + X_2*H^(n-1) + ... + X_n*H
     */
    while (len > 0) {
        uint64x2_t acc[3];
        size_t n, j;

        acc[0] = acc[1] = acc[2] = vdupq_n_u64(0);
        n = MIN(len / 16, GROUP);
        clmult_acc(acc, veorq_u64(y, load_block(block_data, reversed)), expanded->h[n-1]);
        for (j=1; j<n; j++) {
            clmult_acc(acc, load_block(block_data + 16*j, reversed), expanded->h[n-1-j]);
        }
        y = fold_reduce(acc);

        block_data += 16*n;
        len -= 16*n;
    }

    store_swap(y_out, y);
    return 0;
}

EXPORT_SYM int ghash_pmull(
        uint8_t y_out[16],
        const uint8_t block_data[],
        size_t len,
        const uint8_t y_in[16],
        struct exp_key *expanded
        )
{
    return ghash_blocks(y_out, block_data, len, y_in, expanded, 0);
}

/**
 * Like ghash_pmull(), but the bytes of each block of data are in reversed
 * order. This is what POLYVAL needs (RFC 8452, Appendix A).
 */
EXPORT_SYM int ghash_rev_pmull(
        uint8_t y_out[16],
        const uint8_t block_data[],
        size_t len,
        const uint8_t y_in[16],
        struct exp_key *expanded
        )
{
    return ghash_blocks(y_out, block_data, len, y_in, expanded, 1);
}

/**
 * Like ghash_pmull(), but for the len bytes at the given offset
 * in block_data[]. Several threads can call it at the same time,
 * with the same expanded key.
 */
EXPORT_SYM int ghash_at_pmull(
        uint8_t y_out[16],
        const uint8_t block_data[],
        size_t offset,
        size_t len,
        const uint8_t y_in[16],
        struct exp_key *expanded
        )
{
    if (NULL==block_data)
        return ERR_NULL;

    return ghash_pmull(y_out, block_data + offset, len, y_in, expanded);
}

/**
 * Like ghash_rev_pmull(), but for the len bytes at the given offset
 * in block_data[] (see ghash_at_pmull()).
 */
EXPORT_SYM int ghash_rev_at_pmull(
        uint8_t y_out[16],
        const uint8_t block_data[],
        size_t offset,
        size_t len,
        const uint8_t y_in[16],
        struct exp_key *expanded
        )
{
    if (NULL==block_data)
        return ERR_NULL;

    return ghash_rev_pmull(y_out, block_data + offset, len, y_in, expanded);
}

/**
 * Combine the GHASH of two consecutive pieces of data:
 *
 *  y_out = y_in * H^n_blocks + g
 *
 * where y_in is the GHASH of the first piece, and g is the GHASH of
 * the second piece (n_blocks long), computed with Y_0 = 0.
 *
 * y_out can point to the same buffer as y_in or g.
 */
EXPORT_SYM int ghash_combine_pmull(
        uint8_t y_out[16],
        const uint8_t y_in[16],
        size_t n_blocks,
        const uint8_t g[16],
        const struct exp_key *expanded
        )
{
    uint64x2_t y, b;

    if (NULL==y_out || NULL==y_in || NULL==g || NULL==expanded)
        return ERR_NULL;

    y = load_swap(y_in);

    /** Square and multiply, as in ghash_combine_clmul() **/
    b = expanded->h[0];     /** x*H **/
    while (n_blocks > 0) {
        if (n_blocks & 1) {
            y = gf_mult(y, b);
        }
        n_blocks >>= 1;
        if (n_blocks > 0) {
            b = gf_mult(b, b);
        }
    }

    y = veorq_u64(y, load_swap(g));
    store_swap(y_out, y);
    return 0;
}

#endif /* __aarch64__ || _M_ARM64 */
