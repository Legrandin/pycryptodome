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

struct exp_key {
    /**
     *  Powers of H (already swapped in byte endianness, and pre-multiplied by X)
     *
     *  h[0] is x*H   mod p(x)
     *  h[1] is x*H^2 mod p(x)
     *  h[2] is x*H^3 mod p(x)
     *  h[3] is x*H^4 mod p(x)
     */
    uint64x2_t h[4];
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
 * Perform the carry-less multiplication of two polynomials of degree 127.
 */
STATIC void clmult(uint64x2_t *prod_high, uint64x2_t *prod_low, uint64x2_t a, uint64x2_t b)
{
    uint64x2_t c, d, e, f, g, zero;

    zero = vdupq_n_u64(0);
    c = pmull_lo(a, b);                         /* A0*B0 */
    d = pmull_hi(a, b);                         /* A1*B1 */
    e = pmull_lo(a, swap_lanes(b));             /* A0*B1 */
    f = pmull_hi(a, swap_lanes(b));             /* A1*B0 */
    g = veorq_u64(e, f);                        /* E1+F1:E0+F0 */
    *prod_high = veorq_u64(d, vextq_u64(g, zero, 1));   /* 0:E1+F1 */
    *prod_low  = veorq_u64(c, vextq_u64(zero, g, 1));   /* E0+F0:0 */
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

    for (i=1; i<4; i++) {
        uint64x2_t r0, r1;

        clmult(&r0, &r1, (*expanded)->h[i-1], (*expanded)->h[0]);
        (*expanded)->h[i] = reduce(r0, r1);
    }

    return 0;
}

EXPORT_SYM int ghash_destroy_pmull(struct exp_key *expanded)
{
    align_free(expanded);
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
    size_t i;
    uint64x2_t y_temp;
    size_t len16;

    if (NULL==y_out || NULL==block_data || NULL==y_in || NULL==expanded)
        return ERR_NULL;

    if (len % 16)
        return ERR_NOT_ENOUGH_DATA;

    y_temp = load_swap(y_in);

    /** Authenticate 64 bytes per cycle **/
    len16 = len ^ (len & 0x3F);
    for (i=0; i<len16; i+=16*4) {
        uint64x2_t sum0, sum1;
        uint64x2_t xm3, xm2, xm1, x;
        uint64x2_t r0, r1, r2, r3, r4, r5, r6;

        xm3 = load_swap(&block_data[i]);
        xm2 = load_swap(&block_data[i+16]);
        xm1 = load_swap(&block_data[i+16*2]);
        x = load_swap(&block_data[i+16*3]);

        /** (X_{i-3} + Y_{i-4}) * H^4 **/
        r0 = veorq_u64(xm3, y_temp);
        clmult(&sum0, &sum1, r0, expanded->h[3]);

        /** X_{i-2} * H^3 **/
        clmult(&r1, &r2, xm2, expanded->h[2]);
        sum0 = veorq_u64(sum0, r1);
        sum1 = veorq_u64(sum1, r2);

        /** X_{i-1} * H^2 **/
        clmult(&r3, &r4, xm1, expanded->h[1]);
        sum0 = veorq_u64(sum0, r3);
        sum1 = veorq_u64(sum1, r4);

        /** X_{i} * H **/
        clmult(&r5, &r6, x, expanded->h[0]);
        sum0 = veorq_u64(sum0, r5);
        sum1 = veorq_u64(sum1, r6);

        /** mod P **/
        y_temp = reduce(sum0, sum1);
    }

    /** Y_i = (X_i + Y_{i-1}) * H mod P **/
    for (; i<len; i+=16) {
        uint64x2_t z, xi;
        uint64x2_t prod_hi, prod_lo;

        xi = load_swap(&block_data[i]);
        z = veorq_u64(y_temp, xi);
        clmult(&prod_hi, &prod_lo, z, expanded->h[0]);
        y_temp = reduce(prod_hi, prod_lo);
    }

    store_swap(y_out, y_temp);
    return 0;
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
    uint64x2_t y, b, prod_hi, prod_lo;

    if (NULL==y_out || NULL==y_in || NULL==g || NULL==expanded)
        return ERR_NULL;

    y = load_swap(y_in);

    /** Square and multiply, as in ghash_combine_clmul() **/
    b = expanded->h[0];     /** x*H **/
    while (n_blocks > 0) {
        if (n_blocks & 1) {
            clmult(&prod_hi, &prod_lo, y, b);
            y = reduce(prod_hi, prod_lo);
        }
        n_blocks >>= 1;
        if (n_blocks > 0) {
            clmult(&prod_hi, &prod_lo, b, b);
            b = reduce(prod_hi, prod_lo);
        }
    }

    y = veorq_u64(y, load_swap(g));
    store_swap(y_out, y);
    return 0;
}

#endif /* __aarch64__ || _M_ARM64 */
