/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Field arithmetic for the elliptic curves, with a fixed number of words.
 * Only included by ec_common.c.
 *
 * The same algorithms as mont_mul(), mont_sqr(), mod_add() and mod_sub()
 * (nat_mod.c), as always inlined functions with the size as a parameter:
 * the instances for each size (3, 4, 6, 7 and 9 words) call them with a
 * constant, and the loops are unrolled (with a pragma: gcc and clang do
 * not unroll them at -O2). About 1.4x-1.7x faster on the scalar
 * multiplications, except P-521 with gcc. The temporaries are on the
 * stack. 64-bit targets only (NAT_32BIT has its own kernels).
 */

#ifndef EC_FIELD_H
#define EC_FIELD_H

#include "common.h"
#include "nat.h"
#include "nat_ct.h"

#if !defined(NAT_32BIT)

#define FE_MAX_WORDS 9

/* Ask for the loops to be unrolled (gcc and clang do not at -O2) */
/* Inline the kernels, so that the size is a constant in each instance */
#if defined(__GNUC__) || defined(__clang__)
#define FE_INLINE static inline __attribute__((always_inline))
#else
#define FE_INLINE static inline
#endif

#if defined(__clang__)
#define FE_UNROLL _Pragma("unroll")
#elif defined(__GNUC__)
#define FE_UNROLL _Pragma("GCC unroll 20")
#else
#define FE_UNROLL
#endif

FE_INLINE uint64_t fe_addmul_row(uint64_t *t, const uint64_t *a, uint64_t b, size_t nw)
{
    uint64_t c = 0;
    size_t j;

    FE_UNROLL

    for (j=0; j<nw; j++)
        t[j] = ct_mac(a[j], b, t[j], c, &c);
    return c;
}

/* out = t - n if t >= n (t has nw words and a top bit), else t */
FE_INLINE void fe_final_sub(uint64_t *out, const uint64_t *t, uint64_t top, const uint64_t *n, size_t nw)
{
    uint64_t d[FE_MAX_WORDS], borrow = 0, mask;
    size_t i;

    FE_UNROLL

    for (i=0; i<nw; i++)
        d[i] = ct_sub(t[i], n[i], borrow, &borrow);
    mask = ct_mask(top | (1 ^ borrow));
    FE_UNROLL
    for (i=0; i<nw; i++)
        out[i] = ct_select(mask, d[i], t[i]);
}

FE_INLINE void fe_mont_mul_n(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                 const uint64_t *n, uint64_t m0, size_t nw)
{
    uint64_t t[2*FE_MAX_WORDS + 2];
    size_t i;

    FE_UNROLL

    for (i=0; i<2*nw + 2; i++)
        t[i] = 0;

    FE_UNROLL

    for (i=0; i<nw; i++) {
        uint64_t h, c, mq;

        h = fe_addmul_row(t + i, a, b[i], nw);
        t[i + nw] = ct_add(t[i + nw], h, 0, &c);
        t[i + nw + 1] = c;

        mq = t[i] * m0;
        h = fe_addmul_row(t + i, n, mq, nw);
        t[i + nw] = ct_add(t[i + nw], h, 0, &c);
        t[i + nw + 1] += c;
    }

    fe_final_sub(out, t + nw, t[2*nw], n, nw);
}

FE_INLINE void fe_mont_sqr_n(uint64_t *out, const uint64_t *a,
                                 const uint64_t *n, uint64_t m0, size_t nw)
{
    uint64_t t[2*FE_MAX_WORDS + 2];
    uint64_t c, top;
    size_t i;

    FE_UNROLL

    for (i=0; i<2*nw + 2; i++)
        t[i] = 0;

    FE_UNROLL

    for (i=0; i+1<nw; i++)
        t[i + nw] = fe_addmul_row(t + 2*i + 1, a + i + 1, a[i], nw - i - 1);

    top = 0;
    FE_UNROLL
    for (i=0; i<2*nw; i++) {
        uint64_t next = t[i] >> 63;
        t[i] = (t[i] << 1) | top;
        top = next;
    }

    c = 0;
    FE_UNROLL
    for (i=0; i<nw; i++) {
        uint64_t lo, hi;

        lo = ct_mac(a[i], a[i], 0, 0, &hi);
        t[2*i] = ct_add(t[2*i], lo, c, &c);
        t[2*i + 1] = ct_add(t[2*i + 1], hi, c, &c);
    }

    top = 0;
    FE_UNROLL
    for (i=0; i<nw; i++) {
        uint64_t h, mq = t[i] * m0;

        h = fe_addmul_row(t + i, n, mq, nw);
        t[i + nw] = ct_add(t[i + nw], h, top, &top);
    }

    fe_final_sub(out, t + nw, top, n, nw);
}

FE_INLINE void fe_mod_add_n(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                const uint64_t *n, size_t nw)
{
    uint64_t s[FE_MAX_WORDS], carry = 0;
    size_t i;

    FE_UNROLL

    for (i=0; i<nw; i++)
        s[i] = ct_add(a[i], b[i], carry, &carry);
    fe_final_sub(out, s, carry, n, nw);
}

FE_INLINE void fe_mod_sub_n(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                const uint64_t *n, size_t nw)
{
    uint64_t borrow = 0, mask, carry = 0;
    size_t i;

    FE_UNROLL

    for (i=0; i<nw; i++)
        out[i] = ct_sub(a[i], b[i], borrow, &borrow);
    mask = ct_mask(borrow);
    FE_UNROLL
    for (i=0; i<nw; i++)
        out[i] = ct_add(out[i], n[i] & mask, carry, &carry);
}

/* The instances for the sizes of the curves */
#define FE_INSTANCE_MUL(N) \
static void fe_mont_mul_##N(uint64_t *o, const uint64_t *a, const uint64_t *b, const uint64_t *n, uint64_t m0) \
    { fe_mont_mul_n(o, a, b, n, m0, N); } \
static void fe_mont_sqr_##N(uint64_t *o, const uint64_t *a, const uint64_t *n, uint64_t m0) \
    { fe_mont_sqr_n(o, a, n, m0, N); }

#define FE_INSTANCE_ADD(N) \
static void fe_mod_add_##N(uint64_t *o, const uint64_t *a, const uint64_t *b, const uint64_t *n) \
    { fe_mod_add_n(o, a, b, n, N); } \
static void fe_mod_sub_##N(uint64_t *o, const uint64_t *a, const uint64_t *b, const uint64_t *n) \
    { fe_mod_sub_n(o, a, b, n, N); }

FE_INSTANCE_MUL(3)
FE_INSTANCE_MUL(4)
FE_INSTANCE_MUL(6)
FE_INSTANCE_MUL(7)
/* With BMI2 and ADX, P-521 uses the MULX/ADX kernel of mont_mul() instead */
#if !defined(NAT_BMI2_ADX)
FE_INSTANCE_MUL(9)
#endif

FE_INSTANCE_ADD(3)
FE_INSTANCE_ADD(4)
FE_INSTANCE_ADD(6)
FE_INSTANCE_ADD(7)
FE_INSTANCE_ADD(9)

#undef FE_INSTANCE_MUL
#undef FE_INSTANCE_ADD

#endif /* !NAT_32BIT */

#endif
