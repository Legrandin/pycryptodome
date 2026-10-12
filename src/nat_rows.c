/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The core of the modular arithmetic on 64-bit words, written once:
 * the full products (schoolbook), the Montgomery multiplication and
 * squaring, and the modular addition and subtraction.
 * The modular subtraction is also used on 32-bit targets.
 *
 * They are templates: always inlined, with the number of words and the
 * row kernel (t += a*b, see rows_addmul()) as parameters.
 *  - nat_mod.c uses them for any size, with the fastest row of the target
 *    (MULX/ADX in that build);
 *  - ec_field.h has an instance for each size of the elliptic curves,
 *    where the size is a constant, and the loops are unrolled.
 *
 * This file is not compiled on its own: nat_mod.c and ec_field.h include
 * it (like mod25519.c), as the compiler needs the code of the templates
 * to make each instance.
 *
 * All of them are constant time: the loops only depend on nw.
 * 64-bit targets only (NAT_32BIT has its own kernels in nat_mod.c).
 */

#ifndef NAT_ROWS_C
#define NAT_ROWS_C

#include "common.h"
#include "nat_ct.h"

#if defined(__GNUC__) || defined(__clang__)
#define ROWS_INLINE static inline __attribute__((always_inline))
#else
#define ROWS_INLINE static inline
#endif

/* Ask for the loops to be unrolled, when the size is a constant (gcc and clang do not at -O2) */
#if defined(__clang__)
#define ROWS_UNROLL _Pragma("unroll")
#elif defined(__GNUC__)
#define ROWS_UNROLL _Pragma("GCC unroll 20")
#else
#define ROWS_UNROLL
#endif

/** t[0..nw-1] += a[0..nw-1] * b, and return the high word **/
typedef uint64_t (*RowsAddmul)(uint64_t *t, const uint64_t *a, uint64_t b, size_t nw);

/** The row kernel in C **/
ROWS_INLINE uint64_t rows_addmul(uint64_t *t, const uint64_t *a, uint64_t b, size_t nw)
{
    uint64_t c = 0;
    size_t j;

    ROWS_UNROLL
    for (j=0; j<nw; j++)
        t[j] = ct_mac(a[j], b, t[j], c, &c);
    return c;
}

/** t (2*nw words) = a*b (nw words each), the full product **/
ROWS_INLINE void rows_mul(uint64_t *t, const uint64_t *a, const uint64_t *b, size_t nw, RowsAddmul row)
{
    size_t i;

    ROWS_UNROLL
    for (i=0; i<2*nw; i++)
        t[i] = 0;
    ROWS_UNROLL
    for (i=0; i<nw; i++)
        t[i + nw] = row(t + i, a, b[i], nw);
}

/**
 * t (2*nw words) = a*a (nw words), the full square: each cross product
 * a[i]*a[j] (i < j) once, then doubled, then the squares a[i]^2 added.
 * About 1.5*nw^2 word multiplications instead of 2*nw^2.
 */
ROWS_INLINE void rows_sqr(uint64_t *t, const uint64_t *a, size_t nw, RowsAddmul row)
{
    uint64_t c, top;
    size_t i;

    ROWS_UNROLL
    for (i=0; i<2*nw; i++)
        t[i] = 0;

    /* t = sum of a[i]*a[j]*2^(64*(i+j)), for i < j; t[i+nw] is still zero */
    ROWS_UNROLL
    for (i=0; i+1<nw; i++)
        t[i + nw] = row(t + 2*i + 1, a + i + 1, a[i], nw - i - 1);

    /* t = 2*t */
    top = 0;
    ROWS_UNROLL
    for (i=0; i<2*nw; i++) {
        uint64_t next = t[i] >> 63;
        t[i] = (t[i] << 1) | top;
        top = next;
    }

    /* t += a[i]^2 * 2^(128*i) */
    c = 0;
    ROWS_UNROLL
    for (i=0; i<nw; i++) {
        uint64_t lo, hi;

        lo = ct_mac(a[i], a[i], 0, 0, &hi);
        t[2*i] = ct_add(t[2*i], lo, c, &c);
        t[2*i + 1] = ct_add(t[2*i + 1], hi, c, &c);
    }
}

/**
 * out = t - n if t + top*2^(64*nw) >= n, else t (nw words), for a value
 * smaller than 2n. out must not alias t or n.
 */
ROWS_INLINE void rows_final_sub(uint64_t *out, const uint64_t *t, uint64_t top, const uint64_t *n, size_t nw)
{
    uint64_t borrow = 0, mask;
    size_t i;

    ROWS_UNROLL
    for (i=0; i<nw; i++)
        out[i] = ct_sub(t[i], n[i], borrow, &borrow);
    mask = ct_mask(top | (1 ^ borrow));
    ROWS_UNROLL
    for (i=0; i<nw; i++)
        out[i] = ct_select(mask, out[i], t[i]);
}

/**
 * Montgomery multiplication: out = a*b/R mod n, for a, b < n, with
 * m0 = -n^{-1} mod 2^64 and a scratchpad t of 2*nw+2 words.
 * out may alias a or b.
 *
 * Separated operand scanning: for each word of b, add a*b[i] and then
 * mq*n at offset i (mq makes word i zero). The result is in the upper
 * half of t, and it is smaller than 2n.
 */
ROWS_INLINE void rows_mont_mul(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n,
                               uint64_t m0, size_t nw, uint64_t *t, RowsAddmul row)
{
    size_t i;

    ROWS_UNROLL
    for (i=0; i<2*nw + 2; i++)
        t[i] = 0;

    ROWS_UNROLL
    for (i=0; i<nw; i++) {
        uint64_t h, c, mq;

        /* t[i+nw+1] is still zero here */
        h = row(t + i, a, b[i], nw);
        t[i + nw] = ct_add(t[i + nw], h, 0, &c);
        t[i + nw + 1] = c;

        mq = t[i] * m0;
        h = row(t + i, n, mq, nw);
        t[i + nw] = ct_add(t[i + nw], h, 0, &c);
        t[i + nw + 1] += c;
    }

    rows_final_sub(out, t + nw, t[2*nw], n, nw);
}

/**
 * Montgomery squaring: out = a*a/R mod n, for a < n, with a scratchpad t
 * of 2*nw words: the full square, then the reduction one word at a time.
 * out may alias a.
 */
ROWS_INLINE void rows_mont_sqr(uint64_t *out, const uint64_t *a, const uint64_t *n,
                               uint64_t m0, size_t nw, uint64_t *t, RowsAddmul row)
{
    uint64_t top;
    size_t i;

    rows_sqr(t, a, nw, row);

    /* t = t / R mod n, with t < n^2 */
    top = 0;
    ROWS_UNROLL
    for (i=0; i<nw; i++) {
        uint64_t h, mq = t[i] * m0;

        h = row(t + i, n, mq, nw);
        t[i + nw] = ct_add(t[i + nw], h, top, &top);
    }

    rows_final_sub(out, t + nw, top, n, nw);
}

/**
 * out = (a + b) mod n, for a, b < n, with a scratchpad s of nw words;
 * out may alias a or b. The sum goes into s, so that the subtraction of n
 * and the selection are independent passes (faster than a conditional
 * subtraction after a comparison, which nat_mod.c does as it has no
 * scratchpad).
 */
ROWS_INLINE void rows_mod_add(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n,
                              size_t nw, uint64_t *s)
{
    uint64_t carry = 0;
    size_t i;

    ROWS_UNROLL
    for (i=0; i<nw; i++)
        s[i] = ct_add(a[i], b[i], carry, &carry);
    rows_final_sub(out, s, carry, n, nw);
}

/** out = (a - b) mod n, for a, b < n; out may alias a or b **/
ROWS_INLINE void rows_mod_sub(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, size_t nw)
{
    uint64_t borrow = 0, carry = 0, mask;
    size_t i;

    ROWS_UNROLL
    for (i=0; i<nw; i++)
        out[i] = ct_sub(a[i], b[i], borrow, &borrow);
    mask = ct_mask(borrow);
    ROWS_UNROLL
    for (i=0; i<nw; i++)
        out[i] = ct_add(out[i], n[i] & mask, carry, &carry);
}

#endif  /* NAT_ROWS_C */
