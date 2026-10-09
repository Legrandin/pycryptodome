/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Constant-time division of natural numbers.
 */

#include <string.h>

#include "common.h"
#include "nat.h"
#include "nat_ct.h"

/*
 * Restoring division, one bit of the dividend per step.
 * The number of steps only depends on the size of a,
 * and the cost of each step on the size of b.
 *
 * q (q_nw words) receives the quotient, truncated to q_nw words;
 * it can be NULL. r (b->nw words) receives the remainder; it can be NULL.
 * b must not be zero.
 */
int nat_divmod_words(uint64_t *q, size_t q_nw, uint64_t *r, const Nat *a, const Nat *b)
{
    uint64_t *rem = NULL, *bext = NULL, *t = NULL;
    size_t rw, i, nbits;
    int res = ERR_MEMORY;

    rw = b->nw + 1;
    rem = nat_words_alloc(rw);
    bext = nat_words_alloc(rw);
    t = nat_words_alloc(rw);
    if (NULL == rem || NULL == bext || NULL == t)
        goto cleanup;

    memcpy(bext, b->w, b->nw*sizeof(uint64_t));
    if (q)
        memset(q, 0, q_nw*sizeof(uint64_t));

    nbits = 64*a->nw;
    for (i=nbits; i-- > 0;) {
        uint64_t bit, keep, carry;
        size_t j;

        /* rem = 2*rem + bit; it fits because rem < b */
        bit = (a->w[i / 64] >> (i % 64)) & 1;
        carry = bit;
        for (j=0; j<rw; j++) {
            uint64_t top = rem[j] >> 63;
            rem[j] = (rem[j] << 1) | carry;
            carry = top;
        }

        /* if rem >= b then rem -= b and the quotient bit is 1 */
        keep = 1 ^ words_sub(t, rem, bext, rw);
        words_select(rem, ct_mask(keep), t, rem, rw);
        if (q && i / 64 < q_nw)
            q[i / 64] |= keep << (i % 64);
    }

    if (r)
        memcpy(r, rem, b->nw*sizeof(uint64_t));
    res = 0;

cleanup:
    nat_words_free(rem, rw);
    nat_words_free(bext, rw);
    nat_words_free(t, rw);
    return res;
}

/**
 * q = a // b, r = a % b.
 * Either q or r can be NULL, but not both.
 * The quotient is truncated to q->nw words, the remainder to r->nw words.
 * Return ERR_VALUE if b is zero.
 */
EXPORT_SYM int nat_divmod(Nat *q, Nat *r, const Nat *a, const Nat *b)
{
    uint64_t *rem;
    size_t i;
    int res;

    if (NULL == a || NULL == b || (NULL == q && NULL == r))
        return ERR_NULL;
    if ((Nat*)a == q || (Nat*)a == r || (Nat*)b == q || (Nat*)b == r || (q && q == r))
        return ERR_VALUE;

    /* Division by zero: only this fact leaks */
    if (ct_declassify(words_is_zero(b->w, b->nw)))
        return ERR_VALUE;

    rem = nat_words_alloc(b->nw);
    if (NULL == rem)
        return ERR_MEMORY;

    res = nat_divmod_words(q ? q->w : NULL, q ? q->nw : 0, rem, a, b);
    if (res == 0 && r) {
        for (i=0; i<r->nw; i++)
            r->w[i] = i < b->nw ? rem[i] : 0;
    }

    nat_words_free(rem, b->nw);
    return res;
}

/**
 * out = a % d, for a public divisor 0 < d < 2^32.
 * The reduction uses a precomputed reciprocal of d,
 * so no division instruction is applied to the words of a.
 */
EXPORT_SYM int nat_mod_small(Nat *out, const Nat *a, uint64_t d)
{
    uint64_t recip, rem;
    size_t i;

    if (NULL == out || NULL == a)
        return ERR_NULL;
    if (d == 0 || (d >> 32) != 0)
        return ERR_VALUE;

    /* d is public, so a division instruction is fine here */
    recip = UINT64_MAX / d;

    rem = 0;
    for (i=a->nw; i-- > 0;) {
        int half;

        for (half=1; half>=0; half--) {
            uint64_t x, q, hi, lo;
            int k;

            /* x < 2^64, because rem < d < 2^32 */
            x = (rem << 32) | ((a->w[i] >> (32*half)) & 0xFFFFFFFFU);

            /* q is at most 2 less than the exact quotient */
            DP_MULT(x, recip, lo, hi);
            (void)lo;
            q = hi;
            rem = x - q*d;
            for (k=0; k<2; k++) {
                uint64_t ge = 1 ^ ct_lt(rem, d);
                rem -= d & ct_mask(ge);
            }
        }
    }

    return nat_from_uint64(out, rem);
}
