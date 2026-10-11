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
 * Divide the 128-bit number (hi, lo) by d, for d >= 2^63 and hi <= d.
 * Return the quotient, or 2^64 - 1 if it does not fit into 64 bits
 * (which only happens when hi == d).
 *
 * Restoring division, one bit per step: no division instruction is used,
 * as its running time may depend on the operands on some CPUs.
 */
STATIC uint64_t div128_ct(uint64_t hi, uint64_t lo, uint64_t d)
{
    uint64_t rem, q, overflow;
    int i;

    /* With hi == d, the quotient is at least 2^64 */
    overflow = ct_eq(hi, d);
    rem = ct_select(ct_mask(overflow), 0, hi);

    q = 0;
    for (i=63; i>=0; i--) {
        uint64_t top, ge;

        /* rem < d, so 2*rem + bit < 2^65: keep the 65th bit in top */
        top = rem >> 63;
        rem = (rem << 1) | ((lo >> i) & 1);
        ge = top | (1 ^ ct_lt(rem, d));
        rem -= d & ct_mask(ge);
        q |= ge << i;
    }

    return ct_select(ct_mask(overflow), UINT64_MAX, q);
}

/*
 * Reciprocal of d (for d >= 2^63): floor((2^128 - 1) / d) - 2^64.
 */
STATIC uint64_t reciprocal_ct(uint64_t d)
{
    return div128_ct(~d, UINT64_MAX, d);
}

/*
 * Same as div128_ct(hi, lo, d), with the reciprocal of d precomputed
 * (Moller and Granlund, "Improved division by invariant integers", 2011,
 * algorithm 4). The two corrections are done with masks.
 */
STATIC uint64_t div128_preinv_ct(uint64_t hi, uint64_t lo, uint64_t d, uint64_t recip)
{
    uint64_t overflow, q0, q1, r, carry, m;

    /* With hi == d, the quotient is at least 2^64 */
    overflow = ct_eq(hi, d);
    hi = ct_select(ct_mask(overflow), 0, hi);

    /* (q1, q0) = recip * hi + (hi, lo) */
    q0 = ct_mac(recip, hi, 0, 0, &q1);
    q0 = ct_add(q0, lo, 0, &carry);
    q1 = q1 + hi + carry;
    q1 += 1;

    r = lo - q1*d;
    m = ct_mask(ct_lt(q0, r));
    q1 -= 1 & m;
    r += d & m;
    m = ct_mask(1 ^ ct_lt(r, d));
    q1 += 1 & m;

    return ct_select(ct_mask(overflow), UINT64_MAX, q1);
}

/*
 * Word-wise division (Knuth, TAOCP vol. 2, 4.3.1, algorithm D),
 * in constant time.
 *
 * The divisor is shifted left by s bits, so that its top bit is set
 * (s is secret, and the shifts are constant time). Then, for each word
 * of the quotient (from the top), the quotient word is estimated from
 * the two top words of the current remainder and the top word of the
 * divisor. The estimate is never too small, and at most 2 too large:
 * after the multiply-subtract step, the divisor is conditionally added
 * back twice.
 *
 * The cost depends only on the number of words of a and b.
 *
 * q (q_nw words) receives the quotient, truncated to q_nw words;
 * it can be NULL. r (b->nw words) receives the remainder; it can be NULL.
 * b must not be zero.
 */
int nat_divmod_words(uint64_t *q, size_t q_nw, uint64_t *r, const Nat *a, const Nat *b)
{
    uint64_t *u = NULL, *v = NULL, *tmp = NULL;
    size_t na, nb, un, j, k;
    uint64_t s, recip;
    int res = ERR_MEMORY;

    na = a->nw;
    nb = b->nw;
    un = na + nb;

    u = nat_words_alloc(un);
    v = nat_words_alloc(nb);
    tmp = nat_words_alloc(un);
    if (NULL == u || NULL == v || NULL == tmp)
        goto cleanup;

    /* Normalize: v = b << s has its top bit set, u = a << s */
    s = (uint64_t)64*nb - (uint64_t)nat_bit_length(b);
    memcpy(v, b->w, nb*sizeof(uint64_t));
    words_shl_secret(v, s, tmp, nb);
    memcpy(u, a->w, na*sizeof(uint64_t));
    words_shl_secret(u, s, tmp, un);

    if (q)
        memset(q, 0, q_nw*sizeof(uint64_t));

    recip = reciprocal_ct(v[nb-1]);

    /* The window u[j..j+nb] (nb+1 words) is always smaller than v * 2^64 */
    for (j=na; j-- > 0;) {
        uint64_t *w = u + j;
        uint64_t qhat, mul_carry, borrow, neg;
        int round;

        qhat = div128_preinv_ct(w[nb], w[nb-1], v[nb-1], recip);

        /* w -= qhat * v */
        mul_carry = 0;
        borrow = 0;
        for (k=0; k<nb; k++) {
            uint64_t prod = ct_mac(qhat, v[k], mul_carry, 0, &mul_carry);
            w[k] = ct_sub(w[k], prod, borrow, &borrow);
        }
        w[nb] = ct_sub(w[nb], mul_carry, borrow, &borrow);

        /* The estimate is at most 2 too large: add v back, up to twice */
        neg = borrow;
        for (round=0; round<2; round++) {
            uint64_t carry, m;

            m = ct_mask(neg);
            carry = words_cond_add(m, w, v, nb);
            w[nb] = ct_add(w[nb], 0, carry, &carry);
            qhat -= neg;
            /*
             * Still negative unless the addition carried out.
             * The barrier stops clang -Os from turning this into a branch
             * on the carry flag (found with test_nat_ct).
             */
            neg &= 1 ^ ct_barrier(carry);
        }

        if (q && j < q_nw)
            q[j] = qhat;
    }

    /* The remainder is in the low nb words of u, shifted by s */
    if (r) {
        words_shr_secret(u, s, tmp, nb);
        memcpy(r, u, nb*sizeof(uint64_t));
    }
    res = 0;

cleanup:
    nat_words_free(u, un);
    nat_words_free(v, nb);
    nat_words_free(tmp, un);
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
            lo = ct_mac(x, recip, 0, 0, &hi);
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
