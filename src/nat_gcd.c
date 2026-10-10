/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Constant-time GCD, Jacobi symbol and integer square root.
 */

#include <string.h>

#include "common.h"
#include "nat.h"
#include "nat_ct.h"

/** Copy a into nw words (zero extension or truncation) **/
STATIC void nat_to_words(uint64_t *out, const Nat *a, size_t nw)
{
    size_t i;

    for (i=0; i<nw; i++)
        out[i] = nat_word(a, i);
}

/**
 * out = gcd(a, b), with gcd(0, 0) = 0.
 *
 * Binary GCD: remove the common power of two (counted and shifted in
 * constant time), then run 2*64*nw steps that keep v odd and reduce u.
 */
EXPORT_SYM int nat_gcd(Nat *out, const Nat *a, const Nat *b)
{
    uint64_t *u, *v, *tmp;
    uint64_t k;
    size_t nw, i;
    int res = ERR_MEMORY;

    if (NULL == out || NULL == a || NULL == b)
        return ERR_NULL;

    nw = MAX(a->nw, b->nw);
    u = nat_words_alloc(nw);
    v = nat_words_alloc(nw);
    tmp = nat_words_alloc(nw);
    if (NULL == u || NULL == v || NULL == tmp)
        goto cleanup;

    nat_to_words(u, a, nw);
    nat_to_words(v, b, nw);

    /* k = number of trailing zeros of (u | v): the common power of two */
    for (i=0; i<nw; i++)
        tmp[i] = u[i] | v[i];
    k = words_ctz(tmp, nw);
    words_shr_secret(u, k, tmp, nw);
    words_shr_secret(v, k, tmp, nw);

    /* At least one of u and v is odd now (unless both are zero): make it v */
    words_cswap(ct_mask(1 ^ (v[0] & 1)), u, v, nw);

    for (i=0; i<2*64*nw; i++) {
        uint64_t odd, lt;

        odd = u[0] & 1;
        lt = odd & words_lt(u, v, nw);
        words_cswap(ct_mask(lt), u, v, nw);
        words_cond_sub(ct_mask(odd), u, v, nw);
        words_shr1(u, 0, nw);
    }

    words_shl_secret(v, k, tmp, nw);
    for (i=0; i<out->nw; i++)
        out->w[i] = i < nw ? v[i] : 0;
    res = 0;

cleanup:
    nat_words_free(u, nw);
    nat_words_free(v, nw);
    nat_words_free(tmp, nw);
    return res;
}

/**
 * Jacobi symbol (a/n), for n odd. If negate is not zero, compute (-a/n).
 * out receives the symbol plus one: 0 for -1, 1 for 0, 2 for 1.
 *
 * Binary algorithm with a fixed number of steps. The sign is a bit t,
 * flipped by the quadratic reciprocity law when u and v are swapped,
 * and by the second supplement when u is halved.
 */
EXPORT_SYM int nat_jacobi(Nat *out, const Nat *a, const Nat *n, int negate)
{
    uint64_t *u, *v, *unit;
    uint64_t t;
    size_t nw, i;
    int ret = ERR_MEMORY;

    if (NULL == out || NULL == a || NULL == n)
        return ERR_NULL;
    if (ct_declassify(n->w[0] & 1) == 0)
        return ERR_VALUE;

    nw = n->nw;
    u = nat_words_alloc(nw);
    v = nat_words_alloc(nw);
    unit = nat_words_alloc(nw);
    if (NULL == u || NULL == v || NULL == unit)
        goto cleanup;

    ret = nat_divmod_words(NULL, 0, u, a, n);
    if (ret)
        goto cleanup;
    memcpy(v, n->w, nw*sizeof(uint64_t));
    unit[0] = 1;

    /* (-1/n) = -1 if and only if n = 3 mod 4 */
    t = negate ? (n->w[0] >> 1) & 1 : 0;

    for (i=0; i<2*64*nw; i++) {
        uint64_t odd, lt, nz;

        odd = u[0] & 1;
        lt = odd & words_lt(u, v, nw);
        /* Swapping two odd numbers that are both 3 mod 4 flips the sign */
        t ^= lt & (u[0] >> 1) & (v[0] >> 1) & 1;
        words_cswap(ct_mask(lt), u, v, nw);
        words_cond_sub(ct_mask(odd), u, v, nw);

        /* Halving u flips the sign if v = 3 or 5 mod 8 */
        nz = 1 ^ words_is_zero(u, nw);
        t ^= nz & ((v[0] >> 1) ^ (v[0] >> 2)) & 1;
        words_shr1(u, 0, nw);
    }

    /* v = gcd(a, n): the symbol is 0 unless it is 1 */
    ret = nat_from_uint64(out, 1 + words_eq(v, unit, nw)*(1 - 2*t));

cleanup:
    nat_words_free(u, nw);
    nat_words_free(v, nw);
    nat_words_free(unit, nw);
    return ret;
}

/**
 * out = floor(sqrt(a)).
 * Bit-by-bit method, with 32*nw steps.
 */
EXPORT_SYM int nat_isqrt(Nat *out, const Nat *a)
{
    uint64_t *num, *root, *bit, *t;
    size_t nw, i;
    int res = ERR_MEMORY;

    if (NULL == out || NULL == a)
        return ERR_NULL;

    nw = a->nw;
    num = nat_words_alloc(nw);
    root = nat_words_alloc(nw);
    bit = nat_words_alloc(nw);
    t = nat_words_alloc(nw);
    if (NULL == num || NULL == root || NULL == bit || NULL == t)
        goto cleanup;

    memcpy(num, a->w, nw*sizeof(uint64_t));

    for (i=32*nw; i-- > 0;) {
        uint64_t ge;

        /* bit = 4^i */
        memset(bit, 0, nw*sizeof(uint64_t));
        bit[(2*i) / 64] = (uint64_t)1 << ((2*i) % 64);

        /* if num >= root + bit: num -= root + bit, root = root/2 + bit */
        words_add(t, root, bit, nw);
        ge = 1 ^ words_lt(num, t, nw);
        words_cond_sub(ct_mask(ge), num, t, nw);
        words_shr1(root, 0, nw);
        words_cond_add(ct_mask(ge), root, bit, nw);
    }

    for (i=0; i<out->nw; i++)
        out->w[i] = i < nw ? root[i] : 0;
    res = 0;

cleanup:
    nat_words_free(num, nw);
    nat_words_free(root, nw);
    nat_words_free(bit, nw);
    nat_words_free(t, nw);
    return res;
}
