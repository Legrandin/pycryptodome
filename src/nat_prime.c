/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Constant-time primality tests: one Miller-Rabin round,
 * and the Lucas test (FIPS 186-4, C.3.1 and C.3.3).
 *
 * The candidate is usually a secret prime (an RSA factor),
 * so neither test may branch on it.
 */

#include <string.h>

#include "common.h"
#include "nat.h"
#include "nat_ct.h"

/**
 * One round of Miller-Rabin with the given base.
 * n must be odd and at least 5; base must be in [2, n-2].
 * out is 1 if n is a probable prime for this base, 0 if it is composite.
 */
EXPORT_SYM int nat_miller_rabin(Nat *out, const Nat *n, const Nat *base)
{
    MontCtx *ctx = NULL;
    uint64_t *d = NULL, *b = NULL, *z = NULL, *minus_one = NULL, *tmp = NULL;
    uint64_t a, good;
    Nat dn;
    size_t nw, i;
    int ret;

    if (NULL == out || NULL == n || NULL == base)
        return ERR_NULL;
    if (ct_declassify(n->w[0] & 1) == 0)
        return ERR_VALUE;

    nw = n->nw;
    ret = mont_ctx_new(&ctx, n);
    if (ret)
        return ret;

    ret = ERR_MEMORY;
    d = nat_words_alloc(nw);
    b = nat_words_alloc(nw);
    z = nat_words_alloc(nw);
    minus_one = nat_words_alloc(nw);
    tmp = nat_words_alloc(nw);
    if (!d || !b || !z || !minus_one || !tmp)
        goto cleanup;

    /* n - 1 = d * 2^a, with d odd */
    memcpy(d, n->w, nw*sizeof(uint64_t));
    d[0] ^= 1;
    a = words_ctz(d, nw);
    words_shr_secret(d, a, tmp, nw);
    dn.nw = nw;
    dn.w = d;

    /* z = base^d (Montgomery form) */
    ret = nat_divmod_words(NULL, 0, b, base, n);
    if (ret)
        goto cleanup;
    mont_to(b, b, ctx);
    ret = mont_pow(z, b, &dn, ctx);
    if (ret)
        goto cleanup;

    /* -1 in Montgomery form is n - R mod n */
    words_sub(minus_one, ctx->n, ctx->one, nw);

    good = words_eq(z, ctx->one, nw) | words_eq(z, minus_one, nw);

    /* Square a-1 times, but always run the maximum number of steps */
    for (i=1; i<64*nw; i++) {
        uint64_t active = ct_lt(i, a);

        mont_mul(z, z, z, ctx);
        good |= active & words_eq(z, minus_one, nw);
    }

    ret = nat_from_uint64(out, good);

cleanup:
    mont_ctx_free(ctx);
    nat_words_free(d, nw);
    nat_words_free(b, nw);
    nat_words_free(z, nw);
    nat_words_free(minus_one, nw);
    nat_words_free(tmp, nw);
    return ret;
}

/**
 * Lucas test with P = 1 and Q = (1 - D)/4.
 * D = -abs_d if negative_d is not zero, else abs_d.
 * n must be odd and at least 3; D is public.
 * out is 1 if U_{n+1} = 0 mod n (probable prime), 0 otherwise.
 *
 * The sequence starts from (U_0, V_0) = (0, 2) and goes through
 * all the bits of n+1 (including the leading zeros), always computing
 * both the doubling step and the doubling step followed by +1.
 */
EXPORT_SYM int nat_lucas(Nat *out, const Nat *n, uint64_t abs_d, int negative_d)
{
    MontCtx *ctx = NULL;
    uint64_t *dm = NULL, *k = NULL, *u = NULL, *v = NULL;
    uint64_t *u2 = NULL, *v2 = NULL, *u3 = NULL, *v3 = NULL, *t = NULL, *zero = NULL;
    Nat *dn = NULL;
    size_t nw, i;
    uint64_t carry;
    int ret;

    if (NULL == out || NULL == n)
        return ERR_NULL;
    if (ct_declassify(n->w[0] & 1) == 0)
        return ERR_VALUE;

    nw = n->nw;
    ret = mont_ctx_new(&ctx, n);
    if (ret)
        return ret;

    ret = ERR_MEMORY;
    dm = nat_words_alloc(nw);
    k = nat_words_alloc(nw + 1);
    u = nat_words_alloc(nw);
    v = nat_words_alloc(nw);
    u2 = nat_words_alloc(nw);
    v2 = nat_words_alloc(nw);
    u3 = nat_words_alloc(nw);
    v3 = nat_words_alloc(nw);
    t = nat_words_alloc(nw);
    zero = nat_words_alloc(nw);
    dn = nat_alloc(1);
    if (!dm || !k || !u || !v || !u2 || !v2 || !u3 || !v3 || !t || !zero || !dn)
        goto cleanup;

    /* D mod n, in Montgomery form */
    dn->w[0] = abs_d;
    ret = nat_divmod_words(NULL, 0, dm, dn, n);
    if (ret)
        goto cleanup;
    if (negative_d)
        mod_sub(dm, zero, dm, ctx->n, nw);
    mont_to(dm, dm, ctx);

    /* K = n + 1 */
    carry = 1;
    for (i=0; i<nw; i++)
        k[i] = ct_add(n->w[i], 0, carry, &carry);
    k[nw] = carry;

    /* U = 0, V = 2 */
    mod_add(v, ctx->one, ctx->one, ctx->n, nw);

    for (i=64*(nw + 1); i-- > 0;) {
        uint64_t bit = (k[i / 64] >> (i % 64)) & 1;

        /* U2 = U*V, V2 = (V^2 + D*U^2)/2 */
        mont_mul(u2, u, v, ctx);
        mont_mul(t, u, u, ctx);
        mont_mul(t, t, dm, ctx);
        mont_mul(v2, v, v, ctx);
        mod_add(v2, v2, t, ctx->n, nw);
        mod_half(v2, ctx->n, nw);

        /* U3 = (U2 + V2)/2, V3 = (V2 + D*U2)/2 */
        mod_add(u3, u2, v2, ctx->n, nw);
        mod_half(u3, ctx->n, nw);
        mont_mul(t, u2, dm, ctx);
        mod_add(v3, v2, t, ctx->n, nw);
        mod_half(v3, ctx->n, nw);

        words_select(u, ct_mask(bit), u3, u2, nw);
        words_select(v, ct_mask(bit), v3, v2, nw);
    }

    ret = nat_from_uint64(out, words_is_zero(u, nw));

cleanup:
    mont_ctx_free(ctx);
    nat_words_free(dm, nw);
    nat_words_free(k, nw + 1);
    nat_words_free(u, nw);
    nat_words_free(v, nw);
    nat_words_free(u2, nw);
    nat_words_free(v2, nw);
    nat_words_free(u3, nw);
    nat_words_free(v3, nw);
    nat_words_free(t, nw);
    nat_words_free(zero, nw);
    nat_free(dn);
    return ret;
}
