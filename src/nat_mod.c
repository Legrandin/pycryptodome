/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Constant-time modular arithmetic on natural numbers.
 *
 * Montgomery form is only used inside a single call (for an odd
 * modulus), and never leaves this file in that form.
 */

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "nat.h"
#include "nat_ct.h"

/* ---------------------------------------------------------------- */
/* Modular helpers on word arrays                                   */
/* ---------------------------------------------------------------- */

void mod_add(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, size_t nw)
{
    uint64_t carry, lt;

    carry = words_add(out, a, b, nw);
    lt = words_lt(out, n, nw);
    words_cond_sub(ct_mask(carry | (1 ^ lt)), out, n, nw);
}

void mod_sub(uint64_t *out, const uint64_t *a, const uint64_t *b, const uint64_t *n, size_t nw)
{
    uint64_t borrow;

    borrow = words_sub(out, a, b, nw);
    words_cond_add(ct_mask(borrow), out, n, nw);
}

void mod_half(uint64_t *x, const uint64_t *n, size_t nw)
{
    uint64_t carry;

    carry = words_cond_add(ct_mask(x[0] & 1), x, n, nw);
    words_shr1(x, carry, nw);
}

/* ---------------------------------------------------------------- */
/* Montgomery arithmetic                                            */
/* ---------------------------------------------------------------- */

void mont_ctx_free(MontCtx *ctx)
{
    if (NULL == ctx)
        return;
    nat_words_free(ctx->n, ctx->nw);
    nat_words_free(ctx->r2, ctx->nw);
    nat_words_free(ctx->one, ctx->nw);
    nat_words_free(ctx->unit, ctx->nw);
    nat_words_free(ctx->tmp, ctx->nw + 2);
    free(ctx);
}

/** n must be odd **/
int mont_ctx_new(MontCtx **out, const Nat *n)
{
    MontCtx *ctx;
    Nat *big = NULL;
    uint64_t inv;
    size_t nw;
    unsigned i;
    int res = ERR_MEMORY;

    if (ct_declassify(n->w[0] & 1) == 0)
        return ERR_VALUE;

    nw = n->nw;
    *out = ctx = (MontCtx*)calloc(1, sizeof(MontCtx));
    if (NULL == ctx)
        return ERR_MEMORY;
    ctx->nw = nw;
    ctx->n = nat_words_alloc(nw);
    ctx->r2 = nat_words_alloc(nw);
    ctx->one = nat_words_alloc(nw);
    ctx->unit = nat_words_alloc(nw);
    ctx->tmp = nat_words_alloc(nw + 2);
    if (!ctx->n || !ctx->r2 || !ctx->one || !ctx->unit || !ctx->tmp)
        goto cleanup;

    memcpy(ctx->n, n->w, nw*sizeof(uint64_t));
    ctx->unit[0] = 1;

    /* Newton iteration: each step doubles the number of correct bits (3 at start) */
    inv = n->w[0];
    for (i=0; i<5; i++)
        inv *= 2 - n->w[0]*inv;
    ctx->m0 = 0 - inv;

    /* R^2 mod n, with R = 2^(64*nw) */
    big = nat_alloc(2*nw + 1);
    if (NULL == big)
        goto cleanup;
    big->w[2*nw] = 1;
    res = nat_divmod_words(NULL, 0, ctx->r2, big, n);
    if (res)
        goto cleanup;

    /* R mod n */
    memset(big->w, 0, big->nw*sizeof(uint64_t));
    big->nw = nw + 1;
    big->w[nw] = 1;
    res = nat_divmod_words(NULL, 0, ctx->one, big, n);
    big->nw = 2*nw + 1;

cleanup:
    nat_free(big);
    if (res) {
        mont_ctx_free(ctx);
        *out = NULL;
    }
    return res;
}

/*
 * Montgomery multiplication (CIOS method): out = a*b/R mod n.
 * a and b must be smaller than n. out may alias a or b.
 */
void mont_mul(uint64_t *out, const uint64_t *a, const uint64_t *b, MontCtx *ctx)
{
    uint64_t *t = ctx->tmp;
    const uint64_t *n = ctx->n;
    size_t nw = ctx->nw;
    size_t i, j;
    uint64_t borrow;

    memset(t, 0, (nw + 2)*sizeof(uint64_t));

    for (i=0; i<nw; i++) {
        uint64_t c, mq;

        /* t += a * b[i] */
        c = 0;
        for (j=0; j<nw; j++)
            t[j] = ct_mac(a[j], b[i], t[j], c, &c);
        t[nw] = ct_add(t[nw], c, 0, &c);
        t[nw + 1] = c;

        /* t = (t + mq*n) / 2^64 */
        mq = t[0] * ctx->m0;
        ct_mac(mq, n[0], t[0], 0, &c);
        for (j=1; j<nw; j++)
            t[j - 1] = ct_mac(mq, n[j], t[j], c, &c);
        t[nw - 1] = ct_add(t[nw], c, 0, &c);
        t[nw] = t[nw + 1] + c;
    }

    /* t < 2n: subtract n if t >= n */
    borrow = words_sub(out, t, n, nw);
    words_select(out, ct_mask(t[nw] | (1 ^ borrow)), out, t, nw);
}

void mont_to(uint64_t *out, const uint64_t *x, MontCtx *ctx)
{
    mont_mul(out, x, ctx->r2, ctx);
}

void mont_from(uint64_t *out, const uint64_t *x, MontCtx *ctx)
{
    mont_mul(out, x, ctx->unit, ctx);
}

#define WINDOW_SIZE 4
#define TABLE_SIZE (1 << WINDOW_SIZE)

/*
 * Fixed-window exponentiation over all the bits of e (64*e->nw).
 * Each window costs 4 squarings, a scan of the whole table,
 * and one multiplication, whatever the value of e.
 */
int mont_pow(uint64_t *out, const uint64_t *base_m, const Nat *e, MontCtx *ctx)
{
    size_t nw = ctx->nw;
    uint64_t *table, *acc, *sel;
    size_t i, j, k, pos;
    int res = ERR_MEMORY;

    table = nat_words_alloc(TABLE_SIZE*nw);
    acc = nat_words_alloc(nw);
    sel = nat_words_alloc(nw);
    if (NULL == table || NULL == acc || NULL == sel)
        goto cleanup;

    memcpy(table, ctx->one, nw*sizeof(uint64_t));
    memcpy(table + nw, base_m, nw*sizeof(uint64_t));
    for (k=2; k<TABLE_SIZE; k++)
        mont_mul(table + k*nw, table + (k-1)*nw, base_m, ctx);

    memcpy(acc, ctx->one, nw*sizeof(uint64_t));
    for (pos=64*e->nw; pos>0; pos-=WINDOW_SIZE) {
        size_t bitpos = pos - WINDOW_SIZE;
        uint64_t idx;

        for (i=0; i<WINDOW_SIZE; i++)
            mont_mul(acc, acc, acc, ctx);

        idx = (e->w[bitpos / 64] >> (bitpos % 64)) & (TABLE_SIZE - 1);
        memset(sel, 0, nw*sizeof(uint64_t));
        for (k=0; k<TABLE_SIZE; k++) {
            uint64_t m = ct_mask(ct_eq(k, idx));
            for (j=0; j<nw; j++)
                sel[j] |= table[k*nw + j] & m;
        }
        mont_mul(acc, acc, sel, ctx);
    }

    memcpy(out, acc, nw*sizeof(uint64_t));
    res = 0;

cleanup:
    nat_words_free(table, TABLE_SIZE*nw);
    nat_words_free(acc, nw);
    nat_words_free(sel, nw);
    return res;
}

/* ---------------------------------------------------------------- */
/* Modular operations                                               */
/* ---------------------------------------------------------------- */

/** Copy nw words of x into out (out->nw words), with zero extension **/
STATIC void words_to_nat(Nat *out, const uint64_t *x, size_t nw)
{
    size_t i;

    for (i=0; i<out->nw; i++)
        out->w[i] = i < nw ? x[i] : 0;
}

/** out = (x * y) mod m, for x and y with m->nw words; prod has 2*m->nw words **/
STATIC int mulmod_words(uint64_t *out, const uint64_t *x, const uint64_t *y, const Nat *m, Nat *prod)
{
    Nat xn, yn;

    xn.nw = yn.nw = m->nw;
    xn.w = (uint64_t*)x;
    yn.w = (uint64_t*)y;
    nat_mul(prod, &xn, &yn);
    return nat_divmod_words(NULL, 0, out, prod, m);
}

/** out = (a * b) mod m **/
EXPORT_SYM int nat_mulmod(Nat *out, const Nat *a, const Nat *b, const Nat *m)
{
    Nat *prod;
    int res;

    if (NULL == out || NULL == a || NULL == b || NULL == m)
        return ERR_NULL;
    if (ct_declassify(words_is_zero(m->w, m->nw)))
        return ERR_VALUE;

    prod = nat_alloc(a->nw + b->nw);
    if (NULL == prod)
        return ERR_MEMORY;
    nat_mul(prod, a, b);
    res = nat_divmod(NULL, out, prod, m);
    nat_free(prod);
    return res;
}

/** out = (a - b) mod m, for a and b smaller than m **/
EXPORT_SYM int nat_submod(Nat *out, const Nat *a, const Nat *b, const Nat *m)
{
    uint64_t *x, *y, *d;
    size_t nw, i;
    int res = ERR_MEMORY;

    if (NULL == out || NULL == a || NULL == b || NULL == m)
        return ERR_NULL;

    nw = m->nw;
    x = nat_words_alloc(nw);
    y = nat_words_alloc(nw);
    d = nat_words_alloc(nw);
    if (NULL == x || NULL == y || NULL == d)
        goto cleanup;

    for (i=0; i<nw; i++) {
        x[i] = nat_word(a, i);
        y[i] = nat_word(b, i);
    }
    mod_sub(d, x, y, m->w, nw);
    words_to_nat(out, d, nw);
    res = 0;

cleanup:
    nat_words_free(x, nw);
    nat_words_free(y, nw);
    nat_words_free(d, nw);
    return res;
}

/** out = a^e mod m **/
EXPORT_SYM int nat_powmod(Nat *out, const Nat *a, const Nat *e, const Nat *m)
{
    uint64_t *base = NULL, *acc = NULL, *t = NULL;
    MontCtx *ctx = NULL;
    Nat *prod = NULL;
    size_t nw;
    int res;

    if (NULL == out || NULL == a || NULL == e || NULL == m)
        return ERR_NULL;
    if (ct_declassify(words_is_zero(m->w, m->nw)))
        return ERR_VALUE;

    nw = m->nw;
    res = ERR_MEMORY;
    base = nat_words_alloc(nw);
    acc = nat_words_alloc(nw);
    t = nat_words_alloc(nw);
    if (NULL == base || NULL == acc || NULL == t)
        goto cleanup;

    res = nat_divmod_words(NULL, 0, base, a, m);
    if (res)
        goto cleanup;

    if (ct_declassify(m->w[0] & 1)) {
        /* Odd modulus: Montgomery form, only within this block */
        res = mont_ctx_new(&ctx, m);
        if (res)
            goto cleanup;
        mont_to(t, base, ctx);
        res = mont_pow(acc, t, e, ctx);
        if (res)
            goto cleanup;
        mont_from(acc, acc, ctx);
    } else {
        /* Even modulus (>= 2): square-and-multiply with full reductions */
        size_t i;

        res = ERR_MEMORY;
        prod = nat_alloc(2*nw);
        if (NULL == prod)
            goto cleanup;

        acc[0] = 1;
        for (i=64*e->nw; i-- > 0;) {
            uint64_t bit = (e->w[i / 64] >> (i % 64)) & 1;

            res = mulmod_words(acc, acc, acc, m, prod);
            if (res)
                goto cleanup;
            res = mulmod_words(t, acc, base, m, prod);
            if (res)
                goto cleanup;
            words_select(acc, ct_mask(bit), t, acc, nw);
        }
    }

    words_to_nat(out, acc, nw);
    res = 0;

cleanup:
    mont_ctx_free(ctx);
    nat_free(prod);
    nat_words_free(base, nw);
    nat_words_free(acc, nw);
    nat_words_free(t, nw);
    return res;
}

/*
 * Constant-time binary extended GCD, for an odd n and a < n.
 * Invariants: x1*a = u and x2*a = v (mod n), with v always odd.
 * Each step reduces len(u) + len(v) by at least one bit (until u is 0),
 * so 2*64*nw steps are always enough. At the end v = gcd(a, n).
 */
int inv_odd(uint64_t *out, const uint64_t *a, const uint64_t *n, size_t nw)
{
    uint64_t *u, *v, *x1, *x2, *t, *unit;
    size_t i;
    int res = ERR_MEMORY;

    u = nat_words_alloc(nw);
    v = nat_words_alloc(nw);
    x1 = nat_words_alloc(nw);
    x2 = nat_words_alloc(nw);
    t = nat_words_alloc(nw);
    unit = nat_words_alloc(nw);
    if (!u || !v || !x1 || !x2 || !t || !unit)
        goto cleanup;

    memcpy(u, a, nw*sizeof(uint64_t));
    memcpy(v, n, nw*sizeof(uint64_t));
    unit[0] = 1;
    /* x1 = 1 mod n (which is 0 if n == 1) */
    x1[0] = 1 ^ words_eq(n, unit, nw);

    for (i=0; i<2*64*nw; i++) {
        uint64_t odd, lt;

        odd = u[0] & 1;
        lt = odd & words_lt(u, v, nw);
        words_cswap(ct_mask(lt), u, v, nw);
        words_cswap(ct_mask(lt), x1, x2, nw);

        /* if u is odd: u = u - v, x1 = x1 - x2 */
        words_cond_sub(ct_mask(odd), u, v, nw);
        mod_sub(t, x1, x2, n, nw);
        words_select(x1, ct_mask(odd), t, x1, nw);

        /* u is now even: u = u/2, x1 = x1/2 */
        words_shr1(u, 0, nw);
        mod_half(x1, n, nw);
    }

    /* Only the fact that there is no inverse leaks */
    if (!ct_declassify(words_eq(v, unit, nw))) {
        res = ERR_VALUE;
        goto cleanup;
    }
    memcpy(out, x2, nw*sizeof(uint64_t));
    res = 0;

cleanup:
    nat_words_free(u, nw);
    nat_words_free(v, nw);
    nat_words_free(x1, nw);
    nat_words_free(x2, nw);
    nat_words_free(t, nw);
    nat_words_free(unit, nw);
    return res;
}

/**
 * out = a^{-1} mod m.
 * Return ERR_VALUE if there is no inverse (or if m is 0).
 */
EXPORT_SYM int nat_invmod(Nat *out, const Nat *a, const Nat *m)
{
    uint64_t *ar = NULL, *x = NULL, *mr = NULL;
    Nat *num = NULL, *q = NULL;
    size_t nw;
    int res;

    if (NULL == out || NULL == a || NULL == m)
        return ERR_NULL;
    if (ct_declassify(words_is_zero(m->w, m->nw)))
        return ERR_VALUE;

    nw = m->nw;
    res = ERR_MEMORY;
    ar = nat_words_alloc(nw);
    x = nat_words_alloc(nw);
    mr = nat_words_alloc(nw);
    if (NULL == ar || NULL == x || NULL == mr)
        goto cleanup;

    res = nat_divmod_words(NULL, 0, ar, a, m);
    if (res)
        goto cleanup;

    if (ct_declassify(m->w[0] & 1)) {
        res = inv_odd(x, ar, m->w, nw);
        if (res)
            goto cleanup;
    } else {
        /*
         * Even modulus. a must be odd, then:
         *   t = m^{-1} mod a          (odd modulus)
         *   a^{-1} mod m = (1 + m*(a - t)) / a
         */
        Nat an, kn;
        uint64_t *k, carry;
        size_t i;

        if (ct_declassify(ar[0] & 1) == 0) {
            res = ERR_VALUE;
            goto cleanup;
        }

        an.nw = nw;
        an.w = ar;
        res = nat_divmod_words(NULL, 0, mr, m, &an);
        if (res)
            goto cleanup;
        res = inv_odd(x, mr, ar, nw);       /* x = t */
        if (res)
            goto cleanup;

        k = mr;                             /* reuse: k = a - t */
        words_sub(k, ar, x, nw);
        kn.nw = nw;
        kn.w = k;

        res = ERR_MEMORY;
        num = nat_alloc(2*nw + 1);
        q = nat_alloc(2*nw + 1);
        if (NULL == num || NULL == q)
            goto cleanup;

        /* num = 1 + m*k */
        nat_mul(num, m, &kn);
        carry = 1;
        for (i=0; i<num->nw; i++)
            num->w[i] = ct_add(num->w[i], 0, carry, &carry);

        res = nat_divmod_words(q->w, q->nw, NULL, num, &an);
        if (res)
            goto cleanup;
        res = nat_divmod_words(NULL, 0, x, q, m);
        if (res)
            goto cleanup;
    }

    words_to_nat(out, x, nw);
    res = 0;

cleanup:
    nat_words_free(ar, nw);
    nat_words_free(x, nw);
    nat_words_free(mr, nw);
    nat_free(num);
    nat_free(q);
    return res;
}
