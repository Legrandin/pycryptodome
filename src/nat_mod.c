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
    nat_words_free(ctx->tmp, 2*ctx->nw + 1);
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
    ctx->tmp = nat_words_alloc(2*nw + 1);
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

    /* One pass per word of b: t = (t + a*b[i] + mq*n) / 2^64 */
    for (i=0; i<nw; i++) {
        uint64_t c1, c2, mq, lo, top;

        lo = ct_mac(a[0], b[i], t[0], 0, &c1);
        mq = lo * ctx->m0;
        ct_mac(mq, n[0], lo, 0, &c2);           /* the low word becomes 0 */
        for (j=1; j<nw; j++) {
            lo = ct_mac(a[j], b[i], t[j], c1, &c1);
            t[j - 1] = ct_mac(mq, n[j], lo, c2, &c2);
        }
        top = ct_add(t[nw], c1, 0, &c1);
        t[nw - 1] = ct_add(top, c2, 0, &c2);
        t[nw] = c1 + c2;
    }

    /* t < 2n: subtract n if t >= n */
    borrow = words_sub(out, t, n, nw);
    words_select(out, ct_mask(t[nw] | (1 ^ borrow)), out, t, nw);
}

/*
 * Montgomery squaring: out = a*a/R mod n. a must be smaller than n.
 * out may alias a.
 *
 * The square is computed first (each cross product a[i]*a[j], i < j,
 * once, then doubled, then the squares a[i]^2 added), then reduced
 * (one word at a time, like the second half of mont_mul).
 * This takes about 1.5*nw^2 word multiplications instead of 2*nw^2.
 */
void mont_sqr(uint64_t *out, const uint64_t *a, MontCtx *ctx)
{
    uint64_t *t = ctx->tmp;
    const uint64_t *n = ctx->n;
    size_t nw = ctx->nw;
    size_t i, j;
    uint64_t c, top, borrow;

    memset(t, 0, (2*nw + 1)*sizeof(uint64_t));

    /* t = sum of a[i]*a[j]*2^(64*(i+j)), for i < j */
    for (i=0; i+1<nw; i++) {
        c = 0;
        for (j=i+1; j<nw; j++)
            t[i + j] = ct_mac(a[i], a[j], t[i + j], c, &c);
        t[i + nw] = c;
    }

    /* t = 2*t */
    top = 0;
    for (i=0; i<2*nw; i++) {
        uint64_t next = t[i] >> 63;
        t[i] = (t[i] << 1) | top;
        top = next;
    }

    /* t += a[i]^2 * 2^(128*i) */
    c = 0;
    for (i=0; i<nw; i++) {
        uint64_t lo, hi;

        DP_MULT(a[i], a[i], lo, hi);
        t[2*i] = ct_add(t[2*i], lo, c, &c);
        t[2*i + 1] = ct_add(t[2*i + 1], hi, c, &c);
    }

    /* Montgomery reduction: t = t / R mod n, with t < n^2 */
    top = 0;
    for (i=0; i<nw; i++) {
        uint64_t mq = t[i] * ctx->m0;

        c = 0;
        for (j=0; j<nw; j++)
            t[i + j] = ct_mac(mq, n[j], t[i + j], c, &c);
        t[i + nw] = ct_add(t[i + nw], c, top, &top);
    }

    /* The result (t[nw..2nw-1] and top) is smaller than 2n: subtract n if needed */
    borrow = words_sub(out, t + nw, n, nw);
    words_select(out, ct_mask(top | (1 ^ borrow)), out, t + nw, nw);
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
 * Fixed-window exponentiation over the low e_bits bits of e (a public
 * bound: e must be smaller than 2^e_bits; it is capped to 64*e->nw).
 * Each window costs 4 squarings, a scan of the whole table,
 * and one multiplication, whatever the value of e.
 */
int mont_pow(uint64_t *out, const uint64_t *base_m, const Nat *e, size_t e_bits, MontCtx *ctx)
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

    /* Round up to whole windows (64*e->nw is a multiple of the window size) */
    e_bits = MIN(e_bits, 64*e->nw);
    e_bits = (e_bits + WINDOW_SIZE - 1) / WINDOW_SIZE * WINDOW_SIZE;

    memcpy(acc, ctx->one, nw*sizeof(uint64_t));
    for (pos=e_bits; pos>0; pos-=WINDOW_SIZE) {
        size_t bitpos = pos - WINDOW_SIZE;
        uint64_t idx;

        for (i=0; i<WINDOW_SIZE; i++)
            mont_sqr(acc, acc, ctx);

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

/**
 * out = a^e mod m.
 * e_bits is a public bound on the size of e (e < 2^e_bits): only that
 * many bits of e are processed, whatever its value.
 */
EXPORT_SYM int nat_powmod(Nat *out, const Nat *a, const Nat *e, size_t e_bits, const Nat *m)
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
        res = mont_pow(acc, t, e, e_bits, ctx);
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
        for (i=MIN(e_bits, 64*e->nw); i-- > 0;) {
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
 * Constant-time binary extended GCD, for an odd n and a < n, one bit per step.
 * Invariants: x1*a = u and x2*a = v (mod n), with v always odd.
 * Each step reduces len(u) + len(v) by at least one bit (until u is 0),
 * so 2*64*nw steps are always enough. At the end v = gcd(a, n).
 *
 * It is simple but slow: inv_odd() is the optimized version of the same
 * algorithm. This one is the reference for the tests.
 */
STATIC int inv_odd_simple(uint64_t *out, const uint64_t *a, const uint64_t *n, size_t nw)
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

/*
 * Optimized binary GCD (T. Pornin, "Optimized Binary GCD for Modular
 * Inversion", 2020, algorithm 2), with k = 32.
 */

#define BGCD_K 32               /* the approximations have 2*BGCD_K bits */
#define BGCD_STEPS (BGCD_K - 1) /* inner steps per round */

/*
 * out = x*f + y*g modulo 2^(64*(nw+1)), as a signed (two's complement)
 * number of nw+1 words, for unsigned x and y of nw words and
 * |f|, |g| <= 2^31. The result always fits.
 *
 * With fu = f mod 2^64, x*f = x*fu - x*2^64 if f < 0.
 */
STATIC void lin_comb(uint64_t *out, const uint64_t *x, const uint64_t *y, int64_t f, int64_t g, size_t nw)
{
    uint64_t fu = (uint64_t)f, gu = (uint64_t)g;
    uint64_t fneg = ct_mask(fu >> 63), gneg = ct_mask(gu >> 63);
    uint64_t c1 = 0, c2 = 0, b1 = 0, b2 = 0;
    size_t i;

    for (i=0; i<nw; i++) {
        uint64_t lo;

        lo = ct_mac(x[i], fu, c1, 0, &c1);
        out[i] = ct_mac(y[i], gu, lo, c2, &c2);
    }
    out[nw] = c1 + c2;

    /* Subtract x*2^64 if f < 0, and y*2^64 if g < 0 */
    for (i=0; i<nw; i++) {
        out[i + 1] = ct_sub(out[i + 1], x[i] & fneg, b1, &b1);
    }
    for (i=0; i<nw; i++) {
        out[i + 1] = ct_sub(out[i + 1], y[i] & gneg, b2, &b2);
    }
}

/* Arithmetic shift right of a signed number of nw+1 words, by BGCD_STEPS bits */
STATIC void shr_signed(uint64_t *x, size_t nw)
{
    const unsigned s = BGCD_STEPS;
    uint64_t sign = x[nw] >> 63;
    size_t i;

    for (i=0; i<nw; i++)
        x[i] = (x[i] >> s) | (x[i + 1] << (64 - s));
    x[nw] = (x[nw] >> s) | (ct_mask(sign) << (64 - s));
}

/* x = -x if mask is all ones (signed, nw+1 words) */
STATIC void cond_negate(uint64_t mask, uint64_t *x, size_t nw)
{
    uint64_t carry = mask & 1;
    size_t i;

    for (i=0; i<=nw; i++)
        x[i] = ct_add(x[i] ^ mask, 0, carry, &carry);
}

/*
 * The 64-bit approximations of a and b: their low 31 bits, and their
 * top 33 bits, aligned on the length of the larger one.
 * If both fit into 64 bits, they are used as they are.
 */
STATIC void approximations(uint64_t *a_approx, uint64_t *b_approx, const uint64_t *a, const uint64_t *b, size_t nw)
{
    uint64_t a_hi = a[0], a_lo = 0, b_hi = b[0], b_lo = 0, top = a[0] | b[0], big = 0;
    uint64_t s, sm, ta, tb, low_mask;
    size_t i;

    /* The two words of a and b where the top word of (a | b) starts */
    for (i=1; i<nw; i++) {
        uint64_t m = ct_mask(ct_nz(a[i] | b[i]));

        a_hi = ct_select(m, a[i], a_hi);
        a_lo = ct_select(m, a[i - 1], a_lo);
        b_hi = ct_select(m, b[i], b_hi);
        b_lo = ct_select(m, b[i - 1], b_lo);
        top = ct_select(m, a[i] | b[i], top);
        big |= m;
    }

    /* Align on the top bit of (a | b): shift left by s bits (0 <= s <= 63) */
    s = 64 - ct_bitlen64(top);
    s = ct_select(ct_mask(ct_eq(s, 64)), 0, s);
    sm = ct_mask(ct_nz(s));
    ta = (a_hi << s) | ((a_lo >> ((64 - s) & 63)) & sm);
    tb = (b_hi << s) | ((b_lo >> ((64 - s) & 63)) & sm);

    low_mask = ((uint64_t)1 << BGCD_STEPS) - 1;
    *a_approx = ct_select(big, (a[0] & low_mask) | (ta & ~low_mask), a[0]);
    *b_approx = ct_select(big, (b[0] & low_mask) | (tb & ~low_mask), b[0]);
}

/*
 * x = (u*f + v*g) / 2^31 mod n, for u, v < n.
 * The division is a Montgomery reduction by 2^31: add k*n so that the
 * low 31 bits become zero (n0inv = -n^{-1} mod 2^64).
 * t has nw+2 words, kn has nw+1 words.
 */
STATIC void mod_lin_comb(uint64_t *x, const uint64_t *u, const uint64_t *v, int64_t f, int64_t g,
                         const uint64_t *n, uint64_t n0inv, uint64_t *t, uint64_t *kn, size_t nw)
{
    uint64_t k, carry, neg, ge;
    size_t i;

    lin_comb(t, u, v, f, g, nw);

    /* t += k*n, with k < 2^31 such that t = 0 mod 2^31 */
    k = (t[0] * n0inv) & (((uint64_t)1 << BGCD_STEPS) - 1);
    carry = 0;
    for (i=0; i<nw; i++)
        kn[i] = ct_mac(n[i], k, carry, 0, &carry);
    kn[nw] = carry;
    words_add(t, t, kn, nw + 1);

    /* |u*f + v*g| < n*2^31, so the result is in (-n, 2n) */
    shr_signed(t, nw);

    /* Bring it into [0, n) */
    neg = t[nw] >> 63;
    carry = words_cond_add(ct_mask(neg), t, n, nw);
    t[nw] += carry;
    ge = (1 ^ words_lt(t, n, nw)) | ct_nz(t[nw]);
    words_cond_sub(ct_mask(ge), t, n, nw);
    memcpy(x, t, nw*sizeof(uint64_t));
}

/*
 * a^{-1} mod n, for an odd n and a < n (nw words).
 * Return ERR_VALUE if there is no inverse; only that fact leaks.
 *
 * Invariants: a_cur = u*a and b_cur = v*a (mod n), with b_cur odd.
 * Each round runs 31 steps of the binary GCD on 64-bit approximations,
 * keeping track of the update factors (f0, g0, f1, g1), then applies
 * them to the full numbers. The number of rounds only depends on nw:
 * ceil((2*64*nw - 1)/31) rounds are enough (Pornin, 2020).
 */
int inv_odd(uint64_t *out, const uint64_t *a, const uint64_t *n, size_t nw)
{
    uint64_t *ac, *bc, *u, *v, *un, *vn, *t1, *t2, *kn, *unit;
    uint64_t n0inv;
    size_t round, rounds, i;
    int res = ERR_MEMORY;

    ac = nat_words_alloc(nw);
    bc = nat_words_alloc(nw);
    u = nat_words_alloc(nw);
    v = nat_words_alloc(nw);
    un = nat_words_alloc(nw);
    vn = nat_words_alloc(nw);
    t1 = nat_words_alloc(nw + 2);
    t2 = nat_words_alloc(nw + 2);
    kn = nat_words_alloc(nw + 1);
    unit = nat_words_alloc(nw);
    if (!ac || !bc || !u || !v || !un || !vn || !t1 || !t2 || !kn || !unit)
        goto cleanup;

    memcpy(ac, a, nw*sizeof(uint64_t));
    memcpy(bc, n, nw*sizeof(uint64_t));
    unit[0] = 1;
    /* u = 1 mod n (which is 0 if n == 1) */
    u[0] = 1 ^ words_eq(n, unit, nw);

    /* -n^{-1} mod 2^64 (Newton iteration) */
    n0inv = n[0];
    for (i=0; i<5; i++)
        n0inv *= 2 - n[0]*n0inv;
    n0inv = 0 - n0inv;

    rounds = (2*64*nw - 1 + BGCD_STEPS - 1) / BGCD_STEPS;
    for (round=0; round<rounds; round++) {
        uint64_t xa, xb, nega, negb;
        int64_t f0 = 1, g0 = 0, f1 = 0, g1 = 1;
        unsigned j;

        approximations(&xa, &xb, ac, bc, nw);

        for (j=0; j<BGCD_STEPS; j++) {
            uint64_t odd, swap, m, t;

            odd = xa & 1;
            swap = odd & ct_lt(xa, xb);

            m = ct_mask(swap);
            t = m & (xa ^ xb);       xa ^= t; xb ^= t;
            t = m & (uint64_t)(f0 ^ f1); f0 ^= (int64_t)t; f1 ^= (int64_t)t;
            t = m & (uint64_t)(g0 ^ g1); g0 ^= (int64_t)t; g1 ^= (int64_t)t;

            m = ct_mask(odd);
            xa -= xb & m;
            f0 = (int64_t)((uint64_t)f0 - ((uint64_t)f1 & m));
            g0 = (int64_t)((uint64_t)g0 - ((uint64_t)g1 & m));

            xa >>= 1;
            f1 = (int64_t)((uint64_t)f1 << 1);
            g1 = (int64_t)((uint64_t)g1 << 1);
        }

        /* (a, b) = ((a*f0 + b*g0) / 2^31, (a*f1 + b*g1) / 2^31) */
        lin_comb(t1, ac, bc, f0, g0, nw);
        lin_comb(t2, ac, bc, f1, g1, nw);
        shr_signed(t1, nw);
        shr_signed(t2, nw);

        /* Make them non-negative, and flip the factors to match */
        nega = ct_mask(t1[nw] >> 63);
        negb = ct_mask(t2[nw] >> 63);
        cond_negate(nega, t1, nw);
        cond_negate(negb, t2, nw);
        f0 = (int64_t)(((uint64_t)f0 ^ nega) - nega);
        g0 = (int64_t)(((uint64_t)g0 ^ nega) - nega);
        f1 = (int64_t)(((uint64_t)f1 ^ negb) - negb);
        g1 = (int64_t)(((uint64_t)g1 ^ negb) - negb);
        memcpy(ac, t1, nw*sizeof(uint64_t));
        memcpy(bc, t2, nw*sizeof(uint64_t));

        /* (u, v) = ((u*f0 + v*g0) / 2^31, (u*f1 + v*g1) / 2^31) mod n */
        mod_lin_comb(un, u, v, f0, g0, n, n0inv, t1, kn, nw);
        mod_lin_comb(vn, u, v, f1, g1, n, n0inv, t1, kn, nw);
        memcpy(u, un, nw*sizeof(uint64_t));
        memcpy(v, vn, nw*sizeof(uint64_t));
    }

    /* b = gcd(a, n): only the fact that there is no inverse leaks */
    if (!ct_declassify(words_eq(bc, unit, nw))) {
        res = ERR_VALUE;
        goto cleanup;
    }
    memcpy(out, v, nw*sizeof(uint64_t));
    res = 0;

cleanup:
    nat_words_free(ac, nw);
    nat_words_free(bc, nw);
    nat_words_free(u, nw);
    nat_words_free(v, nw);
    nat_words_free(un, nw);
    nat_words_free(vn, nw);
    nat_words_free(t1, nw + 2);
    nat_words_free(t2, nw + 2);
    nat_words_free(kn, nw + 1);
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
