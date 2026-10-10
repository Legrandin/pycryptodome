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

#if defined(NAT_32BIT)

/*
 * 32-bit targets: the Montgomery multiplication and squaring work on
 * arrays of 32-bit words, with 32x32 -> 64 products, which the CPU has.
 * The numbers are converted at the start and at the end of each call;
 * the conversion is linear, while the work is quadratic.
 */

/** d (2*nw 32-bit words) = s (nw 64-bit words) **/
STATIC void to_words32(uint32_t *d, const uint64_t *s, size_t nw)
{
    size_t i;

    for (i=0; i<nw; i++) {
        d[2*i] = (uint32_t)s[i];
        d[2*i + 1] = (uint32_t)(s[i] >> 32);
    }
}

/** d (nw 64-bit words) = s (2*nw 32-bit words) **/
STATIC void from_words32(uint64_t *d, const uint32_t *s, size_t nw)
{
    size_t i;

    for (i=0; i<nw; i++)
        d[i] = ((uint64_t)s[2*i + 1] << 32) | s[2*i];
}

/** t[0..n-1] += a[0..n-1] * b, and return the high word **/
STATIC uint32_t addmul_row32(uint32_t *t, const uint32_t *a, uint32_t b, size_t n)
{
    uint32_t c = 0;
    size_t j;

    for (j=0; j<n; j++) {
        /* (2^32-1)^2 + 2*(2^32-1) = 2^64-1: it always fits */
        uint64_t p = (uint64_t)a[j]*b + t[j] + c;
        t[j] = (uint32_t)p;
        c = (uint32_t)(p >> 32);
    }
    return c;
}

/**
 * out = t[n..2n-1] + top*2^(32n), minus m if that is at least m;
 * the value must be smaller than 2m (n words of 32 bits).
 */
STATIC void final_sub32(uint32_t *out, const uint32_t *t, uint32_t top, const uint32_t *m, size_t n)
{
    uint32_t borrow = 0, mask;
    size_t j;

    for (j=0; j<n; j++) {
        uint64_t d = (uint64_t)t[n + j] - m[j] - borrow;
        out[j] = (uint32_t)d;
        borrow = (uint32_t)(d >> 63);
    }
    /* keep the difference if there was a top word, or no borrow */
    mask = (uint32_t)ct_mask((uint64_t)(ct_nz(top) | (1 ^ borrow)));
    for (j=0; j<n; j++)
        out[j] = (out[j] & mask) | (t[n + j] & ~mask);
}

/** 32-bit version of mont_mul(): out = a*b/R mod m (n = 2*nw words) **/
STATIC void mont_mul32(uint32_t *out, const uint32_t *a, const uint32_t *b, MontCtx *ctx)
{
    uint32_t *t = ctx->t32;
    const uint32_t *m = ctx->n32;
    size_t n = 2*ctx->nw;
    size_t i;

    memset(t, 0, (2*n + 2)*sizeof(uint32_t));

    for (i=0; i<n; i++) {
        uint64_t s;
        uint32_t h, mq;

        /* t[i+n+1] is still zero here */
        h = addmul_row32(t + i, a, b[i], n);
        s = (uint64_t)t[i + n] + h;
        t[i + n] = (uint32_t)s;
        t[i + n + 1] = (uint32_t)(s >> 32);

        mq = t[i] * ctx->m0_32;
        h = addmul_row32(t + i, m, mq, n);
        s = (uint64_t)t[i + n] + h;
        t[i + n] = (uint32_t)s;
        t[i + n + 1] += (uint32_t)(s >> 32);
    }

    final_sub32(out, t, t[2*n], m, n);
}

/** 32-bit version of mont_sqr(): out = a*a/R mod m (n = 2*nw words) **/
STATIC void mont_sqr32(uint32_t *out, const uint32_t *a, MontCtx *ctx)
{
    uint32_t *t = ctx->t32;
    const uint32_t *m = ctx->n32;
    size_t n = 2*ctx->nw;
    size_t i;
    uint32_t top;
    uint64_t c;

    memset(t, 0, (2*n + 2)*sizeof(uint32_t));

    /* Cross products a[i]*a[j], i < j; t[i+n] is still zero */
    for (i=0; i+1<n; i++)
        t[i + n] = addmul_row32(t + 2*i + 1, a + i + 1, a[i], n - i - 1);

    /* Double them */
    top = 0;
    for (i=0; i<2*n; i++) {
        uint32_t next = t[i] >> 31;
        t[i] = (t[i] << 1) | top;
        top = next;
    }

    /* Add the squares a[i]^2 */
    c = 0;
    for (i=0; i<n; i++) {
        uint64_t sq = (uint64_t)a[i]*a[i];

        c += (uint64_t)t[2*i] + (uint32_t)sq;
        t[2*i] = (uint32_t)c;
        c >>= 32;
        c += (uint64_t)t[2*i + 1] + (uint32_t)(sq >> 32);
        t[2*i + 1] = (uint32_t)c;
        c >>= 32;
    }

    /* Montgomery reduction, one word at a time */
    top = 0;
    for (i=0; i<n; i++) {
        uint32_t h, mq = t[i] * ctx->m0_32;
        uint64_t s;

        h = addmul_row32(t + i, m, mq, n);
        s = (uint64_t)t[i + n] + h + top;
        t[i + n] = (uint32_t)s;
        top = (uint32_t)(s >> 32);
    }

    final_sub32(out, t, top, m, n);
}

#endif /* NAT_32BIT */

void mont_ctx_free_private(MontCtx *ctx);

/* Allocate the scratchpads of a context (nw is already set) */
STATIC int mont_ctx_alloc_scratch(MontCtx *ctx)
{
    size_t nw = ctx->nw;

    ctx->tmp = nat_words_alloc(2*nw + 2);
    if (NULL == ctx->tmp)
        return ERR_MEMORY;
#if defined(NAT_32BIT)
    /* Arrays of 32-bit words, allocated as 64-bit words */
    ctx->t32 = (uint32_t*)nat_words_alloc(2*nw + 1);
    ctx->x32 = (uint32_t*)nat_words_alloc(nw);
    ctx->y32 = (uint32_t*)nat_words_alloc(nw);
    if (!ctx->t32 || !ctx->x32 || !ctx->y32)
        return ERR_MEMORY;
#endif
    return 0;
}

STATIC void mont_ctx_free_scratch(MontCtx *ctx)
{
    nat_words_free(ctx->tmp, 2*ctx->nw + 2);
    nat_words_free((uint64_t*)ctx->t32, 2*ctx->nw + 1);
    nat_words_free((uint64_t*)ctx->x32, ctx->nw);
    nat_words_free((uint64_t*)ctx->y32, ctx->nw);
}

int mont_ctx_new_private(MontCtx **out, const MontCtx *ctx)
{
    MontCtx *copy;

    *out = copy = (MontCtx*)calloc(1, sizeof(MontCtx));
    if (NULL == copy)
        return ERR_MEMORY;
    *copy = *ctx;
    copy->tmp = NULL;
    copy->t32 = copy->x32 = copy->y32 = NULL;
    if (mont_ctx_alloc_scratch(copy)) {
        mont_ctx_free_private(copy);
        *out = NULL;
        return ERR_MEMORY;
    }
    return 0;
}

void mont_ctx_free_private(MontCtx *ctx)
{
    if (NULL == ctx)
        return;
    mont_ctx_free_scratch(ctx);
    free(ctx);
}

void mont_ctx_free(MontCtx *ctx)
{
    if (NULL == ctx)
        return;
    nat_words_free(ctx->n, ctx->nw);
    nat_words_free(ctx->r2, ctx->nw);
    nat_words_free(ctx->one, ctx->nw);
    nat_words_free(ctx->unit, ctx->nw);
    /* The 32-bit arrays are allocated as 64-bit words (see mont_ctx_new) */
    nat_words_free((uint64_t*)ctx->n32, ctx->nw);
    mont_ctx_free_scratch(ctx);
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
    if (!ctx->n || !ctx->r2 || !ctx->one || !ctx->unit)
        goto cleanup;
    if (mont_ctx_alloc_scratch(ctx))
        goto cleanup;

    memcpy(ctx->n, n->w, nw*sizeof(uint64_t));
    ctx->unit[0] = 1;

    /* Newton iteration: each step doubles the number of correct bits (3 at start) */
    inv = n->w[0];
    for (i=0; i<5; i++)
        inv *= 2 - n->w[0]*inv;
    ctx->m0 = 0 - inv;

#if defined(NAT_32BIT)
    /*
     * Arrays of 32-bit words, allocated as 64-bit words; they are only
     * accessed as 32-bit words.
     */
    ctx->n32 = (uint32_t*)nat_words_alloc(nw);
    if (!ctx->n32)
        goto cleanup;
    to_words32(ctx->n32, ctx->n, nw);
    ctx->m0_32 = (uint32_t)ctx->m0;
#endif

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
 * The core of the Montgomery multiplication and squaring:
 * t[0..nw-1] += a[0..nw-1] * b, and return the high word h,
 * so that the exact result is t + h*2^(64*nw). nw is at least 1.
 *
 * In the build for CPUs with BMI2 and ADX (NAT_BMI2_ADX, gcc and clang
 * on x86-64), it is written with MULX (a product that does not touch the
 * flags), ADCX (addition with the carry flag) and ADOX (addition with the
 * overflow flag): the low halves of the products are accumulated on one
 * carry chain and the high halves on the other, so the two chains run
 * in parallel. The loop only uses instructions that keep the flags
 * (LEA, JRCXZ, JMP). Otherwise, it is plain C.
 *
 * Both versions are constant time: the loop count only depends on nw.
 */
#if defined(NAT_BMI2_ADX)

STATIC uint64_t addmul_row(uint64_t *t, const uint64_t *a, uint64_t b, size_t nw)
{
    uint64_t *t_end = t + nw;
    const uint64_t *a_end = a + nw;
    int64_t i = -(int64_t)nw;               /* index from the end, up to 0 */
    int64_t r = -(int64_t)(nw & 3);
    uint64_t hi;

    __asm__ volatile (
        "xor %%r10d, %%r10d\n\t"            /* high word so far = 0; CF = OF = 0 */

        /* The first nw % 4 words, one at a time (rcx counts up to 0) */
        "mov %[r], %%rcx\n\t"
        "jrcxz 3f\n\t"
        "4:\n\t"
        "mulx (%[a],%[i],8), %%r8, %%r9\n\t"
        "adcx (%[t],%[i],8), %%r8\n\t"
        "adox %%r10, %%r8\n\t"
        "mov %%r8, (%[t],%[i],8)\n\t"
        "mov %%r9, %%r10\n\t"
        "lea 1(%[i]), %[i]\n\t"
        "lea 1(%%rcx), %%rcx\n\t"
        "jrcxz 3f\n\t"
        "jmp 4b\n\t"

        /* The other words, four at a time (rcx counts up to 0) */
        "3:\n\t"
        "mov %[i], %%rcx\n\t"
        "jrcxz 2f\n\t"
        "1:\n\t"
        "mulx (%[a],%%rcx,8), %%r8, %%r9\n\t"
        "adcx (%[t],%%rcx,8), %%r8\n\t"
        "adox %%r10, %%r8\n\t"
        "mov %%r8, (%[t],%%rcx,8)\n\t"
        "mulx 8(%[a],%%rcx,8), %%r8, %%r10\n\t"
        "adcx 8(%[t],%%rcx,8), %%r8\n\t"
        "adox %%r9, %%r8\n\t"
        "mov %%r8, 8(%[t],%%rcx,8)\n\t"
        "mulx 16(%[a],%%rcx,8), %%r8, %%r9\n\t"
        "adcx 16(%[t],%%rcx,8), %%r8\n\t"
        "adox %%r10, %%r8\n\t"
        "mov %%r8, 16(%[t],%%rcx,8)\n\t"
        "mulx 24(%[a],%%rcx,8), %%r8, %%r10\n\t"
        "adcx 24(%[t],%%rcx,8), %%r8\n\t"
        "adox %%r9, %%r8\n\t"
        "mov %%r8, 24(%[t],%%rcx,8)\n\t"
        "lea 4(%%rcx), %%rcx\n\t"
        "jrcxz 2f\n\t"
        "jmp 1b\n\t"

        /* The high word: the last high half, plus both carries */
        "2:\n\t"
        "mov $0, %%r9d\n\t"
        "adcx %%r9, %%r10\n\t"
        "adox %%r9, %%r10\n\t"
        "mov %%r10, %[hi]\n\t"
        : [i] "+r" (i), [hi] "=r" (hi)
        : [a] "r" (a_end), [t] "r" (t_end), [r] "r" (r), "d" (b)
        : "rcx", "r8", "r9", "r10", "cc", "memory");

    return hi;
}

#elif !defined(NAT_32BIT) || defined(NAT_TESTS)

/* (32-bit targets use mont_mul32 and mont_sqr32 instead, except in the tests) */
STATIC uint64_t addmul_row(uint64_t *t, const uint64_t *a, uint64_t b, size_t nw)
{
    uint64_t c = 0;
    size_t j;

    for (j=0; j<nw; j++)
        t[j] = ct_mac(a[j], b, t[j], c, &c);
    return c;
}

#endif

/*
 * Montgomery multiplication: out = a*b/R mod n.
 * a and b must be smaller than n. out may alias a or b.
 *
 * Separated operand scanning: for each word of b, add a*b[i] and then
 * mq*n at offset i (mq makes word i zero). The result is in the upper
 * half of t, and it is smaller than 2n.
 */
void mont_mul(uint64_t *out, const uint64_t *a, const uint64_t *b, MontCtx *ctx)
{
#if defined(NAT_32BIT)
    to_words32(ctx->x32, a, ctx->nw);
    to_words32(ctx->y32, b, ctx->nw);
    mont_mul32(ctx->x32, ctx->x32, ctx->y32, ctx);
    from_words32(out, ctx->x32, ctx->nw);
#else
    uint64_t *t = ctx->tmp;
    const uint64_t *n = ctx->n;
    size_t nw = ctx->nw;
    size_t i;
    uint64_t borrow;

    memset(t, 0, (2*nw + 2)*sizeof(uint64_t));

    for (i=0; i<nw; i++) {
        uint64_t h, c, mq;

        /* t[i+nw+1] is still zero here */
        h = addmul_row(t + i, a, b[i], nw);
        t[i + nw] = ct_add(t[i + nw], h, 0, &c);
        t[i + nw + 1] = c;

        mq = t[i] * ctx->m0;
        h = addmul_row(t + i, n, mq, nw);
        t[i + nw] = ct_add(t[i + nw], h, 0, &c);
        t[i + nw + 1] += c;
    }

    /* t[nw..2nw] < 2n: subtract n if needed */
    borrow = words_sub(out, t + nw, n, nw);
    words_select(out, ct_mask(t[2*nw] | (1 ^ borrow)), out, t + nw, nw);
#endif
}

/*
 * Montgomery squaring: out = a*a/R mod n. a must be smaller than n.
 * out may alias a.
 *
 * The square is computed first (each cross product a[i]*a[j], i < j,
 * once, then doubled, then the squares a[i]^2 added), then reduced
 * one word at a time.
 * This takes about 1.5*nw^2 word multiplications instead of 2*nw^2.
 */
void mont_sqr(uint64_t *out, const uint64_t *a, MontCtx *ctx)
{
#if defined(NAT_32BIT)
    to_words32(ctx->x32, a, ctx->nw);
    mont_sqr32(ctx->x32, ctx->x32, ctx);
    from_words32(out, ctx->x32, ctx->nw);
#else
    uint64_t *t = ctx->tmp;
    const uint64_t *n = ctx->n;
    size_t nw = ctx->nw;
    size_t i;
    uint64_t c, top, borrow;

    memset(t, 0, (2*nw + 2)*sizeof(uint64_t));

    /* t = sum of a[i]*a[j]*2^(64*(i+j)), for i < j; t[i+nw] is still zero */
    for (i=0; i+1<nw; i++)
        t[i + nw] = addmul_row(t + 2*i + 1, a + i + 1, a[i], nw - i - 1);

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

        lo = ct_mac(a[i], a[i], 0, 0, &hi);
        t[2*i] = ct_add(t[2*i], lo, c, &c);
        t[2*i + 1] = ct_add(t[2*i + 1], hi, c, &c);
    }

    /* Montgomery reduction: t = t / R mod n, with t < n^2 */
    top = 0;
    for (i=0; i<nw; i++) {
        uint64_t h, mq = t[i] * ctx->m0;

        h = addmul_row(t + i, n, mq, nw);
        t[i + nw] = ct_add(t[i + nw], h, top, &top);
    }

    /* The result (t[nw..2nw-1] and top) is smaller than 2n: subtract n if needed */
    borrow = words_sub(out, t + nw, n, nw);
    words_select(out, ct_mask(top | (1 ^ borrow)), out, t + nw, nw);
#endif
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

#if defined(NAT_TESTS)

/*
 * Constant-time binary extended GCD, for an odd n and a < n, one bit per step.
 * Invariants: x1*a = u and x2*a = v (mod n), with v always odd.
 * Each step reduces len(u) + len(v) by at least one bit (until u is 0),
 * so 2*64*nw steps are always enough. At the end v = gcd(a, n).
 *
 * It is simple but slow: inv_odd() is the optimized version of the same
 * algorithm. This one is the reference for the tests (only compiled
 * with NAT_TESTS).
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

#endif /* NAT_TESTS */

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
#if defined(NAT_32BIT)

/** x*f + c, for f < 2^32 and c < 2^32: return the low 64 bits, *hi gets the rest (< 2^32) **/
STATIC uint64_t mul64x32(uint64_t x, uint32_t f, uint64_t c, uint64_t *hi)
{
    uint64_t t0, t1;

    t0 = (uint64_t)(uint32_t)x * f + c;
    t1 = (uint64_t)(uint32_t)(x >> 32) * f + (t0 >> 32);
    *hi = t1 >> 32;
    return (t1 << 32) | (uint32_t)t0;
}

/*
 * 32-bit targets: x*f + y*g with the magnitudes of f and g (they fit
 * into 32 bits), so that each word takes two 32x32 products instead of
 * four. The signs are applied in the same pass, without branches:
 * -P = ~P + 1, with the +1 carried along the words.
 */
STATIC void lin_comb(uint64_t *out, const uint64_t *x, const uint64_t *y, int64_t f, int64_t g, size_t nw)
{
    uint64_t fneg = ct_mask((uint64_t)f >> 63), gneg = ct_mask((uint64_t)g >> 63);
    uint32_t fa = (uint32_t)((((uint64_t)f) ^ fneg) - fneg);
    uint32_t ga = (uint32_t)((((uint64_t)g) ^ gneg) - gneg);
    uint64_t cp = 0, cq = 0, ca = fneg & 1, cb = gneg & 1, cc = 0;
    size_t i;

    for (i=0; i<=nw; i++) {
        uint64_t p, q;

        /* The words of x*|f| and y*|g| (the top word is the last carry) */
        if (i < nw) {
            p = mul64x32(x[i], fa, cp, &cp);
            q = mul64x32(y[i], ga, cq, &cq);
        } else {
            p = cp;
            q = cq;
        }

        /* Conditional negations, then the sum */
        p = ct_add(p ^ fneg, 0, ca, &ca);
        q = ct_add(q ^ gneg, 0, cb, &cb);
        out[i] = ct_add(p, q, cc, &cc);
    }
}

#else

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

#endif /* NAT_32BIT */

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
 * (hi, lo) = (hi, lo) << s, for a secret 0 <= s <= 63 (128 bits, the
 * top bits are lost). Only shifts by constants are used, each selected
 * with a mask: on 32-bit CPUs, a 64-bit shift by a variable amount is
 * compiled into code that branches on the amount (found with test_nat_ct).
 */
STATIC void shl128_ct(uint64_t *hi, uint64_t *lo, uint64_t s)
{
    unsigned j;

    for (j=6; j-- > 0;) {
        const unsigned k = 1U << j;     /* 32, 16, 8, 4, 2, 1 (public) */
        uint64_t m = ct_mask((s >> j) & 1);
        uint64_t new_hi = (*hi << k) | (*lo >> (64 - k));
        uint64_t new_lo = *lo << k;

        *hi = ct_select(m, new_hi, *hi);
        *lo = ct_select(m, new_lo, *lo);
    }
}

/*
 * The 64-bit approximations of a and b: their low 31 bits, and their
 * top 33 bits, aligned on the length of the larger one.
 * If both fit into 64 bits, they are used as they are.
 */
STATIC void approximations(uint64_t *a_approx, uint64_t *b_approx, const uint64_t *a, const uint64_t *b, size_t nw)
{
    uint64_t a_hi = a[0], a_lo = 0, b_hi = b[0], b_lo = 0, top = a[0] | b[0], big = 0;
    uint64_t s, ta, tb, low_mask;
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
    shl128_ct(&a_hi, &a_lo, s);
    shl128_ct(&b_hi, &b_lo, s);
    ta = a_hi;
    tb = b_hi;

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
#if defined(NAT_32BIT)
        kn[i] = mul64x32(n[i], (uint32_t)k, carry, &carry);
#else
        kn[i] = ct_mac(n[i], k, carry, 0, &carry);
#endif
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
