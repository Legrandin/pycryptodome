/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Natural numbers with constant-time operations:
 * memory, conversions, comparisons and basic arithmetic.
 */

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "nat.h"
#include "nat_ct.h"

/*
 * The same code is also compiled for CPUs with BMI2 and ADX, as another
 * module (see nat_bmi2_adx.c).
 */
#ifndef NAT_MODULE
#define NAT_MODULE nat
#endif
FAKE_INIT(NAT_MODULE)

/* ---------------------------------------------------------------- */
/* Memory                                                           */
/* ---------------------------------------------------------------- */

STATIC void wipe(void *p, size_t len)
{
    volatile uint8_t *v = (volatile uint8_t*)p;

    while (len--)
        *v++ = 0;
}

uint64_t *nat_words_alloc(size_t nw)
{
    if (nw == 0 || nw > 4*NAT_MAX_WORDS)
        return NULL;
    return (uint64_t*)calloc(nw, sizeof(uint64_t));
}

void nat_words_free(uint64_t *w, size_t nw)
{
    if (NULL == w)
        return;
    wipe(w, nw*sizeof(uint64_t));
    free(w);
}

Nat *nat_alloc(size_t nw)
{
    Nat *x;

    if (nw == 0 || nw > 4*NAT_MAX_WORDS)
        return NULL;
    x = (Nat*)calloc(1, sizeof(Nat) + nw*sizeof(uint64_t));
    if (NULL == x)
        return NULL;
    x->nw = nw;
    x->w = (uint64_t*)(x + 1);
    return x;
}

EXPORT_SYM int nat_new(Nat **out, size_t nw)
{
    if (NULL == out)
        return ERR_NULL;
    if (nw == 0 || nw > NAT_MAX_WORDS)
        return ERR_VALUE;
    *out = nat_alloc(nw);
    if (NULL == *out)
        return ERR_MEMORY;
    return 0;
}

EXPORT_SYM void nat_free(Nat *x)
{
    if (NULL == x)
        return;
    wipe(x->w, x->nw*sizeof(uint64_t));
    free(x);
}

EXPORT_SYM int nat_copy(Nat *out, const Nat *a)
{
    size_t i;

    if (NULL == out || NULL == a)
        return ERR_NULL;
    for (i=0; i<out->nw; i++)
        out->w[i] = nat_word(a, i);
    return 0;
}

/* ---------------------------------------------------------------- */
/* Word arrays                                                      */
/* ---------------------------------------------------------------- */

uint64_t words_is_zero(const uint64_t *x, size_t nw)
{
    uint64_t acc = 0;
    size_t i;

    for (i=0; i<nw; i++)
        acc |= x[i];
    return ct_z(acc);
}

uint64_t words_eq(const uint64_t *x, const uint64_t *y, size_t nw)
{
    uint64_t acc = 0;
    size_t i;

    for (i=0; i<nw; i++)
        acc |= x[i] ^ y[i];
    return ct_z(acc);
}

uint64_t words_lt(const uint64_t *x, const uint64_t *y, size_t nw)
{
    uint64_t borrow = 0;
    size_t i;

    for (i=0; i<nw; i++)
        ct_sub(x[i], y[i], borrow, &borrow);
    return borrow;
}

void words_select(uint64_t *out, uint64_t mask, const uint64_t *x, const uint64_t *y, size_t nw)
{
    size_t i;

    for (i=0; i<nw; i++)
        out[i] = ct_select(mask, x[i], y[i]);
}

void words_cswap(uint64_t mask, uint64_t *x, uint64_t *y, size_t nw)
{
    size_t i;

    for (i=0; i<nw; i++) {
        uint64_t t = mask & (x[i] ^ y[i]);
        x[i] ^= t;
        y[i] ^= t;
    }
}

uint64_t words_add(uint64_t *out, const uint64_t *a, const uint64_t *b, size_t nw)
{
    uint64_t carry = 0;
    size_t i;

    for (i=0; i<nw; i++)
        out[i] = ct_add(a[i], b[i], carry, &carry);
    return carry;
}

uint64_t words_sub(uint64_t *out, const uint64_t *a, const uint64_t *b, size_t nw)
{
    uint64_t borrow = 0;
    size_t i;

    for (i=0; i<nw; i++)
        out[i] = ct_sub(a[i], b[i], borrow, &borrow);
    return borrow;
}

uint64_t words_cond_sub(uint64_t mask, uint64_t *x, const uint64_t *y, size_t nw)
{
    uint64_t borrow = 0;
    size_t i;

    for (i=0; i<nw; i++)
        x[i] = ct_sub(x[i], y[i] & mask, borrow, &borrow);
    return borrow;
}

uint64_t words_cond_add(uint64_t mask, uint64_t *x, const uint64_t *y, size_t nw)
{
    uint64_t carry = 0;
    size_t i;

    for (i=0; i<nw; i++)
        x[i] = ct_add(x[i], y[i] & mask, carry, &carry);
    return carry;
}

void words_shr1(uint64_t *x, uint64_t top, size_t nw)
{
    size_t i;

    for (i=0; i+1<nw; i++)
        x[i] = (x[i] >> 1) | (x[i+1] << 63);
    x[nw-1] = (x[nw-1] >> 1) | (top << 63);
}

/** out = x >> s, for a public s **/
STATIC void words_shr_public(uint64_t *out, const uint64_t *x, size_t s, size_t nw)
{
    size_t ws = s / 64;
    unsigned bs = (unsigned)(s % 64);
    size_t i;

    for (i=0; i<nw; i++) {
        uint64_t lo, hi;

        lo = (i + ws < nw) ? x[i + ws] : 0;
        hi = (i + ws + 1 < nw) ? x[i + ws + 1] : 0;
        out[i] = bs ? (lo >> bs) | (hi << (64 - bs)) : lo;
    }
}

/** out = x << s, for a public s **/
STATIC void words_shl_public(uint64_t *out, const uint64_t *x, size_t s, size_t nw)
{
    size_t ws = s / 64;
    unsigned bs = (unsigned)(s % 64);
    size_t i;

    for (i=0; i<nw; i++) {
        uint64_t lo, hi;

        hi = (i >= ws) ? x[i - ws] : 0;
        lo = (i >= ws + 1) ? x[i - ws - 1] : 0;
        out[i] = bs ? (hi << bs) | (lo >> (64 - bs)) : hi;
    }
}

void words_shr_secret(uint64_t *x, uint64_t k, uint64_t *tmp, size_t nw)
{
    size_t s;
    unsigned j;

    for (j=0, s=1; s<=64*nw; j++, s<<=1) {
        words_shr_public(tmp, x, s, nw);
        words_select(x, ct_mask((k >> j) & 1), tmp, x, nw);
    }
}

void words_shl_secret(uint64_t *x, uint64_t k, uint64_t *tmp, size_t nw)
{
    size_t s;
    unsigned j;

    for (j=0, s=1; s<=64*nw; j++, s<<=1) {
        words_shl_public(tmp, x, s, nw);
        words_select(x, ct_mask((k >> j) & 1), tmp, x, nw);
    }
}

uint64_t words_ctz(const uint64_t *x, size_t nw)
{
    uint64_t total = 0;
    uint64_t found = 0;
    size_t i;

    for (i=0; i<nw; i++) {
        total += ct_select(ct_mask(found), 0, ct_ctz64(x[i]));
        found |= ct_nz(x[i]);
    }
    return total;
}

/* ---------------------------------------------------------------- */
/* Conversions                                                      */
/* ---------------------------------------------------------------- */

EXPORT_SYM int nat_from_bytes(Nat *out, const uint8_t *in, size_t len, int little_endian)
{
    uint64_t overflow = 0;
    size_t k;

    if (NULL == out || (NULL == in && len > 0))
        return ERR_NULL;

    memset(out->w, 0, out->nw*sizeof(uint64_t));
    for (k=0; k<len; k++) {
        uint64_t byte;
        size_t idx = k / 8;

        byte = little_endian ? in[k] : in[len - 1 - k];
        if (idx < out->nw)
            out->w[idx] |= byte << (8*(k % 8));
        else
            overflow |= byte;
    }

    return ct_declassify(ct_nz(overflow)) ? ERR_VALUE : 0;
}

EXPORT_SYM int nat_to_bytes(uint8_t *out, size_t len, const Nat *a, int little_endian)
{
    uint64_t overflow = 0;
    size_t k;

    if (NULL == a || (NULL == out && len > 0))
        return ERR_NULL;

    for (k=0; k<len; k++) {
        uint8_t byte = (uint8_t)(nat_word(a, k / 8) >> (8*(k % 8)));

        if (little_endian)
            out[k] = byte;
        else
            out[len - 1 - k] = byte;
    }

    /* Bytes of a that do not fit into the output */
    for (k=len; k<8*a->nw; k++)
        overflow |= (a->w[k / 8] >> (8*(k % 8))) & 0xFF;

    return ct_declassify(ct_nz(overflow)) ? ERR_VALUE : 0;
}

EXPORT_SYM int nat_from_uint64(Nat *out, uint64_t v)
{
    if (NULL == out)
        return ERR_NULL;
    memset(out->w, 0, out->nw*sizeof(uint64_t));
    out->w[0] = v;
    return 0;
}

/** Number of significant bits in a (0 for a == 0) **/
EXPORT_SYM int nat_bit_length(const Nat *a)
{
    uint64_t result = 0;
    size_t i;

    for (i=0; i<a->nw; i++) {
        uint64_t m = ct_mask(ct_nz(a->w[i]));
        result = ct_select(m, (uint64_t)i*64 + ct_bitlen64(a->w[i]), result);
    }
    return (int)result;
}

/* ---------------------------------------------------------------- */
/* Predicates and comparison                                        */
/* ---------------------------------------------------------------- */

EXPORT_SYM int nat_is_zero(const Nat *a)
{
    return (int)words_is_zero(a->w, a->nw);
}

EXPORT_SYM int nat_is_odd(const Nat *a)
{
    return (int)(a->w[0] & 1);
}

/** Return -1 if a < b, 0 if a == b, 1 if a > b **/
EXPORT_SYM int nat_cmp(const Nat *a, const Nat *b)
{
    uint64_t lt = 0, gt = 0;
    size_t i, nw;

    nw = MAX(a->nw, b->nw);
    for (i=0; i<nw; i++) {
        uint64_t x = nat_word(a, i);
        uint64_t y = nat_word(b, i);

        ct_sub(x, y, lt, &lt);
        ct_sub(y, x, gt, &gt);
    }
    return (int)gt - (int)lt;
}

/** Bit n of a; n is public **/
EXPORT_SYM int nat_get_bit(const Nat *a, size_t n)
{
    if (n / 64 >= a->nw)
        return 0;
    return (int)((a->w[n / 64] >> (n % 64)) & 1);
}

/* ---------------------------------------------------------------- */
/* Arithmetic                                                       */
/* ---------------------------------------------------------------- */

/** out = a + b (out may be the same object as a or b) **/
EXPORT_SYM int nat_add(Nat *out, const Nat *a, const Nat *b)
{
    uint64_t carry = 0;
    size_t i;

    if (NULL == out || NULL == a || NULL == b)
        return ERR_NULL;

    for (i=0; i<out->nw; i++)
        out->w[i] = ct_add(nat_word(a, i), nat_word(b, i), carry, &carry);
    return 0;
}

/**
 * out = a - b (out may be the same object as a or b).
 * Return ERR_VALUE if b > a. The check covers all words of a and b,
 * also those that do not fit into out.
 */
EXPORT_SYM int nat_sub(Nat *out, const Nat *a, const Nat *b)
{
    uint64_t borrow = 0;
    size_t i, nw;

    if (NULL == out || NULL == a || NULL == b)
        return ERR_NULL;

    nw = MAX(MAX(a->nw, b->nw), out->nw);
    for (i=0; i<nw; i++) {
        uint64_t d = ct_sub(nat_word(a, i), nat_word(b, i), borrow, &borrow);
        if (i < out->nw)
            out->w[i] = d;
    }
    return ct_declassify(borrow) ? ERR_VALUE : 0;
}

/** out = a * b **/
EXPORT_SYM int nat_mul(Nat *out, const Nat *a, const Nat *b)
{
    size_t i, j;

    if (NULL == out || NULL == a || NULL == b)
        return ERR_NULL;
    if (out == a || out == b)
        return ERR_VALUE;

    memset(out->w, 0, out->nw*sizeof(uint64_t));
    for (i=0; i<a->nw && i<out->nw; i++) {
        uint64_t carry = 0;

        for (j=0; j<b->nw && i+j<out->nw; j++)
            out->w[i+j] = ct_mac(a->w[i], b->w[j], out->w[i+j], carry, &carry);
        if (i + b->nw < out->nw)
            out->w[i + b->nw] = carry;
    }
    return 0;
}

/** out = c + a * b **/
EXPORT_SYM int nat_muladd(Nat *out, const Nat *c, const Nat *a, const Nat *b)
{
    size_t i, j;

    if (NULL == out || NULL == a || NULL == b || NULL == c)
        return ERR_NULL;
    if (out == a || out == b)
        return ERR_VALUE;

    nat_copy(out, c);
    for (i=0; i<a->nw && i<out->nw; i++) {
        uint64_t carry = 0;

        for (j=0; j<b->nw && i+j<out->nw; j++)
            out->w[i+j] = ct_mac(a->w[i], b->w[j], out->w[i+j], carry, &carry);
        for (j=i+b->nw; j<out->nw; j++)
            out->w[j] = ct_add(out->w[j], 0, carry, &carry);
    }
    return 0;
}

EXPORT_SYM int nat_and(Nat *out, const Nat *a, const Nat *b)
{
    size_t i;

    if (NULL == out || NULL == a || NULL == b)
        return ERR_NULL;
    for (i=0; i<out->nw; i++)
        out->w[i] = nat_word(a, i) & nat_word(b, i);
    return 0;
}

EXPORT_SYM int nat_or(Nat *out, const Nat *a, const Nat *b)
{
    size_t i;

    if (NULL == out || NULL == a || NULL == b)
        return ERR_NULL;
    for (i=0; i<out->nw; i++)
        out->w[i] = nat_word(a, i) | nat_word(b, i);
    return 0;
}

/** out = a << k, k is public **/
EXPORT_SYM int nat_shl(Nat *out, const Nat *a, size_t k)
{
    size_t ws = k / 64;
    unsigned bs = (unsigned)(k % 64);
    size_t i;

    if (NULL == out || NULL == a)
        return ERR_NULL;
    if (out == a)
        return ERR_VALUE;

    for (i=0; i<out->nw; i++) {
        uint64_t hi, lo;

        hi = (i >= ws) ? nat_word(a, i - ws) : 0;
        lo = (i >= ws + 1) ? nat_word(a, i - ws - 1) : 0;
        out->w[i] = bs ? (hi << bs) | (lo >> (64 - bs)) : hi;
    }
    return 0;
}

/** out = a >> k, k is public **/
EXPORT_SYM int nat_shr(Nat *out, const Nat *a, size_t k)
{
    size_t ws = k / 64;
    unsigned bs = (unsigned)(k % 64);
    size_t i;

    if (NULL == out || NULL == a)
        return ERR_NULL;
    if (out == a)
        return ERR_VALUE;

    for (i=0; i<out->nw; i++) {
        uint64_t lo, hi;

        lo = (ws < a->nw && i < a->nw - ws) ? a->w[i + ws] : 0;
        hi = (ws + 1 < a->nw && i < a->nw - ws - 1) ? a->w[i + ws + 1] : 0;
        out->w[i] = bs ? (lo >> bs) | (hi << (64 - bs)) : lo;
    }
    return 0;
}
