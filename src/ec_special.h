/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Field arithmetic modulo the two primes of a special form, with the
 * elements in plain representation (not in Montgomery form).
 * Only included by ec_common.c.
 *
 *   p448 = 2^448 - 2^224 - 1     (Ed448 and X448), 7 words
 *   p521 = 2^521 - 1             (P-521), 9 words
 *
 * A multiplication is a full product, followed by a reduction made of
 * shifts and additions only, instead of the Montgomery reduction (which
 * costs as many word products as the product itself). The reductions
 * are written once for all targets, on 64-bit words. The full products
 * use the fastest rows of the target: the unrolled code of ec_field.h on
 * 64-bit targets, mul_wide() (32-bit words, or MULX/ADX) otherwise.
 *
 * The additions and subtractions are those of any modulus (fe_add() and
 * fe_sub()): they do not depend on the representation.
 */

#ifndef EC_SPECIAL_H
#define EC_SPECIAL_H

#include "common.h"
#include "nat.h"
#include "nat_ct.h"
#include "ec_common.h"
#include "ec_field.h"

#define P448_WORDS 7
#define P521_WORDS 9

static const uint64_t ec_p448[P448_WORDS] = {
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFEFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL
};

static const uint64_t ec_p521[P521_WORDS] = {
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL, 0x1FF
};

/* The full products */
#if defined(NAT_32BIT)
#define P448_MUL_WIDE(t, a, b, ws)  mul_wide(t, a, b, (ws)->m)
#define P448_SQR_WIDE(t, a, ws)     sqr_wide(t, a, (ws)->m)
#define P521_MUL_WIDE(t, a, b, ws)  mul_wide(t, a, b, (ws)->m)
#define P521_SQR_WIDE(t, a, ws)     sqr_wide(t, a, (ws)->m)
#else
#define P448_MUL_WIDE(t, a, b, ws)  fe_mul_wide_7(t, a, b)
#define P448_SQR_WIDE(t, a, ws)     fe_sqr_wide_7(t, a)
#if defined(NAT_BMI2_ADX)
#define P521_MUL_WIDE(t, a, b, ws)  mul_wide(t, a, b, (ws)->m)
#define P521_SQR_WIDE(t, a, ws)     sqr_wide(t, a, (ws)->m)
#else
#define P521_MUL_WIDE(t, a, b, ws)  fe_mul_wide_9(t, a, b)
#define P521_SQR_WIDE(t, a, ws)     fe_sqr_wide_9(t, a)
#endif
#endif

/* ---------------------------------------------------------------- */
/* p448 = 2^448 - 2^224 - 1                                         */
/* ---------------------------------------------------------------- */

/**
 * r (7 words) += c + c*2^224, for c < 2^32: that is c*2^448 (mod p).
 * Return the carry (0 or 1).
 */
static uint64_t p448_fold(uint64_t *r, uint64_t c)
{
    uint64_t k;

    r[0] = ct_add(r[0], c, 0, &k);
    r[1] = ct_add(r[1], 0, k, &k);
    r[2] = ct_add(r[2], 0, k, &k);
    r[3] = ct_add(r[3], c << 32, k, &k);
    r[4] = ct_add(r[4], 0, k, &k);
    r[5] = ct_add(r[5], 0, k, &k);
    r[6] = ct_add(r[6], 0, k, &k);
    return k;
}

/**
 * out (7 words) = t mod p448, for t < 2^896 (14 words).
 *
 * With t = l + h*2^448 and h = hl + hh*2^224 (224-bit halves), and
 * 2^448 = 2^224 + 1 (mod p):
 *
 *   t = l + (hl + hh) + (hl + 2*hh)*2^224  (mod p)
 *
 * which is smaller than 2^451. The top bits are then folded back twice
 * (2^448 = 2^224 + 1 again), and p subtracted if needed.
 */
STATIC void red_p448(uint64_t *out, const uint64_t *t)
{
    const uint64_t *h = t + P448_WORDS;
    uint64_t hl[4], hh[4], s1[4], s2[4], r[8], d[P448_WORDS];
    uint64_t c, mask;
    unsigned i;

    hl[0] = h[0];
    hl[1] = h[1];
    hl[2] = h[2];
    hl[3] = h[3] & 0xFFFFFFFFU;
    hh[0] = (h[3] >> 32) | (h[4] << 32);
    hh[1] = (h[4] >> 32) | (h[5] << 32);
    hh[2] = (h[5] >> 32) | (h[6] << 32);
    hh[3] = h[6] >> 32;

    /* s1 = hl + hh < 2^225, s2 = s1 + hh < 2^226: no carry out */
    c = 0;
    for (i=0; i<4; i++)
        s1[i] = ct_add(hl[i], hh[i], c, &c);
    c = 0;
    for (i=0; i<4; i++)
        s2[i] = ct_add(s1[i], hh[i], c, &c);

    /* r = l + s1 + s2*2^224 */
    c = 0;
    for (i=0; i<4; i++)
        r[i] = ct_add(t[i], s1[i], c, &c);
    for (; i<P448_WORDS; i++)
        r[i] = ct_add(t[i], 0, c, &c);
    r[7] = c;
    c = 0;
    r[3] = ct_add(r[3], s2[0] << 32, c, &c);
    r[4] = ct_add(r[4], (s2[0] >> 32) | (s2[1] << 32), c, &c);
    r[5] = ct_add(r[5], (s2[1] >> 32) | (s2[2] << 32), c, &c);
    r[6] = ct_add(r[6], (s2[2] >> 32) | (s2[3] << 32), c, &c);
    r[7] += (s2[3] >> 32) + c;

    /*
     * r[7] < 8. Once folded, the carry is 0 or 1; if it is 1, what is
     * left is smaller than 2^228, so the second fold has no carry.
     */
    c = p448_fold(r, r[7]);
    p448_fold(r, c);

    /* r < 2^448 < 2p: subtract p if r >= p */
    c = 0;
    for (i=0; i<P448_WORDS; i++)
        d[i] = ct_sub(r[i], ec_p448[i], c, &c);
    mask = ct_mask(1 ^ c);
    for (i=0; i<P448_WORDS; i++)
        out[i] = ct_select(mask, d[i], r[i]);
}

static void fe_p448_mul(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    uint64_t t[2*P448_WORDS];

    P448_MUL_WIDE(t, a, b, ws);
    red_p448(out, t);
}

static void fe_p448_sqr(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    uint64_t t[2*P448_WORDS];

    P448_SQR_WIDE(t, a, ws);
    red_p448(out, t);
}

/* ---------------------------------------------------------------- */
/* p521 = 2^521 - 1                                                 */
/* ---------------------------------------------------------------- */

/**
 * out (9 words) = t mod p521, for t < 2^1042 (18 words).
 *
 * With t = lo + hi*2^521 and 2^521 = 1 (mod p): t = lo + hi (mod p),
 * smaller than 2^522. Bit 521 is folded back once more, which leaves a
 * value up to 2^521; it is at least p if and only if adding 1 sets bit 521.
 */
STATIC void red_p521(uint64_t *out, const uint64_t *t)
{
    uint64_t r[P521_WORDS], u[P521_WORDS], c, k, mask;
    unsigned i;

    /* r = lo + hi; t[17] is zero */
    c = 0;
    for (i=0; i<8; i++)
        r[i] = ct_add(t[i], (t[8 + i] >> 9) | (t[9 + i] << 55), c, &c);
    r[8] = (t[8] & 0x1FF) + (t[16] >> 9) + c;

    /* r = (r mod 2^521) + (r >> 521) <= 2^521 */
    k = r[8] >> 9;
    r[8] &= 0x1FF;
    r[0] = ct_add(r[0], k, 0, &c);
    for (i=1; i<8; i++)
        r[i] = ct_add(r[i], 0, c, &c);
    r[8] += c;

    /* r >= p if and only if r + 1 >= 2^521; then the result is (r + 1) mod 2^521 */
    u[0] = ct_add(r[0], 1, 0, &c);
    for (i=1; i<P521_WORDS; i++)
        u[i] = ct_add(r[i], 0, c, &c);
    mask = ct_mask(u[8] >> 9);
    u[8] &= 0x1FF;
    for (i=0; i<P521_WORDS; i++)
        out[i] = ct_select(mask, u[i], r[i]);
}

static void fe_p521_mul(EcWs *ws, uint64_t *out, const uint64_t *a, const uint64_t *b)
{
    uint64_t t[2*P521_WORDS];

    P521_MUL_WIDE(t, a, b, ws);
    red_p521(out, t);
}

static void fe_p521_sqr(EcWs *ws, uint64_t *out, const uint64_t *a)
{
    uint64_t t[2*P521_WORDS];

    P521_SQR_WIDE(t, a, ws);
    red_p521(out, t);
}

#endif
