/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Short Weierstrass curves y^2 = x^3 - 3x + b over a prime field p
 * (the NIST curves P-192, P-224, P-256, P-384 and P-521), on the
 * constant-time arithmetic of the nat library (nat_mod.c).
 *
 * - Field elements: arrays of nw 64-bit words, in Montgomery form.
 * - Points: projective coordinates (X:Y:Z); the point at infinity is
 *   (0:1:0). Additions and doublings use the complete formulas of Renes,
 *   Costello and Batina, "Complete addition formulas for prime order
 *   elliptic curves" (2016), for a = -3: they have no special cases.
 * - Scalar multiplications use signed windows of 5 bits (Booth
 *   recoding), always over all the windows of a blinded scalar
 *   k + r*n (r of 64 random bits), with tables that are scanned in full
 *   for each digit. The input point is also randomized (same point,
 *   different projective coordinates).
 *
 * Nothing branches on, or accesses memory at an address that depends on,
 * secret values (the scalar, the points derived from it). Intended leaks
 * (an invalid point, a result that is not on the curve) go through
 * ct_declassify(). Checked with Valgrind by test/test_ec_nat_ct.c.
 *
 * The curve object only holds constants (including the precomputed
 * tables of the generator), so it can be used by several threads at the
 * same time: each operation has its own workspace.
 */

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "nat.h"
#include "nat_ct.h"
#include "ec_common.h"
#include "ec_nat.h"

/* ---------------------------------------------------------------- */
/* Points                                                           */
/* ---------------------------------------------------------------- */

#define MUL(o, a, b)    fe_mul(ws, o, a, b)
#define ADD(o, a, b)    fe_add(ws, o, a, b)
#define SUB(o, a, b)    fe_sub(ws, o, a, b)

/*
 * (x3:y3:z3) = 2*(x1:y1:z1).
 * Algorithm 6 in Renes, Costello, Batina (a = -3). Complete: also for
 * the point at infinity. The output may be the input.
 */
STATIC void point_double(EcWs *ws, const EcCurve *c,
                         uint64_t *x3, uint64_t *y3, uint64_t *z3,
                         const uint64_t *x1, const uint64_t *y1, const uint64_t *z1)
{
    uint64_t *t0 = ws->t[0], *t1 = ws->t[1], *t2 = ws->t[2], *t3 = ws->t[3];
    uint64_t *x = ws->t[4], *y = ws->t[5], *z = ws->t[6];
    const uint64_t *b = c->b;

    fe_copy(ws, x, x1);
    fe_copy(ws, y, y1);
    fe_copy(ws, z, z1);

    MUL(t0, x, x);      /* 1 */
    MUL(t1, y, y);
    MUL(t2, z, z);
    MUL(t3, x, y);      /* 4 */
    ADD(t3, t3, t3);
    MUL(z3, x, z);
    ADD(z3, z3, z3);    /* 7 */
    MUL(y3, b, t2);
    SUB(y3, y3, z3);
    ADD(x3, y3, y3);    /* 10 */
    ADD(y3, x3, y3);
    SUB(x3, t1, y3);
    ADD(y3, t1, y3);    /* 13 */
    MUL(y3, x3, y3);
    MUL(x3, x3, t3);
    ADD(t3, t2, t2);    /* 16 */
    ADD(t2, t2, t3);
    MUL(z3, b, z3);
    SUB(z3, z3, t2);    /* 19 */
    SUB(z3, z3, t0);
    ADD(t3, z3, z3);
    ADD(z3, z3, t3);    /* 22 */
    ADD(t3, t0, t0);
    ADD(t0, t3, t0);
    SUB(t0, t0, t2);    /* 25 */
    MUL(t0, t0, z3);
    ADD(y3, y3, t0);
    MUL(t0, y, z);      /* 28 */
    ADD(t0, t0, t0);
    MUL(z3, t0, z3);
    SUB(x3, x3, z3);    /* 31 */
    MUL(z3, t0, t1);
    ADD(z3, z3, z3);
    ADD(z3, z3, z3);    /* 34 */
}

/*
 * (x3:y3:z3) = (x1:y1:z1) + (x2:y2:z2).
 * Algorithm 4 in Renes, Costello, Batina (a = -3). Complete: also for
 * equal points and for the point at infinity. The output may be an input.
 */
STATIC void point_add(EcWs *ws, const EcCurve *c,
                      uint64_t *x3, uint64_t *y3, uint64_t *z3,
                      const uint64_t *x1i, const uint64_t *y1i, const uint64_t *z1i,
                      const uint64_t *x2i, const uint64_t *y2i, const uint64_t *z2i)
{
    uint64_t *t0 = ws->t[0], *t1 = ws->t[1], *t2 = ws->t[2], *t3 = ws->t[3], *t4 = ws->t[4];
    uint64_t *x1 = ws->t[5], *y1 = ws->t[6], *z1 = ws->t[7];
    uint64_t *x2 = ws->t[8], *y2 = ws->t[9], *z2 = ws->t[10];
    const uint64_t *b = c->b;

    fe_copy(ws, x1, x1i);
    fe_copy(ws, y1, y1i);
    fe_copy(ws, z1, z1i);
    fe_copy(ws, x2, x2i);
    fe_copy(ws, y2, y2i);
    fe_copy(ws, z2, z2i);

    MUL(t0, x1, x2);    /* 1 */
    MUL(t1, y1, y2);
    MUL(t2, z1, z2);
    ADD(t3, x1, y1);    /* 4 */
    ADD(t4, x2, y2);
    MUL(t3, t3, t4);
    ADD(t4, t0, t1);    /* 7 */
    SUB(t3, t3, t4);
    ADD(t4, y1, z1);
    ADD(x3, y2, z2);    /* 10 */
    MUL(t4, t4, x3);
    ADD(x3, t1, t2);
    SUB(t4, t4, x3);    /* 13 */
    ADD(x3, x1, z1);
    ADD(y3, x2, z2);
    MUL(x3, x3, y3);    /* 16 */
    ADD(y3, t0, t2);
    SUB(y3, x3, y3);
    MUL(z3, b, t2);     /* 19 */
    SUB(x3, y3, z3);
    ADD(z3, x3, x3);
    ADD(x3, x3, z3);    /* 22 */
    SUB(z3, t1, x3);
    ADD(x3, t1, x3);
    MUL(y3, b, y3);     /* 25 */
    ADD(t1, t2, t2);
    ADD(t2, t1, t2);
    SUB(y3, y3, t2);    /* 28 */
    SUB(y3, y3, t0);
    ADD(t1, y3, y3);
    ADD(y3, t1, y3);    /* 31 */
    ADD(t1, t0, t0);
    ADD(t0, t1, t0);
    SUB(t0, t0, t2);    /* 34 */
    MUL(t1, t4, y3);
    MUL(t2, t0, y3);
    MUL(y3, x3, z3);    /* 37 */
    ADD(y3, y3, t2);
    MUL(x3, t3, x3);
    SUB(x3, x3, t1);    /* 40 */
    MUL(z3, t4, z3);
    MUL(t1, t3, t0);
    ADD(z3, z3, t1);    /* 43 */
}

/*
 * (x3:y3:z3) = (x1:y1:z1) + (x2, y2), with the second point affine.
 * Algorithm 5 in Renes, Costello, Batina (a = -3). The affine point cannot
 * be the point at infinity: the callers deal with that case with a
 * masked select. The output may be the first input.
 */
STATIC void point_add_mixed(EcWs *ws, const EcCurve *c,
                            uint64_t *x3, uint64_t *y3, uint64_t *z3,
                            const uint64_t *x1i, const uint64_t *y1i, const uint64_t *z1i,
                            const uint64_t *x2, const uint64_t *y2)
{
    uint64_t *t0 = ws->t[0], *t1 = ws->t[1], *t2 = ws->t[2], *t3 = ws->t[3], *t4 = ws->t[4];
    uint64_t *x1 = ws->t[5], *y1 = ws->t[6], *z1 = ws->t[7];
    const uint64_t *b = c->b;

    fe_copy(ws, x1, x1i);
    fe_copy(ws, y1, y1i);
    fe_copy(ws, z1, z1i);

    MUL(t0, x1, x2);    /* 1 */
    MUL(t1, y1, y2);
    ADD(t3, x2, y2);
    ADD(t4, x1, y1);    /* 4 */
    MUL(t3, t3, t4);
    ADD(t4, t0, t1);
    SUB(t3, t3, t4);    /* 7 */
    MUL(t4, y2, z1);
    ADD(t4, t4, y1);
    MUL(y3, x2, z1);    /* 10 */
    ADD(y3, y3, x1);
    MUL(z3, b, z1);
    SUB(x3, y3, z3);    /* 13 */
    ADD(z3, x3, x3);
    ADD(x3, x3, z3);
    SUB(z3, t1, x3);    /* 16 */
    ADD(x3, t1, x3);
    MUL(y3, b, y3);
    ADD(t1, z1, z1);    /* 19 */
    ADD(t2, t1, z1);
    SUB(y3, y3, t2);
    SUB(y3, y3, t0);    /* 22 */
    ADD(t1, y3, y3);
    ADD(y3, t1, y3);
    ADD(t1, t0, t0);    /* 25 */
    ADD(t0, t1, t0);
    SUB(t0, t0, t2);
    MUL(t1, t4, y3);    /* 28 */
    MUL(t2, t0, y3);
    MUL(y3, x3, z3);
    ADD(y3, y3, t2);    /* 31 */
    MUL(x3, t3, x3);
    SUB(x3, x3, t1);
    MUL(z3, t4, z3);    /* 34 */
    MUL(t1, t3, t0);
    ADD(z3, z3, t1);
}

#undef MUL
#undef ADD
#undef SUB

/** (x:y:z) = the point at infinity (0:1:0) **/
STATIC void point_set_infinity(const EcCurve *c, uint64_t *x, uint64_t *y, uint64_t *z)
{
    memset(x, 0, c->nw*sizeof(uint64_t));
    memcpy(y, c->field->one, c->nw*sizeof(uint64_t));
    memset(z, 0, c->nw*sizeof(uint64_t));
}

/**
 * 1 if (x:y:z) is on the curve: Y^2*Z = X^3 - 3*X*Z^2 + b*Z^3
 * (also true for the point at infinity), 0 otherwise.
 */
STATIC uint64_t point_on_curve(EcWs *ws, const EcCurve *c, const uint64_t *x, const uint64_t *y, const uint64_t *z)
{
    uint64_t *lhs = ws->t[0], *rhs = ws->t[1], *z2 = ws->t[2], *t = ws->t[3];

    fe_sqr(ws, lhs, y);         /* Y^2 Z */
    fe_mul(ws, lhs, lhs, z);

    fe_sqr(ws, z2, z);          /* X (X^2 - 3 Z^2) */
    fe_add(ws, t, z2, z2);
    fe_add(ws, t, t, z2);
    fe_sqr(ws, rhs, x);
    fe_sub(ws, rhs, rhs, t);
    fe_mul(ws, rhs, rhs, x);

    fe_mul(ws, t, z2, z);       /* + b Z^3 */
    fe_mul(ws, t, t, c->b);
    fe_add(ws, rhs, rhs, t);

    return words_eq(lhs, rhs, c->nw);
}

/* ---------------------------------------------------------------- */
/* Scalar multiplications                                           */
/* ---------------------------------------------------------------- */

/*
 * (rx:ry:rz) = k * (px:py:pz), for any point (variable base), with the
 * blinded scalar kb.
 *
 * A table of the multiples 0P ... 16P (projective) is built, from a
 * randomized copy of P (coordinates multiplied by lambda); then, for each
 * window from the top: 5 doublings, a full scan of the table for the
 * digit, a conditional negation, and an addition. The output may be
 * the input.
 */
STATIC int scalar_mul_var(EcWs *ws, const EcCurve *c,
                          uint64_t *rx, uint64_t *ry, uint64_t *rz,
                          const uint64_t *px, const uint64_t *py, const uint64_t *pz,
                          const uint64_t *kb, const uint64_t *lambda)
{
    const size_t nw = c->nw;
    const size_t entries = EC_DIGITS + 1;
    uint64_t *table, *acc, *sel, *ny;
    size_t i, j, w;
    int res = ERR_MEMORY;

    table = nat_words_alloc(3*entries*nw);
    acc = nat_words_alloc(3*nw);
    sel = nat_words_alloc(3*nw);
    ny = nat_words_alloc(nw);
    if (!table || !acc || !sel || !ny)
        goto cleanup;

#define TX(j) (table + (3*(j) + 0)*nw)
#define TY(j) (table + (3*(j) + 1)*nw)
#define TZ(j) (table + (3*(j) + 2)*nw)

    /* T[0] = infinity, T[1] = P (randomized), T[j] = T[j-1] + P */
    point_set_infinity(c, TX(0), TY(0), TZ(0));
    fe_mul(ws, TX(1), px, lambda);
    fe_mul(ws, TY(1), py, lambda);
    fe_mul(ws, TZ(1), pz, lambda);
    for (j=2; j<entries; j++)
        point_add(ws, c, TX(j), TY(j), TZ(j), TX(j-1), TY(j-1), TZ(j-1), TX(1), TY(1), TZ(1));

#undef TX
#undef TY
#undef TZ

    point_set_infinity(c, acc, acc + nw, acc + 2*nw);

    for (w=c->windows; w-- > 0;) {
        uint64_t sign, digit;

        for (i=0; i<EC_WINDOW; i++)
            point_double(ws, c, acc, acc + nw, acc + 2*nw, acc, acc + nw, acc + 2*nw);

        ec_booth_digit(kb, c->k_words, w, &sign, &digit);
        ec_table_select(sel, table, entries, 3*nw, digit);

        /* Negative digit: -(x:y:z) = (x:-y:z) */
        fe_neg(ws, ny, sel + nw);
        words_select(sel + nw, ct_mask(sign), ny, sel + nw, nw);

        point_add(ws, c, acc, acc + nw, acc + 2*nw, acc, acc + nw, acc + 2*nw, sel, sel + nw, sel + 2*nw);
    }

    fe_copy(ws, rx, acc);
    fe_copy(ws, ry, acc + nw);
    fe_copy(ws, rz, acc + 2*nw);
    res = 0;

cleanup:
    nat_words_free(table, 3*entries*nw);
    nat_words_free(acc, 3*nw);
    nat_words_free(sel, 3*nw);
    nat_words_free(ny, nw);
    return res;
}

/*
 * (rx:ry:rz) = k * G, with the precomputed tables (fixed base) and the
 * blinded scalar kb.
 *
 * For each window i: a full scan of its table for the digit, a
 * conditional negation, and a mixed addition. There are no doublings.
 * A zero digit selects no point: the addition is computed anyway, and its
 * result discarded with a mask. The accumulator starts as (0:lambda:0),
 * the point at infinity with randomized coordinates.
 */
STATIC int scalar_mul_g(EcWs *ws, const EcCurve *c,
                        uint64_t *rx, uint64_t *ry, uint64_t *rz,
                        const uint64_t *kb, const uint64_t *lambda)
{
    const size_t nw = c->nw;
    uint64_t *acc, *sum, *sel, *ny;
    size_t w;
    int res = ERR_MEMORY;

    acc = nat_words_alloc(3*nw);
    sum = nat_words_alloc(3*nw);
    sel = nat_words_alloc(2*nw);
    ny = nat_words_alloc(nw);
    if (!acc || !sum || !sel || !ny)
        goto cleanup;

    fe_copy(ws, acc + nw, lambda);

    for (w=0; w<c->windows; w++) {
        const uint64_t *window = c->g_table + w*EC_DIGITS*2*nw;
        uint64_t sign, digit;

        ec_booth_digit(kb, c->k_words, w, &sign, &digit);

        /* Entry d of the window is (d+1)*32^w*G; digit 0 selects nothing */
        ec_table_select(sel, window, EC_DIGITS, 2*nw, digit - 1);

        fe_neg(ws, ny, sel + nw);
        words_select(sel + nw, ct_mask(sign), ny, sel + nw, nw);

        point_add_mixed(ws, c, sum, sum + nw, sum + 2*nw, acc, acc + nw, acc + 2*nw, sel, sel + nw);
        words_select(acc, ct_mask(ct_z(digit)), acc, sum, 3*nw);
    }

    fe_copy(ws, rx, acc);
    fe_copy(ws, ry, acc + nw);
    fe_copy(ws, rz, acc + 2*nw);
    res = 0;

cleanup:
    nat_words_free(acc, 3*nw);
    nat_words_free(sum, 3*nw);
    nat_words_free(sel, 2*nw);
    nat_words_free(ny, nw);
    return res;
}

/*
 * The tables of the generator: for each window i, the affine points
 * j * 32^i * G for j = 1..16. The data is public.
 */
STATIC int build_g_table(EcWs *ws, EcCurve *c)
{
    const size_t nw = c->nw;
    const size_t count = c->windows*EC_DIGITS;
    uint64_t *proj, *base;
    size_t i, j, k;
    int res = ERR_MEMORY;

    c->g_table = nat_words_alloc(2*count*nw);
    proj = nat_words_alloc(3*count*nw);
    base = nat_words_alloc(3*nw);
    if (!c->g_table || !proj || !base)
        goto cleanup;

#define PX(k) (proj + (3*(k) + 0)*nw)
#define PY(k) (proj + (3*(k) + 1)*nw)
#define PZ(k) (proj + (3*(k) + 2)*nw)

    /* base = 32^i * G */
    fe_copy(ws, base, c->gx);
    fe_copy(ws, base + nw, c->gy);
    fe_copy(ws, base + 2*nw, c->field->one);

    for (i=0; i<c->windows; i++) {
        k = i*EC_DIGITS;
        fe_copy(ws, PX(k), base);
        fe_copy(ws, PY(k), base + nw);
        fe_copy(ws, PZ(k), base + 2*nw);
        for (j=1; j<EC_DIGITS; j++)
            point_add(ws, c, PX(k+j), PY(k+j), PZ(k+j), PX(k+j-1), PY(k+j-1), PZ(k+j-1),
                      base, base + nw, base + 2*nw);
        /* 32 * base = 2 * (16 * base) */
        point_double(ws, c, base, base + nw, base + 2*nw, PX(k+15), PY(k+15), PZ(k+15));
    }

#undef PX
#undef PY
#undef PZ

    /* No Z is zero: n is prime, larger than 16 */
    res = ec_batch_to_affine(ws, c->g_table, proj, count, c->p_minus_2);

cleanup:
    nat_words_free(proj, 3*count*nw);
    nat_words_free(base, 3*nw);
    return res;
}

/* ---------------------------------------------------------------- */
/* Curves                                                           */
/* ---------------------------------------------------------------- */

EXPORT_SYM void ec_nat_free_curve(EcCurve *c)
{
    if (NULL == c)
        return;
    mont_ctx_free(c->field);
    nat_free(c->p_minus_2);
    nat_free(c->order);
    nat_words_free(c->b, c->nw);
    nat_words_free(c->gx, c->nw);
    nat_words_free(c->gy, c->nw);
    nat_words_free(c->g_table, 2*c->windows*EC_DIGITS*c->nw);
    free(c);
}

/**
 * Create a curve y^2 = x^3 - 3x + b mod p, with the generator (gx, gy) of
 * prime order n. All numbers are big-endian, len bytes long.
 * It also computes the tables of the generator.
 */
EXPORT_SYM int ec_nat_new_curve(EcCurve **out,
                                const uint8_t *p, const uint8_t *b, const uint8_t *order,
                                const uint8_t *gx, const uint8_t *gy, size_t len)
{
    EcCurve *c;
    Nat *pn = NULL, *two = NULL;
    EcWs ws;
    int ws_ready = 0;
    size_t order_bits;
    int res;

    if (!out || !p || !b || !order || !gx || !gy)
        return ERR_NULL;
    if (len == 0 || len > 8*NAT_MAX_WORDS)
        return ERR_VALUE;

    *out = c = (EcCurve*)calloc(1, sizeof(EcCurve));
    if (NULL == c)
        return ERR_MEMORY;
    c->nw = (len + 7) / 8;
    c->len = len;

    res = ERR_MEMORY;
    pn = nat_alloc(c->nw);
    two = nat_alloc(1);
    c->p_minus_2 = nat_alloc(c->nw);
    c->order = nat_alloc(c->nw);
    c->b = nat_words_alloc(c->nw);
    c->gx = nat_words_alloc(c->nw);
    c->gy = nat_words_alloc(c->nw);
    if (!pn || !two || !c->p_minus_2 || !c->order || !c->b || !c->gx || !c->gy)
        goto cleanup;

    /* The field, and the exponent p - 2 of the inversion */
    res = nat_from_bytes(pn, p, len, 0);
    if (res)
        goto cleanup;
    res = mont_ctx_new(&c->field, pn);
    if (res)
        goto cleanup;
    two->w[0] = 2;
    res = nat_sub(c->p_minus_2, pn, two);
    if (res)
        goto cleanup;
    c->p_bits = (size_t)nat_bit_length(pn);

    /* The order, and the size of the blinded scalars */
    res = nat_from_bytes(c->order, order, len, 0);
    if (res)
        goto cleanup;
    order_bits = (size_t)nat_bit_length(c->order);
    c->k_words = ec_k_words(order_bits);
    c->windows = ec_windows(order_bits);

    res = ec_ws_new(&ws, c->field);
    if (res)
        goto cleanup;
    ws_ready = 1;

    res = fe_from_bytes(c->b, &ws, b, len, 0);
    if (res == 0)
        res = fe_from_bytes(c->gx, &ws, gx, len, 0);
    if (res == 0)
        res = fe_from_bytes(c->gy, &ws, gy, len, 0);
    if (res)
        goto cleanup;

    /* The generator must be on the curve */
    if (!point_on_curve(&ws, c, c->gx, c->gy, c->field->one)) {
        res = ERR_EC_POINT;
        goto cleanup;
    }

    res = build_g_table(&ws, c);

cleanup:
    if (ws_ready)
        ec_ws_free(&ws);
    nat_free(pn);
    nat_free(two);
    if (res) {
        ec_nat_free_curve(c);
        *out = NULL;
    }
    return res;
}

/* ---------------------------------------------------------------- */
/* Points                                                           */
/* ---------------------------------------------------------------- */

STATIC EcPointN *point_alloc(const EcCurve *c)
{
    EcPointN *p;

    p = (EcPointN*)calloc(1, sizeof(EcPointN));
    if (NULL == p)
        return NULL;
    p->curve = c;
    p->nw = c->nw;
    p->x = nat_words_alloc(3*c->nw);
    if (NULL == p->x) {
        free(p);
        return NULL;
    }
    p->y = p->x + c->nw;
    p->z = p->y + c->nw;
    return p;
}

EXPORT_SYM void ec_nat_free_point(EcPointN *p)
{
    if (NULL == p)
        return;
    nat_words_free(p->x, 3*p->nw);
    free(p);
}

/**
 * A new point from its affine coordinates (big-endian, len bytes each,
 * where len is the length of the modulus). (0, 0) is the point at
 * infinity. ERR_EC_POINT if the point is not on the curve, or if a
 * coordinate is not smaller than p.
 */
EXPORT_SYM int ec_nat_new_point(EcPointN **out, const uint8_t *x, const uint8_t *y, size_t len,
                                const EcCurve *c)
{
    EcPointN *p;
    EcWs ws;
    int res;

    if (!out || !x || !y || !c)
        return ERR_NULL;
    if (len == 0)
        return ERR_NOT_ENOUGH_DATA;
    if (len > c->len)
        return ERR_VALUE;

    *out = p = point_alloc(c);
    if (NULL == p)
        return ERR_MEMORY;
    res = ec_ws_new(&ws, c->field);
    if (res) {
        ec_nat_free_point(p);
        *out = NULL;
        return res;
    }

    res = fe_from_bytes(p->x, &ws, x, len, 0);
    if (res == 0)
        res = fe_from_bytes(p->y, &ws, y, len, 0);
    /* A coordinate not smaller than p is not a valid point */
    if (res == ERR_VALUE)
        res = ERR_EC_POINT;
    if (res)
        goto cleanup;
    fe_copy(&ws, p->z, c->field->one);

    /* (0, 0) is the point at infinity: only that fact leaks */
    if (ct_declassify(words_is_zero(p->x, 2*c->nw)))
        point_set_infinity(c, p->x, p->y, p->z);
    else if (!ct_declassify(point_on_curve(&ws, c, p->x, p->y, p->z)))
        res = ERR_EC_POINT;

cleanup:
    ec_ws_free(&ws);
    if (res) {
        ec_nat_free_point(p);
        *out = NULL;
    }
    return res;
}

/**
 * The affine coordinates of a point (big-endian, len bytes each, where
 * len is at least the length of the modulus). The point at infinity
 * is (0, 0).
 */
EXPORT_SYM int ec_nat_get_xy(uint8_t *x, uint8_t *y, size_t len, const EcPointN *p)
{
    const EcCurve *c;
    uint64_t *zinv;
    EcWs ws;
    int res;

    if (!x || !y || !p)
        return ERR_NULL;
    c = p->curve;
    if (len < c->len)
        return ERR_NOT_ENOUGH_DATA;

    res = ec_ws_new(&ws, c->field);
    if (res)
        return res;
    zinv = ws.t[0];

    /* For the point at infinity, 1/Z is 0 (Fermat), and so are X/Z and Y/Z */
    res = fe_inv(&ws, zinv, p->z, c->p_minus_2);
    if (res == 0) {
        fe_mul(&ws, ws.t[1], p->x, zinv);
        fe_mul(&ws, ws.t[2], p->y, zinv);
        res = fe_to_bytes(x, len, &ws, ws.t[1]);
    }
    if (res == 0)
        res = fe_to_bytes(y, len, &ws, ws.t[2]);

    ec_ws_free(&ws);
    return res;
}

EXPORT_SYM int ec_nat_clone(EcPointN **out, const EcPointN *p)
{
    if (!out || !p)
        return ERR_NULL;
    *out = point_alloc(p->curve);
    if (NULL == *out)
        return ERR_MEMORY;
    memcpy((*out)->x, p->x, 3*p->nw*sizeof(uint64_t));
    return 0;
}

EXPORT_SYM int ec_nat_copy(EcPointN *dst, const EcPointN *src)
{
    if (!dst || !src)
        return ERR_NULL;
    if (dst->curve != src->curve)
        return ERR_EC_CURVE;
    memcpy(dst->x, src->x, 3*src->nw*sizeof(uint64_t));
    return 0;
}

/**
 * Return 0 if the two points are equal (X1*Z2 = X2*Z1 and Y1*Z2 = Y2*Z1),
 * ERR_VALUE if they are not. Only that fact leaks.
 */
EXPORT_SYM int ec_nat_cmp(const EcPointN *a, const EcPointN *b)
{
    uint64_t equal;
    EcWs ws;

    if (!a || !b)
        return ERR_NULL;
    if (a->curve != b->curve)
        return ERR_EC_CURVE;
    if (ec_ws_new(&ws, a->curve->field))
        return ERR_MEMORY;

    fe_mul(&ws, ws.t[0], a->x, b->z);
    fe_mul(&ws, ws.t[1], b->x, a->z);
    fe_mul(&ws, ws.t[2], a->y, b->z);
    fe_mul(&ws, ws.t[3], b->y, a->z);
    equal = words_eq(ws.t[0], ws.t[1], ws.nw) & words_eq(ws.t[2], ws.t[3], ws.nw);

    ec_ws_free(&ws);
    return ct_declassify(equal) ? 0 : ERR_VALUE;
}

EXPORT_SYM int ec_nat_neg(EcPointN *p)
{
    EcWs ws;

    if (!p)
        return ERR_NULL;
    if (ec_ws_new(&ws, p->curve->field))
        return ERR_MEMORY;
    fe_neg(&ws, p->y, p->y);
    ec_ws_free(&ws);
    return 0;
}

EXPORT_SYM int ec_nat_double(EcPointN *p)
{
    EcWs ws;

    if (!p)
        return ERR_NULL;
    if (ec_ws_new(&ws, p->curve->field))
        return ERR_MEMORY;
    point_double(&ws, p->curve, p->x, p->y, p->z, p->x, p->y, p->z);
    ec_ws_free(&ws);
    return 0;
}

/** a = a + b **/
EXPORT_SYM int ec_nat_add(EcPointN *a, const EcPointN *b)
{
    EcWs ws;

    if (!a || !b)
        return ERR_NULL;
    if (a->curve != b->curve)
        return ERR_EC_CURVE;
    if (ec_ws_new(&ws, a->curve->field))
        return ERR_MEMORY;
    point_add(&ws, a->curve, a->x, a->y, a->z, a->x, a->y, a->z, b->x, b->y, b->z);
    ec_ws_free(&ws);
    return 0;
}

/**
 * p = k*p, for the big-endian scalar k (len bytes, any length), which can
 * be secret. seed is a random value, for the blinding of the scalar and
 * the randomization of the coordinates.
 *
 * If p is the generator, the precomputed tables are used. The result is
 * checked to be on the curve (ERR_EC_POINT otherwise).
 */
EXPORT_SYM int ec_nat_scalar(EcPointN *p, const uint8_t *k, size_t len, uint64_t seed)
{
    const EcCurve *c;
    uint64_t *kb, *lambda;
    uint64_t state = seed, is_g;
    EcWs ws;
    int res;

    if (!p || !k)
        return ERR_NULL;
    if (len == 0)
        return ERR_NOT_ENOUGH_DATA;
    c = p->curve;

    res = ec_ws_new(&ws, c->field);
    if (res)
        return res;
    kb = nat_words_alloc(c->k_words);
    lambda = nat_words_alloc(c->nw);
    if (!kb || !lambda) {
        res = ERR_MEMORY;
        goto cleanup;
    }

    /* The random values: r for the scalar, lambda for the coordinates */
    res = ec_blind_scalar(kb, c->k_words, c->order, k, len, ec_next_random(&state));
    if (res)
        goto cleanup;
    fe_random(&ws, lambda, c->p_bits, &state);

    /* Is it the generator (with Z = 1)? Only that fact leaks */
    is_g = words_eq(p->x, c->gx, c->nw) & words_eq(p->y, c->gy, c->nw) &
           words_eq(p->z, c->field->one, c->nw);

    if (ct_declassify(is_g))
        res = scalar_mul_g(&ws, c, p->x, p->y, p->z, kb, lambda);
    else
        res = scalar_mul_var(&ws, c, p->x, p->y, p->z, p->x, p->y, p->z, kb, lambda);
    if (res)
        goto cleanup;

    if (!ct_declassify(point_on_curve(&ws, c, p->x, p->y, p->z)))
        res = ERR_EC_POINT;

cleanup:
    nat_words_free(kb, c->k_words);
    nat_words_free(lambda, c->nw);
    ec_ws_free(&ws);
    return res;
}
