/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Short Weierstrass curves y^2 = x^3 - 3x + b over a prime field p
 * (the NIST curves P-192, P-224, P-256, P-384 and P-521), on the
 * constant-time arithmetic of the nat library (nat_mod.c).
 *
 * - Field elements: arrays of nw 64-bit words, in Montgomery form,
 *   except for P-521 (plain, with the reduction of 2^521 - 1: see
 *   ec_special.h).
 * - Points: projective coordinates (X:Y:Z); the point at infinity is
 *   (0:1:0). Additions and doublings use the complete formulas of Renes,
 *   Costello and Batina, "Complete addition formulas for prime order
 *   elliptic curves" (2016), for a = -3: they have no special cases.
 * - Scalar multiplications are those of ec_common.c (blinded scalar,
 *   signed windows, full table scans, randomized coordinates).
 * - For a PUBLIC scalar (ec_nat_scalar_public(), as in the verification
 *   of a signature) and a variable base, scalar_mul_var_public() uses
 *   Jacobian coordinates, with faster but incomplete formulas and
 *   branches (about 10-25% faster). Nothing there is constant time.
 *
 * Apart from the public scalars, nothing branches on, or accesses memory
 * at an address that depends on, secret values (the scalar, the points
 * derived from it). Intended leaks
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
STATIC void point_double(EcWs *ws, const EcGroup *g,
                         uint64_t *x3, uint64_t *y3, uint64_t *z3,
                         const uint64_t *x1, const uint64_t *y1, const uint64_t *z1)
{
    uint64_t *t0 = ws->t[0], *t1 = ws->t[1], *t2 = ws->t[2], *t3 = ws->t[3];
    uint64_t *x = ws->t[4], *y = ws->t[5], *z = ws->t[6];
    const uint64_t *b = g->param;

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
STATIC void point_add(EcWs *ws, const EcGroup *g,
                      uint64_t *x3, uint64_t *y3, uint64_t *z3,
                      const uint64_t *x1i, const uint64_t *y1i, const uint64_t *z1i,
                      const uint64_t *x2i, const uint64_t *y2i, const uint64_t *z2i)
{
    uint64_t *t0 = ws->t[0], *t1 = ws->t[1], *t2 = ws->t[2], *t3 = ws->t[3], *t4 = ws->t[4];
    uint64_t *x1 = ws->t[5], *y1 = ws->t[6], *z1 = ws->t[7];
    uint64_t *x2 = ws->t[8], *y2 = ws->t[9], *z2 = ws->t[10];
    const uint64_t *b = g->param;

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
STATIC void point_add_mixed(EcWs *ws, const EcGroup *g,
                            uint64_t *x3, uint64_t *y3, uint64_t *z3,
                            const uint64_t *x1i, const uint64_t *y1i, const uint64_t *z1i,
                            const uint64_t *x2, const uint64_t *y2)
{
    uint64_t *t0 = ws->t[0], *t1 = ws->t[1], *t2 = ws->t[2], *t3 = ws->t[3], *t4 = ws->t[4];
    uint64_t *x1 = ws->t[5], *y1 = ws->t[6], *z1 = ws->t[7];
    const uint64_t *b = g->param;

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

/**
 * 1 if (x:y:z) is on the curve: Y^2*Z = X^3 - 3*X*Z^2 + b*Z^3
 * (also true for the point at infinity), 0 otherwise.
 */
STATIC uint64_t point_on_curve(EcWs *ws, const EcGroup *g, const uint64_t *x, const uint64_t *y, const uint64_t *z)
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
    fe_mul(ws, t, t, g->param);
    fe_add(ws, rhs, rhs, t);

    return words_eq(lhs, rhs, g->nw);
}

/* ---------------------------------------------------------------- */
/* Public scalars only: Jacobian coordinates, NOT constant time     */
/* ---------------------------------------------------------------- */

/*
 * A point (X, Y, Z) in Jacobian coordinates is x = X/Z^2, y = Y/Z^3;
 * Z = 0 is the point at infinity. The formulas are faster than the
 * complete ones, but they have special cases (the point at infinity,
 * equal points), which are dealt with by branches: only for public data.
 */

#define MUL(o, a, b)    fe_mul(ws, o, a, b)
#define SQR(o, a)       fe_sqr(ws, o, a)
#define ADD(o, a, b)    fe_add(ws, o, a, b)
#define SUB(o, a, b)    fe_sub(ws, o, a, b)

/* 3M + 5S, for a = -3 (dbl-2001-b in the Explicit-Formulas Database). In place. */
static void jac_double(EcWs *ws, uint64_t *t, uint64_t *x, uint64_t *y, uint64_t *z)
{
    const size_t nw = ws->nw;
    uint64_t *delta = t, *gamma = t + nw, *beta = t + 2*nw, *alpha = t + 3*nw, *u = t + 4*nw;

    SQR(delta, z);
    SQR(gamma, y);
    MUL(beta, x, gamma);
    SUB(u, x, delta);           /* alpha = 3 (X - delta) (X + delta) */
    ADD(alpha, x, delta);
    MUL(alpha, alpha, u);
    ADD(u, alpha, alpha);
    ADD(alpha, alpha, u);
    ADD(z, y, z);               /* Z3 = (Y + Z)^2 - gamma - delta */
    SQR(z, z);
    SUB(z, z, gamma);
    SUB(z, z, delta);
    ADD(beta, beta, beta);      /* beta = 4 beta */
    ADD(beta, beta, beta);
    SQR(x, alpha);              /* X3 = alpha^2 - 2 (4 beta) */
    SUB(x, x, beta);
    SUB(x, x, beta);
    SUB(beta, beta, x);         /* Y3 = alpha (4 beta - X3) - 8 gamma^2 */
    MUL(y, alpha, beta);
    SQR(gamma, gamma);
    ADD(gamma, gamma, gamma);
    ADD(gamma, gamma, gamma);
    ADD(gamma, gamma, gamma);
    SUB(y, y, gamma);
}

static int fe_is_zero(EcWs *ws, const uint64_t *a)
{
    return (int)words_is_zero(a, ws->nw);
}

/*
 * (x1, y1, z1) += (x2, y2, z2): 11M + 5S (add-2007-bl), plus the special
 * cases. In place.
 */
static void jac_add(EcWs *ws, uint64_t *t, uint64_t *x1, uint64_t *y1, uint64_t *z1,
                    const uint64_t *x2, const uint64_t *y2, const uint64_t *z2)
{
    const size_t nw = ws->nw;
    uint64_t *z1z1 = t, *z2z2 = t + nw, *u1 = t + 2*nw, *u2 = t + 3*nw, *s1 = t + 4*nw, *s2 = t + 5*nw;
    uint64_t *h = t + 6*nw, *i = t + 7*nw, *j = t + 8*nw, *r = t + 9*nw;

    if (fe_is_zero(ws, z2))
        return;
    if (fe_is_zero(ws, z1)) {
        fe_copy(ws, x1, x2);
        fe_copy(ws, y1, y2);
        fe_copy(ws, z1, z2);
        return;
    }

    SQR(z1z1, z1);
    SQR(z2z2, z2);
    MUL(u1, x1, z2z2);
    MUL(u2, x2, z1z1);
    MUL(s1, y1, z2);
    MUL(s1, s1, z2z2);
    MUL(s2, y2, z1);
    MUL(s2, s2, z1z1);
    SUB(h, u2, u1);
    SUB(r, s2, s1);

    if (fe_is_zero(ws, h)) {
        if (fe_is_zero(ws, r)) {
            jac_double(ws, t + 10*nw, x1, y1, z1);
        } else {
            memset(z1, 0, nw*sizeof(uint64_t));     /* P + (-P) */
        }
        return;
    }

    ADD(r, r, r);
    ADD(i, h, h);               /* I = (2H)^2 */
    SQR(i, i);
    MUL(j, h, i);               /* J = H I */
    MUL(u1, u1, i);             /* V = U1 I */
    ADD(z1, z1, z2);            /* Z3 = ((Z1 + Z2)^2 - Z1Z1 - Z2Z2) H */
    SQR(z1, z1);
    SUB(z1, z1, z1z1);
    SUB(z1, z1, z2z2);
    MUL(z1, z1, h);
    SQR(x1, r);                 /* X3 = r^2 - J - 2V */
    SUB(x1, x1, j);
    SUB(x1, x1, u1);
    SUB(x1, x1, u1);
    SUB(u1, u1, x1);            /* Y3 = r (V - X3) - 2 S1 J */
    MUL(y1, r, u1);
    MUL(s1, s1, j);
    ADD(s1, s1, s1);
    SUB(y1, y1, s1);
}

#undef MUL
#undef SQR
#undef ADD
#undef SUB

/*
 * (x:y:z) = k * (x:y:z), for a PUBLIC scalar kb (k_words words) over its
 * lowest windows, in Jacobian coordinates: the same signed windows as
 * ec_mul_var(), but with branches, and the faster formulas.
 * Input and output in projective coordinates.
 */
STATIC int scalar_mul_var_public(EcWs *ws, const EcGroup *g, uint64_t *x, uint64_t *y, uint64_t *z,
                                 const uint64_t *kb, size_t windows)
{
    const size_t nw = g->nw;
    uint64_t *table, *acc, *t, *ny;
    size_t i, w;
    int res = ERR_MEMORY;

    table = nat_words_alloc(3*EC_DIGITS*nw);
    acc = nat_words_alloc(3*nw);
    t = nat_words_alloc(15*nw);
    ny = nat_words_alloc(nw);
    if (!table || !acc || !t || !ny)
        goto cleanup;

    if (words_is_zero(z, nw)) {
        ec_point_set_neutral(g, x, y, z);
        res = 0;
        goto cleanup;
    }

#define TX(j) (table + (3*((j)-1) + 0)*nw)
#define TY(j) (table + (3*((j)-1) + 1)*nw)
#define TZ(j) (table + (3*((j)-1) + 2)*nw)

    /* T[1] = P = (X Z, Y Z^2, Z), T[j] = T[j-1] + P */
    fe_mul(ws, TX(1), x, z);
    fe_sqr(ws, TY(1), z);
    fe_mul(ws, TY(1), TY(1), y);
    fe_copy(ws, TZ(1), z);
    for (i=2; i<=EC_DIGITS; i++) {
        memcpy(TX(i), TX(i-1), 3*nw*sizeof(uint64_t));
        jac_add(ws, t, TX(i), TY(i), TZ(i), TX(1), TY(1), TZ(1));
    }

    memset(acc, 0, 3*nw*sizeof(uint64_t));
    fe_copy(ws, acc, g->field->one);
    fe_copy(ws, acc + nw, g->field->one);

    for (w=windows; w-- > 0;) {
        uint64_t sign, digit;

        if (!words_is_zero(acc + 2*nw, nw)) {
            for (i=0; i<EC_WINDOW; i++)
                jac_double(ws, t, acc, acc + nw, acc + 2*nw);
        }

        ec_booth_digit(kb, g->k_words, w, &sign, &digit);
        if (digit == 0)
            continue;
        if (sign) {
            fe_neg(ws, ny, TY(digit));
            jac_add(ws, t, acc, acc + nw, acc + 2*nw, TX(digit), ny, TZ(digit));
        } else {
            jac_add(ws, t, acc, acc + nw, acc + 2*nw, TX(digit), TY(digit), TZ(digit));
        }
    }

#undef TX
#undef TY
#undef TZ

    /* Back to projective coordinates: (X Z : Y : Z^3) */
    if (words_is_zero(acc + 2*nw, nw)) {
        ec_point_set_neutral(g, x, y, z);
    } else {
        fe_mul(ws, x, acc, acc + 2*nw);
        fe_copy(ws, y, acc + nw);
        fe_sqr(ws, t, acc + 2*nw);
        fe_mul(ws, z, t, acc + 2*nw);
    }
    res = 0;

cleanup:
    nat_words_free(table, 3*EC_DIGITS*nw);
    nat_words_free(acc, 3*nw);
    nat_words_free(t, 15*nw);
    nat_words_free(ny, nw);
    return res;
}

/* ---------------------------------------------------------------- */
/* Curves                                                           */
/* ---------------------------------------------------------------- */

EXPORT_SYM void ec_nat_free_curve(EcCurve *c)
{
    if (NULL == c)
        return;
    ec_group_clear(c);
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
    int res;

    if (!out || !p || !b || !order || !gx || !gy)
        return ERR_NULL;

    *out = c = (EcCurve*)calloc(1, sizeof(EcCurve));
    if (NULL == c)
        return ERR_MEMORY;
    c->edwards = 0;
    c->add = point_add;
    c->add_affine = point_add_mixed;
    c->dbl = point_double;
    c->on_curve = point_on_curve;
    c->mul_public = scalar_mul_var_public;

    res = ec_group_init(c, p, b, order, 0, gx, gy, len);
    if (res) {
        ec_nat_free_curve(c);
        *out = NULL;
    }
    return res;
}

/* ---------------------------------------------------------------- */
/* Points                                                           */
/* ---------------------------------------------------------------- */

EXPORT_SYM void ec_nat_free_point(EcPointN *p)
{
    ec_point_free(p);
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

    *out = p = ec_point_alloc(c);
    if (NULL == p)
        return ERR_MEMORY;
    res = ec_ws_new(&ws, c->field);
    if (res) {
        ec_point_free(p);
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
        ec_point_set_neutral(c, p->x, p->y, p->z);
    else if (!ct_declassify(point_on_curve(&ws, c, p->x, p->y, p->z)))
        res = ERR_EC_POINT;

cleanup:
    ec_ws_free(&ws);
    if (res) {
        ec_point_free(p);
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
    return ec_point_get_xy(x, y, len, p);
}

EXPORT_SYM int ec_nat_clone(EcPointN **out, const EcPointN *p)
{
    return ec_point_clone(out, p);
}

/** 0 if the two points are equal, ERR_VALUE if they are not (only that fact leaks) **/
EXPORT_SYM int ec_nat_cmp(const EcPointN *a, const EcPointN *b)
{
    return ec_point_cmp(a, b);
}

EXPORT_SYM int ec_nat_neg(EcPointN *p)
{
    return ec_point_neg(p);
}

EXPORT_SYM int ec_nat_double(EcPointN *p)
{
    return ec_point_double(p);
}

/** a = a + b **/
EXPORT_SYM int ec_nat_add(EcPointN *a, const EcPointN *b)
{
    return ec_point_add(a, b);
}

/** p = k*p, for a scalar k that can be secret (see ec_point_scalar()) **/
EXPORT_SYM int ec_nat_scalar(EcPointN *p, const uint8_t *k, size_t len, uint64_t seed)
{
    return ec_point_scalar(p, k, len, seed);
}

/** p = k*p, for a PUBLIC scalar k (see ec_point_scalar_public()) **/
EXPORT_SYM int ec_nat_scalar_public(EcPointN *p, const uint8_t *k, size_t len)
{
    return ec_point_scalar_public(p, k, len);
}
