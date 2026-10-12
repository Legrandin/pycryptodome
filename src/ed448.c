/*
 * SPDX-FileCopyrightText: 2022-2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The Edwards curve Ed448 (RFC 8032):
 *
 *      x^2 + y^2 = 1 + d x^2 y^2
 *
 * with d = -39081, over the prime field p = 2^448 - 2^224 - 1, on the
 * constant-time arithmetic of the nat library (nat_mod.c).
 *
 * - Field elements: arrays of 7 64-bit words, in plain representation
 *   (the reduction of p = 2^448 - 2^224 - 1: see ec_special.h).
 * - Points: projective coordinates (X:Y:Z), with x = X/Z and y = Y/Z;
 *   the neutral point is (0:1:1). The addition and doubling formulas
 *   of RFC 8032 (5.2.4) are complete, as d is not a square: they have
 *   no special cases.
 * - Scalar multiplications are those of ec_common.c, with the scalars
 *   taken modulo 4n, the order of the whole group (so that the blinding
 *   also works for points with a small-order component).
 *
 * Nothing branches on, or accesses memory at an address that depends on,
 * secret values. Intended leaks go through ct_declassify(). Checked with
 * Valgrind by test/test_ec_nat_ct.c.
 *
 * The context only holds constants (including the precomputed tables of
 * the generator), so it can be used by several threads at the same time:
 * each operation has its own workspace.
 */

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "nat.h"
#include "nat_ct.h"
#include "ec_common.h"
#include "ed448.h"

static const uint8_t ed448_p[56] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t ed448_d[56] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x67, 0x56
};

static const uint8_t ed448_order[56] = {
    0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x7C, 0xCA, 0x23, 0xE9,
    0xC4, 0x4E, 0xDB, 0x49, 0xAE, 0xD6, 0x36, 0x90,
    0x21, 0x6C, 0xC2, 0x72, 0x8D, 0xC5, 0x8F, 0x55,
    0x23, 0x78, 0xC2, 0x92, 0xAB, 0x58, 0x44, 0xF3
};

static const uint8_t ed448_gx[56] = {
    0x4F, 0x19, 0x70, 0xC6, 0x6B, 0xED, 0x0D, 0xED,
    0x22, 0x1D, 0x15, 0xA6, 0x22, 0xBF, 0x36, 0xDA,
    0x9E, 0x14, 0x65, 0x70, 0x47, 0x0F, 0x17, 0x67,
    0xEA, 0x6D, 0xE3, 0x24, 0xA3, 0xD3, 0xA4, 0x64,
    0x12, 0xAE, 0x1A, 0xF7, 0x2A, 0xB6, 0x65, 0x11,
    0x43, 0x3B, 0x80, 0xE1, 0x8B, 0x00, 0x93, 0x8E,
    0x26, 0x26, 0xA8, 0x2B, 0xC7, 0x0C, 0xC0, 0x5E
};

static const uint8_t ed448_gy[56] = {
    0x69, 0x3F, 0x46, 0x71, 0x6E, 0xB6, 0xBC, 0x24,
    0x88, 0x76, 0x20, 0x37, 0x56, 0xC9, 0xC7, 0x62,
    0x4B, 0xEA, 0x73, 0x73, 0x6C, 0xA3, 0x98, 0x40,
    0x87, 0x78, 0x9C, 0x1E, 0x05, 0xA0, 0xC2, 0xD7,
    0x3A, 0xD3, 0xFF, 0x1C, 0xE6, 0x7C, 0x39, 0xC4,
    0xFD, 0xBD, 0x13, 0x2C, 0x4E, 0xD7, 0xC8, 0xAD,
    0x98, 0x08, 0x79, 0x5B, 0xF2, 0x30, 0xFA, 0x14
};

/* ---------------------------------------------------------------- */
/* Points                                                           */
/* ---------------------------------------------------------------- */

#define MUL(o, a, b)    fe_mul(ws, o, a, b)
#define SQR(o, a)       fe_sqr(ws, o, a)
#define ADD(o, a, b)    fe_add(ws, o, a, b)
#define SUB(o, a, b)    fe_sub(ws, o, a, b)

/*
 * (x3:y3:z3) = 2*(x1:y1:z1) (RFC 8032, 5.2.4).
 * The output may be the input.
 */
STATIC void ed448_point_double(EcWs *ws, const EcGroup *g,
                               uint64_t *x3, uint64_t *y3, uint64_t *z3,
                               const uint64_t *x1, const uint64_t *y1, const uint64_t *z1)
{
    uint64_t *b = ws->t[0], *c = ws->t[1], *d = ws->t[2];
    uint64_t *e = ws->t[3], *h = ws->t[4], *j = ws->t[5];

    (void)g;

    ADD(b, x1, y1);
    SQR(b, b);          /* B = (X1+Y1)^2 */
    SQR(c, x1);         /* C = X1^2 */
    SQR(d, y1);         /* D = Y1^2 */
    ADD(e, c, d);       /* E = C+D */
    SQR(h, z1);         /* H = Z1^2 */
    SUB(j, e, h);
    SUB(j, j, h);       /* J = E-2H */
    SUB(x3, b, e);
    MUL(x3, x3, j);     /* X3 = (B-E)*J */
    SUB(y3, c, d);
    MUL(y3, y3, e);     /* Y3 = E*(C-D) */
    MUL(z3, e, j);      /* Z3 = E*J */
}

/*
 * (x3:y3:z3) = (x1:y1:z1) + (x2:y2:z2) (RFC 8032, 5.2.4).
 * If z2 is NULL, the second point is affine (Z2 = 1).
 * The output may be any of the inputs.
 */
STATIC void ed448_point_add(EcWs *ws, const EcGroup *g,
                            uint64_t *x3, uint64_t *y3, uint64_t *z3,
                            const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                            const uint64_t *x2, const uint64_t *y2, const uint64_t *z2)
{
    uint64_t *a = ws->t[0], *b = ws->t[1], *c = ws->t[2], *d = ws->t[3];
    uint64_t *e = ws->t[4], *f = ws->t[5], *gg = ws->t[6], *h = ws->t[7];

    if (z2)
        MUL(a, z1, z2); /* A = Z1*Z2 */
    else
        fe_copy(ws, a, z1);
    SQR(b, a);          /* B = A^2 */
    MUL(c, x1, x2);     /* C = X1*X2 */
    MUL(d, y1, y2);     /* D = Y1*Y2 */
    MUL(e, c, d);
    MUL(e, e, g->param);    /* E = d*C*D */
    SUB(f, b, e);       /* F = B-E */
    ADD(gg, b, e);      /* G = B+E */
    ADD(h, x1, y1);
    ADD(e, x2, y2);
    MUL(h, h, e);       /* H = (X1+Y1)*(X2+Y2) */
    SUB(x3, h, c);
    SUB(x3, x3, d);
    MUL(x3, x3, f);
    MUL(x3, x3, a);     /* X3 = A*F*(H-C-D) */
    SUB(y3, d, c);
    MUL(y3, y3, gg);
    MUL(y3, y3, a);     /* Y3 = A*G*(D-C) */
    MUL(z3, f, gg);     /* Z3 = F*G */
}

/** 1 if (x:y:z) is on the curve: (X^2 + Y^2) Z^2 = Z^4 + d X^2 Y^2 **/
STATIC uint64_t ed448_on_curve(EcWs *ws, const EcGroup *g,
                               const uint64_t *x, const uint64_t *y, const uint64_t *z)
{
    uint64_t *x2 = ws->t[0], *y2 = ws->t[1], *z2 = ws->t[2];
    uint64_t *lhs = ws->t[3], *rhs = ws->t[4];

    SQR(x2, x);
    SQR(y2, y);
    SQR(z2, z);
    ADD(lhs, x2, y2);
    MUL(lhs, lhs, z2);
    MUL(rhs, x2, y2);
    MUL(rhs, rhs, g->param);
    SQR(z2, z2);
    ADD(rhs, rhs, z2);
    return words_eq(lhs, rhs, ED448_WORDS) & (1 ^ words_is_zero(z, ED448_WORDS));
}

#undef MUL
#undef SQR
#undef ADD
#undef SUB

/* The addition with an affine second point (Z2 = 1) */
STATIC void ed448_point_add_affine(EcWs *ws, const EcGroup *g,
                                   uint64_t *x3, uint64_t *y3, uint64_t *z3,
                                   const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                                   const uint64_t *x2, const uint64_t *y2)
{
    ed448_point_add(ws, g, x3, y3, z3, x1, y1, z1, x2, y2, NULL);
}

#define NW ED448_WORDS

/* ---------------------------------------------------------------- */
/* Context                                                          */
/* ---------------------------------------------------------------- */

EXPORT_SYM void ed448_free_context(Ed448Context *ctx)
{
    if (NULL == ctx)
        return;
    ec_group_clear(&ctx->g);
    nat_free(ctx->sqrt_exp);
    free(ctx);
}

/**
 * Create the context of Ed448, including the tables of the generator.
 */
EXPORT_SYM int ed448_new_context(Ed448Context **out)
{
    Ed448Context *ctx;
    EcGroup *g;
    int res;

    if (NULL == out)
        return ERR_NULL;

    *out = ctx = (Ed448Context*)calloc(1, sizeof(Ed448Context));
    if (NULL == ctx)
        return ERR_MEMORY;
    g = &ctx->g;
    g->edwards = 1;
    g->add = ed448_point_add;
    g->add_affine = ed448_point_add_affine;
    g->dbl = ed448_point_double;
    g->on_curve = ed448_on_curve;
    g->mul_public = NULL;

    /* The scalars are taken modulo 4n, the order of the whole group (448 bits) */
    res = ec_group_init(g, ed448_p, ed448_d, ed448_order, 2, ed448_gx, ed448_gy, ED448_BYTES);

    /* (p-3)/4 = (p-2) >> 2, as p = 3 mod 4 */
    if (res == 0) {
        ctx->sqrt_exp = nat_alloc(NW);
        res = ctx->sqrt_exp ? nat_shr(ctx->sqrt_exp, g->field->p_minus_2, 2) : ERR_MEMORY;
    }

    if (res) {
        ed448_free_context(ctx);
        *out = NULL;
    }
    return res;
}

/* ---------------------------------------------------------------- */
/* Points                                                           */
/* ---------------------------------------------------------------- */

EXPORT_SYM void ed448_free_point(PointEd448 *p)
{
    ec_point_free(p);
}

/**
 * A new point from its affine coordinates (big-endian, len bytes each,
 * at most 56). Coordinates not smaller than p are reduced.
 * ERR_EC_POINT if the point is not on the curve.
 */
EXPORT_SYM int ed448_new_point(PointEd448 **out, const uint8_t *x, const uint8_t *y, size_t len,
                               const Ed448Context *ctx)
{
    PointEd448 *p;
    EcWs ws;
    int res;

    if (!out || !x || !y || !ctx)
        return ERR_NULL;
    if (len == 0)
        return ERR_NOT_ENOUGH_DATA;
    if (len > ED448_BYTES)
        return ERR_VALUE;

    *out = p = ec_point_alloc(&ctx->g);
    if (NULL == p)
        return ERR_MEMORY;
    res = ec_ws_new(&ws, ctx->g.field);
    if (res) {
        ec_point_free(p);
        *out = NULL;
        return res;
    }

    /* 2^448 < 2p: one reduction is enough */
    res = fe_from_bytes(p->x, &ws, x, len, 1);
    if (res == 0)
        res = fe_from_bytes(p->y, &ws, y, len, 1);
    if (res)
        goto cleanup;
    fe_copy(&ws, p->z, ctx->g.field->one);

    if (!ct_declassify(ed448_on_curve(&ws, &ctx->g, p->x, p->y, p->z)))
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
 * Decode a point encoded as in RFC 8032 (5.2.3): 57 bytes, the y-coordinate
 * in little-endian order, then a byte with the least significant bit of x
 * in its top bit (the other bits must be zero).
 *
 * Return ERR_EC_POINT if the encoding is not valid: y not smaller than p,
 * no x for that y, or x = 0 with its bit set.
 * The encoding is public: the function is not constant time.
 */
EXPORT_SYM int ed448_decode_point(PointEd448 **out, const uint8_t *encoded, size_t len,
                                  const Ed448Context *ctx)
{
    PointEd448 *p;
    uint8_t yb[ED448_BYTES];
    uint64_t *y, *x, *u = NULL, *v = NULL, *t = NULL, *w = NULL;
    unsigned x_0;
    size_t i;
    EcWs ws;
    int res;

    if (!out || !encoded || !ctx)
        return ERR_NULL;
    if (len != ED448_BYTES + 1)
        return ERR_MODULUS;
    if (encoded[ED448_BYTES] & 0x7F)
        return ERR_EC_POINT;
    x_0 = encoded[ED448_BYTES] >> 7;

    *out = p = ec_point_alloc(&ctx->g);
    if (NULL == p)
        return ERR_MEMORY;
    res = ec_ws_new(&ws, ctx->g.field);
    if (res) {
        ec_point_free(p);
        *out = NULL;
        return res;
    }
    x = p->x;
    y = p->y;

    res = ERR_MEMORY;
    u = nat_words_alloc(NW);
    v = nat_words_alloc(NW);
    t = nat_words_alloc(NW);
    w = nat_words_alloc(NW);
    if (!u || !v || !t || !w)
        goto cleanup;

    /* y must be smaller than p */
    for (i=0; i<ED448_BYTES; i++)
        yb[i] = encoded[ED448_BYTES - 1 - i];
    res = fe_from_bytes(y, &ws, yb, ED448_BYTES, 0);
    if (res) {
        res = ERR_EC_POINT;
        goto cleanup;
    }

    /* u = y^2 - 1, v = d y^2 - 1 */
    fe_sqr(&ws, t, y);
    fe_sub(&ws, u, t, ctx->g.field->one);
    fe_mul(&ws, v, t, ctx->g.param);
    fe_sub(&ws, v, v, ctx->g.field->one);

    /* x = u^3 v (u^5 v^3)^((p-3)/4) */
    fe_sqr(&ws, t, u);          /* u^2 */
    fe_mul(&ws, w, t, u);       /* u^3 */
    fe_mul(&ws, x, w, v);       /* u^3 v */
    fe_mul(&ws, t, w, t);       /* u^5 */
    fe_sqr(&ws, w, v);          /* v^2 */
    fe_mul(&ws, w, w, v);       /* v^3 */
    fe_mul(&ws, t, t, w);       /* u^5 v^3 */
    fe_pow_public(&ws, t, t, ctx->sqrt_exp);
    fe_mul(&ws, x, x, t);

    /* x is a root if v x^2 = u; otherwise there is none */
    fe_sqr(&ws, t, x);
    fe_mul(&ws, t, t, v);
    if (!words_eq(t, u, NW)) {
        res = ERR_EC_POINT;
        goto cleanup;
    }

    /* Select the root with the right parity */
    fe_to_words(&ws, t, x);
    if (words_is_zero(t, NW) && x_0) {
        res = ERR_EC_POINT;
        goto cleanup;
    }
    if ((t[0] & 1) != x_0)
        fe_neg(&ws, x, x);
    fe_copy(&ws, p->z, ctx->g.field->one);
    res = 0;

cleanup:
    nat_words_free(u, NW);
    nat_words_free(v, NW);
    nat_words_free(t, NW);
    nat_words_free(w, NW);
    ec_ws_free(&ws);
    if (res) {
        ec_point_free(p);
        *out = NULL;
    }
    return res;
}

/**
 * The affine coordinates of a point (big-endian, len bytes each, at
 * least 56).
 */
EXPORT_SYM int ed448_get_xy(uint8_t *x, uint8_t *y, size_t len, const PointEd448 *p)
{
    return ec_point_get_xy(x, y, len, p);
}

EXPORT_SYM int ed448_clone(PointEd448 **out, const PointEd448 *p)
{
    return ec_point_clone(out, p);
}

EXPORT_SYM int ed448_copy(PointEd448 *dst, const PointEd448 *src)
{
    return ec_point_copy(dst, src);
}

/** 0 if the two points are equal, ERR_VALUE if they are not (only that fact leaks) **/
EXPORT_SYM int ed448_cmp(const PointEd448 *a, const PointEd448 *b)
{
    return ec_point_cmp(a, b);
}

/** -(x, y) = (-x, y) **/
EXPORT_SYM int ed448_neg(PointEd448 *p)
{
    return ec_point_neg(p);
}

EXPORT_SYM int ed448_double(PointEd448 *p)
{
    return ec_point_double(p);
}

/** a = a + b **/
EXPORT_SYM int ed448_add(PointEd448 *a, const PointEd448 *b)
{
    return ec_point_add(a, b);
}

/** p = k*p, for a scalar k that can be secret (see ec_point_scalar()) **/
EXPORT_SYM int ed448_scalar(PointEd448 *p, const uint8_t *k, size_t len, uint64_t seed)
{
    return ec_point_scalar(p, k, len, seed);
}

/**
 * p = k*p, for a PUBLIC scalar k (see ec_point_scalar_public()), modulo
 * the order of the whole group, also for points with a small-order component
 */
EXPORT_SYM int ed448_scalar_public(PointEd448 *p, const uint8_t *k, size_t len)
{
    return ec_point_scalar_public(p, k, len);
}

#undef NW
