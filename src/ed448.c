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
 * - Field elements: arrays of 7 64-bit words, in Montgomery form.
 * - Points: projective coordinates (X:Y:Z), with x = X/Z and y = Y/Z;
 *   the neutral point is (0:1:1). The addition and doubling formulas
 *   of RFC 8032 (5.2.4) are complete, as d is not a square: they have
 *   no special cases.
 * - Scalar multiplications use signed windows of 5 bits (Booth
 *   recoding), always over all the windows of a blinded scalar
 *   k + r*4n (r of 64 random bits; 4n is the order of the whole group,
 *   so that the blinding also works for points with a small-order
 *   component), with tables that are scanned in full for each digit.
 *   The coordinates are randomized.
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
STATIC void ed448_point_double(EcWs *ws,
                               uint64_t *x3, uint64_t *y3, uint64_t *z3,
                               const uint64_t *x1, const uint64_t *y1, const uint64_t *z1)
{
    uint64_t *b = ws->t[0], *c = ws->t[1], *d = ws->t[2];
    uint64_t *e = ws->t[3], *h = ws->t[4], *j = ws->t[5];

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
STATIC void ed448_point_add(EcWs *ws, const Ed448Context *ctx,
                            uint64_t *x3, uint64_t *y3, uint64_t *z3,
                            const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                            const uint64_t *x2, const uint64_t *y2, const uint64_t *z2)
{
    uint64_t *a = ws->t[0], *b = ws->t[1], *c = ws->t[2], *d = ws->t[3];
    uint64_t *e = ws->t[4], *f = ws->t[5], *g = ws->t[6], *h = ws->t[7];

    if (z2)
        MUL(a, z1, z2); /* A = Z1*Z2 */
    else
        fe_copy(ws, a, z1);
    SQR(b, a);          /* B = A^2 */
    MUL(c, x1, x2);     /* C = X1*X2 */
    MUL(d, y1, y2);     /* D = Y1*Y2 */
    MUL(e, c, d);
    MUL(e, e, ctx->d);  /* E = d*C*D */
    SUB(f, b, e);       /* F = B-E */
    ADD(g, b, e);       /* G = B+E */
    ADD(h, x1, y1);
    ADD(e, x2, y2);
    MUL(h, h, e);       /* H = (X1+Y1)*(X2+Y2) */
    SUB(x3, h, c);
    SUB(x3, x3, d);
    MUL(x3, x3, f);
    MUL(x3, x3, a);     /* X3 = A*F*(H-C-D) */
    SUB(y3, d, c);
    MUL(y3, y3, g);
    MUL(y3, y3, a);     /* Y3 = A*G*(D-C) */
    MUL(z3, f, g);      /* Z3 = F*G */
}

/** 1 if (x:y:z) is on the curve: (X^2 + Y^2) Z^2 = Z^4 + d X^2 Y^2 **/
STATIC uint64_t ed448_on_curve(EcWs *ws, const Ed448Context *ctx,
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
    MUL(rhs, rhs, ctx->d);
    SQR(z2, z2);
    ADD(rhs, rhs, z2);
    return words_eq(lhs, rhs, ED448_WORDS) & (1 ^ words_is_zero(z, ED448_WORDS));
}

#undef MUL
#undef SQR
#undef ADD
#undef SUB

/* ---------------------------------------------------------------- */
/* Scalar multiplications                                           */
/* ---------------------------------------------------------------- */

#define NW ED448_WORDS

/*
 * p = k*p, for any point (variable base), with the blinded scalar kb.
 *
 * A table of the multiples 0P ... 16P (projective) is built, from a
 * randomized copy of P (coordinates multiplied by lambda); then, for each
 * window from the top: 5 doublings, a full scan of the table for the
 * digit, a conditional negation, and an addition.
 */
STATIC int ed448_mul_var(EcWs *ws, const Ed448Context *ctx, PointEd448 *p,
                         const uint64_t *kb, const uint64_t *lambda)
{
    const size_t entries = EC_DIGITS + 1;
    uint64_t *table, *acc, *sel, *nx;
    size_t i, j, w;
    int res = ERR_MEMORY;

    table = nat_words_alloc(3*entries*NW);
    acc = nat_words_alloc(3*NW);
    sel = nat_words_alloc(3*NW);
    nx = nat_words_alloc(NW);
    if (!table || !acc || !sel || !nx)
        goto cleanup;

#define TX(j) (table + (3*(j) + 0)*NW)
#define TY(j) (table + (3*(j) + 1)*NW)
#define TZ(j) (table + (3*(j) + 2)*NW)

    /* T[0] = (0:1:1), T[1] = P (randomized), T[j] = T[j-1] + P */
    fe_copy(ws, TY(0), ctx->field->one);
    fe_copy(ws, TZ(0), ctx->field->one);
    fe_mul(ws, TX(1), p->x, lambda);
    fe_mul(ws, TY(1), p->y, lambda);
    fe_mul(ws, TZ(1), p->z, lambda);
    for (j=2; j<entries; j++)
        ed448_point_add(ws, ctx, TX(j), TY(j), TZ(j), TX(j-1), TY(j-1), TZ(j-1), TX(1), TY(1), TZ(1));

#undef TX
#undef TY
#undef TZ

    fe_copy(ws, acc + NW, ctx->field->one);
    fe_copy(ws, acc + 2*NW, ctx->field->one);

    for (w=ctx->windows; w-- > 0;) {
        uint64_t sign, digit;

        for (i=0; i<EC_WINDOW; i++)
            ed448_point_double(ws, acc, acc + NW, acc + 2*NW, acc, acc + NW, acc + 2*NW);

        ec_booth_digit(kb, ctx->k_words, w, &sign, &digit);
        ec_table_select(sel, table, entries, 3*NW, digit);

        /* Negative digit: -(x:y:z) = (-x:y:z) */
        fe_neg(ws, nx, sel);
        words_select(sel, ct_mask(sign), nx, sel, NW);

        ed448_point_add(ws, ctx, acc, acc + NW, acc + 2*NW, acc, acc + NW, acc + 2*NW,
                        sel, sel + NW, sel + 2*NW);
    }

    memcpy(p->x, acc, 3*NW*sizeof(uint64_t));
    res = 0;

cleanup:
    nat_words_free(table, 3*entries*NW);
    nat_words_free(acc, 3*NW);
    nat_words_free(sel, 3*NW);
    nat_words_free(nx, NW);
    return res;
}

/*
 * p = k*G, with the precomputed tables (fixed base) and the blinded
 * scalar kb.
 *
 * For each window i: a full scan of its table for the digit, a
 * conditional negation, and a mixed addition. There are no doublings.
 * A zero digit selects the neutral point (0, 1). The accumulator starts as
 * (0:lambda:lambda), the neutral point with randomized coordinates.
 */
STATIC int ed448_mul_g(EcWs *ws, const Ed448Context *ctx, PointEd448 *p,
                       const uint64_t *kb, const uint64_t *lambda)
{
    uint64_t *sel = ws->t[8], *sel_y = ws->t[9], *nx = ws->t[10];
    uint64_t *sel_xy;
    size_t w;

    sel_xy = nat_words_alloc(2*NW);
    if (NULL == sel_xy)
        return ERR_MEMORY;

    memset(p->x, 0, NW*sizeof(uint64_t));
    fe_copy(ws, p->y, lambda);
    fe_copy(ws, p->z, lambda);

    for (w=0; w<ctx->windows; w++) {
        const uint64_t *window = ctx->g_table + w*EC_DIGITS*2*NW;
        uint64_t sign, digit;

        ec_booth_digit(kb, ctx->k_words, w, &sign, &digit);

        /* Entry d of the window is (d+1)*32^w*G; digit 0 selects (0, 1) */
        ec_table_select(sel_xy, window, EC_DIGITS, 2*NW, digit - 1);
        fe_copy(ws, sel, sel_xy);
        words_select(sel_y, ct_mask(ct_z(digit)), ctx->field->one, sel_xy + NW, NW);

        fe_neg(ws, nx, sel);
        words_select(sel, ct_mask(sign), nx, sel, NW);

        ed448_point_add(ws, ctx, p->x, p->y, p->z, p->x, p->y, p->z, sel, sel_y, NULL);
    }

    nat_words_free(sel_xy, 2*NW);
    return 0;
}

/*
 * The tables of the generator: for each window i, the affine points
 * j * 32^i * G for j = 1..16. The data is public.
 */
STATIC int ed448_build_g_table(EcWs *ws, Ed448Context *ctx)
{
    const size_t count = ctx->windows*EC_DIGITS;
    uint64_t *proj, base[3*NW];
    size_t i, j, k;
    int res = ERR_MEMORY;

    ctx->g_table = nat_words_alloc(2*count*NW);
    proj = nat_words_alloc(3*count*NW);
    if (!ctx->g_table || !proj)
        goto cleanup;

#define PX(k) (proj + (3*(k) + 0)*NW)
#define PY(k) (proj + (3*(k) + 1)*NW)
#define PZ(k) (proj + (3*(k) + 2)*NW)

    /* base = 32^i * G */
    fe_copy(ws, base, ctx->gx);
    fe_copy(ws, base + NW, ctx->gy);
    fe_copy(ws, base + 2*NW, ctx->field->one);

    for (i=0; i<ctx->windows; i++) {
        k = i*EC_DIGITS;
        memcpy(PX(k), base, 3*NW*sizeof(uint64_t));
        for (j=1; j<EC_DIGITS; j++)
            ed448_point_add(ws, ctx, PX(k+j), PY(k+j), PZ(k+j), PX(k+j-1), PY(k+j-1), PZ(k+j-1),
                            base, base + NW, base + 2*NW);
        /* 32 * base = 2 * (16 * base) */
        ed448_point_double(ws, base, base + NW, base + 2*NW, PX(k+15), PY(k+15), PZ(k+15));
    }

#undef PX
#undef PY
#undef PZ

    /* Z is never zero (complete formulas) */
    res = ec_batch_to_affine(ws, ctx->g_table, proj, count, ctx->p_minus_2);

cleanup:
    nat_words_free(proj, 3*count*NW);
    return res;
}

/* ---------------------------------------------------------------- */
/* Context                                                          */
/* ---------------------------------------------------------------- */

EXPORT_SYM void ed448_free_context(Ed448Context *ctx)
{
    if (NULL == ctx)
        return;
    mont_ctx_free(ctx->field);
    nat_free(ctx->p_minus_2);
    nat_free(ctx->group_order);
    nat_words_free(ctx->d, NW);
    nat_words_free(ctx->gx, NW);
    nat_words_free(ctx->gy, NW);
    nat_words_free(ctx->g_table, 2*ctx->windows*EC_DIGITS*NW);
    free(ctx);
}

/**
 * Create the context of Ed448, including the tables of the generator.
 */
EXPORT_SYM int ed448_new_context(Ed448Context **out)
{
    Ed448Context *ctx;
    Nat *p = NULL, *n = NULL, *two = NULL;
    EcWs ws;
    int ws_ready = 0;
    int res;

    if (NULL == out)
        return ERR_NULL;

    *out = ctx = (Ed448Context*)calloc(1, sizeof(Ed448Context));
    if (NULL == ctx)
        return ERR_MEMORY;

    res = ERR_MEMORY;
    p = nat_alloc(NW);
    n = nat_alloc(NW);
    two = nat_alloc(1);
    ctx->p_minus_2 = nat_alloc(NW);
    ctx->group_order = nat_alloc(NW);
    ctx->d = nat_words_alloc(NW);
    ctx->gx = nat_words_alloc(NW);
    ctx->gy = nat_words_alloc(NW);
    if (!p || !n || !two || !ctx->p_minus_2 || !ctx->group_order || !ctx->d || !ctx->gx || !ctx->gy)
        goto cleanup;

    res = nat_from_bytes(p, ed448_p, ED448_BYTES, 0);
    if (res == 0)
        res = mont_ctx_new(&ctx->field, p);
    two->w[0] = 2;
    if (res == 0)
        res = nat_sub(ctx->p_minus_2, p, two);
    if (res)
        goto cleanup;
    ctx->p_bits = (size_t)nat_bit_length(p);

    /* The order of the group is 4n (448 bits) */
    res = nat_from_bytes(n, ed448_order, ED448_BYTES, 0);
    if (res == 0)
        res = nat_shl(ctx->group_order, n, 2);
    if (res)
        goto cleanup;
    ctx->k_words = ec_k_words((size_t)nat_bit_length(ctx->group_order));
    ctx->windows = ec_windows((size_t)nat_bit_length(ctx->group_order));

    res = ec_ws_new(&ws, ctx->field);
    if (res)
        goto cleanup;
    ws_ready = 1;

    res = fe_from_bytes(ctx->d, &ws, ed448_d, ED448_BYTES, 0);
    if (res == 0)
        res = fe_from_bytes(ctx->gx, &ws, ed448_gx, ED448_BYTES, 0);
    if (res == 0)
        res = fe_from_bytes(ctx->gy, &ws, ed448_gy, ED448_BYTES, 0);
    if (res == 0)
        res = ed448_build_g_table(&ws, ctx);

cleanup:
    if (ws_ready)
        ec_ws_free(&ws);
    nat_free(p);
    nat_free(n);
    nat_free(two);
    if (res) {
        ed448_free_context(ctx);
        *out = NULL;
    }
    return res;
}

/* ---------------------------------------------------------------- */
/* Points                                                           */
/* ---------------------------------------------------------------- */

STATIC PointEd448 *ed448_point_alloc(const Ed448Context *ctx)
{
    PointEd448 *p;

    p = (PointEd448*)calloc(1, sizeof(PointEd448));
    if (NULL == p)
        return NULL;
    p->ctx = ctx;
    p->x = nat_words_alloc(3*NW);
    if (NULL == p->x) {
        free(p);
        return NULL;
    }
    p->y = p->x + NW;
    p->z = p->y + NW;
    return p;
}

EXPORT_SYM void ed448_free_point(PointEd448 *p)
{
    if (NULL == p)
        return;
    nat_words_free(p->x, 3*NW);
    free(p);
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

    *out = p = ed448_point_alloc(ctx);
    if (NULL == p)
        return ERR_MEMORY;
    res = ec_ws_new(&ws, ctx->field);
    if (res) {
        ed448_free_point(p);
        *out = NULL;
        return res;
    }

    /* 2^448 < 2p: one reduction is enough */
    res = fe_from_bytes(p->x, &ws, x, len, 1);
    if (res == 0)
        res = fe_from_bytes(p->y, &ws, y, len, 1);
    if (res)
        goto cleanup;
    fe_copy(&ws, p->z, ctx->field->one);

    if (!ct_declassify(ed448_on_curve(&ws, ctx, p->x, p->y, p->z)))
        res = ERR_EC_POINT;

cleanup:
    ec_ws_free(&ws);
    if (res) {
        ed448_free_point(p);
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
    EcWs ws;
    int res;

    if (!x || !y || !p)
        return ERR_NULL;
    if (len < ED448_BYTES)
        return ERR_NOT_ENOUGH_DATA;

    res = ec_ws_new(&ws, p->ctx->field);
    if (res)
        return res;
    res = fe_inv(&ws, ws.t[0], p->z, p->ctx->p_minus_2);
    if (res == 0) {
        fe_mul(&ws, ws.t[1], p->x, ws.t[0]);
        fe_mul(&ws, ws.t[2], p->y, ws.t[0]);
        res = fe_to_bytes(x, len, &ws, ws.t[1]);
    }
    if (res == 0)
        res = fe_to_bytes(y, len, &ws, ws.t[2]);
    ec_ws_free(&ws);
    return res;
}

EXPORT_SYM int ed448_clone(PointEd448 **out, const PointEd448 *p)
{
    if (!out || !p)
        return ERR_NULL;
    *out = ed448_point_alloc(p->ctx);
    if (NULL == *out)
        return ERR_MEMORY;
    memcpy((*out)->x, p->x, 3*NW*sizeof(uint64_t));
    return 0;
}

EXPORT_SYM int ed448_copy(PointEd448 *dst, const PointEd448 *src)
{
    if (!dst || !src)
        return ERR_NULL;
    dst->ctx = src->ctx;
    memcpy(dst->x, src->x, 3*NW*sizeof(uint64_t));
    return 0;
}

/**
 * Return 0 if the two points are equal (X1*Z2 = X2*Z1 and Y1*Z2 = Y2*Z1),
 * ERR_VALUE if they are not. Only that fact leaks.
 */
EXPORT_SYM int ed448_cmp(const PointEd448 *a, const PointEd448 *b)
{
    uint64_t equal;
    EcWs ws;

    if (!a || !b)
        return ERR_NULL;
    if (a->ctx != b->ctx)
        return ERR_EC_CURVE;
    if (ec_ws_new(&ws, a->ctx->field))
        return ERR_MEMORY;

    fe_mul(&ws, ws.t[0], a->x, b->z);
    fe_mul(&ws, ws.t[1], b->x, a->z);
    fe_mul(&ws, ws.t[2], a->y, b->z);
    fe_mul(&ws, ws.t[3], b->y, a->z);
    equal = words_eq(ws.t[0], ws.t[1], NW) & words_eq(ws.t[2], ws.t[3], NW);

    ec_ws_free(&ws);
    return ct_declassify(equal) ? 0 : ERR_VALUE;
}

/** -(x, y) = (-x, y) **/
EXPORT_SYM int ed448_neg(PointEd448 *p)
{
    EcWs ws;

    if (!p)
        return ERR_NULL;
    if (ec_ws_new(&ws, p->ctx->field))
        return ERR_MEMORY;
    fe_neg(&ws, p->x, p->x);
    ec_ws_free(&ws);
    return 0;
}

EXPORT_SYM int ed448_double(PointEd448 *p)
{
    EcWs ws;

    if (!p)
        return ERR_NULL;
    if (ec_ws_new(&ws, p->ctx->field))
        return ERR_MEMORY;
    ed448_point_double(&ws, p->x, p->y, p->z, p->x, p->y, p->z);
    ec_ws_free(&ws);
    return 0;
}

/** a = a + b **/
EXPORT_SYM int ed448_add(PointEd448 *a, const PointEd448 *b)
{
    EcWs ws;

    if (!a || !b)
        return ERR_NULL;
    if (a->ctx != b->ctx)
        return ERR_EC_CURVE;
    if (ec_ws_new(&ws, a->ctx->field))
        return ERR_MEMORY;
    ed448_point_add(&ws, a->ctx, a->x, a->y, a->z, a->x, a->y, a->z, b->x, b->y, b->z);
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
EXPORT_SYM int ed448_scalar(PointEd448 *p, const uint8_t *k, size_t len, uint64_t seed)
{
    const Ed448Context *ctx;
    uint64_t *kb, *lambda;
    uint64_t state = seed, is_g;
    EcWs ws;
    int res;

    if (!p || !k)
        return ERR_NULL;
    if (len == 0)
        return ERR_NOT_ENOUGH_DATA;
    ctx = p->ctx;

    res = ec_ws_new(&ws, ctx->field);
    if (res)
        return res;
    kb = nat_words_alloc(ctx->k_words);
    lambda = nat_words_alloc(NW);
    if (NULL == kb || NULL == lambda) {
        res = ERR_MEMORY;
        goto cleanup;
    }

    /* The random values: r for the scalar, lambda for the coordinates */
    res = ec_blind_scalar(kb, ctx->k_words, ctx->group_order, k, len, ec_next_random(&state));
    if (res)
        goto cleanup;
    fe_random(&ws, lambda, ctx->p_bits, &state);

    /* Is it the generator (with Z = 1)? Only that fact leaks */
    is_g = words_eq(p->x, ctx->gx, NW) & words_eq(p->y, ctx->gy, NW) &
           words_eq(p->z, ctx->field->one, NW);

    if (ct_declassify(is_g))
        res = ed448_mul_g(&ws, ctx, p, kb, lambda);
    else
        res = ed448_mul_var(&ws, ctx, p, kb, lambda);
    if (res)
        goto cleanup;

    if (!ct_declassify(ed448_on_curve(&ws, ctx, p->x, p->y, p->z)))
        res = ERR_EC_POINT;

cleanup:
    nat_words_free(kb, ctx->k_words);
    nat_words_free(lambda, NW);
    ec_ws_free(&ws);
    return res;
}

#undef NW
