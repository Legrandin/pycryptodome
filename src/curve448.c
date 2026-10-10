/*
 * SPDX-FileCopyrightText: 2024-2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The Montgomery curve Curve448 (X448, RFC 7748):
 *
 *      y^2 = x^3 + A x^2 + x
 *
 * with A = 156326, over the prime field p = 2^448 - 2^224 - 1, on the
 * constant-time arithmetic of the nat library (nat_mod.c).
 *
 * Only the x coordinate is used: a point is (X:Z), with x = X/Z.
 * Outside of a scalar multiplication Z is always 1, or 0 for the point
 * at infinity (1:0).
 *
 * The scalar multiplication is the Montgomery ladder, over all the bits
 * of the scalar (its length is public), with conditional swaps and
 * randomized projective coordinates. The scalar is not blinded: the
 * point may be on the twist of the curve, whose order differs.
 *
 * Nothing branches on, or accesses memory at an address that depends on,
 * secret values. Checked with Valgrind by test/test_ec_nat_ct.c.
 */

#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "nat.h"
#include "nat_ct.h"
#include "ec_common.h"
#include "curve448.h"

#define NW CURVE448_WORDS

static const uint8_t curve448_p[CURVE448_BYTES] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

/*
 * A step of the Montgomery ladder, with x1 the affine x of the
 * difference P3 - P2 (the input point):
 *
 *   (x2:z2) <- 2*(x2:z2)
 *   (x3:z3) <- (x2:z2) + (x3:z3)
 *
 * https://www.hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#ladder-mladd-1987-m
 */
STATIC void curve448_ladder_step(EcWs *ws, const Curve448Context *ctx,
                                 uint64_t *x2, uint64_t *z2, uint64_t *x3, uint64_t *z3,
                                 const uint64_t *x1)
{
    uint64_t *t0 = ws->t[0], *t1 = ws->t[1];

    fe_sub(ws, t0, x3, z3);         /* t0 = D = X3 - Z3         */
    fe_sub(ws, t1, x2, z2);         /* t1 = B = X2 - Z2         */
    fe_add(ws, x2, x2, z2);         /* x2 = A = X2 + Z2         */
    fe_add(ws, z2, x3, z3);         /* z2 = C = X3 + Z3         */
    fe_mul(ws, z3, t0, x2);         /* z3 = DA                  */
    fe_mul(ws, z2, z2, t1);         /* z2 = CB                  */
    fe_add(ws, x3, z3, z2);         /* x3 = DA+CB               */
    fe_sub(ws, z2, z3, z2);         /* z2 = DA-CB               */
    fe_sqr(ws, x3, x3);             /* x3 = X5 = (DA+CB)^2      */
    fe_sqr(ws, z2, z2);             /* z2 = (DA-CB)^2           */
    fe_sqr(ws, t0, t1);             /* t0 = BB = B^2            */
    fe_sqr(ws, t1, x2);             /* t1 = AA = A^2            */
    fe_sub(ws, x2, t1, t0);         /* x2 = E = AA-BB           */
    fe_mul(ws, z3, x1, z2);         /* z3 = Z5 = X1*(DA-CB)^2   */
    fe_mul(ws, z2, ctx->a24, x2);   /* z2 = a24*E               */
    fe_add(ws, z2, t0, z2);         /* z2 = BB+a24*E            */
    fe_mul(ws, z2, x2, z2);         /* z2 = Z4 = E*(BB+a24*E)   */
    fe_mul(ws, x2, t1, t0);         /* x2 = X4 = AA*BB          */
}

/*
 * p = k*p, with the ladder over all the bits of k (len bytes).
 * The initial points (the point at infinity and p) are randomized.
 */
STATIC int curve448_ladder(EcWs *ws, const Curve448Context *ctx, Curve448Point *p,
                           const uint8_t *k, size_t len, uint64_t seed)
{
    uint64_t *x2, *z2, *x3, *z3, *zinv, *x1 = ws->t[2];
    uint64_t state = seed, swap = 0, z_zero;
    size_t i;
    int res = ERR_MEMORY;

    x2 = nat_words_alloc(5*NW);
    if (NULL == x2)
        return ERR_MEMORY;
    z2 = x2 + NW;
    x3 = z2 + NW;
    z3 = x3 + NW;
    zinv = z3 + NW;

    /* (x2:z2) = (lambda:0), (x3:z3) = (mu*x1:mu) */
    fe_copy(ws, x1, p->x);
    fe_random(ws, x2, ctx->p_bits, &state);
    fe_random(ws, z3, ctx->p_bits, &state);
    fe_mul(ws, x3, x1, z3);

    /* From the most significant bit */
    for (i=0; i<8*len; i++) {
        uint64_t bit = (k[i/8] >> (7 - i%8)) & 1;

        swap ^= bit;
        words_cswap(ct_mask(swap), x2, x3, NW);
        words_cswap(ct_mask(swap), z2, z3, NW);
        curve448_ladder_step(ws, ctx, x2, z2, x3, z3, x1);
        swap = bit;
    }
    words_cswap(ct_mask(swap), x2, x3, NW);
    words_cswap(ct_mask(swap), z2, z3, NW);

    /* Normalize: (X/Z:1), or (1:0) for the point at infinity (1/0 is 0) */
    res = fe_inv(ws, zinv, z2, ctx->p_minus_2);
    if (res)
        goto cleanup;
    z_zero = ct_mask(words_is_zero(z2, NW));
    fe_mul(ws, x2, x2, zinv);
    words_select(p->x, z_zero, ctx->field->one, x2, NW);
    words_select(p->z, z_zero, ws->zero, ctx->field->one, NW);

cleanup:
    nat_words_free(x2, 5*NW);
    return res;
}

/* ---------------------------------------------------------------- */
/* Context                                                          */
/* ---------------------------------------------------------------- */

EXPORT_SYM void curve448_free_context(Curve448Context *ctx)
{
    if (NULL == ctx)
        return;
    mont_ctx_free(ctx->field);
    nat_free(ctx->p_minus_2);
    nat_words_free(ctx->a24, NW);
    free(ctx);
}

EXPORT_SYM int curve448_new_context(Curve448Context **out)
{
    Curve448Context *ctx;
    Nat *p = NULL, *two = NULL, *a24 = NULL;
    int res;

    if (NULL == out)
        return ERR_NULL;

    *out = ctx = (Curve448Context*)calloc(1, sizeof(Curve448Context));
    if (NULL == ctx)
        return ERR_MEMORY;

    res = ERR_MEMORY;
    p = nat_alloc(NW);
    two = nat_alloc(1);
    a24 = nat_alloc(NW);
    ctx->p_minus_2 = nat_alloc(NW);
    ctx->a24 = nat_words_alloc(NW);
    if (!p || !two || !a24 || !ctx->p_minus_2 || !ctx->a24)
        goto cleanup;

    res = nat_from_bytes(p, curve448_p, CURVE448_BYTES, 0);
    if (res == 0)
        res = mont_ctx_new(&ctx->field, p);
    two->w[0] = 2;
    if (res == 0)
        res = nat_sub(ctx->p_minus_2, p, two);
    if (res)
        goto cleanup;
    ctx->p_bits = (size_t)nat_bit_length(p);

    /* a24 = (A + 2)/4 */
    a24->w[0] = 39082;
    mont_to(ctx->a24, a24->w, ctx->field);

cleanup:
    nat_free(p);
    nat_free(two);
    nat_free(a24);
    if (res) {
        curve448_free_context(ctx);
        *out = NULL;
    }
    return res;
}

/* ---------------------------------------------------------------- */
/* Points                                                           */
/* ---------------------------------------------------------------- */

STATIC Curve448Point *curve448_point_alloc(const Curve448Context *ctx)
{
    Curve448Point *p;

    p = (Curve448Point*)calloc(1, sizeof(Curve448Point));
    if (NULL == p)
        return NULL;
    p->ctx = ctx;
    p->x = nat_words_alloc(2*NW);
    if (NULL == p->x) {
        free(p);
        return NULL;
    }
    p->z = p->x + NW;
    return p;
}

EXPORT_SYM void curve448_free_point(Curve448Point *p)
{
    if (NULL == p)
        return;
    nat_words_free(p->x, 2*NW);
    free(p);
}

/**
 * A new point from its x coordinate (big-endian, len bytes, at most 56).
 * A coordinate not smaller than p is reduced (RFC 7748).
 * If x is NULL or len is 0, the point is the point at infinity.
 * The point is not checked to be on the curve (it can be on the twist).
 */
EXPORT_SYM int curve448_new_point(Curve448Point **out, const uint8_t *x, size_t len,
                                  const Curve448Context *ctx)
{
    Curve448Point *p;
    EcWs ws;
    int res = 0;

    if (NULL == out || NULL == ctx)
        return ERR_NULL;
    if (len > CURVE448_BYTES)
        return ERR_VALUE;

    *out = p = curve448_point_alloc(ctx);
    if (NULL == p)
        return ERR_MEMORY;

    if (NULL == x || 0 == len) {
        memcpy(p->x, ctx->field->one, NW*sizeof(uint64_t));
        return 0;
    }

    res = ec_ws_new(&ws, ctx->field);
    if (res == 0) {
        /* 2^448 < 2p: one reduction is enough */
        res = fe_from_bytes(p->x, &ws, x, len, 1);
        fe_copy(&ws, p->z, ctx->field->one);
        ec_ws_free(&ws);
    }
    if (res) {
        curve448_free_point(p);
        *out = NULL;
    }
    return res;
}

EXPORT_SYM int curve448_clone(Curve448Point **out, const Curve448Point *p)
{
    if (NULL == out || NULL == p)
        return ERR_NULL;
    *out = curve448_point_alloc(p->ctx);
    if (NULL == *out)
        return ERR_MEMORY;
    memcpy((*out)->x, p->x, 2*NW*sizeof(uint64_t));
    return 0;
}

/**
 * The x coordinate (big-endian, 56 bytes).
 * ERR_EC_PAI for the point at infinity (only that fact leaks).
 */
EXPORT_SYM int curve448_get_x(uint8_t *x, size_t len, const Curve448Point *p)
{
    EcWs ws;
    int res;

    if (NULL == x || NULL == p)
        return ERR_NULL;
    if (len != CURVE448_BYTES)
        return ERR_MODULUS;
    if (ct_declassify(words_is_zero(p->z, NW)))
        return ERR_EC_PAI;

    res = ec_ws_new(&ws, p->ctx->field);
    if (res)
        return res;
    /* Z is 1 */
    res = fe_to_bytes(x, len, &ws, p->x);
    ec_ws_free(&ws);
    return res;
}

/**
 * p = k*p, for the big-endian scalar k (len bytes, which is public), which
 * can be secret. seed is a random value, for the randomization of the
 * coordinates.
 */
EXPORT_SYM int curve448_scalar(Curve448Point *p, const uint8_t *k, size_t len, uint64_t seed)
{
    EcWs ws;
    int res;

    if (NULL == p || NULL == k)
        return ERR_NULL;

    /* The point at infinity stays there (the input point is public) */
    if (ct_declassify(words_is_zero(p->z, NW)))
        return 0;

    res = ec_ws_new(&ws, p->ctx->field);
    if (res)
        return res;
    res = curve448_ladder(&ws, p->ctx, p, k, len, seed);
    ec_ws_free(&ws);
    return res;
}

/**
 * Return 0 if the two points are equal (X1*Z2 = X2*Z1),
 * ERR_VALUE if they are not. Only that fact leaks.
 */
EXPORT_SYM int curve448_cmp(const Curve448Point *a, const Curve448Point *b)
{
    uint64_t equal;
    EcWs ws;

    if (NULL == a || NULL == b)
        return ERR_NULL;
    if (a->ctx != b->ctx)
        return ERR_EC_CURVE;
    if (ec_ws_new(&ws, a->ctx->field))
        return ERR_MEMORY;

    fe_mul(&ws, ws.t[0], a->x, b->z);
    fe_mul(&ws, ws.t[1], b->x, a->z);
    equal = words_eq(ws.t[0], ws.t[1], NW);

    ec_ws_free(&ws);
    return ct_declassify(equal) ? 0 : ERR_VALUE;
}

#undef NW
