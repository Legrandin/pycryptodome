/* ===================================================================
 *
 * Copyright (c) 2018, Helder Eijs <helderijs@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
 */

#include <assert.h>

#include "common.h"
#include "endianess.h"
#include "multiply.h"
#include "mont.h"
#include "ec.h"

FAKE_INIT(ec_ws)

#ifdef MAIN
STATIC void print_x(const char *s, const uint64_t *number, const MontContext *ctx)
{
    unsigned i;
    size_t size;
    uint8_t *encoded;
    int res;

    size = mont_bytes(ctx);
    encoded = calloc(1, size);
    res = mont_to_bytes(encoded, size, number, ctx);
    assert(res == 0);

    printf("%s: ", s);
    for (i=0; i<size; i++)
        printf("%02X", encoded[i]);
    printf("\n");

    free(encoded);
}
#endif

STATIC Workplace *new_workplace(const MontContext *ctx)
{
    Workplace *wp;
    int res;

    wp = calloc(1, sizeof(Workplace));
    if (NULL == wp)
        return NULL;

    res = mont_number(&wp->a, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->b, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->c, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->d, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->e, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->f, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->g, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->h, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->i, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->j, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->k, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&wp->scratch, SCRATCHPAD_NR, ctx);
    if (res) goto cleanup;
    return wp;

cleanup:
    free(wp->a);
    free(wp->b);
    free(wp->c);
    free(wp->d);
    free(wp->e);
    free(wp->f);
    free(wp->g);
    free(wp->h);
    free(wp->i);
    free(wp->j);
    free(wp->k);
    free(wp->scratch);
    return NULL;
}

STATIC void free_workplace(Workplace *wp)
{
    if (NULL == wp)
        return;
    free(wp->a);
    free(wp->b);
    free(wp->c);
    free(wp->d);
    free(wp->e);
    free(wp->f);
    free(wp->g);
    free(wp->h);
    free(wp->i);
    free(wp->j);
    free(wp->k);
    free(wp->scratch);
    free(wp);
}

/*
 * Convert projective coordinates of an EC point to affine
 */
STATIC void ec_projective_to_affine(uint64_t *x3, uint64_t *y3,
                                    const uint64_t *x1, uint64_t *y1, uint64_t *z1,
                                    Workplace *tmp,
                                    const MontContext *ctx)
{
    uint64_t *a = tmp->a;
    uint64_t *s = tmp->scratch;

    if (mont_is_zero(z1, ctx)) {
        mont_set(x3, 0, NULL, ctx);
        mont_set(y3, 0, NULL, ctx);
        return;
    }

    mont_inv_prime(a, z1, ctx);
    mont_mult(x3, x1, a, s, ctx);     /* X/Z */
    mont_mult(y3, y1, a, s, ctx);     /* Y/Z */
}

/*
 * Double an EC point on a short Weierstrass curve of equation y²=x³-3x+b.
 *
 * @param x3    Projective X coordinate of the output point, in Montgomery form
 * @param y3    Projective Y coordinate of the output point, in Montgomery form
 * @param z3    Projective Z coordinate of the output point, in Montgomery form
 * @param x1    Projective X coordinate of the input point, in Montgomery form
 * @param y1    Projective Y coordinate of the input point, in Montgomery form
 * @param z1    Projective Z coordinate of the input point, in Montgomery form
 * @param b     Parameter b in the equation, in Montgomery form
 * @param tmp   Workplace for temporary variables
 * @param ctx   The Montgomery context
 *
 * Input and output points can match. The input can be the point-at-infinity.
 */
STATIC void ec_full_double(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                           const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                           const uint64_t *b,
                           Workplace *tmp, const MontContext *ctx)
{
    uint64_t *t0 = tmp->a;
    uint64_t *t1 = tmp->b;
    uint64_t *t2 = tmp->c;
    uint64_t *t3 = tmp->d;
    uint64_t *x  = tmp->e;
    uint64_t *y  = tmp->f;
    uint64_t *z  = tmp->g;
    uint64_t *s = tmp->scratch;

    /*
    * Algorithm 6 in "Complete addition formulas for prime order elliptic curves", Renes et al.
    */

    memcpy(x, x1, ctx->bytes);
    memcpy(y, y1, ctx->bytes);
    memcpy(z, z1, ctx->bytes);

    mont_mult(t0, x, x, s, ctx);    /* 1 */
    mont_mult(t1, y, y, s, ctx);
    mont_mult(t2, z, z, s, ctx);

    mont_mult(t3, x, y, s, ctx);    /* 4 */
    mont_add(t3, t3, t3, s, ctx);
    mont_mult(z3, x, z, s, ctx);

    mont_add(z3, z3, z3, s, ctx);   /* 7 */
    mont_mult(y3, b, t2, s, ctx);
    mont_sub(y3, y3, z3, s, ctx);

    mont_add(x3, y3, y3, s, ctx);   /* 10 */
    mont_add(y3, x3, y3, s, ctx);
    mont_sub(x3, t1, y3, s, ctx);

    mont_add(y3, t1, y3, s, ctx);   /* 13 */
    mont_mult(y3, x3, y3, s, ctx);
    mont_mult(x3, x3, t3, s, ctx);

    mont_add(t3, t2, t2, s, ctx);   /* 16 */
    mont_add(t2, t2, t3, s, ctx);
    mont_mult(z3, b, z3, s, ctx);

    mont_sub(z3, z3, t2, s, ctx);   /* 19 */
    mont_sub(z3, z3, t0, s, ctx);
    mont_add(t3, z3, z3, s, ctx);

    mont_add(z3, z3, t3, s, ctx);   /* 22 */
    mont_add(t3, t0, t0, s, ctx);
    mont_add(t0, t3, t0, s, ctx);

    mont_sub(t0, t0, t2, s, ctx);   /* 25 */
    mont_mult(t0, t0, z3, s, ctx);
    mont_add(y3, y3, t0, s, ctx);

    mont_mult(t0, y, z, s, ctx);    /* 28 */
    mont_add(t0, t0, t0, s, ctx);
    mont_mult(z3, t0, z3, s, ctx);

    mont_sub(x3, x3, z3, s, ctx);   /* 31 */
    mont_mult(z3, t0, t1, s, ctx);
    mont_add(z3, z3, z3, s, ctx);

    mont_add(z3, z3, z3, s, ctx);   /* 34 */
}

/*
 * Add two EC points on a short Weierstrass curve of equation y²=x³-3x+b.
 *
 * @param x3    Projective X coordinate of the output point, in Montgomery form
 * @param y3    Projective Y coordinate of the output point, in Montgomery form
 * @param z3    Projective Z coordinate of the output point, in Montgomery form
 * @param x1    Projective X coordinate of the first input point, in Montgomery form
 * @param y1    Projective Y coordinate of the first input point, in Montgomery form
 * @param z1    Projective Z coordinate of the first input point, in Montgomery form
 * @param x2    Affine X coordinate of the second input point, in Montgomery form
 * @param y2    Affine Y coordinate of the second input point, in Montgomery form
 * @param b     Parameter b in the equation, in Montgomery form
 * @param tmp   Workplace for temporary variables
 * @param ctx   The Montgomery context
 *
 * Input and output points can match. The correct is produced if both or either
 * input points are at infinity.
 *
 * @warning The function is regular (constant-time) only if the second point (affine)
 * is NOT the point-at-infinity.
 */
STATIC void ec_mix_add(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                       const uint64_t *x13, const uint64_t *y13, const uint64_t *z13,
                       const uint64_t *x2, const uint64_t *y2,
                       const uint64_t *b,
                       Workplace *tmp,
                       const MontContext *ctx)
{
    uint64_t *t0 = tmp->a;
    uint64_t *t1 = tmp->b;
    uint64_t *t2 = tmp->c;
    uint64_t *t3 = tmp->d;
    uint64_t *t4 = tmp->e;
    uint64_t *x1 = tmp->f;
    uint64_t *y1 = tmp->g;
    uint64_t *z1 = tmp->h;
    uint64_t *s = tmp->scratch;

    /*
    * Algorithm 5 in "Complete addition formulas for prime order elliptic curves", Renes et al.
    */
    
    if (mont_is_zero(x2, ctx) & mont_is_zero(y2, ctx)) {
        mont_copy(x3, x13, ctx);
        mont_copy(y3, y13, ctx);
        mont_copy(z3, z13, ctx);
        return;
    }

    memcpy(x1, x13, ctx->bytes);
    memcpy(y1, y13, ctx->bytes);
    memcpy(z1, z13, ctx->bytes);

    mont_mult(t0, x1, x2, s, ctx);      /* 1 */
    mont_mult(t1, y1, y2, s, ctx);
    mont_add(t3, x2, y2, s, ctx);

    mont_add(t4, x1, y1, s, ctx);       /* 4 */
    mont_mult(t3, t3, t4, s, ctx);
    mont_add(t4, t0, t1, s, ctx);

    mont_sub(t3, t3, t4, s, ctx);       /* 7 */
    mont_mult(t4, y2, z1, s, ctx);
    mont_add(t4, t4, y1, s, ctx);

    mont_mult(y3, x2, z1, s, ctx);      /* 10 */
    mont_add(y3, y3, x1, s, ctx);
    mont_mult(z3, b, z1, s, ctx);

    mont_sub(x3, y3, z3, s, ctx);       /* 13 */
    mont_add(z3, x3, x3, s, ctx);
    mont_add(x3, x3, z3, s, ctx);

    mont_sub(z3, t1, x3, s, ctx);       /* 16 */
    mont_add(x3, t1, x3, s, ctx);
    mont_mult(y3, b, y3, s, ctx);

    mont_add(t1, z1, z1, s, ctx);       /* 19 */
    mont_add(t2, t1, z1, s, ctx);
    mont_sub(y3, y3, t2, s, ctx);

    mont_sub(y3, y3, t0, s, ctx);       /* 22 */
    mont_add(t1, y3, y3, s, ctx);
    mont_add(y3, t1, y3, s, ctx);

    mont_add(t1, t0, t0, s, ctx);       /* 25 */
    mont_add(t0, t1, t0, s, ctx);
    mont_sub(t0, t0, t2, s, ctx);

    mont_mult(t1, t4, y3, s, ctx);      /* 28 */
    mont_mult(t2, t0, y3, s, ctx);
    mont_mult(y3, x3, z3, s, ctx);

    mont_add(y3, y3, t2, s, ctx);       /* 31 */
    mont_mult(x3, t3, x3, s, ctx);
    mont_sub(x3, x3, t1, s, ctx);

    mont_mult(z3, t4, z3, s, ctx);      /* 34 */
    mont_mult(t1, t3, t0, s, ctx);
    mont_add(z3, z3, t1, s, ctx);
}

/*
 * Add two EC points on a short Weierstrass curve of equation y²=x³-3x+b.
 *
 * @param x3    Projective X coordinate of the output point, in Montgomery form
 * @param y3    Projective Y coordinate of the output point, in Montgomery form
 * @param z3    Projective Z coordinate of the output point, in Montgomery form
 * @param x1    Projective X coordinate of the first input point, in Montgomery form
 * @param y1    Projective Y coordinate of the first input point, in Montgomery form
 * @param z1    Projective Z coordinate of the first input point, in Montgomery form
 * @param x2    Projective X coordinate of the second input point, in Montgomery form
 * @param y2    Projective Y coordinate of the second input point, in Montgomery form
 * @param z2    Projective Z coordinate of the second input point, in Montgomery form
 * @param b     Parameter b in the equation, in Montgomery form
 * @param tmp   Workplace for temporary variables
 * @param ctx   The Montgomery context
 */
STATIC void ec_full_add(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                        const uint64_t *x13, const uint64_t *y13, const uint64_t *z13,
                        const uint64_t *x12, const uint64_t *y12, const uint64_t *z12,
                        const uint64_t *b,
                        Workplace *tmp,
                        const MontContext *ctx)
{
    uint64_t *t0 = tmp->a;
    uint64_t *t1 = tmp->b;
    uint64_t *t2 = tmp->c;
    uint64_t *t3 = tmp->d;
    uint64_t *t4 = tmp->e;
    uint64_t *x1 = tmp->f;
    uint64_t *y1 = tmp->g;
    uint64_t *z1 = tmp->h;
    uint64_t *x2 = tmp->i;
    uint64_t *y2 = tmp->j;
    uint64_t *z2 = tmp->k;
    uint64_t *s = tmp->scratch;

    /*
    * Algorithm 4 in "Complete addition formulas for prime order elliptic curves", Renes et al.
    */

    memcpy(x1, x13, ctx->bytes);
    memcpy(y1, y13, ctx->bytes);
    memcpy(z1, z13, ctx->bytes);

    memcpy(x2, x12, ctx->bytes);
    memcpy(y2, y12, ctx->bytes);
    memcpy(z2, z12, ctx->bytes);

    mont_mult(t0, x1, x2, s, ctx);  /* 1 */
    mont_mult(t1, y1, y2, s, ctx);
    mont_mult(t2, z1, z2, s, ctx);

    mont_add(t3, x1, y1, s, ctx);   /* 4 */
    mont_add(t4, x2, y2, s, ctx);
    mont_mult(t3, t3, t4, s, ctx);

    mont_add(t4, t0, t1, s, ctx);   /* 7 */
    mont_sub(t3, t3, t4, s, ctx);
    mont_add(t4, y1, z1, s, ctx);

    mont_add(x3, y2, z2, s, ctx);   /* 10 */
    mont_mult(t4, t4, x3, s, ctx);
    mont_add(x3, t1, t2, s, ctx);

    mont_sub(t4, t4, x3, s, ctx);   /* 13 */
    mont_add(x3, x1, z1, s, ctx);
    mont_add(y3, x2, z2, s, ctx);

    mont_mult(x3, x3, y3, s, ctx);  /* 16 */
    mont_add(y3, t0, t2, s, ctx);
    mont_sub(y3, x3, y3, s, ctx);

    mont_mult(z3, b, t2, s, ctx);   /* 19 */
    mont_sub(x3, y3, z3, s, ctx);
    mont_add(z3, x3, x3, s, ctx);

    mont_add(x3, x3, z3, s, ctx);   /* 22 */
    mont_sub(z3, t1, x3, s, ctx);
    mont_add(x3, t1, x3, s, ctx);

    mont_mult(y3, b, y3, s, ctx);   /* 25 */
    mont_add(t1, t2, t2, s, ctx);
    mont_add(t2, t1, t2, s, ctx);

    mont_sub(y3, y3, t2, s, ctx);   /* 28 */
    mont_sub(y3, y3, t0, s, ctx);
    mont_add(t1, y3, y3, s, ctx);

    mont_add(y3, t1, y3, s, ctx);   /* 31 */
    mont_add(t1, t0, t0, s, ctx);
    mont_add(t0, t1, t0, s, ctx);

    mont_sub(t0, t0, t2, s, ctx);   /* 34 */
    mont_mult(t1, t4, y3, s, ctx);
    mont_mult(t2, t0, y3, s, ctx);

    mont_mult(y3, x3, z3, s, ctx);  /* 37 */
    mont_add(y3, y3, t2, s, ctx);
    mont_mult(x3, t3, x3, s, ctx);

    mont_sub(x3, x3, t1, s, ctx);   /* 40 */
    mont_mult(z3, t4, z3, s, ctx);
    mont_mult(t1, t3, t0, s, ctx);

    mont_add(z3, z3, t1, s, ctx);   /* 43 */
}

#define WINDOW_SIZE_BITS 4
#define WINDOW_SIZE_ITEMS (1<<WINDOW_SIZE_BITS)

/*
 * Compute the scalar multiplication of an EC point.
 * Projective coordinates as output and input.
 */
STATIC int ec_scalar(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                     const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                     const uint64_t *b,
                     const uint8_t *exp, size_t exp_size,
                     uint64_t seed,
                     Workplace *wp1,
                     Workplace *wp2,
                     const MontContext *ctx)
{
    unsigned z1_is_one;
    unsigned i;
    int res;
    uint64_t *window_x[WINDOW_SIZE_ITEMS],
             *window_y[WINDOW_SIZE_ITEMS],
             *window_z[WINDOW_SIZE_ITEMS];
    uint64_t *xw=NULL, *yw=NULL, *zw=NULL;
    ProtMemory *prot_x=NULL, *prot_y=NULL, *prot_z=NULL;

    struct BitWindow_LR bw;

    z1_is_one = (unsigned)mont_is_one(z1, ctx);
    res = ERR_MEMORY;

    #define alloc(n) n=calloc(ctx->words, 8); if (NULL == n) goto cleanup;

    alloc(xw);
    alloc(yw);
    alloc(zw);

    /** Create window O, P, P² .. P¹⁵ **/
    memset(window_x, 0, sizeof window_x);
    memset(window_y, 0, sizeof window_y);
    memset(window_z, 0, sizeof window_z);

    for (i=0; i<WINDOW_SIZE_ITEMS; i++) {
        alloc(window_x[i]);
        alloc(window_y[i]);
        alloc(window_z[i]);
    }

    #undef alloc

    mont_set(window_x[0], 0, NULL, ctx);
    mont_set(window_y[0], 1, NULL, ctx);
    mont_set(window_z[0], 0, NULL, ctx);

    mont_copy(window_x[1], x1, ctx);
    mont_copy(window_y[1], y1, ctx);
    mont_copy(window_z[1], z1, ctx);

    for (i=2; i<WINDOW_SIZE_ITEMS; i++) {
        if (z1_is_one)
            ec_mix_add(window_x[i],   window_y[i],   window_z[i],
                       window_x[i-1], window_y[i-1], window_z[i-1],
                       x1, y1,
                       b,
                       wp1, ctx);
        else
            ec_full_add(window_x[i],   window_y[i],   window_z[i],
                        window_x[i-1], window_y[i-1], window_z[i-1],
                        x1, y1, z1,
                        b,
                        wp1, ctx);
    }

    res = scatter(&prot_x, (const void**)window_x, WINDOW_SIZE_ITEMS, mont_bytes(ctx), seed);
    if (res) goto cleanup;
    res = scatter(&prot_y, (const void**)window_y, WINDOW_SIZE_ITEMS, mont_bytes(ctx), seed);
    if (res) goto cleanup;
    res = scatter(&prot_z, (const void**)window_z, WINDOW_SIZE_ITEMS, mont_bytes(ctx), seed);
    if (res) goto cleanup;

    /** Start from PAI **/
    mont_set(x3, 0, NULL, ctx);
    mont_set(y3, 1, NULL, ctx);
    mont_set(z3, 0, NULL, ctx);

    /** Find first non-zero byte in exponent **/
    for (; exp_size && *exp==0; exp++, exp_size--);
    bw = init_bit_window_lr(WINDOW_SIZE_BITS, exp, exp_size);

    /** For every nibble, double 16 times and add window value **/
    for (i=0; i < bw.nr_windows; i++) {
        unsigned index;
        int j;

        index = get_next_digit_lr(&bw);
        gather(xw, prot_x, index);
        gather(yw, prot_y, index);
        gather(zw, prot_z, index);
        for (j=0; j<WINDOW_SIZE_BITS; j++)
            ec_full_double(x3, y3, z3, x3, y3, z3, b, wp1, ctx);
        ec_full_add(x3, y3, z3, x3, y3, z3, xw, yw, zw, b, wp1, ctx);
    }

    res = 0;

cleanup:
    free(xw);
    free(yw);
    free(zw);
    for (i=0; i<WINDOW_SIZE_ITEMS; i++) {
        free(window_x[i]);
        free(window_y[i]);
        free(window_z[i]);
    }
    free_scattered(prot_x);
    free_scattered(prot_y);
    free_scattered(prot_z);

    return res;
}

#ifndef MAKE_TABLE
#include "p256_table.c"
#include "p384_table.c"
#include "p521_table.c"

STATIC void free_g_p256(ProtMemory **prot_g)
{
    unsigned i;

    if (prot_g) {
        for (i=0; i<p256_n_tables; i++)
            free_scattered(prot_g[i]);
        free(prot_g);
    }
}

STATIC void free_g_p384(ProtMemory **prot_g)
{
    unsigned i;

    if (prot_g) {
        for (i=0; i<p384_n_tables; i++)
            free_scattered(prot_g[i]);
        free(prot_g);
    }
}

STATIC void free_g_p521(ProtMemory **prot_g)
{
    unsigned i;

    if (prot_g) {
        for (i=0; i<p521_n_tables; i++)
            free_scattered(prot_g[i]);
        free(prot_g);
    }
}

/*
 * Fill the pre-computed table for the generator point in the P-256 EC context.
 */
STATIC ProtMemory** ec_scramble_g_p256(const MontContext *ctx, uint64_t seed)
{
    const void **tables_ptrs;
    ProtMemory **prot_g;
    unsigned i;
    int res;

    tables_ptrs = (const void**)calloc(p256_points_per_table, sizeof(void*));
    if (NULL == tables_ptrs)
        return NULL;

    prot_g = (ProtMemory**)calloc(p256_n_tables, sizeof(ProtMemory*));
    if (NULL == prot_g) {
        free(tables_ptrs);
        return NULL;
    }

    res = 0;
    for (i=0; res==0 && i<p256_n_tables; i++) {
        unsigned j;

        for (j=0; j<p256_points_per_table; j++) {
            tables_ptrs[j] = &p256_tables[i][j];
        }
        res = scatter(&prot_g[i], tables_ptrs, (uint8_t)p256_points_per_table, 2*mont_bytes(ctx), seed);
    }

    if (res) {
        free_g_p256(prot_g);
        prot_g = NULL;
    }

    free(tables_ptrs);
    return prot_g;
}

/*
 * Fill the pre-computed table for the generator point in the P-384 EC context.
 */
STATIC ProtMemory** ec_scramble_g_p384(const MontContext *ctx, uint64_t seed)
{
    const void **tables_ptrs;
    ProtMemory **prot_g;
    unsigned i;
    int res;

    tables_ptrs = (const void**)calloc(p384_points_per_table, sizeof(void*));
    if (NULL == tables_ptrs)
        return NULL;

    prot_g = (ProtMemory**)calloc(p384_n_tables, sizeof(ProtMemory*));
    if (NULL == prot_g) {
        free(tables_ptrs);
        return NULL;
    }

    res = 0;
    for (i=0; res==0 && i<p384_n_tables; i++) {
        unsigned j;

        for (j=0; j<p384_points_per_table; j++) {
            tables_ptrs[j] = &p384_tables[i][j];
        }
        res = scatter(&prot_g[i], tables_ptrs, (uint8_t)p384_points_per_table, 2*mont_bytes(ctx), seed);
    }

    if (res) {
        free_g_p384(prot_g);
        prot_g = NULL;
    }

    free(tables_ptrs);
    return prot_g;
}

/*
 * Fill the pre-computed table for the generator point in the P-521 EC context.
 */
STATIC ProtMemory** ec_scramble_g_p521(const MontContext *ctx, uint64_t seed)
{
    const void **tables_ptrs;
    ProtMemory **prot_g;
    unsigned i;
    int res;

    tables_ptrs = (const void**)calloc(p521_points_per_table, sizeof(void*));
    if (NULL == tables_ptrs)
        return NULL;

    prot_g = (ProtMemory**)calloc(p521_n_tables, sizeof(ProtMemory*));
    if (NULL == prot_g) {
        free(tables_ptrs);
        return NULL;
    }

    res = 0;
    for (i=0; res==0 && i<p521_n_tables; i++) {
        unsigned j;

        for (j=0; j<p521_points_per_table; j++) {
            tables_ptrs[j] = &p521_tables[i][j];
        }
        res = scatter(&prot_g[i], tables_ptrs, (uint8_t)p521_points_per_table, 2*mont_bytes(ctx), seed);
    }

    if (res) {
        free_g_p521(prot_g);
        prot_g = NULL;
    }

    free(tables_ptrs);
    return prot_g;
}

STATIC int ec_scalar_g_p256(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                            const uint64_t *b,
                            const uint8_t *exp, size_t exp_size,
                            uint64_t seed,
                            Workplace *wp1,
                            Workplace *wp2,
                            ProtMemory **prot_g,
                            const MontContext *ctx)
{
    unsigned i;
    struct BitWindow_RL bw;

    /** Start from PAI **/
    mont_set(x3, 0, NULL, ctx);
    mont_set(y3, 1, NULL, ctx);
    mont_set(z3, 0, NULL, ctx);

    /** Find first non-zero byte in exponent **/
    for (; exp_size && *exp==0; exp++, exp_size--);
    bw = init_bit_window_rl(p256_window_size, exp, exp_size);

    if (bw.nr_windows > p256_n_tables)
        return ERR_VALUE;

    for (i=0; i < bw.nr_windows; i++) {
        unsigned index;
        uint64_t buffer[4*2];   /* X and Y affine coordinates **/
        uint64_t *xw, *yw;

        index = get_next_digit_rl(&bw);
        gather(buffer, prot_g[i], index);
        xw = &buffer[0];
        yw = &buffer[4];
        ec_mix_add(x3, y3, z3,
                   x3, y3, z3,
                   xw, yw,
                   b,
                   wp1, ctx);
    }

    return 0;
}

STATIC int ec_scalar_g_p384(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                            const uint64_t *b,
                            const uint8_t *exp, size_t exp_size,
                            uint64_t seed,
                            Workplace *wp1,
                            Workplace *wp2,
                            ProtMemory **prot_g,
                            const MontContext *ctx)
{
    unsigned i;
    struct BitWindow_RL bw;

    /** Start from PAI **/
    mont_set(x3, 0, NULL, ctx);
    mont_set(y3, 1, NULL, ctx);
    mont_set(z3, 0, NULL, ctx);

    /** Find first non-zero byte in exponent **/
    for (; exp_size && *exp==0; exp++, exp_size--);
    bw = init_bit_window_rl(p384_window_size, exp, exp_size);

    if (bw.nr_windows > p384_n_tables)
        return ERR_VALUE;

    for (i=0; i < bw.nr_windows; i++) {
        unsigned index;
        uint64_t buffer[6*2];   /* X and Y affine coordinates **/
        uint64_t *xw, *yw;

        index = get_next_digit_rl(&bw);
        gather(buffer, prot_g[i], index);
        xw = &buffer[0];
        yw = &buffer[6];

        ec_mix_add(x3, y3, z3,
                   x3, y3, z3,
                   xw, yw,
                   b,
                   wp1, ctx);
    }

    return 0;
}

STATIC int ec_scalar_g_p521(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                            const uint64_t *b,
                            const uint8_t *exp, size_t exp_size,
                            uint64_t seed,
                            Workplace *wp1,
                            Workplace *wp2,
                            ProtMemory **prot_g,
                            const MontContext *ctx)
{
    unsigned i;
    struct BitWindow_RL bw;

    /** Start from PAI **/
    mont_set(x3, 0, NULL, ctx);
    mont_set(y3, 1, NULL, ctx);
    mont_set(z3, 0, NULL, ctx);

    /** Find first non-zero byte in exponent **/
    for (; exp_size && *exp==0; exp++, exp_size--);
    bw = init_bit_window_rl(p521_window_size, exp, exp_size);

    if (exp_size == 66) {
        if (exp[0] >> 1) {
            return ERR_VALUE;
        }
        switch (p521_window_size) {
            case 1: bw.nr_windows -= 7; break;
            case 2: bw.nr_windows -= 3; break;
            case 3: bw.nr_windows -= 2; break;
            case 4:
            case 5:
            case 6:
            case 7: bw.nr_windows -= 1; break;
        }
    }

    if (exp_size > 66)
        return ERR_VALUE;

    if (bw.nr_windows > p521_n_tables)
        return ERR_VALUE;

    for (i=0; i < bw.nr_windows; i++) {
        unsigned index;
        uint64_t buffer[9*2];   /* X and Y affine coordinates **/
        uint64_t *xw, *yw;

        index = get_next_digit_rl(&bw);
        gather(buffer, prot_g[i], index);
        xw = &buffer[0];
        yw = &buffer[9];

        ec_mix_add(x3, y3, z3,
                   x3, y3, z3,
                   xw, yw,
                   b,
                   wp1, ctx);
    }

    return 0;
}

#endif

/*
 * Create an Elliptic Curve context for Weierstress curves y²=x³+ax+b with a=-3
 *
 * @param pec_ctx   The memory area where the pointer to the newly allocated
 *                  EC context will be stored.
 * @param modulus   The prime modulus for the curve, big-endian encoded
 * @param b         The constant b, big-endian encoded
 * @param order     The order of the EC curve
 * @param len       The length in bytes of modulus, b, and order
 * @return          0 for success, the appopriate error code otherwise
 */
EXPORT_SYM int ec_ws_new_context(EcContext **pec_ctx,
                                 const uint8_t *modulus,
                                 const uint8_t *b,
                                 const uint8_t *order,
                                 size_t len,
                                 uint64_t seed)
{
    EcContext *ec_ctx = NULL;
    unsigned order_words;
    int res;
    MontContext *ctx;

    if (NULL == pec_ctx || NULL == modulus || NULL == b)
        return ERR_NULL;

    *pec_ctx = NULL;

    if (len == 0)
        return ERR_NOT_ENOUGH_DATA;

    *pec_ctx = ec_ctx = (EcContext*)calloc(1, sizeof(EcContext));
    if (NULL == ec_ctx)
        return ERR_MEMORY;

    res = mont_context_init(&ec_ctx->mont_ctx, modulus, len);
    if (res) goto cleanup;
    ctx = ec_ctx->mont_ctx;

    res = mont_from_bytes(&ec_ctx->b, b, len, ctx);
    if (res) goto cleanup;

    order_words = ((unsigned)len+7)/8;
    ec_ctx->order = (uint64_t*)calloc(order_words, sizeof(uint64_t));
    if (NULL == ec_ctx->order) {
        res = ERR_MEMORY;
        goto cleanup;
    }
    bytes_to_words(ec_ctx->order, order_words, order, len);

#ifndef MAKE_TABLE
    /* Scramble lookup table for special generators */
    switch (ctx->modulus_type) {
        case ModulusP256: {
            ec_ctx->prot_g = ec_scramble_g_p256(ec_ctx->mont_ctx, seed);
            if (NULL == ec_ctx->prot_g) {
                res = ERR_MEMORY;
                goto cleanup;
            }
            break;
        }
        case ModulusP384: {
            ec_ctx->prot_g = ec_scramble_g_p384(ec_ctx->mont_ctx, seed);
            if (NULL == ec_ctx->prot_g) {
                res = ERR_MEMORY;
                goto cleanup;
            }
            break;
        }
        case ModulusP521: {
            ec_ctx->prot_g = ec_scramble_g_p521(ec_ctx->mont_ctx, seed);
            if (NULL == ec_ctx->prot_g) {
                res = ERR_MEMORY;
                goto cleanup;
            }
            break;
        }
        case ModulusGeneric:
            break;
    }
#endif

    return 0;

cleanup:
    free(ec_ctx->b);
    free(ec_ctx->order);
    mont_context_free(ec_ctx->mont_ctx);
    free(ec_ctx);
    return res;
}

EXPORT_SYM void ec_free_context(EcContext *ec_ctx)
{
    if (NULL == ec_ctx)
        return;
#ifndef MAKE_TABLE
    switch (ec_ctx->mont_ctx->modulus_type) {
        case ModulusP256:
            free_g_p256(ec_ctx->prot_g);
            break;
        case ModulusP384:
            free_g_p384(ec_ctx->prot_g);
            break;
        case ModulusP521:
            free_g_p521(ec_ctx->prot_g);
            break;
        case ModulusGeneric:
            break;
    }
#endif
    free(ec_ctx->b);
    free(ec_ctx->order);
    mont_context_free(ec_ctx->mont_ctx);
    free(ec_ctx);
}

/*
 * Create a new EC point on the given EC curve.
 *
 *  @param pecp         The memory area where the pointer to the newly allocated EC
 *                      point will be stored. Use ec_free_point() for deallocating it.
 *  @param x            The X-coordinate (affine, big-endian)
 *  @param y            The Y-coordinate (affine, big-endian)
 *  @param len          The length of x and y in bytes
 *  @param ec_ctx       The EC context
 *  @return             0 for success, the appopriate error code otherwise
 */
EXPORT_SYM int ec_ws_new_point(EcPoint **pecp,
                               const uint8_t *x,
                               const uint8_t *y,
                               size_t len,
                               const EcContext *ec_ctx)
{
    int res;
    Workplace *wp = NULL;
    EcPoint *ecp;
    MontContext *ctx;
    
    if (NULL == pecp || NULL == x || NULL == y || NULL == ec_ctx)
        return ERR_NULL;
    ctx = ec_ctx->mont_ctx;

    if (len == 0)
        return ERR_NOT_ENOUGH_DATA;

    if (len > ctx->bytes)
        return ERR_VALUE;

    *pecp = ecp = (EcPoint*)calloc(1, sizeof(EcPoint));
    if (NULL == ecp)
        return ERR_MEMORY;

    ecp->ec_ctx = ec_ctx;
   
    res = mont_from_bytes(&ecp->x, x, len, ctx);
    if (res) goto cleanup;
    res = mont_from_bytes(&ecp->y, y, len, ctx);
    if (res) goto cleanup;
    res = mont_number(&ecp->z, 1, ctx);
    if (res) goto cleanup;
    mont_set(ecp->z, 1, NULL, ctx);

    /** Convert PAI: (0, 0) to (0, 1, 0) */
    /** Verify the point is on the curve, if not point-at-infinity */
    if (mont_is_zero(ecp->x, ctx) && mont_is_zero(ecp->y, ctx)) {
        mont_set(ecp->x, 0, NULL, ctx);
        mont_set(ecp->y, 1, NULL, ctx);
        mont_set(ecp->z, 0, NULL, ctx);
    } else {
        wp = new_workplace(ctx);
        mont_mult(wp->a, ecp->y, ecp->y, wp->scratch, ctx);
        mont_mult(wp->c, ecp->x, ecp->x, wp->scratch, ctx);
        mont_mult(wp->c, wp->c, ecp->x, wp->scratch, ctx);
        mont_sub(wp->c, wp->c, ecp->x, wp->scratch, ctx);
        mont_sub(wp->c, wp->c, ecp->x, wp->scratch, ctx);
        mont_sub(wp->c, wp->c, ecp->x, wp->scratch, ctx);
        mont_add(wp->c, wp->c, ec_ctx->b, wp->scratch, ctx);
        res = !mont_is_equal(wp->a, wp->c, ctx);
        free_workplace(wp);

        if (res) {
            res = ERR_EC_POINT;
            goto cleanup;
        }
    }
    return 0;

cleanup:
    free(ecp->x);
    free(ecp->y);
    free(ecp->z);
    free(ecp);
    *pecp = NULL;
    return res;
}

EXPORT_SYM void ec_free_point(EcPoint *ecp)
{
    if (NULL == ecp)
        return;

    /* It is not up to us to deallocate the EC context */
    free(ecp->x);
    free(ecp->y);
    free(ecp->z);
    free(ecp);
}

/*
 * Encode the affine coordinates of an EC point.
 *
 * @param x     The location where the affine X-coordinate will be store in big-endian mode
 * @param y     The location where the affine Y-coordinate will be store in big-endian mode
 * @param len   The memory available for x and y in bytes.
 *              It must be as long as the prime modulus of the curve field.
 * @param ecp   The EC point to encode.
 */
EXPORT_SYM int ec_ws_get_xy(uint8_t *x, uint8_t *y, size_t len, const EcPoint *ecp)
{
    uint64_t *xw=NULL, *yw=NULL;
    Workplace *wp;
    MontContext *ctx;
    int res;

    if (NULL == x || NULL == y || NULL == ecp)
        return ERR_NULL;
    ctx = ecp->ec_ctx->mont_ctx;

    if (len < ctx->modulus_len)
        return ERR_NOT_ENOUGH_DATA;

    wp = new_workplace(ctx);
    if (NULL == wp)
        return ERR_MEMORY;

    res = mont_number(&xw, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&yw, 1, ctx);
    if (res) goto cleanup;

    ec_projective_to_affine(xw, yw, ecp->x, ecp->y, ecp->z, wp, ctx);

    res = mont_to_bytes(x, len, xw, ctx);
    if (res) goto cleanup;
    res = mont_to_bytes(y, len, yw, ctx);
    if (res) goto cleanup;

    res = 0;

cleanup:
    free_workplace(wp);
    free(xw);
    free(yw);
    return res;
}

/*
 * Double an EC point
 */
EXPORT_SYM int ec_ws_double(EcPoint *p)
{
    Workplace *wp;
    MontContext *ctx;

    if (NULL == p)
        return ERR_NULL;
    ctx = p->ec_ctx->mont_ctx;

    wp = new_workplace(ctx);
    if (NULL == wp)
        return ERR_MEMORY;

    ec_full_double(p->x, p->y, p->z, p->x, p->y, p->z, p->ec_ctx->b, wp, ctx);

    free_workplace(wp);
    return 0;
}

/*
 * Add an EC point to another
 */
EXPORT_SYM int ec_ws_add(EcPoint *ecpa, EcPoint *ecpb)
{
    Workplace *wp;
    MontContext *ctx;

    if (NULL == ecpa || NULL == ecpb)
        return ERR_NULL;
    if (ecpa->ec_ctx != ecpb->ec_ctx)
        return ERR_EC_CURVE;
    ctx = ecpa->ec_ctx->mont_ctx;

    wp = new_workplace(ctx);
    if (NULL == wp)
        return ERR_MEMORY;

    ec_full_add(ecpa->x, ecpa->y, ecpa->z,
                ecpa->x, ecpa->y, ecpa->z,
                ecpb->x, ecpb->y, ecpb->z,
                ecpa->ec_ctx->b,
                wp, ctx);

    free_workplace(wp);
    return 0;
}

/*
 * Normalize the projective representation of a point
 * so that Z=1 or Z=0.
 */
EXPORT_SYM int ec_ws_normalize(EcPoint *ecp)
{
    MontContext *ctx;
    Workplace *wp = NULL;

    if (NULL == ecp)
        return ERR_NULL;
    ctx = ecp->ec_ctx->mont_ctx;

    wp = new_workplace(ctx);
    if (NULL == wp)
        return ERR_MEMORY;

    if (!mont_is_zero(ecp->z, ctx)) {
        ec_projective_to_affine(ecp->x, ecp->y,
                                ecp->x, ecp->y, ecp->z,
                                wp, ctx);
        mont_set(ecp->z, 1, NULL, ctx);
    }

    free_workplace(wp);
    return 0;
}

EXPORT_SYM int ec_ws_is_pai(EcPoint *ecp)
{
    if (NULL == ecp)
        return FALSE;

    return mont_is_zero(ecp->z, ecp->ec_ctx->mont_ctx);
}

/*
 * Blind the scalar factor to be used in an EC multiplication
 *
 * @param blind_scalar      The area of memory where the pointer to a newly
 *                          allocated blind scalar is stored, in big endian mode.
 *                          The caller must deallocate this memory.
 * @param blind_scalar_len  The area where the length of the blind scalar in bytes will be written to.
 * @param scalar            The (secret) scalar to blind.
 * @param scalar_len        The length of the secret scalar in bytes.
 * @param R_seed            The 32-bit factor to use to blind the scalar.
 * @param order             The order of the EC curve, big-endian mode, 64 bit words
 * @param order_words       The number of words making up the order
 */
static int blind_scalar_factor(uint8_t **blind_scalar,
                        size_t *blind_scalar_len,
                        const uint8_t *scalar,
                        size_t scalar_len,
                        uint32_t R_seed,
                        uint64_t *order,
                        size_t order_words)
{
    size_t scalar_words;
    size_t blind_scalar_words;
    uint64_t *output_u64 = NULL;
    int res = ERR_MEMORY;

    scalar_words = (scalar_len+7)/8;
    blind_scalar_words = MAX(order_words+2, scalar_words+2);
    *blind_scalar_len = blind_scalar_words*sizeof(uint64_t);

    *blind_scalar = (uint8_t*)calloc(*blind_scalar_len, 1);
    if (NULL == *blind_scalar)
        goto cleanup;

    output_u64 = (uint64_t*)calloc(blind_scalar_words, sizeof(uint64_t));
    if (NULL == output_u64)
        goto cleanup;

    bytes_to_words(output_u64, blind_scalar_words, scalar, scalar_len);
    addmul128(output_u64, order, R_seed, 0, order_words);
    words_to_bytes(*blind_scalar, *blind_scalar_len, output_u64, blind_scalar_words);

    res = 0;

cleanup:
    free(output_u64);
    return res;
}

/*
 * Multiply an EC point by a scalar
 *
 * @param ecp   The EC point to multiply
 * @param k     The scalar, encoded in big endian mode
 * @param len   The length of the scalar, in bytes
 * @param seed  The 64-bit to drive the randomizations against SCAs
 * @return      0 in case of success, the appropriate error code otherwise
 */
EXPORT_SYM int ec_ws_scalar(EcPoint *ecp, const uint8_t *k, size_t len, uint64_t seed)
{
    Workplace *wp1=NULL, *wp2=NULL;
    MontContext *ctx;
    int res;

    if (NULL == ecp || NULL == k)
        return ERR_NULL;
    ctx = ecp->ec_ctx->mont_ctx;

    if (len == 0) {
        return ERR_NOT_ENOUGH_DATA;
    }

    wp1 = new_workplace(ctx);
    if (NULL == wp1) {
        res = ERR_MEMORY;
        goto cleanup;
    }

    wp2 = new_workplace(ctx);
    if (NULL == wp2) {
        res = ERR_MEMORY;
        goto cleanup;
    }

#ifndef MAKE_TABLE
    switch (ctx->modulus_type) {
        case ModulusP256: {
            /** Coordinates in Montgomery form **/
            const uint64_t mont_Gx[4] = { 0x79E730D418A9143CU, 0x75BA95FC5FEDB601U, 0x79FB732B77622510U, 0x18905F76A53755C6U };
            const uint64_t mont_Gy[4] = { 0xDDF25357CE95560AU, 0x8B4AB8E4BA19E45CU, 0xD2E88688DD21F325U, 0x8571FF1825885D85U };
            unsigned is_generator;
            unsigned i;

            is_generator = 1;
            for (i=0; i<4; i++) {
                is_generator &= (mont_Gx[i] == ecp->x[i]);
                is_generator &= (mont_Gy[i] == ecp->y[i]);
            }
            is_generator &= (unsigned)mont_is_one(ecp->z, ctx);

            if (is_generator) {
                res = ec_scalar_g_p256(ecp->x, ecp->y, ecp->z,
                                       ecp->ec_ctx->b,
                                       k, len,
                                       seed + 2,
                                       wp1, wp2,
                                       ecp->ec_ctx->prot_g,
                                       ctx);
                goto cleanup;
            }
            break;
        }
        case ModulusP384: {
            /** Coordinates in Montgomery form **/
            const uint64_t mont_Gx[6] = { 0x3DD0756649C0B528, 0x20E378E2A0D6CE38, 0x879C3AFC541B4D6E, 0x6454868459A30EFF, 0x812FF723614EDE2B, 0x4D3AADC2299E1513 };
            const uint64_t mont_Gy[6] = { 0x23043DAD4B03A4FE, 0xA1BFA8BF7BB4A9AC, 0x8BADE7562E83B050, 0xC6C3521968F4FFD9, 0xDD8002263969A840, 0x2B78ABC25A15C5E9 };
            unsigned is_generator;
            unsigned i;

            is_generator = 1;
            for (i=0; i<6; i++) {
                is_generator &= (mont_Gx[i] == ecp->x[i]);
                is_generator &= (mont_Gy[i] == ecp->y[i]);
            }
            is_generator &= (unsigned)mont_is_one(ecp->z, ctx);

            if (is_generator) {
                res = ec_scalar_g_p384(ecp->x, ecp->y, ecp->z,
                                       ecp->ec_ctx->b,
                                       k, len,
                                       seed + 2,
                                       wp1, wp2,
                                       ecp->ec_ctx->prot_g,
                                       ctx);
                goto cleanup;
            }
            break;
        }
        case ModulusP521: {
            /** Coordinates in normal form **/
            const uint64_t mont_Gx[9] = { 0xF97E7E31C2E5BD66, 0x3348B3C1856A429B, 0xFE1DC127A2FFA8DE, 0xA14B5E77EFE75928, 0xF828AF606B4D3DBA, 0x9C648139053FB521, 0x9E3ECB662395B442, 0x858E06B70404E9CD, 0x00000000000000C6 };
            const uint64_t mont_Gy[9] = { 0x88BE94769FD16650, 0x353C7086A272C240, 0xC550B9013FAD0761, 0x97EE72995EF42640, 0x17AFBD17273E662C, 0x98F54449579B4468, 0x5C8A5FB42C7D1BD9, 0x39296A789A3BC004, 0x0000000000000118 };
            unsigned is_generator;
            unsigned i;

            is_generator = 1;
            for (i=0; i<9; i++) {
                is_generator &= (mont_Gx[i] == ecp->x[i]);
                is_generator &= (mont_Gy[i] == ecp->y[i]);
            }
            is_generator &= (unsigned)mont_is_one(ecp->z, ctx);

            if (is_generator) {
                res = ec_scalar_g_p521(ecp->x, ecp->y, ecp->z,
                                       ecp->ec_ctx->b,
                                       k, len,
                                       seed + 2,
                                       wp1, wp2,
                                       ecp->ec_ctx->prot_g,
                                       ctx);
                goto cleanup;
            }
            break;
        }
        case ModulusGeneric:
            break;
    }
#endif

    if (seed != 0) {
        uint8_t *blind_scalar=NULL;
        size_t blind_scalar_len;
        uint64_t *factor=NULL;

        /* Create the blinding factor for the base point */
        res = mont_random_number(&factor, 1, seed, ctx);
        if (res)
            goto cleanup;

        /* Blind the base point */
        mont_mult(ecp->x, ecp->x, factor, wp1->scratch, ctx);
        mont_mult(ecp->y, ecp->y, factor, wp1->scratch, ctx);
        mont_mult(ecp->z, ecp->z, factor, wp1->scratch, ctx);

        free(factor);

        /* Blind the scalar, by adding R*order where R is at least 32 bits */
        res = blind_scalar_factor(&blind_scalar,
                                  &blind_scalar_len,
                                  k, len,
                                  (uint32_t)seed,
                                  ecp->ec_ctx->order,
                                  ctx->words);
        if (res) goto cleanup;
        res = ec_scalar(ecp->x, ecp->y, ecp->z,
                     ecp->x, ecp->y, ecp->z,
                     ecp->ec_ctx->b,
                     blind_scalar, blind_scalar_len,
                     seed + 1,
                     wp1, wp2, ctx);

        free(blind_scalar);
        if (res) goto cleanup;
    } else {
        /* No blinding */
        res = ec_scalar(ecp->x, ecp->y, ecp->z,
                     ecp->x, ecp->y, ecp->z,
                     ecp->ec_ctx->b,
                     k, len,
                     seed + 1,
                     wp1, wp2, ctx);
        if (res) goto cleanup;
    }

    res = 0;

cleanup:
    free_workplace(wp1);
    free_workplace(wp2);
    return res;
}

EXPORT_SYM int ec_ws_clone(EcPoint **pecp2, const EcPoint *ecp)
{
    int res;
    EcPoint *ecp2;
    MontContext *ctx;

    if (NULL == pecp2 || NULL == ecp)
        return ERR_NULL;
    ctx = ecp->ec_ctx->mont_ctx;

    *pecp2 = ecp2 = (EcPoint*)calloc(1, sizeof(EcPoint));
    if (NULL == ecp2)
        return ERR_MEMORY;

    ecp2->ec_ctx = ecp->ec_ctx;

    res = mont_number(&ecp2->x, 1, ctx);
    if (res) goto cleanup;
    mont_copy(ecp2->x, ecp->x, ctx);

    res = mont_number(&ecp2->y, 1, ctx);
    if (res) goto cleanup;
    mont_copy(ecp2->y, ecp->y, ctx);

    res = mont_number(&ecp2->z, 1, ctx);
    if (res) goto cleanup;
    mont_copy(ecp2->z, ecp->z, ctx);

    return 0;

cleanup:
    free(ecp2->x);
    free(ecp2->y);
    free(ecp2->z);
    free(ecp2);
    *pecp2 = NULL;
    return res;
}

EXPORT_SYM int ec_ws_copy(EcPoint *ecp1, const EcPoint *ecp2)
{
    MontContext *ctx;

    if (NULL == ecp1 || NULL == ecp2)
        return ERR_NULL;
    ctx = ecp2->ec_ctx->mont_ctx;

    ecp1->ec_ctx = ecp2->ec_ctx;
    mont_copy(ecp1->x, ecp2->x, ctx);
    mont_copy(ecp1->y, ecp2->y, ctx);
    mont_copy(ecp1->z, ecp2->z, ctx);

    return 0;
}

/*
 * Compare two EC points and return 0 if they match
 */
EXPORT_SYM int ec_ws_cmp(const EcPoint *ecp1, const EcPoint *ecp2)
{
    Workplace *wp;
    MontContext *ctx;
    int p1_is_pai;
    int p2_is_pai;
    int result;

    if (NULL == ecp1 || NULL == ecp2)
        return ERR_NULL;

    if (ecp1->ec_ctx != ecp2->ec_ctx)
        return ERR_EC_CURVE;
    ctx = ecp1->ec_ctx->mont_ctx;

    p1_is_pai = mont_is_zero(ecp1->z, ctx);
    p2_is_pai = mont_is_zero(ecp2->z, ctx);

    /* Check for point-at-infinity */
    if (p1_is_pai | p2_is_pai) {
        return (p1_is_pai & p2_is_pai) ? 0 : ERR_VALUE;
    }

    /** Normalize to have the same Z coordinate */
    wp = new_workplace(ctx);
    if (NULL == wp)
        return ERR_MEMORY;

    mont_mult(wp->b, ecp1->x, ecp2->z, wp->scratch, ctx);   /* B = X1*Z2 */
    mont_mult(wp->d, ecp2->x, ecp1->z, wp->scratch, ctx);   /* D = X2*Z1 */
    mont_mult(wp->e, ecp1->y, ecp2->z, wp->scratch, ctx);   /* E = Y1*Z2 */
    mont_mult(wp->f, ecp2->y, ecp1->z, wp->scratch, ctx);   /* F = Y2*Z1 */
    result = (mont_is_equal(wp->b, wp->d, ctx) & mont_is_equal(wp->e, wp->f, ctx)) ? 0 : ERR_VALUE;

    free_workplace(wp);

    return result;
}

EXPORT_SYM int ec_ws_neg(EcPoint *p)
{
    MontContext *ctx;
    uint64_t *tmp;
    int res;

    if (NULL == p)
        return ERR_NULL;
    ctx = p->ec_ctx->mont_ctx;
    
    res = mont_number(&tmp, SCRATCHPAD_NR, ctx);
    if (res)
        return res;

    mont_sub(p->y, ctx->modulus, p->y, tmp, ctx);
    free(tmp);
    return 0;
}

