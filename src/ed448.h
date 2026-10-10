/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The Edwards curve Ed448 (RFC 8032), on the constant-time arithmetic of
 * the nat library. See ed448.c.
 */

#ifndef ED448_H
#define ED448_H

#include "common.h"
#include "nat.h"
#include "ec_common.h"

/* 64-bit words of a field element, and bytes of an encoded coordinate */
#define ED448_WORDS 7
#define ED448_BYTES 56

typedef struct {
    MontCtx *field;         /* Montgomery arithmetic modulo p (constants only) */
    Nat *p_minus_2;         /* the exponent of the inversion (Fermat) */
    size_t p_bits;
    uint64_t *d;            /* d, in Montgomery form */
    uint64_t *gx, *gy;      /* the generator G (affine, Montgomery form) */
    Nat *group_order;       /* 4*n: the order of the whole group (cofactor 4) */
    size_t k_words;         /* 64-bit words of a blinded scalar */
    size_t windows;         /* windows of a blinded scalar */
    uint64_t *g_table;      /* windows*EC_DIGITS affine points, x then y:
                               entry j of window i is (j+1) * 32^i * G */
} Ed448Context;

/*
 * A point in projective coordinates (X:Y:Z), in Montgomery form.
 * It can be freed after its context.
 */
typedef struct {
    const Ed448Context *ctx;
    uint64_t *x, *y, *z;
} PointEd448;

EXPORT_SYM int ed448_new_context(Ed448Context **out);
EXPORT_SYM void ed448_free_context(Ed448Context *ctx);
EXPORT_SYM int ed448_new_point(PointEd448 **out, const uint8_t *x, const uint8_t *y, size_t len,
                               const Ed448Context *ctx);
EXPORT_SYM void ed448_free_point(PointEd448 *p);
EXPORT_SYM int ed448_clone(PointEd448 **out, const PointEd448 *p);
EXPORT_SYM int ed448_copy(PointEd448 *dst, const PointEd448 *src);
EXPORT_SYM int ed448_get_xy(uint8_t *x, uint8_t *y, size_t len, const PointEd448 *p);
EXPORT_SYM int ed448_add(PointEd448 *a, const PointEd448 *b);
EXPORT_SYM int ed448_double(PointEd448 *p);
EXPORT_SYM int ed448_scalar(PointEd448 *p, const uint8_t *k, size_t len, uint64_t seed);
EXPORT_SYM int ed448_cmp(const PointEd448 *a, const PointEd448 *b);
EXPORT_SYM int ed448_neg(PointEd448 *p);

#endif
