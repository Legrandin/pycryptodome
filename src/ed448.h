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

/*
 * The curve (d is the constant of the formulas: g.param; the scalars are
 * taken modulo 4n, the order of the whole group, as the cofactor is 4).
 */
typedef struct {
    EcGroup g;
    Nat *sqrt_exp;          /* (p-3)/4, for the square roots (RFC 8032, 5.2.3) */
} Ed448Context;

/* A point in projective coordinates (X:Y:Z); the neutral point is (0:1:1) */
typedef EcPoint PointEd448;

EXPORT_SYM int ed448_new_context(Ed448Context **out);
EXPORT_SYM void ed448_free_context(Ed448Context *ctx);
EXPORT_SYM int ed448_new_point(PointEd448 **out, const uint8_t *x, const uint8_t *y, size_t len,
                               const Ed448Context *ctx);
EXPORT_SYM int ed448_decode_point(PointEd448 **out, const uint8_t *encoded, size_t len,
                                  const Ed448Context *ctx);
EXPORT_SYM void ed448_free_point(PointEd448 *p);
EXPORT_SYM int ed448_clone(PointEd448 **out, const PointEd448 *p);
EXPORT_SYM int ed448_copy(PointEd448 *dst, const PointEd448 *src);
EXPORT_SYM int ed448_get_xy(uint8_t *x, uint8_t *y, size_t len, const PointEd448 *p);
EXPORT_SYM int ed448_add(PointEd448 *a, const PointEd448 *b);
EXPORT_SYM int ed448_double(PointEd448 *p);
EXPORT_SYM int ed448_scalar(PointEd448 *p, const uint8_t *k, size_t len, uint64_t seed);
EXPORT_SYM int ed448_scalar_public(PointEd448 *p, const uint8_t *k, size_t len);
EXPORT_SYM int ed448_cmp(const PointEd448 *a, const PointEd448 *b);
EXPORT_SYM int ed448_neg(PointEd448 *p);

#endif
