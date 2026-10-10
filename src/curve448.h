/*
 * SPDX-FileCopyrightText: 2024-2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The Montgomery curve Curve448 (X448, RFC 7748), on the constant-time
 * arithmetic of the nat library. See curve448.c.
 */

#ifndef CURVE448_H
#define CURVE448_H

#include "common.h"
#include "nat.h"
#include "ec_common.h"

/* 64-bit words of a field element, and bytes of an encoded coordinate */
#define CURVE448_WORDS 7
#define CURVE448_BYTES 56

typedef struct {
    MontCtx *field;         /* Montgomery arithmetic modulo p (constants only) */
    Nat *p_minus_2;         /* the exponent of the inversion (Fermat) */
    size_t p_bits;
    uint64_t *a24;          /* (A+2)/4 = 39082, in Montgomery form */
} Curve448Context;

/*
 * A point (X:Z), with x = X/Z, in Montgomery form: Z is 1, or 0 for
 * the point at infinity (1:0). It can be freed after its context.
 */
typedef struct {
    const Curve448Context *ctx;
    uint64_t *x, *z;
} Curve448Point;

EXPORT_SYM int curve448_new_context(Curve448Context **out);
EXPORT_SYM void curve448_free_context(Curve448Context *ctx);
EXPORT_SYM int curve448_new_point(Curve448Point **out, const uint8_t *x, size_t len,
                                  const Curve448Context *ctx);
EXPORT_SYM void curve448_free_point(Curve448Point *p);
EXPORT_SYM int curve448_clone(Curve448Point **out, const Curve448Point *p);
EXPORT_SYM int curve448_get_x(uint8_t *x, size_t len, const Curve448Point *p);
EXPORT_SYM int curve448_scalar(Curve448Point *p, const uint8_t *k, size_t len, uint64_t seed);
EXPORT_SYM int curve448_cmp(const Curve448Point *a, const Curve448Point *b);

#endif
