/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Short Weierstrass curves y^2 = x^3 - 3x + b over a prime field
 * (the NIST curves P-192, P-224, P-256, P-384 and P-521), on the
 * constant-time arithmetic of the nat library. See ec_nat.c.
 */

#ifndef EC_NAT_H
#define EC_NAT_H

#include "common.h"
#include "nat.h"
#include "ec_common.h"

typedef struct {
    size_t nw;              /* 64-bit words of a field element */
    size_t len;             /* bytes of an encoded coordinate */
    MontCtx *field;         /* Montgomery arithmetic modulo p (constants only) */
    Nat *p_minus_2;         /* the exponent of the inversion (Fermat) */
    size_t p_bits;
    uint64_t *b;            /* b, in Montgomery form */
    uint64_t *gx, *gy;      /* the generator G (affine, Montgomery form) */
    Nat *order;             /* n */
    size_t k_words;         /* 64-bit words of a blinded scalar */
    size_t windows;         /* windows of a blinded scalar */
    uint64_t *g_table;      /* windows*EC_DIGITS affine points, x then y:
                               entry j of window i is (j+1) * 32^i * G */
} EcCurve;

/*
 * A point in projective coordinates (X:Y:Z), in Montgomery form.
 * It can be freed after its curve (nw is a copy).
 */
typedef struct {
    const EcCurve *curve;
    size_t nw;
    uint64_t *x, *y, *z;
} EcPointN;

EXPORT_SYM int ec_nat_new_curve(EcCurve **out,
                                const uint8_t *p, const uint8_t *b, const uint8_t *order,
                                const uint8_t *gx, const uint8_t *gy, size_t len);
EXPORT_SYM void ec_nat_free_curve(EcCurve *curve);

EXPORT_SYM int ec_nat_new_point(EcPointN **out, const uint8_t *x, const uint8_t *y, size_t len,
                                const EcCurve *curve);
EXPORT_SYM void ec_nat_free_point(EcPointN *p);
EXPORT_SYM int ec_nat_get_xy(uint8_t *x, uint8_t *y, size_t len, const EcPointN *p);
EXPORT_SYM int ec_nat_clone(EcPointN **out, const EcPointN *p);
EXPORT_SYM int ec_nat_copy(EcPointN *dst, const EcPointN *src);
EXPORT_SYM int ec_nat_cmp(const EcPointN *a, const EcPointN *b);
EXPORT_SYM int ec_nat_neg(EcPointN *p);
EXPORT_SYM int ec_nat_double(EcPointN *p);
EXPORT_SYM int ec_nat_add(EcPointN *a, const EcPointN *b);
EXPORT_SYM int ec_nat_scalar(EcPointN *p, const uint8_t *k, size_t len, uint64_t seed);

#endif
