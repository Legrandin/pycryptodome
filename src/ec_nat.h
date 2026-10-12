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

/* A curve (b is the constant of the formulas: g->param) */
typedef EcGroup EcCurve;

/* A point in projective coordinates (X:Y:Z); the point at infinity is (0:1:0) */
typedef EcPoint EcPointN;

EXPORT_SYM int ec_nat_new_curve(EcCurve **out,
                                const uint8_t *p, const uint8_t *b, const uint8_t *order,
                                const uint8_t *gx, const uint8_t *gy, size_t len);
EXPORT_SYM void ec_nat_free_curve(EcCurve *curve);

EXPORT_SYM int ec_nat_new_point(EcPointN **out, const uint8_t *x, const uint8_t *y, size_t len,
                                const EcCurve *curve);
EXPORT_SYM void ec_nat_free_point(EcPointN *p);
EXPORT_SYM int ec_nat_get_xy(uint8_t *x, uint8_t *y, size_t len, const EcPointN *p);
EXPORT_SYM int ec_nat_clone(EcPointN **out, const EcPointN *p);
EXPORT_SYM int ec_nat_cmp(const EcPointN *a, const EcPointN *b);
EXPORT_SYM int ec_nat_neg(EcPointN *p);
EXPORT_SYM int ec_nat_double(EcPointN *p);
EXPORT_SYM int ec_nat_add(EcPointN *a, const EcPointN *b);
EXPORT_SYM int ec_nat_scalar(EcPointN *p, const uint8_t *k, size_t len, uint64_t seed);
EXPORT_SYM int ec_nat_scalar_public(EcPointN *p, const uint8_t *k, size_t len);

#endif
