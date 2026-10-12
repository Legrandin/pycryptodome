/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Field arithmetic for the elliptic curves, with a fixed number of words.
 * Only included by ec_common.c.
 *
 * The instances of the templates of nat_rows.c (the same code as
 * mont_mul(), mont_sqr(), mod_add() and mod_sub() in nat_mod.c) for each
 * size of the curves (3, 4, 6, 7 and 9 words): the size is a constant, so
 * the loops are unrolled. About 1.4x-1.7x faster on the scalar
 * multiplications, except P-521 with gcc. The temporaries are on the
 * stack. 64-bit targets only (NAT_32BIT has its own kernels).
 */

#ifndef EC_FIELD_H
#define EC_FIELD_H

#include "common.h"
#include "nat.h"
#include "nat_ct.h"
#include "nat_rows.c"

#if !defined(NAT_32BIT)


/* The Montgomery multiplication and squaring, with the C row */
#define FE_INSTANCE_MUL(N) \
static void fe_mont_mul_##N(uint64_t *o, const uint64_t *a, const uint64_t *b, const uint64_t *n, uint64_t m0) \
    { uint64_t t[2*N + 2]; rows_mont_mul(o, a, b, n, m0, N, t, rows_addmul); } \
static void fe_mont_sqr_##N(uint64_t *o, const uint64_t *a, const uint64_t *n, uint64_t m0) \
    { uint64_t t[2*N]; rows_mont_sqr(o, a, n, m0, N, t, rows_addmul); }

#define FE_INSTANCE_ADD(N) \
static void fe_mod_add_##N(uint64_t *o, const uint64_t *a, const uint64_t *b, const uint64_t *n) \
    { uint64_t s[N]; rows_mod_add(o, a, b, n, N, s); } \
static void fe_mod_sub_##N(uint64_t *o, const uint64_t *a, const uint64_t *b, const uint64_t *n) \
    { rows_mod_sub(o, a, b, n, N); }

FE_INSTANCE_MUL(3)
FE_INSTANCE_MUL(4)
FE_INSTANCE_MUL(6)
FE_INSTANCE_MUL(7)
/* With BMI2 and ADX, P-521 uses the MULX/ADX kernel of mont_mul() instead */
#if !defined(NAT_BMI2_ADX)
FE_INSTANCE_MUL(9)
#endif

/* The full products, for the primes of a special form (ec_special.h) */
#define FE_INSTANCE_WIDE(N) \
static void fe_mul_wide_##N(uint64_t *o, const uint64_t *a, const uint64_t *b) \
    { rows_mul(o, a, b, N, rows_addmul); } \
static void fe_sqr_wide_##N(uint64_t *o, const uint64_t *a) \
    { rows_sqr(o, a, N, rows_addmul); }

FE_INSTANCE_WIDE(7)
/* With BMI2 and ADX, P-521 uses the MULX/ADX rows of mul_wide() instead */
#if !defined(NAT_BMI2_ADX)
FE_INSTANCE_WIDE(9)
#endif

FE_INSTANCE_ADD(3)
FE_INSTANCE_ADD(4)
FE_INSTANCE_ADD(6)
FE_INSTANCE_ADD(7)
FE_INSTANCE_ADD(9)

#undef FE_INSTANCE_MUL
#undef FE_INSTANCE_WIDE
#undef FE_INSTANCE_ADD

#endif /* !NAT_32BIT */

#endif
