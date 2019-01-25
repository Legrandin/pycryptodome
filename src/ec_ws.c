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
#include "mont.h"
#include "ec.h"

FAKE_INIT(modexp)

#ifdef MAIN
STATIC void print_x(const char *s, const uint64_t *number, const MontContext *ctx)
{
    unsigned i;
    size_t size;
    uint8_t *encoded;
    int res;

    size = mont_bytes(ctx);
    encoded = calloc(1, size);
    assert(size == 32);
    res = mont_to_bytes(encoded, number, ctx);
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
    free(wp->scratch);
    free(wp);
}

/*
 * Convert jacobian coordinates to affine.
 */
STATIC void ec_ws_normalize(uint64_t *x3, uint64_t *y3,
                         const uint64_t *x1, uint64_t *y1, uint64_t *z1,
                         Workplace *tmp,
                         const MontContext *ctx)
{
    uint64_t *a = tmp->a;
    uint64_t *b = tmp->b;
    uint64_t *c = tmp->c;
    uint64_t *s = tmp->scratch;

    if (mont_is_zero(z1, ctx)) {
        mont_set(x3, 0, NULL, ctx);
        mont_set(y3, 0, NULL, ctx);
        return;
    }

    mont_inv_prime(a, z1, ctx);
    mont_mult(b, a, a, s, ctx);
    mont_mult(c, b, a, s, ctx);
    mont_mult(x3, x1, b, s, ctx);     /* X/Z² */
    mont_mult(y3, y1, c, s, ctx);     /* Y/Z³ */
}

/*
 * Double an EC point on a short Weierstrass curve of equation y²=x³-3x+b.
 * Jacobian coordinates.
 * Input and output points can match.
 */
STATIC void ec_full_double(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                           const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                           Workplace *tmp, const MontContext *ctx)
{
    uint64_t *a = tmp->a;
    uint64_t *b = tmp->b;
    uint64_t *c = tmp->c;
    uint64_t *d = tmp->d;
    uint64_t *e = tmp->e;
    uint64_t *s = tmp->scratch;

    if (mont_is_zero(z1, ctx)) {
        mont_set(x3, 1, NULL, ctx);
        mont_set(y3, 1, NULL, ctx);
        mont_set(z3, 0, NULL, ctx);
        return;
    }

    /* No need to explicitly handle the case y1=0 (for x1≠0).
     * The following code will already produce the point at infinity (t²,t³,0).
     */

    mont_mult(a, z1, z1, s, ctx);       /* a = delta = Z1² */
    mont_mult(b, y1, y1, s, ctx);       /* b = gamma = Y1² */
    mont_mult(c, x1, b, s, ctx);        /* c = beta = X1*gamma */
    mont_sub(d, x1, a, s, ctx);
    mont_add(e, x1, a, s, ctx);
    mont_mult(d, d, e, s, ctx);
    mont_add(e, d, d, s, ctx);
    mont_add(d, d, e, s, ctx);          /* d = alpha = 3*(X1-delta)*(X1+delta) */

    mont_add(z3, y1, z1, s, ctx);
    mont_mult(z3, z3, z3, s, ctx);
    mont_sub(z3, z3, b, s, ctx);
    mont_sub(z3, z3, a, s, ctx);        /* Z3 = (Y1+Z1)²-gamma-delta */

    mont_mult(x3, d, d, s, ctx);
    mont_add(e, c, c, s, ctx);
    mont_add(e, e, e, s, ctx);
    mont_add(e, e, e, s, ctx);
    mont_sub(x3, x3, e, s, ctx);        /* X3 = alpha²-8*beta */

    mont_add(e, c, c, s, ctx);
    mont_add(y3, e, e, s, ctx);
    mont_sub(y3, y3, x3, s, ctx);
    mont_mult(y3, d, y3, s, ctx);
    mont_mult(e, b, b, s, ctx);
    mont_add(e, e, e, s, ctx);
    mont_add(e, e, e, s, ctx);
    mont_add(e, e, e, s, ctx);
    mont_sub(y3, y3, e, s, ctx);        /* Y3 = alpha*(4*beta-X3)-8*gamma² */
}

/*
 * Add two EC points on a short Weierstrass curve of equation y²=x³-3x+b.
 * One input point has affine coordinates.
 * The other input and the the output points have Jacobian coordinates.
 * Input and output points can match.
 */
STATIC void ec_mix_add(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                       const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                       const uint64_t *x2, const uint64_t *y2,
                       Workplace *tmp,
                       const MontContext *ctx)
{
    uint64_t *a = tmp->a;
    uint64_t *b = tmp->b;
    uint64_t *c = tmp->c;
    uint64_t *d = tmp->d;
    uint64_t *e = tmp->e;
    uint64_t *f = tmp->f;
    uint64_t *s = tmp->scratch;

    /* First term may be point at infinity */
    if (mont_is_zero(z1, ctx)) {
        mont_copy(x3, x2, ctx);
        mont_copy(y3, y2, ctx);
        mont_set(z3, 1, tmp->scratch, ctx);
        return;
    }

    /* Second term may be point at infinity */
    if (mont_is_zero(x2, ctx) && mont_is_zero(y2, ctx)) {
        mont_copy(x3, x1, ctx);
        mont_copy(y3, y1, ctx);
        mont_copy(z3, z1, ctx);
        return;
    }

    mont_mult(a, z1, z1, s, ctx);       /* a = Z1Z1 = Z1² */
    mont_mult(b, x2, a, s, ctx);        /* b = U2 = X2*Z1Z1 */
    mont_mult(c, y2, z1, s, ctx);
    mont_mult(c, c, a, s, ctx);         /* c = S2 = Y2*Z1*Z1Z1 */

    /* Now that affine (x2, y2) is converted to Jacobian (U2, S2, Z1)
     * we can check if P1 is ±P2 and handle such special case */
    if (mont_is_equal(x1, b, ctx)) {
        if (mont_is_equal(y1, c, ctx)) {
            ec_full_double(x3, y3, z3, x1, y1, z1, tmp, ctx);
            return;
        } else {
            mont_set(x3, 1, NULL, ctx);
            mont_set(y3, 1, NULL, ctx);
            mont_set(z3, 0, NULL, ctx);
            return;
        }
    }

    mont_sub(b, b, x1, s, ctx);         /* b = H = U2-X1 */
    mont_mult(d, b, b, s, ctx);         /* d = HH = H² */
    mont_add(e, d, d, s, ctx);
    mont_add(e, e, e, s, ctx);          /* e = I = 4*HH */
    mont_mult(f, b, e, s, ctx);         /* f = J = H*I */

    mont_sub(c, c, y1, s, ctx);
    mont_add(c, c, c, s, ctx);          /* c = r = 2*(S2-Y1) */
    mont_mult(e, x1, e, s, ctx);        /* e = V = X1*I */

    mont_mult(x3, c, c, s, ctx);
    mont_sub(x3, x3, f, s, ctx);
    mont_sub(x3, x3, e, s, ctx);
    mont_sub(x3, x3, e, s, ctx);        /* X3 = r²-J-2*V */

    mont_mult(f, y1, f, s, ctx);
    mont_add(f, f, f, s, ctx);
    mont_sub(y3, e, x3, s, ctx);
    mont_mult(y3, c, y3, s, ctx);
    mont_sub(y3, y3, f, s, ctx);        /* Y3 = r*(V-X3)-2*Y1*J */

    mont_add(z3, z1, b, s, ctx);
    mont_mult(z3, z3, z3, s, ctx);
    mont_sub(z3, z3, a, s, ctx);
    mont_sub(z3, z3, d, s, ctx);        /* Z3 = (Z1+H)²-Z1Z1-HH **/
}

/*
 * Add two EC points on a short Weierstrass curve of equation y²=x³-3x+b.
 * All points have Jacobian coordinates.
 * Input and output points can match.
 */
STATIC void ec_full_add(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                        const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                        const uint64_t *x2, const uint64_t *y2, const uint64_t *z2,
                        Workplace *tmp,
                        const MontContext *ctx)
{
    uint64_t *a = tmp->a;
    uint64_t *b = tmp->b;
    uint64_t *c = tmp->c;
    uint64_t *d = tmp->d;
    uint64_t *e = tmp->e;
    uint64_t *f = tmp->f;
    uint64_t *g = tmp->g;
    uint64_t *h = tmp->h;
    uint64_t *s = tmp->scratch;

    /* First term may be point at infinity */
    if (mont_is_zero(z1, ctx)) {
        mont_copy(x3, x2, ctx);
        mont_copy(y3, y2, ctx);
        mont_copy(z3, z2, ctx);
        return;
    }

    /* Second term may be point at infinity */
    if (mont_is_zero(z2, ctx)) {
        mont_copy(x3, x1, ctx);
        mont_copy(y3, y1, ctx);
        mont_copy(z3, z1, ctx);
        return;
    }

    mont_mult(a, z1, z1, s, ctx);       /* a = Z1Z1 = Z1² */
    mont_mult(b, z2, z2, s, ctx);       /* b = Z2Z2 = Z2² */
    mont_mult(c, x1, b, s, ctx);        /* c = U1 = X1*Z2Z2 */
    mont_mult(d, x2, a, s, ctx);        /* d = U2 = X2*Z1Z1 */
    mont_mult(e, y1, z2, s, ctx);
    mont_mult(e, e, b, s, ctx);         /* e = S1 = Y1*Z2*Z2Z2 */
    mont_mult(f, y2, z1, s, ctx);
    mont_mult(f, f, a, s, ctx);         /* f = S2 = Y2*Z1*Z1Z1 */

    /* We can check if P1 is ±P2 and handle such special case */
    if (mont_is_equal(c, d, ctx)) {
        if (mont_is_equal(e, f, ctx)) {
            ec_full_double(x3, y3, z3, x1, y1, z1, tmp, ctx);
        } else {
            mont_set(x3, 1, NULL, ctx);
            mont_set(y3, 1, NULL, ctx);
            mont_set(z3, 0, NULL, ctx);
        }
        return;
    }

    mont_sub(d, d, c, s, ctx);          /* d = H = U2-U1 */
    mont_add(g, d, d, s, ctx);
    mont_mult(g, g, g, s, ctx);         /* g = I = (2*H)² */
    mont_mult(h, d, g, s, ctx);         /* h = J = H*I */
    mont_sub(f, f, e, s, ctx);
    mont_add(f, f, f, s, ctx);          /* f = r = 2*(S2-S1) */
    mont_mult(c, c, g, s, ctx);         /* c = V = U1*I */

    mont_mult(x3, f, f, s, ctx);
    mont_sub(x3, x3, h, s, ctx);
    mont_sub(x3, x3, c, s, ctx);
    mont_sub(x3, x3, c, s, ctx);        /* x3 = r²-J-2*V */

    mont_sub(y3, c, x3, s, ctx);
    mont_mult(y3, f, y3, s, ctx);
    mont_mult(g, e, h, s, ctx);
    mont_add(g, g, g, s, ctx);
    mont_sub(y3, y3, g, s, ctx);        /* y3 = r*(V-X3)-2*S1*J */

    mont_add(z3, z1, z2, s, ctx);
    mont_mult(z3, z3, z3, s, ctx);
    mont_sub(z3, z3, a, s, ctx);
    mont_sub(z3, z3, b, s, ctx);
    mont_mult(z3, z3, d, s, ctx);       /* z3 = ((Z1+Z2)²-Z1Z1-Z2Z2)*H */
}

/*
 * Compute the scalar multiplication of an EC point.
 * Jacobian coordinates as output, affine an input.
 */
STATIC void ec_exp(uint64_t *x3, uint64_t *y3, uint64_t *z3,
                   const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
                   const uint8_t *exp, size_t exp_size,
                   Workplace *wp1,
                   Workplace *wp2,
                   const MontContext *ctx)
{
    unsigned bit;
    unsigned z1_is_one;
    uint64_t *xa = wp2->a;
    uint64_t *ya = wp2->b;
    uint64_t *za = wp2->c;
    uint64_t *xb = wp2->d;
    uint64_t *yb = wp2->e;
    uint64_t *zb = wp2->f;

    z1_is_one = mont_is_one(z1, ctx);

    /** Start from PAI **/
    mont_set(xa, 1, NULL, ctx);
    mont_set(ya, 1, NULL, ctx);
    mont_set(za, 0, NULL, ctx);

    /** Find first non-zero bit **/
    for (; exp_size && *exp==0; exp++, exp_size--);
    for (bit=0x80; exp_size && (*exp & bit)==0; bit>>=1);

    /** Left-to-right exponentiation **/
    for (; exp_size; exp++, exp_size--) {
       while (bit) {
            ec_full_double(xa, ya, za, xa, ya, za, wp1, ctx);
            if (z1_is_one)
                ec_mix_add(xb, yb, zb, xa, ya, za, x1, y1, wp1, ctx);
            else
                ec_full_add(xb, yb, zb, xa, ya, za, x1, y1, z1, wp1, ctx);
            /* If bit is set, choose 2*P+Q, otherwise 2*P  */
            mont_select(xa, xb, xa, bit & *exp, ctx);
            mont_select(ya, yb, ya, bit & *exp, ctx);
            mont_select(za, zb, za, bit & *exp, ctx);

            bit>>=1;
        }
        bit = 0x80;
    }
    mont_copy(x3, xa, ctx);
    mont_copy(y3, ya, ctx);
    mont_copy(z3, za, ctx);
}

/*
 * Create an Elliptic Curve context for Weierstress curves y²=x³+ax+b with a=-3
 *
 * @param pec_ctx   The memory area where the pointer to the newly allocated
 *                  EC context will be stored.
 * @param modulus   The prime modulus for the curve, big-endian encoded
 * @param b         The constant b, big-endian encoded
 * @param len       The length in bytes of modulus and b
 * @return          0 for success, the appopriate error code otherwise
 */
int ec_ws_new_context(EcContext **pec_ctx,
                      const uint8_t *modulus,
                      const uint8_t *b,
                      size_t len)
{
    EcContext *ec_ctx = NULL;
    int res;

    if (NULL == pec_ctx || NULL == modulus || NULL == b)
        return ERR_NULL;
    if (len == 0)
        return ERR_NOT_ENOUGH_DATA;

    *pec_ctx = ec_ctx = (EcContext*)calloc(1, sizeof(EcContext));
    if (NULL == ec_ctx)
        return ERR_MEMORY;

    res = mont_context_init(&ec_ctx->mont_ctx, modulus, len);
    if (res) goto cleanup;
    res = mont_from_bytes(&ec_ctx->b, b, len, ec_ctx->mont_ctx);
    if (res) goto cleanup;

    return 0;

cleanup:
    free(ec_ctx->b);
    mont_context_free(ec_ctx->mont_ctx);
    free(ec_ctx);
    *pec_ctx = NULL;
    return res;
}

void ec_free_context(EcContext *ec_ctx)
{
    if (NULL == ec_ctx)
        return;

    free(ec_ctx->b);
    mont_context_free(ec_ctx->mont_ctx);
    free(ec_ctx);
}

/*
 * Create a new EC point on the given EC curve.
 *
 *  @param pecp     The memory area where the pointer to the newly allocated EC
 *                  point will be stored. Use ec_free_point() for deallocating it.
 *  @param x        The X-coordinate (affine, big-endian)
 *  @param y        The Y-coordinate (affine, big-endian)
 *  @param len      The length of x and y in bytes
 *  @param ec_ctx   The EC context
 *  @return         0 for success, the appopriate error code otherwise
 */
int ec_ws_new_point(EcPoint **pecp, uint8_t *x, uint8_t *y, size_t len, const EcContext *ec_ctx)
{
    int res;
    Workplace *wp = NULL;
    EcPoint *ecp;
    MontContext *ctx;
    
    if (NULL == pecp || NULL == x || NULL == y || NULL == ec_ctx)
        return ERR_NULL;
    ctx = ec_ctx->mont_ctx;

    if (len != ctx->bytes)
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

    /** Convert (0, 0) to (1, 1, 0) */
    /** Verify the point is on the curve, if not point-at-infinity */
    if (mont_is_zero(ecp->x, ctx) && mont_is_zero(ecp->y, ctx)) {
        mont_set(ecp->x, 1, NULL, ctx);
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

void ec_free_point(EcPoint *ecp)
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
int ec_ws_get_xy(uint8_t *x, uint8_t *y, size_t len, const EcPoint *ecp)
{
    uint64_t *xw=NULL, *yw=NULL;
    Workplace *wp;
    MontContext *ctx;
    int res;

    if (NULL == x || NULL == y || NULL == ecp)
        return ERR_NULL;
    ctx = ecp->ec_ctx->mont_ctx;

    if (len != mont_bytes(ctx))
        return ERR_VALUE;

    wp = new_workplace(ctx);
    if (NULL == wp)
        return ERR_MEMORY;

    res = mont_number(&xw, 1, ctx);
    if (res) goto cleanup;
    res = mont_number(&yw, 1, ctx);
    if (res) goto cleanup;

    ec_ws_normalize(xw, yw, ecp->x, ecp->y, ecp->z, wp, ctx);
    res = mont_to_bytes(x, xw, ctx);
    if (res) goto cleanup;
    res = mont_to_bytes(y, yw, ctx);
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
int ec_ws_double(EcPoint *p)
{
    Workplace *wp;
    MontContext *ctx;

    if (NULL == p)
        return ERR_NULL;
    ctx = p->ec_ctx->mont_ctx;

    wp = new_workplace(ctx);
    if (NULL == wp)
        return ERR_MEMORY;

    ec_full_double(p->x, p->y, p->z, p->x, p->y, p->z, wp, ctx);

    free_workplace(wp);
    return 0;
}

/*
 * Add an EC point to another
 */
int ec_ws_add(EcPoint *ecpa, EcPoint *ecpb)
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
                wp, ctx);
 
    free_workplace(wp);
    return 0;
}

/*
 * Multiply an EC point by a scalar
 */
int ec_ws_scalar_multiply(EcPoint *ecp, const uint8_t *k, size_t len)
{
    Workplace *wp1, *wp2;
    MontContext *ctx;

    if (NULL == ecp || NULL == k)
        return ERR_NULL;
    ctx = ecp->ec_ctx->mont_ctx;

    wp1 = new_workplace(ctx);
    if (NULL == wp1)
        return ERR_MEMORY;

    wp2 = new_workplace(ctx);
    if (NULL == wp2) {
        free_workplace(wp1);
        return ERR_MEMORY;
    }

    ec_exp(ecp->x, ecp->y, ecp->z,
           ecp->x, ecp->y, ecp->z,
           k, len, wp1, wp2, ctx);

    free_workplace(wp1);
    free_workplace(wp2);
    return 0;
}

int ec_ws_clone(EcPoint **pecp2, const EcPoint *ecp)
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

int ec_ws_cmp(const EcPoint *ecp1, const EcPoint *ecp2)
{
    MontContext *ctx;

    if (NULL == ecp1 || NULL == ecp2)
        return ERR_NULL;

    if (ecp1->ec_ctx != ecp2->ec_ctx)
        return ERR_EC_CURVE;
    ctx = ecp1->ec_ctx->mont_ctx;

    if (!mont_is_equal(ecp1->z, ecp2->z, ctx))
        return -1;
    if (mont_is_zero(ecp1->z, ctx))
        return 0;
    if (!mont_is_equal(ecp1->x, ecp2->x, ctx))
        return -1;
    if (!mont_is_equal(ecp1->y, ecp2->y, ctx))
        return -1;
    return 0;
}

int ec_ws_neg(EcPoint *p)
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

#ifdef MAIN
int main(void)
{
    MontContext *ctx;
    Workplace *wp1, *wp2;
    const uint8_t p256_mod[32] = "\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    const uint8_t p256_Gx[32] = "\x6b\x17\xd1\xf2\xe1\x2c\x42\x47\xf8\xbc\xe6\xe5\x63\xa4\x40\xf2\x77\x03\x7d\x81\x2d\xeb\x33\xa0\xf4\xa1\x39\x45\xd8\x98\xc2\x96";
    const uint8_t p256_Gy[32] = "\x4f\xe3\x42\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xeb\x4a\x7c\x0f\x9e\x16\x2b\xce\x33\x57\x6b\x31\x5e\xce\xcb\xb6\x40\x68\x37\xbf\x51\xf5";

    uint64_t *Gx, *Gy, *Gz;
    uint64_t *Qx, *Qy, *Qz;
    unsigned i;

    mont_context_init(&ctx, p256_mod, sizeof(p256_mod));
    wp1 = new_workplace(ctx);
    wp2 = new_workplace(ctx);

    mont_from_bytes(&Gx, p256_Gx, sizeof(p256_Gx), ctx);
    mont_from_bytes(&Gy, p256_Gy, sizeof(p256_Gy), ctx);
    mont_number(&Gz, 1, ctx);
    mont_set(Gz, 1, NULL, ctx);

    /* Create point in Jacobian coordinates */
    mont_number(&Qx, 1, ctx);
    mont_number(&Qy, 1, ctx);
    mont_number(&Qz, 1, ctx);

    printf("----------------------------\n");

    for (i=0; i<1000; i++)
        ec_exp(Qx, Qy, Qz, Gx, Gy, Gz, (uint8_t*)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8, wp1, wp2, ctx);

    print_x("Qx", Qx, ctx);
    print_x("Qy", Qy, ctx);
    print_x("Qz", Qz, ctx);

    printf("----------------------------\n");

    ec_ws_normalize(Qx, Qy, Qx, Qy, Qz, wp1, ctx);

    print_x("Qx", Qx, ctx);
    print_x("Qy", Qy, ctx);

    free(Gx);
    free(Gy);
    free(Qx);
    free(Qy);
    free(Qz);
    free_workplace(wp1);
    free_workplace(wp2);
    mont_context_free(ctx);

    return 0;
}
#endif
