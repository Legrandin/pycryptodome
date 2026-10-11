/* ===================================================================
 *
 * Copyright (c) 2022, Helder Eijs <helderijs@gmail.com>
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

/*
 * Twisted Edward curve with equation:
 *
 *      ax² + y² = 1 + dx²y²
 *
 *  where a = -1 and d = - 121665/121666 over the prime field 2²⁵⁵ - 19.
 *
 *  Points (x, y) can be represented as extended homogeneous coordinates
 *  (X, Y, Z, T) with x = X/Z, y = Y/Z, and x*y = T/Z for a non-zero Z.
 *
 *  The PAI (or neutral point) is (0, Z, Z, 0) or equivalently (0, 1).
 *  The point (x, y) can be obtained by normalizing to (x, y, 1, x*y).
 */

#include "common.h"
#include "endianess.h"
#include "ed25519.h"

FAKE_INIT(ed25519)

#include "mod25519.c"

/*
 * P3 can be P1 or P2
 */
STATIC void ed25519_add_internal(Point *P3, const Point *P1, const Point *P2)
{
    uint32_t A[10], B[10], C[10], D[10];
    /* d = 37095705934669439343138083508754565189542113879843219016388785533085940283555 */
    /* k = 2 * d (mod 2²⁵⁵ - 19) */
    static const uint32_t k[10] = { 0x2B2F159, 0x1A6E509, 0x22ADD7A, 0xD4141D, 0x38052,
                                    0xF3D130, 0x3407977, 0x19CE331, 0x1C56DFF, 0x901B67 };

    /* https://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3 */

    sub_25519(A, P1->Y, P1->X);         /* (Y1-X1)      each limb < 2²⁶ */
    sub_25519(B, P2->Y, P2->X);         /* (Y2-X2)      < 2²⁶ */
    mul_25519(A, A, B);                 /* A            < 2²⁶ */
    add32(B, P1->Y, P1->X);             /* (Y1+X1)      < 2²⁷ */
    add32(C, P2->Y, P2->X);             /* (Y2+X2)      < 2²⁷ */
    mul_25519(B, B, C);                 /* B            < 2²⁶ */
    mul_25519(C, P1->T, P2->T);         /* T1*T2        < 2²⁶ */
    mul_25519(C, C, k);                 /* C            < 2²⁶ */
    mul_25519(D, P1->Z, P2->Z);         /* Z1*Z2        < 2²⁶ */
    add_25519(D, D, D);                 /* D            < 2²⁶ */
    sub_25519(P3->T, B, A);             /* E=B-A        < 2²⁶ */
    sub_25519(P3->Z, D, C);             /* F=D-C        < 2²⁶ */
    add32(D, D, C);                     /* G=D+C        < 2²⁷ */
    add32(B, B, A);                     /* H=B+A        < 2²⁷ */
    mul_25519(P3->X, P3->T, P3->Z);     /* X3=E*F       < 2²⁶ */
    mul_25519(P3->Y, D, B);             /* Y3=G*H       < 2²⁶ */
    mul_25519(P3->T, P3->T, B);         /* T3=E*H       < 2²⁶ */
    mul_25519(P3->Z, P3->Z, D);         /* Z3=F*G       < 2²⁶ */
}

STATIC void ed25519_double_internal(Point *P3, const Point *P1)
{
    uint32_t A[10], B[10], C[10], D[10];

    mul_25519(A, P1->X, P1->X);         /* X1^2             each limb < 2²⁶ */
    mul_25519(B, P1->Y, P1->Y);         /* Y1^2             < 2²⁶ */
    mul_25519(C, P1->Z, P1->Z);         /* Z1^2             < 2²⁶ */
    add_25519(C, C, C);                 /* C=2*Z1^2         < 2²⁶ */
    add32(D, A, B);                     /* H=A+B            < 2²⁷ */
    add32(P3->T, P1->X, P1->Y);         /* X1+Y1            < 2²⁷ */
    mul_25519(P3->T, P3->T, P3->T);     /* (X1+Y1)^2        < 2²⁶ */
    sub_25519(P3->T, D, P3->T);         /* E=H-(X1+Y1)^2    < 2²⁶ */
    sub_25519(P3->Z, A, B);             /* G=A-B            < 2²⁶ */
    add_25519(A, C, P3->Z);             /* F=C+G            < 2²⁶ */
    mul_25519(P3->X, P3->T, A);         /* X3=E*F           < 2²⁶ */
    mul_25519(P3->Y, P3->Z, D);         /* Y3=G*H           < 2²⁶ */
    mul_25519(P3->T, P3->T, D);         /* T3=E*H           < 2²⁶ */
    mul_25519(P3->Z, A, P3->Z);         /* Z3=F*G           < 2²⁶ */
}

#if 0
static void print_point_le8(const Point *p)
{
    uint8_t bin[32];
    unsigned i;
    uint32_t tmp[32];
    uint32_t invz[32];

    invert_25519(invz, p->Z);
    mul_25519(tmp, p->X, invz);
    convert_le25p5_to_le8(bin, tmp);
    printf("X=");
    for (i=0; i<32; i++)
        printf("%02X", bin[i]);
    printf("\n");

    invert_25519(invz, p->Z);
    mul_25519(tmp, p->Y, invz);
    convert_le25p5_to_le8(bin, tmp);
    printf("Y=");
    for (i=0; i<32; i++)
        printf("%02X", bin[i]);
    printf("\n");
}
#endif

/*
 * Size of the random factor for the blinding of the scalar.
 * Each bit adds one step to the ladder: 32 bits cost about 13%
 * (64 bits, as for Ed448, would cost about 25%).
 */
#ifndef ED25519_BLIND_BITS
#define ED25519_BLIND_BITS 32
#endif

#if (ED25519_BLIND_BITS < 1) || (ED25519_BLIND_BITS > 64)
#error ED25519_BLIND_BITS must be between 1 and 64
#endif

/*
 * 8L, the order of the whole group (L is the order of the base point),
 * in little-endian 64-bit words.
 */
static const uint64_t order8[4] = { 0xc09318d2e7ae9f68ULL, 0xa6f7cef517bce6b2ULL, 0, 0x8000000000000000ULL };

/** The next value of a SplitMix64 generator, as ec_next_random() in ec_common.c **/
static uint64_t ed25519_next_random(uint64_t *state)
{
    uint64_t z;

    *state += 0x9E3779B97F4A7C15ULL;
    z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/** A random field element in [1, 2²⁵⁴), so never zero modulo 2²⁵⁵ - 19 **/
static void ed25519_random_fe(uint32_t out[10], uint64_t *state)
{
    unsigned i;

    for (i=0; i<10; i++) {
        out[i] = (uint32_t)(ed25519_next_random(state) & ((i & 1) ? MASK25 : MASK26));
    }
    out[9] &= (1U << 24) - 1;
    out[0] |= 1;
}

/*
 * Allocate the 64-bit words (little-endian) for a number of nbits bits,
 * and load the big-endian scalar k (len bytes, with 8*len <= nbits) in it.
 */
static uint64_t *ed25519_load_scalar(size_t *nw, size_t nbits, const uint8_t *k, size_t len)
{
    uint64_t *kw;
    size_t i;

    *nw = (nbits + 63) / 64;
    if (*nw == 0)
        *nw = 1;
    kw = (uint64_t*)calloc(*nw, sizeof(uint64_t));
    if (NULL == kw)
        return NULL;
    for (i=0; i<len; i++) {
        kw[i/8] |= (uint64_t)k[len-1-i] << (8*(i%8));
    }
    return kw;
}

/*
 * Montgomery ladder over the nbits lowest bits of kw (little-endian words).
 *
 * R0 is the neutral point and R1 the input point, in any
 * projective coordinates. The result goes into R0.
 */
static void ed25519_ladder(Point *R0, Point *R1, const uint64_t *kw, size_t nbits)
{
    size_t i;
    unsigned swap;

    /* https://eprint.iacr.org/2020/956.pdf */

    /* OPTIMIZE: with pre-computed tables in case of fixed-point multiplication */

    /* Scan all bits from MSB to LSB */
    swap = 0;
    for (i=nbits; i-- > 0;) {
        unsigned bit;

        bit = (unsigned)(kw[i/64] >> (i%64)) & 1;
        swap ^= bit;

        cswap(R0->X, R0->Y, R1->X, R1->Y, swap);
        cswap(R0->Z, R0->T, R1->Z, R1->T, swap);

        ed25519_add_internal(R1, R0, R1);       /* R1 <-- R0 + R1 */
        ed25519_double_internal(R0, R0);        /* R0 <-- 2R0 */

        swap = bit;
    }
    cswap(R0->X, R0->Y, R1->X, R1->Y, swap);
    cswap(R0->Z, R0->T, R1->Z, R1->T, swap);
}

/*
 * Scalar multiplication Q = k*B, for a scalar k that can be secret.
 *
 * The scalar is blinded: the ladder runs over k + r*8L, for a random r of
 * ED25519_BLIND_BITS bits, which gives the same point for any B on the curve.
 * The projective coordinates are randomized too.
 *
 * @param[out]  Pout    The resulting point Q (it can be the same as Pin).
 * @param[in]   k       The scalar encoded in big-endian mode.
 * @param[in]   len     Length of the scalar in bytes.
 * @param[in]   Pin     The input point B.
 * @param[in]   seed    A random value, for the blinding.
 */
STATIC int ed25519_scalar_internal(Point *Pout,
                                   const uint8_t *k, size_t len,
                                   const Point *Pin,
                                   uint64_t seed)
{
    Point R0, R1;
    uint32_t lambda[10];
    uint64_t *kb, r, carry, state = seed;
    volatile uint64_t *wipe;
    size_t nbits, nw, i;

    if (len > (SIZE_MAX - 64) / 8)
        return ERR_MAX_DATA;

    /* k + r*8L < 2^nbits */
    nbits = 8*len > 256 + ED25519_BLIND_BITS ? 8*len : 256 + ED25519_BLIND_BITS;
    nbits++;

    kb = ed25519_load_scalar(&nw, nbits, k, len);
    if (NULL == kb)
        return ERR_MEMORY;

    /* kb = k + r*8L */
    r = ed25519_next_random(&state) >> (64 - ED25519_BLIND_BITS);
    carry = 0;
    for (i=0; i<nw; i++) {
        kb[i] = ct_mac(i < 4 ? order8[i] : 0, r, kb[i], carry, &carry);
    }

    /* R0 = (0, lambda, lambda, 0), the neutral point */
    ed25519_random_fe(lambda, &state);
    memset(&R0, 0, sizeof R0);
    memcpy(R0.Y, lambda, sizeof lambda);
    memcpy(R0.Z, lambda, sizeof lambda);

    /* R1 = (lambda*X, lambda*Y, lambda*Z, lambda*T), the input point */
    mul_25519(R1.X, Pin->X, lambda);
    mul_25519(R1.Y, Pin->Y, lambda);
    mul_25519(R1.Z, Pin->Z, lambda);
    mul_25519(R1.T, Pin->T, lambda);

    ed25519_ladder(&R0, &R1, kb, nbits);
    *Pout = R0;

    wipe = kb;
    for (i=0; i<nw; i++) {
        wipe[i] = 0;
    }
    free(kb);
    return 0;
}

/*
 * Scalar multiplication Q = k*B, for a public scalar k (as in the
 * verification of a signature): no blinding, and the ladder only runs
 * over the bits of k. Its running time depends on the length of k.
 *
 * @param[out]  Pout    The resulting point Q (it can be the same as Pin).
 * @param[in]   k       The scalar encoded in big-endian mode.
 * @param[in]   len     Length of the scalar in bytes.
 * @param[in]   Pin     The input point B.
 */
STATIC int ed25519_scalar_public_internal(Point *Pout,
                                          const uint8_t *k, size_t len,
                                          const Point *Pin)
{
    Point R0, R1;
    uint64_t *kw;
    size_t nw;

    if (len > SIZE_MAX / 8)
        return ERR_MAX_DATA;

    kw = ed25519_load_scalar(&nw, 8*len, k, len);
    if (NULL == kw)
        return ERR_MEMORY;

    /* R0 = (0, 1, 1, 0), the neutral point */
    memset(&R0, 0, sizeof R0);
    R0.Y[0] = R0.Z[0] = 1;
    R1 = *Pin;

    ed25519_ladder(&R0, &R1, kw, 8*len);
    *Pout = R0;

    free(kw);
    return 0;
}

/* ---- */

EXPORT_SYM int ed25519_new_point(Point **out,
                      const uint8_t x[32], const uint8_t y[32],
                      size_t modsize, void *context)
{
    uint32_t A[10], B[10], C[10];
    uint8_t bb[32], cb[32];
    const char d[] = "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";

    if ((NULL == out) || (NULL == x) || (NULL == y))
        return ERR_NULL;

    if (modsize != 32)
        return ERR_MODULUS;

    *out = calloc(1, sizeof(Point));
    if (NULL == *out)
        return ERR_MEMORY;

    convert_be8_to_le25p5((*out)->X, x);
    convert_be8_to_le25p5((*out)->Y, y);
    (*out)->Z[0] = 1;
    mul_25519((*out)->T, (*out)->X, (*out)->Y);

    /** Verify that the point is on the Ed25519 curve **/
    mul_25519(A, (*out)->X, (*out)->X);     /* x² */
    mul_25519(B, (*out)->Y, (*out)->Y);     /* y² */

    convert_behex_to_le25p5(C, d);          /* d */
    mul_25519(C, C, B);                     /* dy² */
    mul_25519(C, C, A);                     /* dx²y² */
    add_25519(C, C, A);                     /* dx²y² - ax² */

    memset(A, 0, sizeof A);
    A[0] = 1;
    add_25519(C, C, A);                     /* 1 + dx²y² - ax² */

    /* Compare the values fully reduced: the limbs alone can differ by p */
    convert_le25p5_to_le8(bb, B);
    convert_le25p5_to_le8(cb, C);
    if (0 != memcmp(bb, cb, sizeof bb)) {
        free(*out);
        *out = NULL;
        return ERR_EC_POINT;
    }

    return 0;
}

/*
 * Decode a point encoded as in RFC 8032 (5.1.3): the y-coordinate in
 * little-endian order, with the least significant bit of x in the top bit.
 *
 * Return ERR_EC_POINT if the encoding is not valid: y not smaller than p,
 * no x for that y, or x = 0 with its bit set.
 * The encoding is public: the function is not constant time.
 */
EXPORT_SYM int ed25519_decode_point(Point **out, const uint8_t *encoded, size_t len, void *context)
{
    const char d_hex[] = "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";
    const char sqrtm1_hex[] = "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0";
    const uint32_t zero[10] = { 0 };
    uint32_t y[10], x[10], u[10], v[10], v3[10], t[10], d[10];
    uint8_t yb[32], check[32], ub[32];
    unsigned x_0;

    if ((NULL == out) || (NULL == encoded))
        return ERR_NULL;
    if (len != 32)
        return ERR_MODULUS;

    memcpy(yb, encoded, 32);
    x_0 = yb[31] >> 7;
    yb[31] &= 0x7F;

    /* y must be smaller than p: it is unchanged by the reduction */
    convert_le8_to_le25p5(y, yb);
    convert_le25p5_to_le8(check, y);
    if (0 != memcmp(check, yb, 32))
        return ERR_EC_POINT;

    /* u = y² - 1, v = dy² + 1 */
    convert_behex_to_le25p5(d, d_hex);
    mul_25519(t, y, y);
    memset(u, 0, sizeof u);
    u[0] = 1;
    add_25519(v, t, zero);
    mul_25519(v, v, d);
    add_25519(v, v, u);
    sub_25519(u, t, u);

    /* x = u v³ (u v⁷)^((p-5)/8) */
    mul_25519(v3, v, v);
    mul_25519(v3, v3, v);
    mul_25519(t, v3, v3);
    mul_25519(t, t, v);
    mul_25519(t, t, u);
    pow22523_25519(t, t);
    mul_25519(x, u, v3);
    mul_25519(x, x, t);

    /* v x² is u (x is a root), -u (x √-1 is a root), or else there is no root */
    mul_25519(t, x, x);
    mul_25519(t, t, v);
    convert_le25p5_to_le8(check, t);
    convert_le25p5_to_le8(ub, u);
    if (0 != memcmp(check, ub, 32)) {
        sub_25519(t, zero, t);
        convert_le25p5_to_le8(check, t);
        if (0 != memcmp(check, ub, 32))
            return ERR_EC_POINT;
        convert_behex_to_le25p5(t, sqrtm1_hex);
        mul_25519(x, x, t);
    }

    /* Select the root with the right parity */
    convert_le25p5_to_le8(check, x);
    if (is_le25p5_zero(x) && x_0)
        return ERR_EC_POINT;
    if ((check[0] & 1) != x_0)
        sub_25519(x, zero, x);

    *out = calloc(1, sizeof(Point));
    if (NULL == *out)
        return ERR_MEMORY;
    memcpy((*out)->X, x, sizeof x);
    memcpy((*out)->Y, y, sizeof y);
    (*out)->Z[0] = 1;
    mul_25519((*out)->T, x, y);

    (void)context;
    return 0;
}

EXPORT_SYM int ed25519_clone(Point **P, const Point *Q)
{
    if ((NULL == P) || (NULL == Q))
        return ERR_NULL;

    *P = calloc(1, sizeof(Point));
    if (NULL == *P)
        return ERR_MEMORY;

    **P = *Q;
    return 0;
}

EXPORT_SYM void ed25519_free_point(Point *p)
{
    if (p)
        free(p);
}

EXPORT_SYM int ed25519_cmp(const Point *p1, const Point *p2)
{
    uint32_t tmp[10];
    uint8_t bin1[32], bin2[32];
    unsigned int i;
    int res = 0;

    mul_25519(tmp, p1->X, p2->Z);
    convert_le25p5_to_le8(bin1, tmp);
    mul_25519(tmp, p2->X, p1->Z);
    convert_le25p5_to_le8(bin2, tmp);
    for (i=0; i<sizeof bin1; i++) {
        res |= bin1[i] != bin2[i];
    }

    mul_25519(tmp, p1->Y, p2->Z);
    convert_le25p5_to_le8(bin1, tmp);
    mul_25519(tmp, p2->Y, p1->Z);
    convert_le25p5_to_le8(bin2, tmp);
    for (i=0; i<sizeof bin1; i++) {
        res |= bin1[i] != bin2[i];
    }

    return res;
}

EXPORT_SYM int ed25519_neg(Point *p)
{
    const uint32_t zero[10] = { 0 };

    sub_25519(p->X, zero, p->X);
    sub_25519(p->T, zero, p->T);
    return 0;
}

EXPORT_SYM int ed25519_get_xy(uint8_t *xb, uint8_t *yb, size_t modsize, Point *p)
{
    uint32_t invz[10], tmp[10];

    if ((NULL == xb) || (NULL == yb) || (NULL == p))
        return ERR_NULL;
    if (modsize != 32)
        return ERR_MODULUS;

    invert_25519(invz, p->Z);
    mul_25519(tmp, p->X, invz);
    convert_le25p5_to_be8(xb, tmp);
    mul_25519(tmp, p->Y, invz);
    convert_le25p5_to_be8(yb, tmp);

    return 0;
}

EXPORT_SYM int ed25519_double(Point *p)
{
    if (NULL == p)
        return ERR_NULL;
    ed25519_double_internal(p, p);
    return 0;
}

EXPORT_SYM int ed25519_add(Point *P1, const Point *P2)
{
    if ((NULL == P1) || (NULL == P2))
        return ERR_NULL;
    ed25519_add_internal(P1, P1, P2);
    return 0;
}

EXPORT_SYM int ed25519_scalar(Point *P, const uint8_t *scalar, size_t scalar_len, uint64_t seed)
{
    if ((NULL == P) || (NULL == scalar))
        return ERR_NULL;

    return ed25519_scalar_internal(P, scalar, scalar_len, P, seed);
}

EXPORT_SYM int ed25519_scalar_public(Point *P, const uint8_t *scalar, size_t scalar_len)
{
    if ((NULL == P) || (NULL == scalar))
        return ERR_NULL;

    return ed25519_scalar_public_internal(P, scalar, scalar_len, P);
}
