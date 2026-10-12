/*
 * SPDX-FileCopyrightText: 2026 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The Salsa20 core function, shared by the Salsa20 stream cipher
 * (Salsa20.c, 20 rounds) and by scrypt (scrypt.c, Salsa20/8).
 *
 * - SALSA20_DOUBLE_ROUND() is one column round and one row round, on 16
 *   variables of any type, given the operations ADD, XOR and ROTL on that type.
 *   With 32-bit integers, it computes one block; with SIMD registers that hold
 *   the same word of several blocks, it computes all of them at once.
 *
 * - salsa20_core() computes one block. With SSE2, the 16 words of the block
 *   are not stored in the natural order, but at the positions given by
 *   SALSA20_WORD_POS(), so that each diagonal of the state lies in one 128-bit
 *   register. Without SSE2, SALSA20_WORD_POS() does not change the order.
 */

#ifndef SALSA20_CORE_H
#define SALSA20_CORE_H

#include "common.h"

#if defined(USE_SSE2)
#if defined(HAVE_INTRIN_H)
#include <intrin.h>
#elif defined(HAVE_X86INTRIN_H)
#include <x86intrin.h>
#elif defined(HAVE_EMMINTRIN_H)
#include <xmmintrin.h>
#include <emmintrin.h>
#endif
#endif

#define SALSA20_ROTL32(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define SALSA20_ADD32(a, b) ((a) + (b))
#define SALSA20_XOR32(a, b) ((a) ^ (b))

#define SALSA20_QUARTER_ROUND(ADD, XOR, ROTL, a, b, c, d) do { \
        b = XOR(b, ROTL(ADD(a, d), 7));     \
        c = XOR(c, ROTL(ADD(b, a), 9));     \
        d = XOR(d, ROTL(ADD(c, b), 13));    \
        a = XOR(a, ROTL(ADD(d, c), 18));    \
    } while (0)

#define SALSA20_DOUBLE_ROUND(ADD, XOR, ROTL, x0, x1, x2, x3, x4, x5, x6, x7, \
                             x8, x9, x10, x11, x12, x13, x14, x15) do {    \
        /* Columns */                                                     \
        SALSA20_QUARTER_ROUND(ADD, XOR, ROTL, x0,  x4,  x8,  x12);        \
        SALSA20_QUARTER_ROUND(ADD, XOR, ROTL, x5,  x9,  x13, x1);         \
        SALSA20_QUARTER_ROUND(ADD, XOR, ROTL, x10, x14, x2,  x6);         \
        SALSA20_QUARTER_ROUND(ADD, XOR, ROTL, x15, x3,  x7,  x11);        \
        /* Rows */                                                        \
        SALSA20_QUARTER_ROUND(ADD, XOR, ROTL, x0,  x1,  x2,  x3);         \
        SALSA20_QUARTER_ROUND(ADD, XOR, ROTL, x5,  x6,  x7,  x4);         \
        SALSA20_QUARTER_ROUND(ADD, XOR, ROTL, x10, x11, x8,  x9);         \
        SALSA20_QUARTER_ROUND(ADD, XOR, ROTL, x15, x12, x13, x14);        \
    } while (0)

#if defined(USE_SSE2)

#define SALSA20_ROTL_SSE2(v, c) _mm_or_si128(_mm_slli_epi32((v), (c)), _mm_srli_epi32((v), 32-(c)))

/* Position in memory of word i of a block (inverse of i -> 5i mod 16) */
#define SALSA20_WORD_POS(i) (((i)*13) % 16)

/**
 * Compute B = Salsa20(B xor Bx xor By), in place, with the given number of rounds.
 * @Bx and @By may be NULL.
 * The words are in native endianess, at the positions given by SALSA20_WORD_POS().
 */
static inline void salsa20_core(unsigned rounds, uint32_t B[16], const uint32_t *Bx, const uint32_t *By)
{
    __m128i X0, X1, X2, X3, Y0, Y1, Y2, Y3;
    __m128i *b = (__m128i*)B;
    const __m128i *bx = (const __m128i*)Bx;
    const __m128i *by = (const __m128i*)By;
    unsigned i;

    X0 = _mm_loadu_si128(b+0);
    X1 = _mm_loadu_si128(b+1);
    X2 = _mm_loadu_si128(b+2);
    X3 = _mm_loadu_si128(b+3);
    if (bx != NULL) {
        X0 = _mm_xor_si128(X0, _mm_loadu_si128(bx+0));
        X1 = _mm_xor_si128(X1, _mm_loadu_si128(bx+1));
        X2 = _mm_xor_si128(X2, _mm_loadu_si128(bx+2));
        X3 = _mm_xor_si128(X3, _mm_loadu_si128(bx+3));
    }
    if (by != NULL) {
        X0 = _mm_xor_si128(X0, _mm_loadu_si128(by+0));
        X1 = _mm_xor_si128(X1, _mm_loadu_si128(by+1));
        X2 = _mm_xor_si128(X2, _mm_loadu_si128(by+2));
        X3 = _mm_xor_si128(X3, _mm_loadu_si128(by+3));
    }
    Y0 = X0;
    Y1 = X1;
    Y2 = X2;
    Y3 = X3;

    /*
     * X0 = (x0, x5, x10, x15), X1 = (x4, x9, x14, x3),
     * X2 = (x8, x13, x2, x7), X3 = (x12, x1, x6, x11):
     * the 4 quarter rounds of the columns are computed together.
     * For the rows, X1, X2 and X3 are rotated so that
     * X3 = (x1, x6, x11, x12), X2 = (x2, x7, x8, x13), X1 = (x3, x4, x9, x14).
     */
    for (i=0; i<rounds; i+=2) {
        SALSA20_QUARTER_ROUND(_mm_add_epi32, _mm_xor_si128, SALSA20_ROTL_SSE2, X0, X1, X2, X3);
        X1 = _mm_shuffle_epi32(X1, 0x93);
        X2 = _mm_shuffle_epi32(X2, 0x4E);
        X3 = _mm_shuffle_epi32(X3, 0x39);
        SALSA20_QUARTER_ROUND(_mm_add_epi32, _mm_xor_si128, SALSA20_ROTL_SSE2, X0, X3, X2, X1);
        X1 = _mm_shuffle_epi32(X1, 0x39);
        X2 = _mm_shuffle_epi32(X2, 0x4E);
        X3 = _mm_shuffle_epi32(X3, 0x93);
    }

    _mm_storeu_si128(b+0, _mm_add_epi32(X0, Y0));
    _mm_storeu_si128(b+1, _mm_add_epi32(X1, Y1));
    _mm_storeu_si128(b+2, _mm_add_epi32(X2, Y2));
    _mm_storeu_si128(b+3, _mm_add_epi32(X3, Y3));
}

#else

#define SALSA20_WORD_POS(i) (i)

/**
 * Compute B = Salsa20(B xor Bx xor By), in place, with the given number of rounds.
 * @Bx and @By may be NULL.
 * The words are in native endianess.
 */
static inline void salsa20_core(unsigned rounds, uint32_t B[16], const uint32_t *Bx, const uint32_t *By)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
    unsigned i;

    if (Bx != NULL) {
        for (i=0; i<16; i++)
            B[i] ^= Bx[i];
    }
    if (By != NULL) {
        for (i=0; i<16; i++)
            B[i] ^= By[i];
    }

    x0  = B[0];
    x1  = B[1];
    x2  = B[2];
    x3  = B[3];
    x4  = B[4];
    x5  = B[5];
    x6  = B[6];
    x7  = B[7];
    x8  = B[8];
    x9  = B[9];
    x10 = B[10];
    x11 = B[11];
    x12 = B[12];
    x13 = B[13];
    x14 = B[14];
    x15 = B[15];

    for (i=0; i<rounds; i+=2) {
        SALSA20_DOUBLE_ROUND(SALSA20_ADD32, SALSA20_XOR32, SALSA20_ROTL32,
                             x0, x1, x2, x3, x4, x5, x6, x7,
                             x8, x9, x10, x11, x12, x13, x14, x15);
    }

    B[0]  += x0;
    B[1]  += x1;
    B[2]  += x2;
    B[3]  += x3;
    B[4]  += x4;
    B[5]  += x5;
    B[6]  += x6;
    B[7]  += x7;
    B[8]  += x8;
    B[9]  += x9;
    B[10] += x10;
    B[11] += x11;
    B[12] += x12;
    B[13] += x13;
    B[14] += x14;
    B[15] += x15;
}

#endif /* USE_SSE2 */

#endif /* SALSA20_CORE_H */
