/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The memory-hard part of Argon2 (argon2.c), with the compression function G
 * computed with AVX2, 4 words at a time. This module is compiled with AVX2,
 * BMI1 and BMI2 enabled, and it can only be loaded on a CPU that supports all
 * three. BMI1 and BMI2 are not used, but they come with the same compiler
 * flags and CPU check as the other *_avx2_bmi2 modules.
 *
 * Everything else, including the macros GB_SIMD and P_SIMD, comes from
 * argon2.c, included first.
 */

#define ARGON2_MODULE argon2_core_avx2_bmi2
#define ARGON2_AVX2
#include "argon2.c"

#include <immintrin.h>

/* a + b + 2 * trunc(a) * trunc(b), on each word */
static inline __m256i blamka(__m256i a, __m256i b)
{
    __m256i p = _mm256_mul_epu32(a, b);
    return _mm256_add_epi64(_mm256_add_epi64(a, b), _mm256_add_epi64(p, p));
}

#define XOR(a, b)   _mm256_xor_si256(a, b)
#define ROTR32(x)   _mm256_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1))
#define ROTR24(x)   _mm256_shuffle_epi8(x, rot24)
#define ROTR16(x)   _mm256_shuffle_epi8(x, rot16)
#define ROTR63(x)   _mm256_xor_si256(_mm256_srli_epi64(x, 63), _mm256_add_epi64(x, x))

/*
 * For the rows of the block, each register holds one row of a matrix,
 * and the 8 registers hold two matrices (x0 is a row of the first one,
 * x1 the same row of the second one): the words rotate inside each register.
 */
#define ROTATE_WORDS_1(x)   _mm256_permute4x64_epi64(x, _MM_SHUFFLE(0, 3, 2, 1))
#define ROTATE_WORDS_2(x)   _mm256_permute4x64_epi64(x, _MM_SHUFFLE(1, 0, 3, 2))
#define ROTATE_WORDS_3(x)   _mm256_permute4x64_epi64(x, _MM_SHUFFLE(2, 1, 0, 3))

#define P_TWO_ROWS(a0, b0, c0, d0, a1, b1, c1, d1) do {     \
        GB_SIMD(a0, b0, c0, d0);                            \
        GB_SIMD(a1, b1, c1, d1);                            \
        b0 = ROTATE_WORDS_1(b0); b1 = ROTATE_WORDS_1(b1);   \
        c0 = ROTATE_WORDS_2(c0); c1 = ROTATE_WORDS_2(c1);   \
        d0 = ROTATE_WORDS_3(d0); d1 = ROTATE_WORDS_3(d1);   \
        GB_SIMD(a0, b0, c0, d0);                            \
        GB_SIMD(a1, b1, c1, d1);                            \
        b0 = ROTATE_WORDS_3(b0); b1 = ROTATE_WORDS_3(b1);   \
        c0 = ROTATE_WORDS_2(c0); c1 = ROTATE_WORDS_2(c1);   \
        d0 = ROTATE_WORDS_1(d0); d1 = ROTATE_WORDS_1(d1);   \
    } while (0)

/*
 * For the columns of the block, the 8 registers hold two columns:
 * the first one in the low half of each register, the second one in the
 * high half. In each half, a row (x[0..3]) of a matrix is split across
 * two registers: x[0..1] in x0, and x[2..3] in x1.
 *
 * To rotate the row by one word, (x[0] x[1], x[2] x[3]) becomes
 * (x[1] x[2], x[3] x[0]): each new half takes one word from x0 and one from
 * x1 (BLEND), and then its two words are swapped (SWAP_WORDS).
 */
#define BLEND_01(x, y)  _mm256_blend_epi32(x, y, 0x33)  /* (y[0], x[1], y[2], x[3]) */
#define BLEND_10(x, y)  _mm256_blend_epi32(x, y, 0xCC)  /* (x[0], y[1], x[2], y[3]) */
#define SWAP_WORDS(x)   _mm256_permute4x64_epi64(x, _MM_SHUFFLE(2, 3, 0, 1))

#define ROTATE_ROW_1(x0, x1) do {                       \
        __m256i t0 = SWAP_WORDS(BLEND_01(x0, x1));      \
        x1 = SWAP_WORDS(BLEND_10(x0, x1));              \
        x0 = t0;                                        \
    } while (0)
#define ROTATE_ROW_2(x0, x1) do { __m256i t = x0; x0 = x1; x1 = t; } while (0)
#define ROTATE_ROW_3(x0, x1) do {                       \
        __m256i t0 = SWAP_WORDS(BLEND_10(x0, x1));      \
        x1 = SWAP_WORDS(BLEND_01(x0, x1));              \
        x0 = t0;                                        \
    } while (0)

static void fill_block(const block *prev, const block *ref, block *next, int with_xor)
{
    /* The byte shuffles that rotate each word right by 24 and 16 bits */
    const __m256i rot24 = _mm256_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10,
                                           3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10);
    const __m256i rot16 = _mm256_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9,
                                           2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9);
    __m256i r[32], tmp[32];
    unsigned i;

    for (i=0; i<32; i++) {
        r[i] = XOR(_mm256_loadu_si256((const __m256i*)&prev->v[4*i]),
                   _mm256_loadu_si256((const __m256i*)&ref->v[4*i]));
        tmp[i] = r[i];
        if (with_xor) {
            tmp[i] = XOR(tmp[i], _mm256_loadu_si256((const __m256i*)&next->v[4*i]));
        }
    }

    /* Rows 2i and 2i+1: registers 8i..8i+3 and 8i+4..8i+7 */
    for (i=0; i<4; i++) {
        P_TWO_ROWS(r[8*i+0], r[8*i+1], r[8*i+2], r[8*i+3],
                   r[8*i+4], r[8*i+5], r[8*i+6], r[8*i+7]);
    }

    /* Columns 2i and 2i+1: registers i, i+4, ..., i+28 */
    for (i=0; i<4; i++) {
        P_SIMD(r[i+0],  r[i+4],  r[i+8],  r[i+12],
               r[i+16], r[i+20], r[i+24], r[i+28]);
    }

    for (i=0; i<32; i++) {
        _mm256_storeu_si256((__m256i*)&next->v[4*i], XOR(tmp[i], r[i]));
    }
}
