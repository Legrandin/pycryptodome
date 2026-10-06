/* ===================================================================
 *
 * Copyright (c) 2026, Legrandin <helderijs@gmail.com>
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
 * Four independent Keccak-p[1600] states, permuted at the same time
 * with AVX2 intrinsics.
 *
 * Each 256-bit register holds the same 64-bit lane of the 4 states:
 * bits 0-63 belong to state 0, bits 64-127 to state 1, and so on.
 * Since the 4 states are processed with exactly the same operations,
 * the code is the textbook Keccak-p round, applied to vectors.
 *
 * This file is not a module: it must be included after keccak.c,
 * whose round constants it uses, and compiled with AVX2 enabled.
 *
 * See KECCAK_K12.txt for which file includes which, and the resulting modules.
 */

#include <immintrin.h>

/* Rotation offsets of the Rho step, for lane x + 5*y */
static const unsigned rho_offsets[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

/* Rotate each 64-bit word of x to the left by n bits (0 <= n < 64) */
static inline __m256i rol64_x4(__m256i x, unsigned n)
{
    return _mm256_or_si256(_mm256_slli_epi64(x, (int)n),
                           _mm256_srli_epi64(x, (int)(64 - n)));
}

/* Compute (~a & b) ^ c on each bit */
static inline __m256i andnot_xor_x4(__m256i a, __m256i b, __m256i c)
{
    return _mm256_xor_si256(_mm256_andnot_si256(a, b), c);
}

/*
 * The loops inside a round must be unrolled, so that the rotation offsets
 * become constants and the state can stay in registers: without unrolling,
 * this code is slower than the scalar one.
 */
#define UNROLL _Pragma("GCC unroll 5")

static void keccak_function_x4(__m256i A[25], unsigned rounds)
{
    __m256i B[25];
    __m256i C[5];
    __m256i D;
    unsigned round, x, y;

    for (round = KECCAK_ROUNDS - rounds; round < KECCAK_ROUNDS; round++) {

        /* Theta: parity of each column */
        UNROLL
        for (x=0; x<5; x++) {
            C[x] = _mm256_xor_si256(A[x], A[x+5]);
            C[x] = _mm256_xor_si256(C[x], A[x+10]);
            C[x] = _mm256_xor_si256(C[x], A[x+15]);
            C[x] = _mm256_xor_si256(C[x], A[x+20]);
        }

        /* Theta + Rho + Pi: lane (x, y) moves to (y, 2x + 3y) */
        UNROLL
        for (x=0; x<5; x++) {
            D = _mm256_xor_si256(C[(x+4) % 5], rol64_x4(C[(x+1) % 5], 1));
            UNROLL
            for (y=0; y<5; y++) {
                B[y + 5*((2*x + 3*y) % 5)] = rol64_x4(_mm256_xor_si256(A[x + 5*y], D),
                                                      rho_offsets[x + 5*y]);
            }
        }

        /* Chi */
        UNROLL
        for (y=0; y<25; y+=5) {
            UNROLL
            for (x=0; x<5; x++) {
                A[y + x] = andnot_xor_x4(B[y + (x+1) % 5], B[y + (x+2) % 5], B[y + x]);
            }
        }

        /* Iota */
        A[0] = _mm256_xor_si256(A[0], _mm256_set1_epi64x((long long)roundconstants[round]));
    }
}

/*
 * XOR n 64-bit words (n <= 25) into each of the 4 states.
 *
 * in[j] is the input for state j: it points to at least 8*n bytes
 * (with any alignment), read as n little-endian 64-bit words.
 * Word i of in[j] is XOR-ed into lane i of state j.
 */
static void keccak_absorb_x4(__m256i A[25], const uint8_t *in[4], unsigned n)
{
    unsigned i;
    __m256i w;

    for (i=0; i<n; i++) {
        w = _mm256_set_epi64x((long long)LOAD_U64_LITTLE(in[3] + 8*i),
                              (long long)LOAD_U64_LITTLE(in[2] + 8*i),
                              (long long)LOAD_U64_LITTLE(in[1] + 8*i),
                              (long long)LOAD_U64_LITTLE(in[0] + 8*i));
        A[i] = _mm256_xor_si256(A[i], w);
    }
}

/*
 * Write the first n 64-bit words (n <= 25) of each of the 4 states.
 *
 * out[j] is the output for state j: it points to at least 8*n bytes
 * (with any alignment), written as n little-endian 64-bit words.
 * Lane i of state j is written into word i of out[j].
 */
static void keccak_extract_x4(const __m256i A[25], uint8_t *out[4], unsigned n)
{
    unsigned i, j;
    uint64_t w[4];

    for (i=0; i<n; i++) {
        memcpy(w, &A[i], sizeof w);
        for (j=0; j<4; j++) {
            STORE_U64_LITTLE(out[j] + 8*i, w[j]);
        }
    }
}
