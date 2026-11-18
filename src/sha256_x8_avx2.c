/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The SHA-256 compression function (FIPS 180-4, Section 6.2.2) for
 * eight independent blocks at once, with AVX2 intrinsics.
 *
 * Each 256-bit register holds the same 32-bit word of the 8 computations:
 * bits 0-31 belong to block 0, bits 32-63 to block 1, and so on.
 * Since the 8 blocks are processed with exactly the same operations,
 * the code is the textbook SHA-256 round, applied to vectors.
 *
 * This file is not a module: it must be included by a file
 * compiled with AVX2 enabled (see slhdsa.c).
 */

#include <immintrin.h>

static const uint32_t sha256_x8_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Rotate each 32-bit word of x to the right by n bits (0 < n < 32) */
#define ROTR_X8(x, n)   _mm256_or_si256(_mm256_srli_epi32(x, n), _mm256_slli_epi32(x, 32 - (n)))

#define XOR3_X8(a, b, c) _mm256_xor_si256(_mm256_xor_si256(a, b), c)

/* The functions of FIPS 180-4, Section 4.1.2 */
#define BSIG0_X8(x)     XOR3_X8(ROTR_X8(x, 2), ROTR_X8(x, 13), ROTR_X8(x, 22))
#define BSIG1_X8(x)     XOR3_X8(ROTR_X8(x, 6), ROTR_X8(x, 11), ROTR_X8(x, 25))
#define SSIG0_X8(x)     XOR3_X8(ROTR_X8(x, 7), ROTR_X8(x, 18), _mm256_srli_epi32(x, 3))
#define SSIG1_X8(x)     XOR3_X8(ROTR_X8(x, 17), ROTR_X8(x, 19), _mm256_srli_epi32(x, 10))
#define CH_X8(x, y, z)  _mm256_xor_si256(_mm256_and_si256(x, y), _mm256_andnot_si256(x, z))
#define MAJ_X8(x, y, z) _mm256_or_si256(_mm256_and_si256(x, y), _mm256_and_si256(z, _mm256_or_si256(x, y)))

#define ADD_X8(a, b)    _mm256_add_epi32(a, b)

/*
 * Round t, with W[t mod 16] = W_t: only d and h change
 * (the caller rotates the roles of the 8 working variables)
 */
#define ROUND_X8(a, b, c, d, e, f, g, h, t) do { \
    __m256i T1, T2; \
    T1 = ADD_X8(ADD_X8(h, BSIG1_X8(e)), ADD_X8(CH_X8(e, f, g), \
         ADD_X8(_mm256_set1_epi32((int)sha256_x8_K[t]), W[(t) & 15]))); \
    T2 = ADD_X8(BSIG0_X8(a), MAJ_X8(a, b, c)); \
    d = ADD_X8(d, T1); \
    h = ADD_X8(T1, T2); \
    } while (0)

/* W_t for 16 <= t < 64, in place of W_{t-16} */
#define SCHEDULE_X8(t) do { \
    W[(t) & 15] = ADD_X8(ADD_X8(SSIG1_X8(W[((t) - 2) & 15]), W[((t) - 7) & 15]), \
                         ADD_X8(SSIG0_X8(W[((t) - 15) & 15]), W[(t) & 15])); \
    } while (0)

/*
 * Transpose the 8x8 matrix of 32-bit words in r[0..7]:
 * word j of r[i] becomes word i of r[j]
 */
static inline void transpose_8x8_x8(__m256i r[8])
{
    __m256i t0, t1, t2, t3, t4, t5, t6, t7;
    __m256i u0, u1, u2, u3, u4, u5, u6, u7;

    t0 = _mm256_unpacklo_epi32(r[0], r[1]);
    t1 = _mm256_unpackhi_epi32(r[0], r[1]);
    t2 = _mm256_unpacklo_epi32(r[2], r[3]);
    t3 = _mm256_unpackhi_epi32(r[2], r[3]);
    t4 = _mm256_unpacklo_epi32(r[4], r[5]);
    t5 = _mm256_unpackhi_epi32(r[4], r[5]);
    t6 = _mm256_unpacklo_epi32(r[6], r[7]);
    t7 = _mm256_unpackhi_epi32(r[6], r[7]);

    u0 = _mm256_unpacklo_epi64(t0, t2);
    u1 = _mm256_unpackhi_epi64(t0, t2);
    u2 = _mm256_unpacklo_epi64(t1, t3);
    u3 = _mm256_unpackhi_epi64(t1, t3);
    u4 = _mm256_unpacklo_epi64(t4, t6);
    u5 = _mm256_unpackhi_epi64(t4, t6);
    u6 = _mm256_unpacklo_epi64(t5, t7);
    u7 = _mm256_unpackhi_epi64(t5, t7);

    r[0] = _mm256_permute2x128_si256(u0, u4, 0x20);
    r[1] = _mm256_permute2x128_si256(u1, u5, 0x20);
    r[2] = _mm256_permute2x128_si256(u2, u6, 0x20);
    r[3] = _mm256_permute2x128_si256(u3, u7, 0x20);
    r[4] = _mm256_permute2x128_si256(u0, u4, 0x31);
    r[5] = _mm256_permute2x128_si256(u1, u5, 0x31);
    r[6] = _mm256_permute2x128_si256(u2, u6, 0x31);
    r[7] = _mm256_permute2x128_si256(u3, u7, 0x31);
}

/*
 * Compress eight independent blocks of 64 bytes at once:
 * block[j] from the state h_in[j] (8 words) into h_out[j],
 * which may be the same array as h_in[j].
 */
static void sha256_compress_x8_avx2(const uint32_t *h_in[8], uint32_t *h_out[8],
                                    const uint8_t *block[8])
{
    /* Each 32-bit word is big-endian in the blocks */
    const __m256i bswap = _mm256_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
                                          12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    __m256i W[16], S[8];
    __m256i a, b, c, d, e, f, g, h;
    unsigned j, t;

    /* W[0..7] and W[8..15]: words 0 to 7, then 8 to 15 of each block */
    for (j = 0; j < 8; j++) {
        W[j] = _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i*)(const void*)block[j]), bswap);
        W[j + 8] = _mm256_shuffle_epi8(_mm256_loadu_si256((const __m256i*)(const void*)(block[j] + 32)), bswap);
    }
    transpose_8x8_x8(W);
    transpose_8x8_x8(W + 8);

    for (j = 0; j < 8; j++)
        S[j] = _mm256_loadu_si256((const __m256i*)(const void*)h_in[j]);
    transpose_8x8_x8(S);

    a = S[0]; b = S[1]; c = S[2]; d = S[3];
    e = S[4]; f = S[5]; g = S[6]; h = S[7];

    for (t = 0; t < 64; t += 8) {
        if (t >= 16) {
            SCHEDULE_X8(t);
            SCHEDULE_X8(t + 1);
            SCHEDULE_X8(t + 2);
            SCHEDULE_X8(t + 3);
            SCHEDULE_X8(t + 4);
            SCHEDULE_X8(t + 5);
            SCHEDULE_X8(t + 6);
            SCHEDULE_X8(t + 7);
        }
        ROUND_X8(a, b, c, d, e, f, g, h, t);
        ROUND_X8(h, a, b, c, d, e, f, g, t + 1);
        ROUND_X8(g, h, a, b, c, d, e, f, t + 2);
        ROUND_X8(f, g, h, a, b, c, d, e, t + 3);
        ROUND_X8(e, f, g, h, a, b, c, d, t + 4);
        ROUND_X8(d, e, f, g, h, a, b, c, t + 5);
        ROUND_X8(c, d, e, f, g, h, a, b, t + 6);
        ROUND_X8(b, c, d, e, f, g, h, a, t + 7);
    }

    S[0] = ADD_X8(S[0], a);
    S[1] = ADD_X8(S[1], b);
    S[2] = ADD_X8(S[2], c);
    S[3] = ADD_X8(S[3], d);
    S[4] = ADD_X8(S[4], e);
    S[5] = ADD_X8(S[5], f);
    S[6] = ADD_X8(S[6], g);
    S[7] = ADD_X8(S[7], h);

    transpose_8x8_x8(S);
    for (j = 0; j < 8; j++)
        _mm256_storeu_si256((__m256i*)(void*)h_out[j], S[j]);
}

#undef ROTR_X8
#undef XOR3_X8
#undef BSIG0_X8
#undef BSIG1_X8
#undef SSIG0_X8
#undef SSIG1_X8
#undef CH_X8
#undef MAJ_X8
#undef ADD_X8
#undef ROUND_X8
#undef SCHEDULE_X8
