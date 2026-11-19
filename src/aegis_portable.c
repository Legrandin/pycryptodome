/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * AEGIS-128L and AEGIS-256 (RFC 10032), for CPUs without AES instructions.
 *
 * The AES round is bitsliced (constant time, no table lookups), as described in
 * F. Denis, "Bitslicing the AEGIS", ePrint 2026/1338, with the barrel-shiftrows
 * layout of A. Adomnicai and T. Peyrin ("Fixslicing AES-like Ciphers", TCHES 2021):
 *  - 8 blocks are the 8 bits (lanes) of every byte;
 *  - each AES row has its own 32-bit words, one per bit of the bytes, in which
 *    ShiftRows is a rotation.
 * With NEON or SSE2, a 128-bit vector holds the four rows of a bit (Section 6.2
 * of the paper). The state is kept as plain blocks: each update converts its 8
 * blocks (6 for AEGIS-256) to the bitsliced form and back, so that only 8 vectors
 * are live in the round, and the keystream is a few XORs.
 * Otherwise, a 64-bit word holds two rows (0 and 2, or 1 and 3), the state stays
 * bitsliced (the rotation of the blocks in an update is a rotation of each byte),
 * the keystream is computed in that form, and the input blocks are converted
 * 8 at a time.
 *
 * The S-box is the smallest circuit of A. Maximov and P. Ekdahl (TCHES 2019).
 */

#include <string.h>
#include "common.h"
#include "endianess.h"
#include "aegis.h"

FAKE_INIT(raw_aegis)

#define AEGIS_PREFIX AEGIS_

/* The words of the bitsliced form */
#if (defined(__aarch64__) || defined(__ARM_NEON)) && defined(__GNUC__) && !defined(__ARM_BIG_ENDIAN)
#define AEGIS_NEON
#define AEGIS_SIMD
#include <arm_neon.h>
typedef uint64_t word __attribute__((vector_size(16)));
#elif defined(USE_SSE2)
#define AEGIS_SSE2
#define AEGIS_SIMD
#if defined(HAVE_INTRIN_H)
#include <intrin.h>
#elif defined(HAVE_X86INTRIN_H)
#include <x86intrin.h>
#elif defined(HAVE_EMMINTRIN_H)
#include <xmmintrin.h>
#include <emmintrin.h>
#endif
#include "sse2_unaligned.h"
typedef __m128i word;
#else
typedef uint64_t word;
#endif

/* Inline the functions of an update, so that the state stays in the registers */
#if defined(__GNUC__)
#define HOT static inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define HOT static __forceinline
#else
#define HOT static inline
#endif

/* Fully unroll a short loop, so that an in-order CPU can interleave the iterations */
#if defined(__GNUC__)
#define UNROLL  _Pragma("GCC unroll 16")
#else
#define UNROLL
#endif

/*
 * The operations on words: ANDN(a, b) is a & ~b, MUX(s, a, b) is s ? a : b,
 * XMUX(s, a, b) is s ? ~a : b, SHL and SHR shift the 64-bit lanes, and
 * MASK(c) has the 32-bit constant c in every 32-bit lane.
 */
#ifdef AEGIS_SSE2
#define XOR(a, b)       _mm_xor_si128(a, b)
#define AND(a, b)       _mm_and_si128(a, b)
#define OR(a, b)        _mm_or_si128(a, b)
#define ANDN(a, b)      _mm_andnot_si128(b, a)
#define NOT(a)          _mm_xor_si128(a, _mm_set1_epi32(-1))
#define MUX(s, a, b)    XOR(b, AND(s, XOR(a, b)))
#define XMUX(s, a, b)   XOR(b, ANDN(s, XOR(a, b)))
#define SHL(w, n)       _mm_slli_epi64(w, n)
#define SHR(w, n)       _mm_srli_epi64(w, n)
#define MASK(c)         _mm_set1_epi32((int)(c))
#else
#define XOR(a, b)       ((a) ^ (b))
#define AND(a, b)       ((a) & (b))
#define OR(a, b)        ((a) | (b))
#define ANDN(a, b)      ((a) & ~(b))
#define NOT(a)          (~(a))
#ifdef AEGIS_NEON
#define MUX(s, a, b)    ((word)vbslq_u8((uint8x16_t)(s), (uint8x16_t)(a), (uint8x16_t)(b)))
#define XMUX(s, a, b)   MUX(s, ~(a), b)
#else
#define MUX(s, a, b)    ((b) ^ ((s) & ((a) ^ (b))))
#define XMUX(s, a, b)   ((b) ^ ((s) & ~((a) ^ (b))))
#endif
#if defined(AEGIS_NEON) && !defined(__aarch64__)
/* Explicit on 32-bit ARM, where GCC shifts vectors of 64-bit integers in the integer registers */
#define SHL(w, n)       ((word)vshlq_n_u64((uint64x2_t)(w), n))
#define SHR(w, n)       ((word)vshrq_n_u64((uint64x2_t)(w), n))
#else
#define SHL(w, n)       ((w) << (n))
#define SHR(w, n)       ((w) >> (n))
#endif
#define MASK(c)         ((uint64_t)(c) * 0x100000001ULL)
#endif

/*
 * The AES S-box on the 8 bits of the bytes (q[k] holds bit k), with the circuit
 * of 102 gates of A. Maximov and P. Ekdahl, "New Circuit Minimization Techniques
 * for Smaller and Faster AES SBoxes", TCHES 2019(4), Appendix D.5 (Listing 7).
 * U0 and R0 are the most significant bits. The NOTs of the NAND, NOR, XNOR and
 * MUX gates of the circuit are moved into the following gates (AND to OR, AND
 * to ANDN, MUX to XMUX), which leaves 4 NOTs.
 */
HOT void bitslice_Sbox(word *q)
{
    const word U0 = q[7];
    const word U1 = q[6];
    const word U2 = q[5];
    const word U3 = q[4];
    const word U4 = q[3];
    const word U5 = q[2];
    const word U6 = q[1];
    const word U7 = q[0];

    /* Top linear layer */
    const word Z24 = XOR(U3, U4);
    const word Q17 = XOR(U1, U7);
    const word Q16 = XOR(U5, Q17);
    const word Q0 = XOR(Z24, Q16);
    const word Z66 = XOR(U1, U6);
    const word Q7 = XOR(Z24, Z66);
    const word Q2 = XOR(U2, Q0);
    const word Q1 = XOR(Q7, Q2);
    const word Q3 = XOR(U0, Q7);
    const word Q4 = XOR(U0, Q2);
    const word Q5 = XOR(U1, Q4);
    const word Q6 = XOR(U2, U3);
    const word Q10 = XOR(Q6, Q7);
    const word Q8 = XOR(U0, Q10);
    const word Q9 = XOR(Q8, Q2);
    const word Q12 = XOR(Z24, Q17);
    const word Q15 = XOR(U7, Q4);
    const word Q13 = XOR(Z24, Q15);
    const word Q14 = XOR(Q15, Q0);

    /* Inversion in GF(2^4) */
    const word T20 = AND(Q6, Q12);
    const word T21 = AND(Q3, Q14);
    const word T22 = AND(Q1, Q16);
    const word T10 = XOR(OR(Q3, Q14), AND(Q0, Q7));
    const word T11 = XOR(OR(Q4, Q13), AND(Q10, U5));
    const word T12 = XOR(OR(Q2, Q17), AND(Q5, Q9));
    const word T13 = XOR(OR(Q8, Q15), AND(Q2, Q17));
    const word X0 = XOR(T10, XOR(T20, T22));
    const word X1 = XOR(T11, XOR(T21, T20));
    const word X2 = XOR(T12, XOR(T21, T22));
    const word X3 = XOR(T13, XOR(T21, AND(Q4, Q13)));
    const word T0 = AND(X0, X2);
    const word T1 = OR(X1, X3);
    const word T2 = XOR(T0, T1);
    const word Y0 = XMUX(X2, T2, X3);
    const word Y2 = XMUX(X0, T2, X1);
    const word T3 = ANDN(X1, X2);
    const word Y1 = XMUX(T2, T3, X3);
    const word T4 = ANDN(X3, X0);
    const word Y3 = XMUX(T2, T4, X1);
    const word Y02 = XOR(Y2, Y0);
    const word Y13 = XOR(Y3, Y1);
    const word Y23 = XOR(Y3, Y2);
    const word Y01 = XOR(Y1, Y0);
    const word Y00 = XOR(Y02, Y13);

    /* Multiplications */
    const word N0 = AND(Y01, U5);
    const word N1 = AND(Y0, Q12);
    const word N2 = AND(Y1, Q0);
    const word N3 = AND(Y23, Q17);
    const word N4 = AND(Y2, Q5);
    const word N5 = AND(Y3, Q15);
    const word N6 = AND(Y13, Q14);
    const word N7 = AND(Y00, Q16);
    const word N8 = AND(Y02, Q13);
    const word N9 = AND(Y01, Q7);
    const word N10 = AND(Y0, Q10);
    const word N11 = AND(Y1, Q6);
    const word N12 = AND(Y23, Q2);
    const word N13 = AND(Y2, Q9);
    const word N14 = AND(Y3, Q8);
    const word N15 = AND(Y13, Q3);
    const word N16 = AND(Y00, Q1);
    const word N17 = AND(Y02, Q4);

    /* Bottom linear layer, with the affine constant */
    const word H0 = XOR(N1, N5);
    const word H1 = XOR(N4, H0);
    const word R2 = XOR(N2, H1);
    const word H2 = XOR(N9, N15);
    const word H3 = XOR(N11, N17);
    const word R6 = XOR(H2, H3);
    const word H4 = XOR(N11, N14);
    const word H5 = XOR(N9, N12);
    const word R5 = XOR(H4, H5);
    const word H6 = XOR(N16, H2);
    const word H7 = XOR(R2, R6);
    const word H8 = XOR(N10, H7);
    const word R7 = XOR(H6, H8);
    const word H9 = XOR(N8, H1);
    const word H10 = XOR(N13, H8);
    const word R3 = XOR(H5, H10);
    const word H11 = XOR(H9, H10);
    const word H12 = XOR(N7, H11);
    const word H13 = XOR(H4, H12);
    const word R4 = XOR(N1, H13);
    const word H14 = XOR(N0, R7);
    const word H15 = XOR(H9, H14);
    const word H16 = XOR(H7, H15);
    const word R1 = XOR(N6, H16);
    const word H17 = XOR(N4, H14);
    const word H18 = XOR(N3, H17);
    const word R0 = XOR(H13, H18);

    q[7] = R0;
    q[6] = NOT(R1);
    q[5] = NOT(R2);
    q[4] = R3;
    q[3] = R4;
    q[2] = R5;
    q[1] = NOT(R6);
    q[0] = NOT(R7);
}

/* Exchange the bits of a in mask << n with the bits of b in mask */
#define SWAPMOVE(a, b, mask, n) do {                            \
        word t_ = AND(XOR(b, SHR(a, n)), MASK(mask));           \
        b = XOR(b, t_);                                         \
        a = XOR(a, SHL(t_, n));                                 \
    } while (0)

/*
 * Transpose the block index (word) and the bit index (lane) of the bytes
 * of 8 words; it is its own inverse.
 */
HOT void bit_stage(word *x)
{
    unsigned j;

    UNROLL
    for (j = 0; j < 4; j++)
        SWAPMOVE(x[j], x[j + 4], 0x0F0F0F0F, 4);
    UNROLL
    for (j = 0; j < 4; j++)                         /* 0, 1, 4, 5 */
        SWAPMOVE(x[j + (j & 2)], x[j + (j & 2) + 2], 0x33333333, 2);
    UNROLL
    for (j = 0; j < 8; j += 2)
        SWAPMOVE(x[j], x[j + 1], 0x55555555, 1);
}

/*
 * AESRound without AddRoundKey, on the 8 blocks.
 * ShiftRows rotates row r by 8r bits towards the LSB.
 * MixColumns: a'[r] = xtime(d[r]) ^ s[r], with d[r] = a[r] ^ a[r+1] and
 * s[r] = a[r+1] ^ a[r+2] ^ a[r+3]; xtime(d) moves bit k-1 of d to bit k,
 * and bit 7 to bits 0, 1, 3 and 4.
 */
HOT void mix_xtime(word *x, const word *d)
{
    unsigned k;

    x[0] = XOR(x[0], d[7]);
    UNROLL
    for (k = 1; k < 8; k++)
        x[k] = XOR(x[k], d[k - 1]);
    x[1] = XOR(x[1], d[7]);
    x[3] = XOR(x[3], d[7]);
    x[4] = XOR(x[4], d[7]);
}

#ifdef AEGIS_SIMD

/*
 * The vectors: an AES block (16 bytes in memory order), and its bitsliced form,
 * with row r in lane r.
 * TO_WORD() and TO_BLOCK() transpose the 4x4 bytes of a block (column-major
 * to row-major, and back).
 * shift_rows() rotates lane r by r bytes (byte i gets byte i + r).
 * LANES1(w) and LANES2(w) have lane r + 1 and r + 2 of w (mod 4) in lane r.
 */
#ifdef AEGIS_NEON

typedef uint8x16_t aes_block;

#define blk_load(p)         vld1q_u8(p)
#define blk_store(p, x)     vst1q_u8(p, x)
#define blk_xor(a, b)       veorq_u8(a, b)
#define blk_and(a, b)       vandq_u8(a, b)

/* Permute the bytes of v (TBL on AArch64, two VTBLs on 32-bit ARM) */
static inline uint8x16_t permute(uint8x16_t v, const uint8_t *idx)
{
#ifdef __aarch64__
    return vqtbl1q_u8(v, vld1q_u8(idx));
#else
    uint8x8x2_t t = { { vget_low_u8(v), vget_high_u8(v) } };

    return vcombine_u8(vtbl2_u8(t, vld1_u8(idx)), vtbl2_u8(t, vld1_u8(idx + 8)));
#endif
}

static const uint8_t transpose_idx[16] = {
    0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15
};

static const uint8_t shift_rows_idx[16] = {
    0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14
};

#define TO_WORD(x)      ((word)permute(x, transpose_idx))
#define TO_BLOCK(w)     permute((uint8x16_t)(w), transpose_idx)
#define shift_rows(w)   ((word)permute((uint8x16_t)(w), shift_rows_idx))
#define LANES1(w)       ((word)vextq_u32((uint32x4_t)(w), (uint32x4_t)(w), 1))
#define LANES2(w)       ((word)vextq_u32((uint32x4_t)(w), (uint32x4_t)(w), 2))
#define ZERO            ((word){ 0, 0 })

#else

typedef __m128i aes_block;

#define blk_load(p)         LOADU_128(p)
#define blk_store(p, x)     STOREU_128(p, x)
#define blk_xor(a, b)       _mm_xor_si128(a, b)
#define blk_and(a, b)       _mm_and_si128(a, b)

HOT __m128i transpose(__m128i v)
{
    /* Bytes 0, 8, 1, 9, ..., 7, 15, then 0, 4, 8, 12, 1, 5, ... */
    v = _mm_unpacklo_epi8(v, _mm_srli_si128(v, 8));
    return _mm_unpacklo_epi8(v, _mm_srli_si128(v, 8));
}

HOT __m128i shift_rows(__m128i w)
{
    /* Lanes 2 and 3 by 16 bits, then lanes 1 and 3 by 8 bits */
    __m128i r;

    w = _mm_shufflehi_epi16(w, _MM_SHUFFLE(2, 3, 0, 1));
    r = _mm_or_si128(_mm_srli_epi32(w, 8), _mm_slli_epi32(w, 24));
    return XOR(w, AND(XOR(w, r), _mm_set_epi32(-1, 0, -1, 0)));
}

#define TO_WORD(x)      transpose(x)
#define TO_BLOCK(w)     transpose(w)
#define LANES1(w)       _mm_shuffle_epi32(w, _MM_SHUFFLE(0, 3, 2, 1))
#define LANES2(w)       _mm_shuffle_epi32(w, _MM_SHUFFLE(1, 0, 3, 2))
#define ZERO            _mm_setzero_si128()

#endif

HOT void bs_round(word *x)
{
    word d[8];
    unsigned k;

    bitslice_Sbox(x);
    UNROLL
    for (k = 0; k < 8; k++) {
        word a = shift_rows(x[k]);
        word a1 = LANES1(a);
        word dk = XOR(a, a1);

        d[k] = dk;
        x[k] = XOR(a1, LANES2(dk));
    }
    mix_xtime(x, d);
}

/* The updates are inlined in the loop over the message blocks */
#define UPDATE_INLINE HOT

/* out[i] = AESRound(in[i], rk[i]) for i < n (6 or 8): the blocks are bitsliced together */
HOT void aes_rounds(aes_block *out, const aes_block *in, const aes_block *rk, unsigned n)
{
    word q[8];
    unsigned b;

    UNROLL
    for (b = 0; b < 8; b++)
        q[b] = b < n ? TO_WORD(in[b]) : ZERO;
    bit_stage(q);
    bs_round(q);
    bit_stage(q);
    UNROLL
    for (b = 0; b < 8; b++)
        if (b < n)
            out[b] = blk_xor(TO_BLOCK(q[b]), rk[b]);
}

#else

/* An AES block, as 16 bytes in memory order */
typedef struct {
    uint64_t w[2];
} aes_block;

static inline aes_block blk_load(const uint8_t *p)
{
    aes_block r;
    memcpy(r.w, p, 16);
    return r;
}

static inline void blk_store(uint8_t *p, aes_block x)
{
    memcpy(p, x.w, 16);
}

static inline aes_block blk_xor(aes_block a, aes_block b)
{
    a.w[0] ^= b.w[0];
    a.w[1] ^= b.w[1];
    return a;
}

/*
 * The bitsliced form of 8 blocks, in which bit b of each byte (lane b) is block b.
 * Each 32-bit half holds bit k of the bytes of one AES row, in which byte c is
 * the AES column c: w[k] holds rows 0 and 2, w[8 + k] holds rows 1 and 3.
 */
typedef struct {
    word w[16];
} sliced;

#define NW      16
#define LANE0   0x0101010101010101ULL
#define LANE04  0x1111111111111111ULL

static inline void swapmove32(uint32_t *a, uint32_t *b, uint32_t mask, unsigned n)
{
    uint32_t t = (*b ^ (*a >> n)) & mask;

    *b ^= t;
    *a ^= t << n;
}

/* Transpose the 4x4 bytes of a block: w[j] (column j) <-> w[r] (row r) */
static void byte_stage(uint32_t *w)
{
    swapmove32(&w[0], &w[1], 0x00FF00FF, 8);
    swapmove32(&w[2], &w[3], 0x00FF00FF, 8);
    swapmove32(&w[0], &w[2], 0x0000FFFF, 16);
    swapmove32(&w[1], &w[3], 0x0000FFFF, 16);
}

/* Convert the blocks at blk[b] into lane b (a NULL pointer is a zero block) */
static void bs_pack(sliced *x, const uint8_t *const *blk)
{
    uint32_t w[4];
    unsigned b, j;

    for (b = 0; b < 8; b++) {
        UNROLL
        for (j = 0; j < 4; j++)
            w[j] = blk[b] ? LOAD_U32_LITTLE(blk[b] + 4*j) : 0;
        byte_stage(w);
        x->w[b] = w[0] | (uint64_t)w[2] << 32;
        x->w[8 + b] = w[1] | (uint64_t)w[3] << 32;
    }
    bit_stage(x->w);
    bit_stage(x->w + 8);
}

/* Convert lane b into the block at out[b] (skipped if NULL); x is overwritten */
static void bs_unpack(uint8_t *const *out, sliced *x)
{
    uint32_t w[4];
    unsigned b, j;

    bit_stage(x->w);
    bit_stage(x->w + 8);
    for (b = 0; b < 8; b++) {
        if (NULL == out[b])
            continue;
        w[0] = (uint32_t)x->w[b];
        w[2] = (uint32_t)(x->w[b] >> 32);
        w[1] = (uint32_t)x->w[8 + b];
        w[3] = (uint32_t)(x->w[8 + b] >> 32);
        byte_stage(w);
        UNROLL
        for (j = 0; j < 4; j++)
            STORE_U32_LITTLE(out[b] + 4*j, w[j]);
    }
}

#define SWAP_HALVES(x)  (((x) << 32) | ((x) >> 32))

static inline uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

/*
 * The next row of the rows 0 and 2 (in p) is in q, that of the rows 1 and 3
 * is in p with the halves swapped.
 */
HOT void bs_round(sliced *x)
{
    word d0[8], d1[8];
    word *p = x->w, *q = x->w + 8;
    unsigned k;

    bitslice_Sbox(p);
    bitslice_Sbox(q);
    UNROLL
    for (k = 0; k < 8; k++) {
        /* Rows 0 (by 0) and 2 (by 16), rows 1 (by 8) and 3 (by 24) */
        p[k] = (uint32_t)p[k] | (uint64_t)rotr32((uint32_t)(p[k] >> 32), 16) << 32;
        q[k] = rotr32((uint32_t)q[k], 8) | (uint64_t)rotr32((uint32_t)(q[k] >> 32), 24) << 32;
        d0[k] = p[k] ^ q[k];
        d1[k] = q[k] ^ SWAP_HALVES(p[k]);
    }
    UNROLL
    for (k = 0; k < 8; k++) {
        word s0 = d1[k] ^ SWAP_HALVES(q[k]);
        word s1 = SWAP_HALVES(d0[k]) ^ p[k];

        p[k] = s0;
        q[k] = s1;
    }
    mix_xtime(p, d0);
    mix_xtime(q, d1);
}

/* The AEGIS state */
typedef sliced aegis_core;

#define AEGIS_CORE

/*
 * Each byte rotated left by one lane, within lanes 0-7 (AEGIS-128L) or 0-5
 * (the other lanes get unspecified values), or right by one lane
 */
#define ROT8(w)     ((((w) & 0x7F7F7F7F7F7F7F7FULL) << 1) | (((w) & 0x8080808080808080ULL) >> 7))
#define ROT6(w)     ((((w) & 0x1F1F1F1F1F1F1F1FULL) << 1) | (((w) & 0x2020202020202020ULL) >> 5))
#define ROTR8(w)    ((((w) >> 1) & 0x7F7F7F7F7F7F7F7FULL) | (((w) & 0x0101010101010101ULL) << 7))

/*
 * Update (3.3 and 4.3): S'[i] = AESRound(S[i-1], S[i]), with the message blocks
 * in lanes 0 and 4 (AEGIS-128L) or in lane 0 (AEGIS-256) of m.
 * The blocks are rotated (S[i-1] to lane i) before the round, which is the same
 * as after it (Section 4.1). For AEGIS-256 (lanes 0 to 5), lanes 6 and 7 then hold
 * values that are never used: the rotation, the keystream and the tag ignore them.
 */
HOT void bs_update(aegis_core *c, unsigned variant, const sliced *m, sliced *t)
{
    unsigned k;

    if (variant == AEGIS_128L) {
        UNROLL
        for (k = 0; k < NW; k++) {
            t->w[k] = ROT8(c->w[k]);
            c->w[k] ^= m->w[k] & LANE04;
        }
        bs_round(t);
        UNROLL
        for (k = 0; k < NW; k++)
            c->w[k] ^= t->w[k];
    } else {
        UNROLL
        for (k = 0; k < NW; k++) {
            t->w[k] = ROT6(c->w[k]);
            c->w[k] ^= m->w[k] & LANE0;
        }
        bs_round(t);
        UNROLL
        for (k = 0; k < NW; k++)
            c->w[k] ^= t->w[k];
    }
}

/* The keystream of 3.6 (z0 in lane 0, z1 in lane 4) or of 4.6 (z in lane 0) */
static inline word ks_128l(word w)
{
    /* Lane 0: S1 ^ (S2 & S3) ^ S6; lane 4: S5 ^ (S6 & S7) ^ S2 */
    return (((w >> 1) ^ ((w >> 2) & (w >> 3))) & LANE04)
         ^ ((w >> 6) & LANE0) ^ ((w << 2) & (LANE0 << 4));
}

static inline word ks_256(word w)
{
    /* S1 ^ S4 ^ S5 ^ (S2 & S3) */
    return ((w >> 1) ^ (w >> 4) ^ (w >> 5) ^ ((w >> 2) & (w >> 3))) & LANE0;
}

HOT void bs_keystream(sliced *z, const aegis_core *c, unsigned variant)
{
    unsigned k;

    if (variant == AEGIS_128L) {
        UNROLL
        for (k = 0; k < NW; k++)
            z->w[k] = ks_128l(c->w[k]);
    } else {
        UNROLL
        for (k = 0; k < NW; k++)
            z->w[k] = ks_256(c->w[k]);
    }
}

static void core_load(aegis_core *c, unsigned variant, const aes_block *S)
{
    uint8_t b[128];
    const uint8_t *blk[8];
    unsigned i;

    for (i = 0; i < 8; i++) {
        blk_store(b + 16*i, S[i]);
        blk[i] = (variant == AEGIS_256 && i >= 6) ? NULL : b + 16*i;
    }
    bs_pack(c, blk);
    wipe(b, sizeof b);
}

static void core_store(aes_block *S, const aegis_core *c, unsigned variant)
{
    uint8_t b[128];
    uint8_t *blk[8];
    sliced x = *c;
    unsigned i;

    (void)variant;
    for (i = 0; i < 8; i++)
        blk[i] = b + 16*i;
    bs_unpack(blk, &x);
    for (i = 0; i < 8; i++)
        S[i] = blk_load(b + 16*i);
    wipe(&x, sizeof x);
    wipe(b, sizeof b);
}

static void core_absorb(aegis_core *c, unsigned variant, const uint8_t *p)
{
    const uint8_t *blk[8] = { NULL };
    sliced m, t;

    blk[0] = p;
    if (variant == AEGIS_128L)
        blk[4] = p + 16;
    bs_pack(&m, blk);
    bs_update(c, variant, &m, &t);
    wipe(&m, sizeof m);
    wipe(&t, sizeof t);
}

static void core_keystream(const aegis_core *c, unsigned variant, uint8_t *ks)
{
    uint8_t *blk[8] = { NULL };
    sliced z;

    blk[0] = ks;
    if (variant == AEGIS_128L)
        blk[4] = ks + 16;
    bs_keystream(&z, c, variant);
    bs_unpack(blk, &z);
    wipe(&z, sizeof z);
}

/*
 * Up to 128 bytes at a time (4 updates of AEGIS-128L, 8 of AEGIS-256): the input
 * blocks are converted together, and so is the keystream. The blocks of update u
 * are in lane u (and in lane 4 + u for the second block of AEGIS-128L).
 * When decrypting, the plaintext absorbed by the state is the converted ciphertext
 * XOR the keystream (the conversion is linear).
 */
static size_t core_crypt(aegis_core *c, unsigned variant,
                         const uint8_t *in, uint8_t *out, size_t len, int decrypt)
{
    unsigned bpu = variant == AEGIS_128L ? 2 : 1;       /* Blocks per update */
    uint64_t dmask = decrypt ? ~(uint64_t)0 : 0;
    sliced s, x, t, m;
    size_t done = 0;

    /* A local copy of the state, which the output pointer cannot alias */
    s = *c;
    while (len - done >= 16*bpu) {
        size_t left = (len - done) / (16*bpu);
        unsigned n = left >= 8/bpu ? 8/bpu : (unsigned)left;   /* Updates */
        const uint8_t *src[8];
        uint8_t *dst[8];
        unsigned u, k, lane;

        /*
         * Update u takes lane u (and 4 + u for AEGIS-128L): the keystream
         * is added in lane 0 (and 4), then the lanes of x are rotated by one.
         * After n updates, the block of lane L is in lane L - n (mod 8).
         */
        for (lane = 0; lane < 8; lane++) {
            size_t pos;

            u = lane & (8/bpu - 1);
            pos = done + 16*(bpu*u + lane / (8/bpu));
            src[lane] = u < n ? in + pos : NULL;
            dst[(lane - n) & 7] = u < n && NULL != out ? out + pos : NULL;
        }
        bs_pack(&x, src);
        for (u = 0; u < n; u++) {
            bs_keystream(&t, &s, variant);
            UNROLL
            for (k = 0; k < NW; k++) {
                m.w[k] = x.w[k] ^ (t.w[k] & dmask);     /* The plaintext */
                x.w[k] = ROTR8(x.w[k] ^ t.w[k]);
            }
            bs_update(&s, variant, &m, &t);
        }
        bs_unpack(dst, &x);
        done += 16*bpu*n;
    }
    *c = s;

    wipe(&s, sizeof s);
    wipe(&x, sizeof x);
    wipe(&t, sizeof t);
    wipe(&m, sizeof m);
    return done;
}

#endif

#include "aegis.c"
