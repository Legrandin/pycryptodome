/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The layout of aegis_portable.c with NEON or SSE2, on 128-bit vectors.
 * This file is not a module: it is included by aegis_portable.c after the type
 * word, and before the S-box, bit_stage() and mix_xtime(), which use the
 * operations on words defined here (see aegis_portable.c).
 */

/*
 * The vectors: an AES block (16 bytes in memory order), and its bitsliced form,
 * with row r in 32-bit element r.
 * TO_WORD() and TO_BLOCK() transpose the 4x4 bytes of a block (column-major
 * to row-major, and back).
 * shift_rows() rotates row r by r bytes (byte i gets byte i + r).
 * ROWS1(w) and ROWS2(w) have rows r + 1 and r + 2 of w (mod 4) in element r.
 */
#ifdef AEGIS_NEON

#define XOR(a, b)       ((a) ^ (b))
#define AND(a, b)       ((a) & (b))
#define OR(a, b)        ((a) | (b))
#define ANDN(a, b)      ((a) & ~(b))
#define NOT(a)          (~(a))
#define MUX(s, a, b)    ((word)vbslq_u8((uint8x16_t)(s), (uint8x16_t)(a), (uint8x16_t)(b)))
#define XMUX(s, a, b)   MUX(s, ~(a), b)
#ifdef __aarch64__
#define SHL(w, n)       ((w) << (n))
#define SHR(w, n)       ((w) >> (n))
#else
/* Explicit on 32-bit ARM, where GCC shifts vectors of 64-bit integers in the integer registers */
#define SHL(w, n)       ((word)vshlq_n_u64((uint64x2_t)(w), n))
#define SHR(w, n)       ((word)vshrq_n_u64((uint64x2_t)(w), n))
#endif
/*
 * MASK(c): the 32-bit constant c in both 32-bit halves of a uint64_t, which
 * the vector operations apply to both 64-bit elements of the word
 */
#define MASK(c)         ((uint64_t)(c) * 0x100000001ULL)

typedef uint8x16_t aes_block;

#define blk_load(p)         vld1q_u8(p)
#define blk_store(p, x)     vst1q_u8(p, x)
#define blk_xor(a, b)       veorq_u8(a, b)
#define blk_and(a, b)       vandq_u8(a, b)

/* Permute the bytes of v (TBL on AArch64, two VTBLs on 32-bit ARM) */
static inline uint8x16_t permute(uint8x16_t v, const uint8_t idx[16])
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
#define ROWS1(w)        ((word)vextq_u32((uint32x4_t)(w), (uint32x4_t)(w), 1))
#define ROWS2(w)        ((word)vextq_u32((uint32x4_t)(w), (uint32x4_t)(w), 2))
#define ZERO            ((word){ 0, 0 })

#elif defined(AEGIS_SSE2)

#define XOR(a, b)       _mm_xor_si128(a, b)
#define AND(a, b)       _mm_and_si128(a, b)
#define OR(a, b)        _mm_or_si128(a, b)
#define ANDN(a, b)      _mm_andnot_si128(b, a)
#define NOT(a)          _mm_xor_si128(a, _mm_set1_epi32(-1))
#define MUX(s, a, b)    XOR(b, AND(s, XOR(a, b)))
#define XMUX(s, a, b)   XOR(b, ANDN(s, XOR(a, b)))
#define SHL(w, n)       _mm_slli_epi64(w, n)
#define SHR(w, n)       _mm_srli_epi64(w, n)
/* MASK(c): the 32-bit constant c in all four 32-bit elements of the word */
#define MASK(c)         _mm_set1_epi32((int)(c))

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
    /* Rows 2 and 3 by 16 bits, then rows 1 and 3 by 8 bits */
    __m128i r;

    w = _mm_shufflehi_epi16(w, _MM_SHUFFLE(2, 3, 0, 1));
    r = _mm_or_si128(_mm_srli_epi32(w, 8), _mm_slli_epi32(w, 24));
    return XOR(w, AND(XOR(w, r), _mm_set_epi32(-1, 0, -1, 0)));
}

#define TO_WORD(x)      transpose(x)
#define TO_BLOCK(w)     transpose(w)
#define ROWS1(w)        _mm_shuffle_epi32(w, _MM_SHUFFLE(0, 3, 2, 1))
#define ROWS2(w)        _mm_shuffle_epi32(w, _MM_SHUFFLE(1, 0, 3, 2))
#define ZERO            _mm_setzero_si128()

#else
#error "aegis_simd.c requires NEON or SSE2"
#endif

/*
 * AESRound without AddRoundKey (SubBytes, ShiftRows, MixColumns)
 * on 8 bitsliced blocks: bit[k] holds bit k of their bytes, row r in element r.
 */
HOT void bitslice_aes_round(word bit[8])
{
    word d[8];
    unsigned k;

    bitslice_Sbox(bit);
    UNROLL
    for (k = 0; k < 8; k++) {
        word row = shift_rows(bit[k]);      /* a[r] */
        word next = ROWS1(row);             /* a[r+1] */

        d[k] = XOR(row, next);
        bit[k] = XOR(next, ROWS2(d[k]));    /* s[r] */
    }
    mix_xtime(bit, d);
}

/* The updates are inlined in the loop over the message blocks */
#define UPDATE_INLINE HOT

/* out[i] = AESRound(in[i], rk[i]) for i < n (6 or 8): the blocks are bitsliced together */
HOT void aes_rounds(aes_block *out, const aes_block *in, const aes_block *rk, unsigned n)
{
    word w[8];
    unsigned b;

    /* Convert from AES column form to AES row form for all 8 blocks */
    UNROLL
    for (b = 0; b < 8; b++)
        w[b] = b < n ? TO_WORD(in[b]) : ZERO;

    /* Convert to bitsliced form */
    bit_stage(w);

    bitslice_aes_round(w);

    /* Convert from bitsliced form */
    bit_stage(w);

    /* Convert from AES row form to AES column form for all 8 blocks */
    /* Also adds the round key */
    UNROLL
    for (b = 0; b < 8; b++)
        if (b < n)
            out[b] = blk_xor(TO_BLOCK(w[b]), rk[b]);
}
