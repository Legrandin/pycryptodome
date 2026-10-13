/*
 * SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"
#include "endianess.h"

/*
 * - if CHACHA20_MODULE is defined, the functions are exported from the
 *   Python extension module with that name (default: chacha20)
 * - if CHACHA20_AVX2 is defined, the key stream is computed with AVX2
 *   (see chacha20_avx2_bmi2.c)
 */
#ifndef CHACHA20_MODULE
#define CHACHA20_MODULE chacha20
#endif

FAKE_INIT(CHACHA20_MODULE)

#define KEY_SIZE   32

/*
 * With SSE2, the key stream is computed 4 blocks at a time
 * (each 128-bit register holds the same word of the 4 blocks),
 * and with AVX2 8 blocks at a time (in 256-bit registers).
 */
#if defined(CHACHA20_AVX2)
#define KS_BLOCKS 8
#elif defined(USE_SSE2)
#define KS_BLOCKS 4
#else
#define KS_BLOCKS 1
#endif
#define KS_SIZE (64*KS_BLOCKS)

#if defined(CHACHA20_AVX2)
#include <immintrin.h>
#elif defined(USE_SSE2)
#if defined(HAVE_INTRIN_H)
#include <intrin.h>
#elif defined(HAVE_X86INTRIN_H)
#include <x86intrin.h>
#elif defined(HAVE_EMMINTRIN_H)
#include <xmmintrin.h>
#include <emmintrin.h>
#endif
#endif

/*
 * Ask for the loops to be unrolled (gcc does not at -O2):
 * once unrolled, the indices of the arrays of SIMD registers are
 * constants, and the arrays can stay in registers.
 */
#define CHACHA20_PRAGMA(x) _Pragma(#x)
#if defined(__clang__)
#define UNROLL(n) CHACHA20_PRAGMA(unroll n)
#elif defined(__GNUC__)
#define UNROLL(n) CHACHA20_PRAGMA(GCC unroll n)
#else
#define UNROLL(n)
#endif

typedef struct {
    /** Initial state, with the counter of the block after keyStream[] **/
    uint32_t h[16];
    size_t nonceSize;  /** in bytes **/

    /** How many bytes at the beginning of the key stream
      * have already been used.
      */
    unsigned usedKeyStream;

    /** Always computed: the KS_BLOCKS blocks before the counter **/
    uint8_t keyStream[KS_SIZE];
} stream_state;

/*
 * The block counter has 64 bits with a nonce of 8 bytes (h[12] and h[13]),
 * and 32 bits with a nonce of 12 bytes (h[12]). The key stream ends with
 * the block whose counter is the largest value: using the blocks after it
 * would mean reusing the key stream from block 0, so that must fail.
 *
 * keyStream[] always holds the KS_BLOCKS blocks before the counter in h[],
 * and the counter of the first one is a multiple of KS_BLOCKS (1, 4 or 8),
 * which divides 2^32: the last KS_BLOCKS blocks of the key stream end exactly
 * with its last block, and the counter after them is 0.
 */

#define ROTL(q, n)  (((q) << (n)) | ((q) >> (32 - (n))))

#define QR(a, b, c, d) {\
    a+=b; d^=a; d=ROTL(d,16); \
    c+=d; b^=c; b=ROTL(b,12); \
    a+=b; d^=a; d=ROTL(d,8);  \
    c+=d; b^=c; b=ROTL(b,7);  \
}

/** The 20 rounds of ChaCha20 on the state in[], without the final addition **/
static void chacha20_rounds(const uint32_t in[16], uint32_t h[16])
{
    unsigned i;

    memcpy(h, in, 16*sizeof(uint32_t));

    for (i=0; i<10; i++) {
        /** Column round **/
        QR(h[0], h[4], h[ 8], h[12]);
        QR(h[1], h[5], h[ 9], h[13]);
        QR(h[2], h[6], h[10], h[14]);
        QR(h[3], h[7], h[11], h[15]);
        /** Diagonal round **/
        QR(h[0], h[5], h[10], h[15]);
        QR(h[1], h[6], h[11], h[12]);
        QR(h[2], h[7], h[ 8], h[13]);
        QR(h[3], h[4], h[ 9], h[14]);
    }
}

/**
 * High word of the counter of block i of a batch, from block (hi:lo):
 * with a nonce of 8 bytes (wide), the carry goes into the high word.
 * Batches never cross a multiple of 2^32 (they start at a multiple of
 * KS_BLOCKS), so there is no carry in practice.
 **/
#define COUNTER_HIGH(lo, hi, i, wide) ((wide) ? (hi) + ((lo) + (i) < (lo)) : (hi))

#if defined(CHACHA20_AVX2)

#define ADD8(a, b)  _mm256_add_epi32(a, b)
#define XOR8(a, b)  _mm256_xor_si256(a, b)
#define ROTL8_SHIFT(v, c) _mm256_or_si256(_mm256_slli_epi32((v), (c)), _mm256_srli_epi32((v), 32-(c)))

/** The rotations by 16 and 8 bits move whole bytes (with a shuffle) **/
#define QR8(a, b, c, d) do {                                                \
        a = ADD8(a, b); d = XOR8(d, a); d = _mm256_shuffle_epi8(d, rot16);  \
        c = ADD8(c, d); b = XOR8(b, c); b = ROTL8_SHIFT(b, 12);             \
        a = ADD8(a, b); d = XOR8(d, a); d = _mm256_shuffle_epi8(d, rot8);   \
        c = ADD8(c, d); b = XOR8(b, c); b = ROTL8_SHIFT(b, 7);              \
    } while (0)

/**
 * Store 4 registers, each with word w (v[0]), w+1 (v[1]), w+2 (v[2]) and w+3 (v[3])
 * of 8 consecutive blocks: the low 128-bit lane of each register holds
 * blocks 0..3, the high lane blocks 4..7.
 */
static inline void store_4x8(const __m256i v[4], uint8_t *out)
{
    __m256i t0, t1, t2, t3, r0, r1, r2, r3;

    t0 = _mm256_unpacklo_epi32(v[0], v[1]);
    t1 = _mm256_unpacklo_epi32(v[2], v[3]);
    t2 = _mm256_unpackhi_epi32(v[0], v[1]);
    t3 = _mm256_unpackhi_epi32(v[2], v[3]);
    r0 = _mm256_unpacklo_epi64(t0, t1);
    r1 = _mm256_unpackhi_epi64(t0, t1);
    r2 = _mm256_unpacklo_epi64(t2, t3);
    r3 = _mm256_unpackhi_epi64(t2, t3);
    _mm_storeu_si128((__m128i*)(out + 0*64), _mm256_castsi256_si128(r0));
    _mm_storeu_si128((__m128i*)(out + 1*64), _mm256_castsi256_si128(r1));
    _mm_storeu_si128((__m128i*)(out + 2*64), _mm256_castsi256_si128(r2));
    _mm_storeu_si128((__m128i*)(out + 3*64), _mm256_castsi256_si128(r3));
    _mm_storeu_si128((__m128i*)(out + 4*64), _mm256_extracti128_si256(r0, 1));
    _mm_storeu_si128((__m128i*)(out + 5*64), _mm256_extracti128_si256(r1, 1));
    _mm_storeu_si128((__m128i*)(out + 6*64), _mm256_extracti128_si256(r2, 1));
    _mm_storeu_si128((__m128i*)(out + 7*64), _mm256_extracti128_si256(r3, 1));
}

/** Compute 8 blocks of key stream, from the counter in h[] **/
static void chacha20_keystream(const uint32_t h[16], uint64_t counter, size_t nonceSize, uint8_t out[KS_SIZE])
{
    const __m256i rot16 = _mm256_setr_epi8(2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13,
                                           2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13);
    const __m256i rot8 = _mm256_setr_epi8(3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14,
                                          3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14);
    __m256i x[16], y[16];
    uint32_t c = (uint32_t)counter, hi = nonceSize == 8 ? (uint32_t)(counter >> 32) : h[13];
    int wide = nonceSize == 8;
    unsigned i;

    UNROLL(16)
    for (i=0; i<16; i++) {
        y[i] = _mm256_set1_epi32((int)h[i]);
    }
    y[12] = _mm256_setr_epi32((int)c, (int)(c+1), (int)(c+2), (int)(c+3),
                              (int)(c+4), (int)(c+5), (int)(c+6), (int)(c+7));
    y[13] = _mm256_setr_epi32((int)hi,
                              (int)COUNTER_HIGH(c, hi, 1, wide), (int)COUNTER_HIGH(c, hi, 2, wide),
                              (int)COUNTER_HIGH(c, hi, 3, wide), (int)COUNTER_HIGH(c, hi, 4, wide),
                              (int)COUNTER_HIGH(c, hi, 5, wide), (int)COUNTER_HIGH(c, hi, 6, wide),
                              (int)COUNTER_HIGH(c, hi, 7, wide));
    UNROLL(16)
    for (i=0; i<16; i++) {
        x[i] = y[i];
    }

    for (i=0; i<10; i++) {
        QR8(x[0], x[4], x[ 8], x[12]);
        QR8(x[1], x[5], x[ 9], x[13]);
        QR8(x[2], x[6], x[10], x[14]);
        QR8(x[3], x[7], x[11], x[15]);
        QR8(x[0], x[5], x[10], x[15]);
        QR8(x[1], x[6], x[11], x[12]);
        QR8(x[2], x[7], x[ 8], x[13]);
        QR8(x[3], x[4], x[ 9], x[14]);
    }

    UNROLL(16)
    for (i=0; i<16; i++) {
        x[i] = ADD8(x[i], y[i]);
    }
    UNROLL(4)
    for (i=0; i<16; i+=4) {
        store_4x8(&x[i], out + 4*i);
    }
}

#elif defined(USE_SSE2)

#define ADD4(a, b)  _mm_add_epi32(a, b)
#define XOR4(a, b)  _mm_xor_si128(a, b)
#define ROTL4(v, c) _mm_or_si128(_mm_slli_epi32((v), (c)), _mm_srli_epi32((v), 32-(c)))
/** Rotation by 16 bits: swap the two 16-bit halves of each word **/
#define ROTL4_16(v) _mm_shufflehi_epi16(_mm_shufflelo_epi16((v), 0xB1), 0xB1)

#define QR4(a, b, c, d) do {                                    \
        a = ADD4(a, b); d = XOR4(d, a); d = ROTL4_16(d);        \
        c = ADD4(c, d); b = XOR4(b, c); b = ROTL4(b, 12);       \
        a = ADD4(a, b); d = XOR4(d, a); d = ROTL4(d, 8);        \
        c = ADD4(c, d); b = XOR4(b, c); b = ROTL4(b, 7);        \
    } while (0)

/**
 * Transpose 4 registers, each with word w (v[0]), w+1 (v[1]), w+2 (v[2]) and w+3 (v[3])
 * of 4 consecutive blocks, and store words w..w+3 of each block.
 *
 * The registers come through a pointer, not by value: on 32-bit x86, MSVC cannot
 * pass more than three vectors by value (error C2719).
 */
static inline void store_4x4(const __m128i v[4], uint8_t *out)
{
    __m128i t0, t1, t2, t3;

    t0 = _mm_unpacklo_epi32(v[0], v[1]);
    t1 = _mm_unpacklo_epi32(v[2], v[3]);
    t2 = _mm_unpackhi_epi32(v[0], v[1]);
    t3 = _mm_unpackhi_epi32(v[2], v[3]);
    _mm_storeu_si128((__m128i*)(out + 0*64), _mm_unpacklo_epi64(t0, t1));
    _mm_storeu_si128((__m128i*)(out + 1*64), _mm_unpackhi_epi64(t0, t1));
    _mm_storeu_si128((__m128i*)(out + 2*64), _mm_unpacklo_epi64(t2, t3));
    _mm_storeu_si128((__m128i*)(out + 3*64), _mm_unpackhi_epi64(t2, t3));
}

/** Compute 4 blocks of key stream, from the counter in h[] (x86 is little-endian) **/
static void chacha20_keystream(const uint32_t h[16], uint64_t counter, size_t nonceSize, uint8_t out[KS_SIZE])
{
    __m128i x[16], y[16];
    uint32_t c = (uint32_t)counter, hi = nonceSize == 8 ? (uint32_t)(counter >> 32) : h[13];
    int wide = nonceSize == 8;
    unsigned i;

    UNROLL(16)
    for (i=0; i<16; i++) {
        y[i] = _mm_set1_epi32((int)h[i]);
    }
    y[12] = _mm_setr_epi32((int)c, (int)(c+1), (int)(c+2), (int)(c+3));
    y[13] = _mm_setr_epi32((int)hi,
                           (int)COUNTER_HIGH(c, hi, 1, wide),
                           (int)COUNTER_HIGH(c, hi, 2, wide),
                           (int)COUNTER_HIGH(c, hi, 3, wide));
    UNROLL(16)
    for (i=0; i<16; i++) {
        x[i] = y[i];
    }

    for (i=0; i<10; i++) {
        QR4(x[0], x[4], x[ 8], x[12]);
        QR4(x[1], x[5], x[ 9], x[13]);
        QR4(x[2], x[6], x[10], x[14]);
        QR4(x[3], x[7], x[11], x[15]);
        QR4(x[0], x[5], x[10], x[15]);
        QR4(x[1], x[6], x[11], x[12]);
        QR4(x[2], x[7], x[ 8], x[13]);
        QR4(x[3], x[4], x[ 9], x[14]);
    }

    UNROLL(16)
    for (i=0; i<16; i++) {
        x[i] = ADD4(x[i], y[i]);
    }
    UNROLL(4)
    for (i=0; i<16; i+=4) {
        store_4x4(&x[i], out + 4*i);
    }
}

#else

/** Compute the block of key stream with the counter in h[] **/
static void chacha20_keystream(const uint32_t h[16], uint64_t counter, size_t nonceSize, uint8_t out[KS_SIZE])
{
    uint32_t x[16];
    uint32_t c_lo = (uint32_t)counter;
    uint32_t c_hi = nonceSize == 8 ? (uint32_t)(counter >> 32) : h[13];
    unsigned i;

    memcpy(x, h, sizeof x);
    x[12] = c_lo;
    x[13] = c_hi;
    for (i=0; i<10; i++) {
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    x[12] += c_lo;
    x[13] += c_hi;
    for (i=0; i<16; i++) {
        uint32_t sum = x[i] + (i == 12 || i == 13 ? 0 : h[i]);
        STORE_U32_LITTLE(out + 4*i, sum);
    }
}

#endif /* CHACHA20_AVX2, USE_SSE2 */

/** out = in xor ks, for len bytes. @in and @out may be the same buffer. **/
static void xor_keystream(uint8_t *out, const uint8_t *in, const uint8_t *ks, size_t len)
{
    size_t i;

    for (i=0; i+8<=len; i+=8) {
        uint64_t a, b;

        memcpy(&a, in + i, 8);
        memcpy(&b, ks + i, 8);
        a ^= b;
        memcpy(out + i, &a, 8);
    }
    for (; i<len; i++) {
        out[i] = in[i] ^ ks[i];
    }
}

/** Block counter after keyStream[] **/
static uint64_t get_next_counter(const stream_state *state)
{
    if (state->nonceSize == 8)
        return ((uint64_t)state->h[13] << 32) | state->h[12];
    return state->h[12];
}

/** Write the block counter into h[] (of a stream_state, or a copy of it) **/
static void put_counter(uint32_t h[16], size_t nonceSize, uint64_t counter)
{
    h[12] = (uint32_t)counter;
    if (nonceSize == 8)
        h[13] = (uint32_t)(counter >> 32);
}

/** Compute keyStream[] for the KS_BLOCKS blocks from block first, and set the counter after them **/
static void load_batch(stream_state *state, uint64_t first)
{
    /*
     * The counter of the first block is not stored in the state: if several
     * threads used the object at once (not supported), a counter of 0 would
     * look like the end of the key stream
     */
    chacha20_keystream(state->h, first, state->nonceSize, state->keyStream);
    put_counter(state->h, state->nonceSize, first + KS_BLOCKS);
}

/**
 * Return 0 if len more bytes of key stream are available, when ks_avail
 * bytes are left in keyStream[] and next_counter is the counter after it.
 **/
static int check_length(size_t nonceSize, uint64_t next_counter, unsigned ks_avail, size_t len)
{
    uint64_t left;

    if (len <= ks_avail)
        return 0;

    /* Blocks after keyStream[] (none if the counter is 0, after the last block) */
    if (nonceSize == 8) {
        left = 0 - next_counter;
        /* With 2^58 blocks or more, any len fits */
        if (left >= ((uint64_t)1 << 58))
            return 0;
    } else {
        left = (uint32_t)(0 - (uint32_t)next_counter);
    }

    if ((uint64_t)(len - ks_avail) > 64 * left)
        return ERR_MAX_DATA;
    return 0;
}

EXPORT_SYM int chacha20_init(stream_state **pState,
                             const uint8_t *key,
                             size_t keySize,
                             const uint8_t *nonce,
                             size_t nonceSize)
{
    stream_state *hs;
    unsigned i;

    if (NULL == pState || NULL == nonce)
        return ERR_NULL;

    if (NULL == key || keySize != KEY_SIZE)
        return ERR_KEY_SIZE;

    if (nonceSize != 8 && nonceSize != 12 && nonceSize != 16)
        return ERR_NONCE_SIZE;

    *pState = hs = (stream_state*) calloc(1, sizeof(stream_state));
    if (NULL == hs)
        return ERR_MEMORY;

    hs->h[0] = 0x61707865;
    hs->h[1] = 0x3320646e;
    hs->h[2] = 0x79622d32;
    hs->h[3] = 0x6b206574;

    /** Move 256-bit/32-byte key into h[4..11] **/
    for (i=0; i<32/4; i++) {
        hs->h[4+i] = LOAD_U32_LITTLE(key + 4*i);
    }

    switch (nonceSize) {
    case 8: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                bbbbbbbb  BBBBBBBB  nnnnnnnn  nnnnnnnn

                c=constant k=key b=blockcount(low) B=blockcount(high) n=nonce
                */

                /** h[12] remains 0 (offset) **/
                /** h[13] remains 0 (offset) **/
                hs->h[14] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 4);
                break;
                }
    case 12: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

                c=constant k=key b=blockcount n=nonce
                */

                /** h[12] remains 0 (offset) **/
                hs->h[13] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[14] = LOAD_U32_LITTLE(nonce + 4);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 8);
                break;
            }
    case 16: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn

                c=constant k=key n=nonce
                */

                hs->h[12] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[13] = LOAD_U32_LITTLE(nonce + 4);
                hs->h[14] = LOAD_U32_LITTLE(nonce + 8);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 12);
                break;
            }
    default:
             return ERR_NONCE_SIZE;
    }

    hs->nonceSize = nonceSize;

    if (nonceSize == 16) {
        /*
         * HChaCha20: h[12..15] hold the input, and there is no block counter.
         * hchacha20() only calls chacha20_rounds(), and the state cannot be used
         * to encrypt (the key stream stays empty).
         */
        hs->usedKeyStream = KS_SIZE;
    } else {
        /** The key stream from block 0 on **/
        load_batch(hs, 0);
        hs->usedKeyStream = 0;
    }

    return 0;
}

EXPORT_SYM int chacha20_destroy(stream_state *state)
{
    if (NULL == state)
        return ERR_NULL;
    free(state);
    return 0;
}

EXPORT_SYM int chacha20_encrypt(stream_state *state,
                                const uint8_t in[],
                                uint8_t out[],
                                size_t len)
{
    unsigned used;
    int result;

    if (NULL == state || NULL == in || NULL == out)
        return ERR_NULL;

    if ((state->nonceSize != 8) && (state->nonceSize != 12))
        return ERR_NONCE_SIZE;

    /*
     * Read the position in the key stream only once, and check it:
     * if several threads used the object at once (not supported),
     * the state could be inconsistent, but the key stream must never
     * be read out of bounds.
     */
    used = state->usedKeyStream;
    if (used > KS_SIZE)
        return ERR_STATE;

    /* Fail before encrypting anything if the key stream would run out */
    result = check_length(state->nonceSize, get_next_counter(state), KS_SIZE - used, len);
    if (result)
        return result;

    while (len>0) {
        size_t n;

        if (used == KS_SIZE) {
            load_batch(state, get_next_counter(state));
            used = 0;
        }

        n = MIN(len, KS_SIZE - used);
        xor_keystream(out, in, state->keyStream + used, n);
        in += n;
        out += n;
        len -= n;
        used += (unsigned)n;
    }

    state->usedKeyStream = used;
    return 0;
}

EXPORT_SYM int chacha20_seek(stream_state *state,
                             unsigned long block_high,
                             unsigned long block_low,
                             unsigned offset)
{
    uint64_t block;
    unsigned in_batch;

    if (NULL == state)
        return ERR_NULL;

    if ((state->nonceSize != 8) && (state->nonceSize != 12))
        return ERR_NONCE_SIZE;

    if (offset >= 64)
        return ERR_MAX_OFFSET;

    if (block_high > 0xFFFFFFFFUL || block_low > 0xFFFFFFFFUL)
        return ERR_MAX_OFFSET;

    /** With a nonce of 12 bytes, the counter is one word **/
    if (state->nonceSize == 12 && block_high > 0)
        return ERR_MAX_OFFSET;

    /** The KS_BLOCKS blocks that include this one, from a multiple of KS_BLOCKS **/
    block = ((uint64_t)block_high << 32) | block_low;
    in_batch = (unsigned)(block % KS_BLOCKS);
    load_batch(state, block - in_batch);
    state->usedKeyStream = 64*in_batch + offset;

    return 0;
}

/*
 * Encryption with several threads (see ChaCha20.py), like in CTR mode:
 * - chacha20_check() verifies upfront that the data fits in the key stream;
 * - each thread calls chacha20_encrypt_at() on its own part of the data,
 *   which does not change the state (so the threads can share it);
 * - chacha20_skip() then moves the state past all the data.
 */

/** Current position in the key stream: block counter and offset in the block **/
static void get_position(const stream_state *state, unsigned used, uint64_t *block, unsigned *offset)
{
    uint64_t first = get_next_counter(state) - KS_BLOCKS;

    if (state->nonceSize == 12)
        first &= 0xFFFFFFFF;
    *block = first + used / 64;
    *offset = used % 64;
}

/** Move a position forward by len bytes **/
static void add_to_position(uint64_t *block, unsigned *offset, size_t len)
{
    unsigned off = *offset + (unsigned)(len % 64);

    *block += len / 64 + off / 64;
    *offset = off % 64;
}

EXPORT_SYM int chacha20_check(const stream_state *state, size_t len)
{
    unsigned used;

    if (NULL == state)
        return ERR_NULL;
    if ((state->nonceSize != 8) && (state->nonceSize != 12))
        return ERR_NONCE_SIZE;
    used = state->usedKeyStream;
    if (used > KS_SIZE)
        return ERR_STATE;

    return check_length(state->nonceSize, get_next_counter(state), KS_SIZE - used, len);
}

/*
 * Encrypt len bytes at offset bytes after the current position,
 * without changing the state.
 */
EXPORT_SYM int chacha20_encrypt_at(const stream_state *state,
                                   const uint8_t in[],
                                   uint8_t out[],
                                   size_t offset,
                                   size_t len)
{
    uint8_t ks[KS_SIZE];
    uint64_t block;
    unsigned used, off, skip;
    int result;

    if (NULL == state || NULL == in || NULL == out)
        return ERR_NULL;
    if ((state->nonceSize != 8) && (state->nonceSize != 12))
        return ERR_NONCE_SIZE;
    used = state->usedKeyStream;
    if (used > KS_SIZE)
        return ERR_STATE;

    /* The whole range up to offset+len must be in the key stream */
    if (len > (size_t)-1 - offset)
        return ERR_MAX_DATA;
    result = check_length(state->nonceSize, get_next_counter(state), KS_SIZE - used, offset + len);
    if (result)
        return result;

    get_position(state, used, &block, &off);
    add_to_position(&block, &off, offset);

    /* Batches start at a multiple of KS_BLOCKS, like in keyStream[] */
    skip = (unsigned)(64*(block % KS_BLOCKS) + off);
    block -= block % KS_BLOCKS;
    while (len > 0) {
        size_t n;

        chacha20_keystream(state->h, block, state->nonceSize, ks);
        n = MIN(len, KS_SIZE - skip);
        xor_keystream(out + offset, in + offset, ks + skip, n);
        offset += n;
        len -= n;
        block += KS_BLOCKS;
        skip = 0;
    }

    return 0;
}

/*
 * Move the current position forward by len bytes.
 */
EXPORT_SYM int chacha20_skip(stream_state *state, size_t len)
{
    uint64_t block;
    unsigned used, off;
    int result;

    result = chacha20_check(state, len);
    if (result)
        return result;
    if (len == 0)
        return 0;

    used = state->usedKeyStream;
    get_position(state, used, &block, &off);
    add_to_position(&block, &off, len);

    if (off == 0 && block % KS_BLOCKS == 0) {
        /* On a batch boundary (possibly the end of the key stream): keyStream[] is used up */
        put_counter(state->h, state->nonceSize, block);
        state->usedKeyStream = KS_SIZE;
    } else {
        load_batch(state, block - block % KS_BLOCKS);
        state->usedKeyStream = (unsigned)(64*(block % KS_BLOCKS) + off);
    }

    return 0;
}

/*
 * Based on https://tools.ietf.org/html/draft-arciszewski-xchacha-03
 */
EXPORT_SYM int hchacha20(const uint8_t key[KEY_SIZE],
                         const uint8_t nonce16[16],                 /* First 16 bytes of the 24 byte nonce */
                         uint8_t subkey[KEY_SIZE])
{
    stream_state *pState;
    uint32_t h[16];

    if (NULL == key || NULL == nonce16 || NULL == subkey) {
        return ERR_NULL;
    }

    chacha20_init(&pState, key, KEY_SIZE, nonce16, 16);
    if (NULL == pState)
        return ERR_MEMORY;

    chacha20_rounds(pState->h, h);
    /* We only keep first and last row from the new state */
    STORE_U32_LITTLE(subkey + 0,  h[0]);
    STORE_U32_LITTLE(subkey + 4,  h[1]);
    STORE_U32_LITTLE(subkey + 8,  h[2]);
    STORE_U32_LITTLE(subkey + 12, h[3]);
    STORE_U32_LITTLE(subkey + 16, h[12]);
    STORE_U32_LITTLE(subkey + 20, h[13]);
    STORE_U32_LITTLE(subkey + 24, h[14]);
    STORE_U32_LITTLE(subkey + 28, h[15]);
    chacha20_destroy(pState);

    return 0;
}

#ifdef PROFILE
int main(void)
{
    const unsigned data_size = 1024*1024;
    const uint8_t key[32] = "12345678901234561234567890123456";
    const uint8_t nonce[8] = "12345678";
    stream_state *state;
    uint8_t *data;

    data = malloc(data_size);
    for (int i=0; i<data_size; i++) {
        data[i] = (uint8_t) i;
    }

    chacha20_init(&state, key, 32, nonce, 8);

    for (int i=0; i<1024; i++)
        chacha20_encrypt(state, data, data, data_size);

    chacha20_destroy(state);
    free(data);
}
#endif
