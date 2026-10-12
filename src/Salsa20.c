/*
 * Salsa20.c : Source for the Salsa20 stream cipher.
 *
 * Part of the Python Cryptography Toolkit
 *
 * Contributed by Fabrizio Tarizzo <fabrizio@fabriziotarizzo.org>.
 * Based on the reference implementation by D. J. Bernstein
 * <http://cr.yp.to/snuffle/salsa20/regs/salsa20.c>
 *
 * =======================================================================
 * The contents of this file are dedicated to the public domain.  To the
 * extent that dedication to the public domain is not available, everyone
 * is granted a worldwide, perpetual, royalty-free, non-exclusive license
 * to exercise all rights associated with the contents of this file for
 * any purpose whatsoever.  No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =======================================================================
 */

#include "common.h"
#include "endianess.h"
#include "salsa20_core.h"

/*
 * - if SALSA20_MODULE is defined, the functions are exported from the
 *   Python extension module with that name (default: Salsa20)
 * - if SALSA20_AVX2 is defined, the key stream is computed with AVX2
 *   (see Salsa20_avx2_bmi2.c)
 */
#ifndef SALSA20_MODULE
#define SALSA20_MODULE Salsa20
#endif

FAKE_INIT(SALSA20_MODULE)

#define ROUNDS 20
#define MAX_KEY_SIZE 32

/*
 * With SSE2, the key stream is computed 4 blocks at a time
 * (each 128-bit register holds the same word of the 4 blocks),
 * and with AVX2 8 blocks at a time (in 256-bit registers).
 */
#if defined(SALSA20_AVX2)
#define KS_BLOCKS 8
#elif defined(USE_SSE2)
#define KS_BLOCKS 4
#else
#define KS_BLOCKS 1
#endif
#define KS_SIZE (64*KS_BLOCKS)

/*
 * Ask for the loops to be unrolled (gcc does not at -O2).
 * In salsa20_keystream(), the loops index arrays of SIMD registers:
 * once unrolled, the indices are constants and the arrays can stay in
 * registers (about 6% faster with SSE2, 10% with AVX2).
 */
#define SALSA20_PRAGMA(x) _Pragma(#x)
#if defined(__clang__)
#define UNROLL(n) SALSA20_PRAGMA(unroll n)
#elif defined(__GNUC__)
#define UNROLL(n) SALSA20_PRAGMA(GCC unroll n)
#else
#define UNROLL(n)
#endif

static const uint8_t sigma[16] = "expand 32-byte k";
static const uint8_t tau[16]   = "expand 16-byte k";

typedef struct  {
    uint32_t input[16];             /* Words in the natural order */
    unsigned ks_index;              /* Next unused byte in keystream[] */
    uint8_t  keystream[KS_SIZE];
} stream_state;

#if defined(SALSA20_AVX2)

#include <immintrin.h>

#define SALSA20_ROTL_AVX2(v, c) _mm256_or_si256(_mm256_slli_epi32((v), (c)), _mm256_srli_epi32((v), 32-(c)))

/**
 * Like store_4x4(), for 8 blocks: the low 128-bit lane of each register
 * holds blocks 0..3, the high lane blocks 4..7.
 */
static inline void store_4x8(const __m256i v[4], uint8_t *out)
{
    __m256i a = v[0], b = v[1], c = v[2], d = v[3];
    __m256i t0, t1, t2, t3, r0, r1, r2, r3;

    t0 = _mm256_unpacklo_epi32(a, b);
    t1 = _mm256_unpacklo_epi32(c, d);
    t2 = _mm256_unpackhi_epi32(a, b);
    t3 = _mm256_unpackhi_epi32(c, d);
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

/** Compute the next 8 blocks of key stream **/
static void salsa20_keystream(const uint32_t input[16], uint8_t out[KS_SIZE])
{
    __m256i x[16], y[16];
    uint32_t c = input[8], h = input[9];
    unsigned i;

    UNROLL(16)
    for (i=0; i<16; i++) {
        y[i] = _mm256_set1_epi32((int)input[i]);
    }
    y[8] = _mm256_setr_epi32((int)c, (int)(c+1), (int)(c+2), (int)(c+3),
                             (int)(c+4), (int)(c+5), (int)(c+6), (int)(c+7));
    y[9] = _mm256_setr_epi32((int)h, (int)(h + (c+1 < c)), (int)(h + (c+2 < c)), (int)(h + (c+3 < c)),
                             (int)(h + (c+4 < c)), (int)(h + (c+5 < c)), (int)(h + (c+6 < c)), (int)(h + (c+7 < c)));
    UNROLL(16)
    for (i=0; i<16; i++) {
        x[i] = y[i];
    }

    for (i=0; i<ROUNDS; i+=2) {
        SALSA20_DOUBLE_ROUND(_mm256_add_epi32, _mm256_xor_si256, SALSA20_ROTL_AVX2,
                             x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
                             x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]);
    }

    UNROLL(16)
    for (i=0; i<16; i++) {
        x[i] = _mm256_add_epi32(x[i], y[i]);
    }
    UNROLL(16)
    for (i=0; i<16; i+=4) {
        store_4x8(&x[i], out + 4*i);
    }
}

#elif defined(USE_SSE2)

/**
 * Transpose 4 registers, each with word w (v[0]), w+1 (v[1]), w+2 (v[2]) and w+3 (v[3])
 * of 4 consecutive blocks, and store words w..w+3 of each block.
 *
 * The registers come through a pointer, not by value: on 32-bit x86, MSVC cannot
 * pass more than three vectors by value (error C2719).
 */
static inline void store_4x4(const __m128i v[4], uint8_t *out)
{
    __m128i a = v[0], b = v[1], c = v[2], d = v[3];
    __m128i t0, t1, t2, t3;

    t0 = _mm_unpacklo_epi32(a, b);
    t1 = _mm_unpacklo_epi32(c, d);
    t2 = _mm_unpackhi_epi32(a, b);
    t3 = _mm_unpackhi_epi32(c, d);
    _mm_storeu_si128((__m128i*)(out + 0*64), _mm_unpacklo_epi64(t0, t1));
    _mm_storeu_si128((__m128i*)(out + 1*64), _mm_unpackhi_epi64(t0, t1));
    _mm_storeu_si128((__m128i*)(out + 2*64), _mm_unpacklo_epi64(t2, t3));
    _mm_storeu_si128((__m128i*)(out + 3*64), _mm_unpackhi_epi64(t2, t3));
}

/** Compute the next 4 blocks of key stream (x86 is little-endian) **/
static void salsa20_keystream(const uint32_t input[16], uint8_t out[KS_SIZE])
{
    __m128i x[16], y[16];
    uint32_t c = input[8];
    unsigned i;

    UNROLL(16)
    for (i=0; i<16; i++) {
        y[i] = _mm_set1_epi32((int)input[i]);
    }
    /* Block counters (with the carry into the high word) */
    y[8] = _mm_setr_epi32((int)c, (int)(c+1), (int)(c+2), (int)(c+3));
    y[9] = _mm_setr_epi32((int)input[9],
                          (int)(input[9] + (c+1 < c)),
                          (int)(input[9] + (c+2 < c)),
                          (int)(input[9] + (c+3 < c)));
    UNROLL(16)
    for (i=0; i<16; i++) {
        x[i] = y[i];
    }

    for (i=0; i<ROUNDS; i+=2) {
        SALSA20_DOUBLE_ROUND(_mm_add_epi32, _mm_xor_si128, SALSA20_ROTL_SSE2,
                             x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7],
                             x[8], x[9], x[10], x[11], x[12], x[13], x[14], x[15]);
    }

    UNROLL(16)
    for (i=0; i<16; i++) {
        x[i] = _mm_add_epi32(x[i], y[i]);
    }
    UNROLL(16)
    for (i=0; i<16; i+=4) {
        store_4x4(&x[i], out + 4*i);
    }
}

#else

/** Compute the next block of key stream **/
static void salsa20_keystream(const uint32_t input[16], uint8_t out[KS_SIZE])
{
    uint32_t block[16];
    unsigned i;

    memcpy(block, input, sizeof block);
    salsa20_core(ROUNDS, block, NULL, NULL);
    UNROLL(16)
    for (i=0; i<16; i++) {
        STORE_U32_LITTLE(out + 4*i, block[i]);
    }
}

#endif /* SALSA20_AVX2, USE_SSE2 */

/** out = in xor ks, for len bytes. @in and @out may be the same buffer. **/
static void xor_keystream(uint8_t *out, const uint8_t *in, const uint8_t *ks, size_t len)
{
    size_t i;

    UNROLL(4)
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

EXPORT_SYM int Salsa20_stream_init(uint8_t *key, size_t keylen,
                        uint8_t *nonce, size_t nonce_len,
                        stream_state **pSalsaState)
{
    const uint8_t *constants;
    uint32_t *input;
    stream_state *salsaState;
    unsigned i;

    if (NULL == pSalsaState || NULL == key || NULL == nonce)
        return ERR_NULL;

    if (keylen != 16 && keylen != 32)
        return ERR_KEY_SIZE;
    constants = keylen == 32 ? sigma : tau;

    if (nonce_len != 8)
        return ERR_NONCE_SIZE;

    *pSalsaState = salsaState = calloc(1, sizeof(stream_state));
    if (NULL == salsaState)
        return ERR_MEMORY;

    input = salsaState->input;

    input[0] = LOAD_U32_LITTLE(constants + 0);
    /** Set input[1..4] **/
    for (i=0; i<4; i++)
        input[i+1] = LOAD_U32_LITTLE(key + 4*i);
    input[5] = LOAD_U32_LITTLE(constants + 4);
    input[6] = LOAD_U32_LITTLE(nonce + 0);
    input[7] = LOAD_U32_LITTLE(nonce + 4);
    /* Block counter setup*/
    input[8]  = 0;
    input[9]  = 0;
    input[10] = LOAD_U32_LITTLE(constants + 8);
    /** Set input[11..14] **/
    if (keylen == 32) {
        key += 16;
    }
    for (i=0; i<4; i++)
        input[i+11] = LOAD_U32_LITTLE(key + 4*i);
    input[15] = LOAD_U32_LITTLE(constants + 12);

    salsaState->ks_index = KS_SIZE;
    return 0;
}

EXPORT_SYM int Salsa20_stream_destroy(stream_state *salsaState)
{
    free(salsaState);
    return 0;
}

EXPORT_SYM int Salsa20_stream_encrypt(stream_state *salsaState, const uint8_t in[],
                           uint8_t out[], size_t len)
{
    unsigned ks_index;

    if (NULL == salsaState || NULL == in || NULL == out)
        return ERR_NULL;

    /*
     * Read the position in the key stream only once, and check it:
     * if several threads used the object at once (not supported),
     * the state could be inconsistent, but the key stream must never
     * be read out of bounds.
     */
    ks_index = salsaState->ks_index;
    if (ks_index > KS_SIZE)
        return ERR_STATE;

    while (len > 0) {
        size_t n;

        if (ks_index == KS_SIZE) {
            uint32_t *input = salsaState->input;

            salsa20_keystream(input, salsaState->keystream);
            ks_index = 0;

            /* Increment block counter */
            input[8] += KS_BLOCKS;
            if (input[8] < KS_BLOCKS) {
                input[9]++;
                /* stopping at 2^70 bytes per nonce is user's responsibility */
            }
        }

        n = MIN(len, KS_SIZE - ks_index);
        xor_keystream(out, in, salsaState->keystream + ks_index, n);
        in += n;
        out += n;
        len -= n;
        ks_index += (unsigned)n;
    }

    salsaState->ks_index = ks_index;
    return 0;
}
