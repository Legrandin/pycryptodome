/*
 *  AESNI.c: AES using AES-NI instructions
 *
 * Written in 2013 by Sebastian Ramacher <sebastian@ramacher.at>
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain.  To
 * the extent that dedication to the public domain is not available,
 * everyone is granted a worldwide, perpetual, royalty-free,
 * non-exclusive license to exercise all rights associated with the
 * contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ===================================================================
 */

#include "pycrypto_common.h"
#include "block_base.h"
#include <wmmintrin.h>
#include <stdlib.h>

FAKE_INIT(raw_aesni)

#define MODULE_NAME AESNI
#define BLOCK_SIZE 16
#define KEY_SIZE 0

#define MAXKC (256/32)
#define MAXKB (256/8)
#define MAXNR 14

#define ALIGNMENT 16

typedef struct {
    /** Both ek and dk points into the buffer and are aligned to the 16 byte boundary **/
    __m128i* ek;
    __m128i* dk;
    int rounds;

    uint8_t buffer[(MAXNR+1)*sizeof(__m128i)*2 + ALIGNMENT];
} block_state;

/* Helper functions to expand keys */

static __m128i aes128_keyexpand(__m128i key)
{
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, _mm_slli_si128(key, 4));
}

static __m128i aes192_keyexpand_2(__m128i key, __m128i key2)
{
    key = _mm_shuffle_epi32(key, 0xff);
    key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
    return _mm_xor_si128(key, key2);
}

#define KEYEXP128_H(K1, K2, I, S) _mm_xor_si128(aes128_keyexpand(K1), \
        _mm_shuffle_epi32(_mm_aeskeygenassist_si128(K2, I), S))

#define KEYEXP128(K, I) KEYEXP128_H(K, K, I, 0xff)
#define KEYEXP192(K1, K2, I) KEYEXP128_H(K1, K2, I, 0x55)
#define KEYEXP192_2(K1, K2) aes192_keyexpand_2(K1, K2)
#define KEYEXP256(K1, K2, I)  KEYEXP128_H(K1, K2, I, 0xff)
#define KEYEXP256_2(K1, K2) KEYEXP128_H(K1, K2, 0x00, 0xaa)

#define SHUFFLE128_0(a, b)      \
    _mm_castpd_si128(           \
      _mm_shuffle_pd(           \
        _mm_castsi128_pd(a),    \
        _mm_castsi128_pd(b),    \
        0))

#define SHUFFLE128_1(a, b)      \
    _mm_castpd_si128(           \
      _mm_shuffle_pd(           \
        _mm_castsi128_pd(a),    \
        _mm_castsi128_pd(b),    \
        1))

/* Encryption key setup */
static void aes_key_setup_enc(__m128i *rk, const uint8_t* cipherKey, int keylen)
{
    switch (keylen) {
        case 16:
        {
            /* 128 bit key setup */
            rk[0] = _mm_loadu_si128((const __m128i*) cipherKey);
            rk[1] = KEYEXP128(rk[0], 0x01);
            rk[2] = KEYEXP128(rk[1], 0x02);
            rk[3] = KEYEXP128(rk[2], 0x04);
            rk[4] = KEYEXP128(rk[3], 0x08);
            rk[5] = KEYEXP128(rk[4], 0x10);
            rk[6] = KEYEXP128(rk[5], 0x20);
            rk[7] = KEYEXP128(rk[6], 0x40);
            rk[8] = KEYEXP128(rk[7], 0x80);
            rk[9] = KEYEXP128(rk[8], 0x1B);
            rk[10] = KEYEXP128(rk[9], 0x36);
            break;
        }
        case 24:
        {
            /* 192 bit key setup */
            uint8_t key[24];

            __m128i temp[2];
            memcpy(key, cipherKey, 24);
            rk[0] = _mm_loadu_si128((const __m128i*) key);
            rk[1] = _mm_loadu_si128((const __m128i*) (key+16));
            temp[0] = KEYEXP192(rk[0], rk[1], 0x01);
            temp[1] = KEYEXP192_2(temp[0], rk[1]);
            rk[1] = SHUFFLE128_0(rk[1], temp[0]);
            rk[2] = SHUFFLE128_1(temp[0], temp[1]);
            rk[3] = KEYEXP192(temp[0], temp[1], 0x02);
            rk[4] = KEYEXP192_2(rk[3], temp[1]);
            temp[0] = KEYEXP192(rk[3], rk[4], 0x04);
            temp[1] = KEYEXP192_2(temp[0], rk[4]);
            rk[4] = SHUFFLE128_0(rk[4], temp[0]);
            rk[5] = SHUFFLE128_1(temp[0], temp[1]);
            rk[6] = KEYEXP192(temp[0], temp[1], 0x08);
            rk[7] = KEYEXP192_2(rk[6], temp[1]);
            temp[0] = KEYEXP192(rk[6], rk[7], 0x10);
            temp[1] = KEYEXP192_2(temp[0], rk[7]);
            rk[7] = SHUFFLE128_0(rk[7], temp[0]);
            rk[8] = SHUFFLE128_1(temp[0], temp[1]);
            rk[9] = KEYEXP192(temp[0], temp[1], 0x20);
            rk[10] = KEYEXP192_2(rk[9], temp[1]);
            temp[0] = KEYEXP192(rk[9], rk[10], 0x40);
            temp[1] = KEYEXP192_2(temp[0], rk[10]);
            rk[10] = SHUFFLE128_0(rk[10], temp[0]);
            rk[11] = SHUFFLE128_1(temp[0], temp[1]);
            rk[12] = KEYEXP192(temp[0], temp[1], 0x80);
            break;
        }
        case 32:
        {
            /* 256 bit key setup */
            rk[0] = _mm_loadu_si128((const __m128i*) cipherKey);
            rk[1] = _mm_loadu_si128((const __m128i*) (cipherKey+16));
            rk[2] = KEYEXP256(rk[0], rk[1], 0x01);
            rk[3] = KEYEXP256_2(rk[1], rk[2]);
            rk[4] = KEYEXP256(rk[2], rk[3], 0x02);
            rk[5] = KEYEXP256_2(rk[3], rk[4]);
            rk[6] = KEYEXP256(rk[4], rk[5], 0x04);
            rk[7] = KEYEXP256_2(rk[5], rk[6]);
            rk[8] = KEYEXP256(rk[6], rk[7], 0x08);
            rk[9] = KEYEXP256_2(rk[7], rk[8]);
            rk[10] = KEYEXP256(rk[8], rk[9], 0x10);
            rk[11] = KEYEXP256_2(rk[9], rk[10]);
            rk[12] = KEYEXP256(rk[10], rk[11], 0x20);
            rk[13] = KEYEXP256_2(rk[11], rk[12]);
            rk[14] = KEYEXP256(rk[12], rk[13], 0x40);
            break;
        }
    }
}

/* Decryption key setup */
static void aes_key_setup_dec(__m128i *dk, const __m128i *ek, int rounds)
{
    int i;

    dk[rounds] = ek[0];
    for (i = 1; i < rounds; ++i) {
        dk[rounds - i] = _mm_aesimc_si128(ek[i]);
    }
    dk[0] = ek[rounds];
}

static int block_init(block_state* self, unsigned char* key, int keylen)
{
    int nr = 0;
    int offset;

    switch (keylen) {
        case 16: nr = 10; break;
        case 24: nr = 12; break;
        case 32: nr = 14; break;
        default:
            return ERR_NR_ROUNDS;
    }

    /* ensure that self->ek and self->dk are aligned to 16 byte boundaries */
    offset = ALIGNMENT - ((uintptr_t)self->buffer & (ALIGNMENT-1));
    self->ek = (__m128i*)((uint8_t*)self->buffer + offset);
    self->dk = (__m128i*)((uint8_t*)self->ek + (MAXNR+1)*sizeof(__m128i));

    self->rounds = nr;
    aes_key_setup_enc(self->ek, key, keylen);
    aes_key_setup_dec(self->dk, self->ek, nr);

    return 0;
}

static void block_finalize(block_state* self)
{
    memset(self, 0, sizeof(*self));
}

static void block_encrypt(block_state* self, const uint8_t* in, uint8_t* out)
{
    __m128i m = _mm_loadu_si128((const __m128i*) in);
    /* first 9 rounds */
    m = _mm_xor_si128(m, self->ek[0]);
    m = _mm_aesenc_si128(m, self->ek[1]);
    m = _mm_aesenc_si128(m, self->ek[2]);
    m = _mm_aesenc_si128(m, self->ek[3]);
    m = _mm_aesenc_si128(m, self->ek[4]);
    m = _mm_aesenc_si128(m, self->ek[5]);
    m = _mm_aesenc_si128(m, self->ek[6]);
    m = _mm_aesenc_si128(m, self->ek[7]);
    m = _mm_aesenc_si128(m, self->ek[8]);
    m = _mm_aesenc_si128(m, self->ek[9]);
    if (self->rounds != 10) {
        /* two additional rounds for AES-192/256 */
        m = _mm_aesenc_si128(m, self->ek[10]);
        m = _mm_aesenc_si128(m, self->ek[11]);
        if (self->rounds == 14) {
            /* another two additional rounds for AES-256 */
            m = _mm_aesenc_si128(m, self->ek[12]);
            m = _mm_aesenc_si128(m, self->ek[13]);
        }
    }
    m = _mm_aesenclast_si128(m, self->ek[self->rounds]);
    _mm_storeu_si128((__m128i*) out, m);
}

static void block_decrypt(block_state* self, const uint8_t* in, uint8_t* out)
{
    __m128i m = _mm_loadu_si128((const __m128i*) in);
    /* first 9 rounds */
    m = _mm_xor_si128(m, self->dk[0]);
    m = _mm_aesdec_si128(m, self->dk[1]);
    m = _mm_aesdec_si128(m, self->dk[2]);
    m = _mm_aesdec_si128(m, self->dk[3]);
    m = _mm_aesdec_si128(m, self->dk[4]);
    m = _mm_aesdec_si128(m, self->dk[5]);
    m = _mm_aesdec_si128(m, self->dk[6]);
    m = _mm_aesdec_si128(m, self->dk[7]);
    m = _mm_aesdec_si128(m, self->dk[8]);
    m = _mm_aesdec_si128(m, self->dk[9]);
    if (self->rounds != 10) {
        /* two additional rounds for AES-192/256 */
        m = _mm_aesdec_si128(m, self->dk[10]);
        m = _mm_aesdec_si128(m, self->dk[11]);
        if (self->rounds == 14) {
            /* another two additional rounds for AES-256 */
            m = _mm_aesdec_si128(m, self->dk[12]);
            m = _mm_aesdec_si128(m, self->dk[13]);
        }
    }
    m = _mm_aesdeclast_si128(m, self->dk[self->rounds]);
    _mm_storeu_si128((__m128i*) out, m);
}

#include "block_common.c"
