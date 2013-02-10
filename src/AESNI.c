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

#include "Python.h"
#include <wmmintrin.h>

#define MODULE_NAME _AESNI
#define BLOCK_SIZE 16
#define KEY_SIZE 0

#define MAXKC	(256/32)
#define MAXKB	(256/8)
#define MAXNR	14

typedef unsigned char u8;

typedef struct {
	__m128i ek[MAXNR + 1];
	__m128i dk[MAXNR + 1];
	int rounds;
} block_state;

/* Helper functions to expand keys */

static __m128i aes128_keyexpand(__m128i key, __m128i keygened, int shuf)
{
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    keygened = _mm_shuffle_epi32(keygened, shuf);
    return _mm_xor_si128(key, keygened);
}

static __m128i aes192_keyexpand_2(__m128i key, __m128i key2)
{
    key = _mm_shuffle_epi32(key, 0xff);
    key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
    return _mm_xor_si128(key, key2);
}

#define KEYEXP128(K, I) aes128_keyexpand(K, _mm_aeskeygenassist_si128(K, I), 0xff)
#define KEYEXP192(K1, K2, I) aes128_keyexpand(K1, _mm_aeskeygenassist_si128(K2, I), 0x55)
#define KEYEXP192_2(K1, K2) aes192_keyexpand_2(K1, K2)
#define KEYEXP256(K1, K2, I) aes128_keyexpand(K1, _mm_aeskeygenassist_si128(K2, I), 0xff)
#define KEYEXP256_2(K1, K2) aes128_keyexpand(K1, _mm_aeskeygenassist_si128(K2, 0x00), 0xaa)

/* Encryption key setup */
static void aes_key_setup_enc(__m128i rk[], const u8* cipherKey, int keylen)
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
            __m128i temp[2];
            rk[0] = _mm_loadu_si128((const __m128i*) cipherKey);
            rk[1] = _mm_loadu_si128((const __m128i*) (cipherKey+16));
            temp[0] = KEYEXP192(rk[0], rk[1], 0x01);
            temp[1] = KEYEXP192_2(temp[0], rk[1]);
            rk[1] = (__m128i)_mm_shuffle_pd((__m128d)rk[1], (__m128d)temp[0], 0);
            rk[2] = (__m128i)_mm_shuffle_pd((__m128d)temp[0], (__m128d)temp[1], 1);
            rk[3] = KEYEXP192(temp[0], temp[1], 0x02);
            rk[4] = KEYEXP192_2(rk[3], temp[1]);
            temp[0] = KEYEXP192(rk[3], rk[4], 0x04);
            temp[1] = KEYEXP192_2(temp[0], rk[4]);
            rk[4] = (__m128i)_mm_shuffle_pd((__m128d)rk[4], (__m128d)temp[0], 0);
            rk[5] = (__m128i)_mm_shuffle_pd((__m128d)temp[0], (__m128d)temp[1], 1);
            rk[6] = KEYEXP192(temp[0], temp[1], 0x08);
            rk[7] = KEYEXP192_2(rk[6], temp[1]);
            temp[0] = KEYEXP192(rk[6], rk[7], 0x10);
            temp[1] = KEYEXP192_2(temp[0], rk[7]);
            rk[7] = (__m128i)_mm_shuffle_pd((__m128d)rk[7], (__m128d)temp[0], 0);
            rk[8] = (__m128i)_mm_shuffle_pd((__m128d)temp[0], (__m128d)temp[1], 1);
            rk[9] = KEYEXP192(temp[0], temp[1], 0x20);
            rk[10] = KEYEXP192_2(rk[9], temp[1]);
            temp[0] = KEYEXP192(rk[9], rk[10], 0x40);
            temp[1] = KEYEXP192_2(temp[0], rk[10]);
            rk[10] = (__m128i)_mm_shuffle_pd((__m128d)rk[10], (__m128d) temp[0], 0);
            rk[11] = (__m128i)_mm_shuffle_pd((__m128d)temp[0],(__m128d) temp[1], 1);
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
static void aes_key_setup_dec(__m128i dk[], const __m128i ek[], int rounds)
{
    dk[rounds] = ek[0];
    for (int i = 1; i < rounds; ++i) {
        dk[rounds - i] = _mm_aesimc_si128(ek[i]);
    }
    dk[0] = ek[rounds];
}

static void block_init(block_state* self, unsigned char* key, int keylen)
{
	int nr = 0;
	switch (keylen) {
	    case 16: nr = 10; break;
	    case 24: nr = 12; break;
	    case 32: nr = 14; break;
        default:
            PyErr_SetString(PyExc_ValueError,
                "AES key must be either 16, 24, or 32 bytes long");
		    return;
	}
	self->rounds = nr;
	aes_key_setup_enc(self->ek, key, keylen);
    aes_key_setup_dec(self->dk, self->ek, nr);
}

static void block_encrypt(block_state* self, const u8* in, u8* out)
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

static void block_decrypt(block_state* self, const u8* in, u8* out)
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

#include "block_template.c"
