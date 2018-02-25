/* ===================================================================
 *
 * Copyright (c) 2018, Helder Eijs <helderijs@gmail.com>
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

#include "pycrypto_common.h"
#include <stdio.h>

FAKE_INIT(MODULE_NAME)

#define FUNC_NAME(pf) _PASTE2(MODULE_NAME, pf)

/**
 * SHA-2 as defined in FIPS 180-4 http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

#define CH(x,y,z)       (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ROTR32(n, x)    (((x)>>(n)) | ((x)<<(32-(n))))
#define ROTR64(n, x)    (((x)>>(n)) | ((x)<<(64-(n))))
#define SHR(n,x)        ((x)>>(n))

#if WORD_SIZE==4

/** SHA-224, SHA-256 **/

typedef uint32_t sha2_word_t;

#define SCHEDULE_SIZE 64
#define BLOCK_SIZE 64

#define SIGMA_0_256(x)    (ROTR32(2,x)  ^ ROTR32(13,x) ^ ROTR32(22,x))
#define SIGMA_1_256(x)    (ROTR32(6,x)  ^ ROTR32(11,x) ^ ROTR32(25,x))
#define sigma_0_256(x)    (ROTR32(7,x)  ^ ROTR32(18,x) ^ SHR(3,x))
#define sigma_1_256(x)    (ROTR32(17,x) ^ ROTR32(19,x) ^ SHR(10,x))

static const uint64_t K[SCHEDULE_SIZE] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define SCHEDULE(i) (sigma_1_256(W[i-2]) + W[i-7] + sigma_0_256(W[i-15]) + W[i-16])

#define ROUND(t) do {                                       \
    sha2_word_t T1, T2;                                     \
    T1 = h + SIGMA_1_256(e) + CH(e,f,g) + K[t]  + W[t];     \
    T2 = SIGMA_0_256(a) + MAJ(a,b,c);                       \
    h = g;                                                  \
    g = f;                                                  \
    f = e;                                                  \
    e = d + T1;                                             \
    d = c;                                                  \
    c = b;                                                  \
    b = a;                                                  \
    a = T1 + T2;                                            \
    } while(0)

#elif WORD_SIZE==8

/** SHA-384, SHA-512 **/

typedef uint64_t sha2_word_t;

#define SCHEDULE_SIZE 80
#define BLOCK_SIZE 128

#define SIGMA_0_512(x)    (ROTR64(28,x) ^ ROTR64(34,x) ^ ROTR64(39,x))
#define SIGMA_1_512(x)    (ROTR64(14,x) ^ ROTR64(18,x) ^ ROTR64(41,x))
#define sigma_0_512(x)    (ROTR64(1,x)  ^ ROTR64(8,x)  ^ SHR(7,x))
#define sigma_1_512(x)    (ROTR64(19,x) ^ ROTR64(61,x) ^ SHR(6,x))

static const uint64_t K[SCHEDULE_SIZE] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

#define SCHEDULE(i) (sigma_1_512(W[i-2]) + W[i-7] + sigma_0_512(W[i-15]) + W[i-16])

#define ROUND(t) do {                                       \
    sha2_word_t T1, T2;                                     \
    T1 = h + SIGMA_1_512(e) + CH(e,f,g) + K[t]  + W[t];     \
    T2 = SIGMA_0_512(a) + MAJ(a,b,c);                       \
    h = g;                                                  \
    g = f;                                                  \
    f = e;                                                  \
    e = d + T1;                                             \
    d = c;                                                  \
    c = b;                                                  \
    b = a;                                                  \
    a = T1 + T2;                                            \
    } while(0)

#else
#error Invalid WORD_SIZE
#endif

#define MIN(a,b) (a<b?a:b)

static inline sha2_word_t get_be(const uint8_t *p)
{
    sha2_word_t result;
    int i;

    result = 0;
    for (i=0; i<WORD_SIZE; i++) {
        result = (result << 8) | p[i];
    }
    
    return result;
}

static inline void put_be(sha2_word_t number, uint8_t *p)
{
    int i;

    for (i=0; i<WORD_SIZE; i++) {
        p[WORD_SIZE-1-i] = number >> (i*8);
    }
}

typedef struct t_hash_state {
    sha2_word_t h[8];
    uint8_t buf[BLOCK_SIZE];    /** 16 words **/
    int curlen;                 /** Useful message bytes in buf[] (leftmost) **/
    sha2_word_t totbits[2];     /** Total message length in bits **/
} hash_state;

static int add_bits(hash_state *hs, sha2_word_t bits)
{
    hs->totbits[0] += bits;
    if (hs->totbits[0] >= bits) {
        return 0;
    }

    /** Overflow **/
    hs->totbits[1] += 1;
    if (hs->totbits[1] > 0) {
        return 0;
    }

    return ERR_MAX_DATA;
}

static void sha_compress(hash_state * hs)
{
    sha2_word_t a, b, c, d, e, f, g, h;
    sha2_word_t W[SCHEDULE_SIZE];
    int i;

    /** Words flow in in big-endian mode **/
    for (i=0; i<16; i++) {
        W[i] = get_be(&hs->buf[i*WORD_SIZE]);
    }
    for (;i<SCHEDULE_SIZE; i++) {
        W[i] = SCHEDULE(i);
    }

    a = hs->h[0];
    b = hs->h[1];
    c = hs->h[2];
    d = hs->h[3];
    e = hs->h[4];
    f = hs->h[5];
    g = hs->h[6];
    h = hs->h[7];

    ROUND(0);
    ROUND(1);
    ROUND(2);
    ROUND(3);
    ROUND(4);
    ROUND(5);
    ROUND(6);
    ROUND(7);
    ROUND(8);
    ROUND(9);
    ROUND(10);
    ROUND(11);
    ROUND(12);
    ROUND(13);
    ROUND(14);
    ROUND(15);
    ROUND(16);
    ROUND(17);
    ROUND(18);
    ROUND(19);
    ROUND(20);
    ROUND(21);
    ROUND(22);
    ROUND(23);
    ROUND(24);
    ROUND(25);
    ROUND(26);
    ROUND(27);
    ROUND(28);
    ROUND(29);
    ROUND(30);
    ROUND(31);
    ROUND(32);
    ROUND(33);
    ROUND(34);
    ROUND(35);
    ROUND(36);
    ROUND(37);
    ROUND(38);
    ROUND(39);
    ROUND(40);
    ROUND(41);
    ROUND(42);
    ROUND(43);
    ROUND(44);
    ROUND(45);
    ROUND(46);
    ROUND(47);
    ROUND(48);
    ROUND(49);
    ROUND(50);
    ROUND(51);
    ROUND(52);
    ROUND(53);
    ROUND(54);
    ROUND(55);
    ROUND(56);
    ROUND(57);
    ROUND(58);
    ROUND(59);
    ROUND(60);
    ROUND(61);
    ROUND(62);
    ROUND(63);
#if SCHEDULE_SIZE==80
    ROUND(64);
    ROUND(65);
    ROUND(66);
    ROUND(67);
    ROUND(68);
    ROUND(69);
    ROUND(70);
    ROUND(71);
    ROUND(72);
    ROUND(73);
    ROUND(74);
    ROUND(75);
    ROUND(76);
    ROUND(77);
    ROUND(78);
    ROUND(79);
#endif

    /** compute new intermediate hash **/
    hs->h[0] += a;
    hs->h[1] += b;
    hs->h[2] += c;
    hs->h[3] += d;
    hs->h[4] += e;
    hs->h[5] += f;
    hs->h[6] += g;
    hs->h[7] += h;
}

EXPORT_SYM int FUNC_NAME(_init)(hash_state **shaState)
{
    hash_state *hs;

    if (NULL == shaState) {
        return ERR_NULL;
    }

    *shaState = hs = (hash_state*) calloc(1, sizeof(hash_state));
    if (NULL == hs)
        return ERR_MEMORY;

    hs->curlen = 0;
    hs->totbits[0] = hs->totbits[1] = 0;

    /** Initial intermediate hash value **/
    hs->h[0] = H[0];
    hs->h[1] = H[1];
    hs->h[2] = H[2];
    hs->h[3] = H[3];
    hs->h[4] = H[4];
    hs->h[5] = H[5];
    hs->h[6] = H[6];
    hs->h[7] = H[7];

    return 0;
}

EXPORT_SYM int FUNC_NAME(_destroy)(hash_state *shaState)
{
    free(shaState);
    return 0;
}

EXPORT_SYM int FUNC_NAME(_update)(hash_state *hs, const uint8_t *buf, size_t len)
{
    if (NULL == hs || NULL == buf) {
        return ERR_NULL;
    }

    while (len>0) {
        int btc;

        btc = MIN(BLOCK_SIZE - hs->curlen, (int)len);
        memcpy(&hs->buf[hs->curlen], buf, btc);
        buf += btc;
        hs->curlen += btc;
        len -= btc;

        if (hs->curlen == BLOCK_SIZE) {
            sha_compress(hs);
            hs->curlen = 0;
            if (add_bits(hs, BLOCK_SIZE*8)) {
                return ERR_MAX_DATA;
            }
        }
    }

    return 0;
}

static int sha_finalize(hash_state *hs, uint8_t *hash /** [DIGEST_SIZE] **/)
{
    int left, i;
    uint8_t hash_tmp[WORD_SIZE*8];

    /* remaining length of the message */
    if (add_bits(hs, hs->curlen*8)) {
        return ERR_MAX_DATA;
    }

    /* append the '1' bit */
    /* buf[] is guaranteed to have at least 1 byte free */
    hs->buf[hs->curlen++] = 0x80;

    /** if there are less then 64/128 bits left, just pad with zeroes and compress **/
    left = BLOCK_SIZE - hs->curlen;
    if (left < WORD_SIZE*2) {
        memset(&hs->buf[hs->curlen], 0, left);
        sha_compress(hs);
        hs->curlen = 0;
    }

    /**
     * pad with zeroes and close the block with the bit length
     * encoded as 64-bit integer big endian.
     **/
    left = BLOCK_SIZE - hs->curlen;
    memset(&hs->buf[hs->curlen], 0, left);
    put_be(hs->totbits[1], &hs->buf[BLOCK_SIZE-(2*WORD_SIZE)]);
    put_be(hs->totbits[0], &hs->buf[BLOCK_SIZE-(  WORD_SIZE)]);

    /** compress one last time **/
    sha_compress(hs);

    /** create final hash **/
    for (i=0; i<8; i++) {
        put_be(hs->h[i], &hash_tmp[i*WORD_SIZE]);
    }
    memcpy(hash, hash_tmp, DIGEST_SIZE);

    return 0;
}

EXPORT_SYM int FUNC_NAME(_digest)(const hash_state *shaState, uint8_t digest[DIGEST_SIZE])
{
    hash_state temp;

    if (NULL == shaState) {
        return ERR_NULL;
    }

    temp = *shaState;
    sha_finalize(&temp, digest);
    return 0;
}

EXPORT_SYM int FUNC_NAME(_copy)(const hash_state *src, hash_state *dst)
{
    if (NULL == src || NULL == dst) {
        return ERR_NULL;
    }

    *dst = *src;
    return 0;
}

/**
 * This is a specialized function to efficiently perform the inner loop of PBKDF2-HMAC.
 *
 * - inner, the hash after the inner padded secret has been absorbed
 * - outer, the hash after the outer padded secret has been absorbed
 * - first_hmac, the output of the first HMAC iteration (with salt and counter)
 * - result, the XOR of the HMACs from all iterations
 * - iterations, the total number of PBKDF2 iterations (>0)
 *
 * This function does not change the state of either hash.
 */
EXPORT_SYM int FUNC_NAME(_pbkdf2_hmac_assist)(const hash_state *inner, const hash_state *outer,
                                             const uint8_t first_hmac[DIGEST_SIZE],
                                             uint8_t result[DIGEST_SIZE],
                                             size_t iterations)
{
    hash_state inner_temp, outer_temp;
    size_t i;
    uint8_t last_hmac[DIGEST_SIZE];

    if (NULL == inner || NULL == outer || NULL == first_hmac || NULL == result) {
        return ERR_NULL;
    }

    if (iterations == 0) {
        return ERR_NR_ROUNDS;
    }

    memcpy(result, first_hmac, DIGEST_SIZE);
    memcpy(last_hmac, first_hmac, DIGEST_SIZE);

    for (i=1; i<iterations; i++) {
        int j;

        inner_temp = *inner;
        outer_temp = *outer;

        FUNC_NAME(_update)(&inner_temp, last_hmac, DIGEST_SIZE);
        sha_finalize(&inner_temp, last_hmac);

        /** last_hmac is now the intermediate digest **/

        FUNC_NAME(_update)(&outer_temp, last_hmac, DIGEST_SIZE);
        sha_finalize(&outer_temp, last_hmac);

        for (j=0; j<DIGEST_SIZE; j++) {
            result[j] ^= last_hmac[j];
        }
    }

    return 0;
}

#ifdef MAIN
int main(void)
{
    hash_state *hs;
    const uint8_t tv[] = "The quick brown fox jumps over the lazy dog";
    uint8_t result[DIGEST_SIZE];
    int i;

    FUNC_NAME(_init)(&hs);
    FUNC_NAME(_update)(hs, tv, sizeof tv - 1);
    FUNC_NAME(_digest)(hs, result);
    FUNC_NAME(_destroy)(hs);

    for (i=0; i<sizeof result; i++) {
        printf("%02X", result[i]);
    }
    printf("\n");

    FUNC_NAME(_init)(&hs);
    FUNC_NAME(_digest)(hs, result);
    FUNC_NAME(_destroy)(hs);

    for (i=0; i<sizeof result; i++) {
        printf("%02X", result[i]);
    }
    printf("\n");

    FUNC_NAME(_init)(&hs);
    for (i=0; i<10000000; i++) {
        FUNC_NAME(_update)(hs, tv, sizeof tv - 1);
    }
    FUNC_NAME(_destroy)(hs);

    printf("\n");
}
#endif
