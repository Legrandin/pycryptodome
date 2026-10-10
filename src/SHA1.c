/*
 * SPDX-FileCopyrightText: 2018 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include "common.h"
#include "endianess.h"

FAKE_INIT(SHA1)

/**
 * SHA-1 as defined in FIPS 180-4 http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */

#define CH(x,y,z)       ((x & y) ^ (~x & z))            /** 0  <= t <= 19 **/
#define PARITY(x,y,z)   (x ^ y ^ z)                     /** 20 <= t <= 39  and 60 <= t <= 79 **/
#define MAJ(x,y,z)      ((x & y) ^ (x & z) ^ (y & z))   /** 40 <= t <= 59 **/

#define ROTL1(x)        (((x)<<1)  | ((x)>>(32-1)))
#define ROTL5(x)        (((x)<<5)  | ((x)>>(32-5)))
#define ROTL30(x)       (((x)<<30) | ((x)>>(32-30)))

#define Kx  0x5a827999  /** 0  <= t <= 19 **/
#define Ky  0x6ed9eba1  /** 20 <= t <= 39 **/
#define Kz  0x8f1bbcdc  /** 40 <= t <= 59 **/
#define Kw  0xca62c1d6  /** 60 <= t <= 79 **/

/** Compute and update W[t] for t>=16 **/
#define SCHED(t)        (W[t&15]=ROTL1(W[(t-3)&15] ^ W[(t-8)&15] ^ W[(t-14)&15] ^ W[t&15]))

#define ROUND_0_15(t) {                         \
    uint32_t T;                                 \
    T = ROTL5(a) + CH(b,c,d) + e + Kx + W[t];   \
    e = d;                                      \
    d = c;                                      \
    c = ROTL30(b);                              \
    b = a;                                      \
    a = T; }

#define ROUND_16_19(t) {                                \
    uint32_t T;                                         \
    T = ROTL5(a) + CH(b,c,d) + e + Kx + SCHED(t);       \
    e = d;                                              \
    d = c;                                              \
    c = ROTL30(b);                                      \
    b = a;                                              \
    a = T; }

#define ROUND_20_39(t) {                                \
    uint32_t T;                                         \
    T = ROTL5(a) + PARITY(b,c,d) + e + Ky + SCHED(t); \
    e = d;                                              \
    d = c;                                              \
    c = ROTL30(b);                                      \
    b = a;                                              \
    a = T; }

#define ROUND_40_59(t) {                            \
    uint32_t T;                                     \
    T = ROTL5(a) + MAJ(b,c,d) + e + Kz + SCHED(t);  \
    e = d;                                          \
    d = c;                                          \
    c = ROTL30(b);                                  \
    b = a;                                          \
    a = T; }

#define ROUND_60_79(t) {                                \
    uint32_t T;                                         \
    T = ROTL5(a) + PARITY(b,c,d) + e + Kw + SCHED(t);   \
    e = d;                                              \
    d = c;                                              \
    c = ROTL30(b);                                      \
    b = a;                                              \
    a = T; }

#define BLOCK_SIZE 64

#define DIGEST_SIZE (160/8)

typedef struct t_hash_state {
    uint32_t h[5];
    uint8_t buf[BLOCK_SIZE];    /** 64 bytes == 512 bits == sixteen 32-bit words **/
    unsigned curlen;            /** Useful message bytes in buf[] (leftmost) **/
    uint64_t totbits;           /** Total message length in bits **/
} hash_state;

static int add_bits(hash_state *hs, unsigned bits)
{
    /** Maximum message length for SHA-1 is 2**64 bits **/
    hs->totbits += bits;
    return (hs->totbits < bits) ? ERR_MAX_DATA : 0;
}

/**
 * Compress one block, already decoded into sixteen 32-bit words.
 * h_out[] may be the same array as h_in[] or M[].
 */
static void sha_compress_words(const uint32_t h_in[5], uint32_t h_out[5], const uint32_t M[16])
{
    uint32_t a, b, c, d, e;
    uint32_t W[16];

    memcpy(W, M, sizeof W);

    a = h_in[0];
    b = h_in[1];
    c = h_in[2];
    d = h_in[3];
    e = h_in[4];

    /** 0 <= t <= 15 **/
    ROUND_0_15(0);
    ROUND_0_15(1);
    ROUND_0_15(2);
    ROUND_0_15(3);
    ROUND_0_15(4);
    ROUND_0_15(5);
    ROUND_0_15(6);
    ROUND_0_15(7);
    ROUND_0_15(8);
    ROUND_0_15(9);
    ROUND_0_15(10);
    ROUND_0_15(11);
    ROUND_0_15(12);
    ROUND_0_15(13);
    ROUND_0_15(14);
    ROUND_0_15(15);
    /** 16 <= t <= 19 **/
    ROUND_16_19(16);
    ROUND_16_19(17);
    ROUND_16_19(18);
    ROUND_16_19(19);
    /** 20 <= t <= 39 **/
    ROUND_20_39(20);
    ROUND_20_39(21);
    ROUND_20_39(22);
    ROUND_20_39(23);
    ROUND_20_39(24);
    ROUND_20_39(25);
    ROUND_20_39(26);
    ROUND_20_39(27);
    ROUND_20_39(28);
    ROUND_20_39(29);
    ROUND_20_39(30);
    ROUND_20_39(31);
    ROUND_20_39(32);
    ROUND_20_39(33);
    ROUND_20_39(34);
    ROUND_20_39(35);
    ROUND_20_39(36);
    ROUND_20_39(37);
    ROUND_20_39(38);
    ROUND_20_39(39);
    /** 40 <= t <= 59 **/
    ROUND_40_59(40);
    ROUND_40_59(41);
    ROUND_40_59(42);
    ROUND_40_59(43);
    ROUND_40_59(44);
    ROUND_40_59(45);
    ROUND_40_59(46);
    ROUND_40_59(47);
    ROUND_40_59(48);
    ROUND_40_59(49);
    ROUND_40_59(50);
    ROUND_40_59(51);
    ROUND_40_59(52);
    ROUND_40_59(53);
    ROUND_40_59(54);
    ROUND_40_59(55);
    ROUND_40_59(56);
    ROUND_40_59(57);
    ROUND_40_59(58);
    ROUND_40_59(59);
    /** 60 <= t <= 79 **/
    ROUND_60_79(60);
    ROUND_60_79(61);
    ROUND_60_79(62);
    ROUND_60_79(63);
    ROUND_60_79(64);
    ROUND_60_79(65);
    ROUND_60_79(66);
    ROUND_60_79(67);
    ROUND_60_79(68);
    ROUND_60_79(69);
    ROUND_60_79(70);
    ROUND_60_79(71);
    ROUND_60_79(72);
    ROUND_60_79(73);
    ROUND_60_79(74);
    ROUND_60_79(75);
    ROUND_60_79(76);
    ROUND_60_79(77);
    ROUND_60_79(78);
    ROUND_60_79(79);

    /** compute new intermediate hash **/
    h_out[0] = h_in[0] + a;
    h_out[1] = h_in[1] + b;
    h_out[2] = h_in[2] + c;
    h_out[3] = h_in[3] + d;
    h_out[4] = h_in[4] + e;
}

static void sha_compress(hash_state * hs)
{
    uint32_t M[16];
    int i;

    /** Words flow in in big-endian mode **/
    for (i=0; i<16; i++) {
        M[i] = LOAD_U32_BIG(&hs->buf[i*4]);
    }

    sha_compress_words(hs->h, hs->h, M);
}

EXPORT_SYM int SHA1_init(hash_state **shaState)
{
    hash_state *hs;

    if (NULL == shaState) {
        return ERR_NULL;
    }

    *shaState = hs = (hash_state*) calloc(1, sizeof(hash_state));
    if (NULL == hs)
        return ERR_MEMORY;

    hs->curlen = 0;
    hs->totbits = 0;

    /** Initial intermediate hash value **/
    hs->h[0] = 0x67452301;
    hs->h[1] = 0xefcdab89;
    hs->h[2] = 0x98badcfe;
    hs->h[3] = 0x10325476;
    hs->h[4] = 0xc3d2e1f0;

    return 0;
}

EXPORT_SYM int SHA1_destroy (hash_state *shaState)
{
    free(shaState);
    return 0;
}

EXPORT_SYM int SHA1_update(hash_state *hs, const uint8_t *buf, size_t len)
{
    unsigned curlen;

    if (NULL == hs || NULL == buf) {
        return ERR_NULL;
    }

    /*
     * Read the position in buf[] only once, and check it: if several
     * threads used the object at once (not supported), the state could
     * be inconsistent, but buf[] must never overflow.
     */
    curlen = hs->curlen;
    if (curlen >= BLOCK_SIZE) {
        return ERR_STATE;
    }

    while (len>0) {
        unsigned btc, left;

        left = BLOCK_SIZE - curlen;
        btc = (unsigned)MIN(left, len);
        memcpy(&hs->buf[curlen], buf, btc);
        buf += btc;
        curlen += btc;
        len -= btc;

        if (curlen == BLOCK_SIZE) {
            sha_compress(hs);
            curlen = 0;
            if (add_bits(hs, BLOCK_SIZE*8)) {
                hs->curlen = 0;
                return ERR_MAX_DATA;
            }
        }
    }

    hs->curlen = curlen;
    return 0;
}

static int sha_finalize(hash_state *hs, uint8_t *hash /** [DIGEST_SIZE] **/)
{
    unsigned left, i;
    uint32_t lo, high;

    /* hs is a private copy, but it may come from an inconsistent state */
    if (hs->curlen >= BLOCK_SIZE) {
        return ERR_STATE;
    }

    /* remaining length of the message */
    if (add_bits(hs, hs->curlen*8)) {
        return ERR_MAX_DATA;
    }

    /* append the '1' bit */
    /* buf[] is guaranteed to have at least 1 byte free */
    hs->buf[hs->curlen++] = 0x80;

    /** if there are less then 64 bits lef, just pad with zeroes and compress **/
    left = BLOCK_SIZE - hs->curlen;
    if (left < 8) {
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
    lo = (uint32_t)(hs->totbits >> 32);
    high = (uint32_t)hs->totbits;
    STORE_U32_BIG(&hs->buf[BLOCK_SIZE-8], lo);
    STORE_U32_BIG(&hs->buf[BLOCK_SIZE-4], high);

    /** compress one last time **/
    sha_compress(hs);

    /** create final hash **/
    for (i=0; i<5; i++) {
        STORE_U32_BIG(hash, hs->h[i]);
        hash += 4;
    }

    return 0;
}

EXPORT_SYM int SHA1_digest(const hash_state *shaState, uint8_t digest[DIGEST_SIZE])
{
    hash_state temp;

    if (NULL == shaState) {
        return ERR_NULL;
    }

    temp = *shaState;
    return sha_finalize(&temp, digest);
}

EXPORT_SYM int SHA1_copy(const hash_state *src, hash_state *dst)
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
EXPORT_SYM int SHA1_pbkdf2_hmac_assist(const hash_state *inner, const hash_state *outer,
                                             const uint8_t first_hmac[DIGEST_SIZE],
                                             uint8_t result[DIGEST_SIZE],
                                             size_t iterations)
{
    uint32_t M[16], result_words[5];
    size_t i;
    unsigned j;

    if (NULL == inner || NULL == outer || NULL == first_hmac || NULL == result) {
        return ERR_NULL;
    }

    if (iterations == 0) {
        return ERR_NR_ROUNDS;
    }

    /** Both hashes must have absorbed exactly one block (the padded HMAC key) **/
    if (inner->curlen != 0 || outer->curlen != 0 ||
        inner->totbits != BLOCK_SIZE*8 || outer->totbits != BLOCK_SIZE*8) {
        return ERR_STATE;
    }

    for (j=0; j<5; j++) {
        result_words[j] = LOAD_U32_BIG(&first_hmac[j*4]);
    }

    /**
     * Each hash in the loop processes a single, already padded block,
     * so we skip the buffering logic and call the compression function directly.
     **/
    memset(M, 0, sizeof M);
    memcpy(M, result_words, sizeof result_words);
    M[5] = 0x80000000U;
    M[15] = (BLOCK_SIZE + DIGEST_SIZE)*8;

    for (i=1; i<iterations; i++) {

        /** Inner hash **/
        sha_compress_words(inner->h, M, M);

        /** Outer hash **/
        sha_compress_words(outer->h, M, M);

        for (j=0; j<5; j++) {
            result_words[j] ^= M[j];
        }
    }

    for (j=0; j<5; j++) {
        STORE_U32_BIG(&result[j*4], result_words[j]);
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

    SHA1_init(&hs);
    SHA1_update(hs, tv, sizeof tv - 1);
    SHA1_digest(hs, result);
    SHA1_destroy(hs);

    for (i=0; i<sizeof result; i++) {
        printf("%02X", result[i]);
    }
    printf("\n");

    SHA1_init(&hs);
    SHA1_digest(hs, result);
    SHA1_destroy(hs);

    for (i=0; i<sizeof result; i++) {
        printf("%02X", result[i]);
    }
    printf("\n");

    SHA1_init(&hs);
    for (i=0; i<10000000; i++) {
        SHA1_update(hs, tv, sizeof tv - 1);
    }
    SHA1_destroy(hs);

    printf("\n");
}
#endif
