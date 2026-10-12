/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * DES and Triple DES (FIPS 46-3, NIST SP 800-67).
 *
 * The implementation runs in constant time: there are no memory accesses
 * at secret addresses and no secret-dependent branches.
 * Each output bit of an S-box is a 64-bit truth table (des_tables.h),
 * and the lookup is a shift by the (secret) 6-bit S-box input.
 */

#include "common.h"
#include "endianess.h"
#include "block_base.h"

#include "des_tables.h"

#ifndef PCT_DES3_MODULE
FAKE_INIT(raw_des)
#define MODULE_NAME DES
#define KEY_SIZE    8
#define NKEYS       1
#else
FAKE_INIT(raw_des3)
#define MODULE_NAME DES3
#define KEY_SIZE    0       /* 16 or 24 bytes, including parity */
#define NKEYS       3
#endif

#define BLOCK_SIZE  8

/* Subkey of each round, as eight 6-bit chunks (one per S-box) */
typedef struct {
    uint8_t k[16][8];
} des_ks;

struct block_state {
    des_ks ks[NKEYS];
};

/* FIPS 46-3, permuted choice 1 (bit 1 is the most significant) */
static const uint8_t PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

/* FIPS 46-3, permuted choice 2 (bit 1 is the most significant) */
static const uint8_t PC2[48] = {
    14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

/* FIPS 46-3, left shifts of C and D for each round */
static const uint8_t SHIFTS[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

static void des_key_schedule(des_ks *ks, const uint8_t key[8])
{
    uint64_t k, cd;
    uint32_t c, d;
    unsigned i, j, round;

    k = LOAD_U64_BIG(key);

    cd = 0;
    for (i=0; i<56; i++) {
        cd = (cd << 1) | ((k >> (64 - PC1[i])) & 1);
    }
    c = (uint32_t)(cd >> 28);
    d = (uint32_t)cd & 0x0FFFFFFF;

    for (round=0; round<16; round++) {
        unsigned s = SHIFTS[round];

        c = ((c << s) | (c >> (28 - s))) & 0x0FFFFFFF;
        d = ((d << s) | (d >> (28 - s))) & 0x0FFFFFFF;
        cd = ((uint64_t)c << 28) | d;

        for (j=0; j<8; j++) {
            uint8_t chunk = 0;

            for (i=0; i<6; i++) {
                chunk = (uint8_t)((chunk << 1) | ((cd >> (56 - PC2[6*j + i])) & 1));
            }
            ks->k[round][j] = chunk;
        }
    }
}

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/*
 * Swap the bits of a and b selected by mask (shifted by n in a).
 */
#define DELTA_SWAP(a, b, n, mask) do {      \
        uint32_t t = (((a) >> (n)) ^ (b)) & (mask); \
        (b) ^= t;                           \
        (a) ^= t << (n);                    \
    } while (0)

/*
 * Initial permutation, on a block split in a big-endian left
 * half (bits 1..32) and right half (bits 33..64).
 */
static inline void des_ip(uint32_t *l, uint32_t *r)
{
    DELTA_SWAP(*l, *r,  4, 0x0F0F0F0F);
    DELTA_SWAP(*l, *r, 16, 0x0000FFFF);
    DELTA_SWAP(*r, *l,  2, 0x33333333);
    DELTA_SWAP(*r, *l,  8, 0x00FF00FF);
    DELTA_SWAP(*l, *r,  1, 0x55555555);
}

/*
 * Final permutation (inverse of the initial permutation).
 */
static inline void des_fp(uint32_t *l, uint32_t *r)
{
    DELTA_SWAP(*l, *r,  1, 0x55555555);
    DELTA_SWAP(*r, *l,  8, 0x00FF00FF);
    DELTA_SWAP(*r, *l,  2, 0x33333333);
    DELTA_SWAP(*l, *r, 16, 0x0000FFFF);
    DELTA_SWAP(*l, *r,  4, 0x0F0F0F0F);
}

/*
 * Return bit x of the truth table tt, for a secret x in [0, 63].
 */
static inline uint32_t tt_bit(uint64_t tt, uint32_t x)
{
#if SYS_BITS == 64
    return (uint32_t)(tt >> x) & 1;
#else
    /** On 32-bit platforms, a 64-bit shift by a variable amount
     *  may be a function call with branches **/
    uint32_t lo, hi, mask;
    unsigned s;

    lo = (uint32_t)tt;
    hi = (uint32_t)(tt >> 32);
    mask = 0U - (x >> 5);
    s = x & 31;
    return (((lo >> s) & ~mask) | ((hi >> s) & mask)) & 1;
#endif
}

/*
 * Feed S-box j with the input x (6 bits) and
 * return the output bits after the permutation P.
 */
#define SBOX(j, x) (                                    \
        (tt_bit(des_tt[j][0], x) << des_pos[j][0]) |    \
        (tt_bit(des_tt[j][1], x) << des_pos[j][1]) |    \
        (tt_bit(des_tt[j][2], x) << des_pos[j][2]) |    \
        (tt_bit(des_tt[j][3], x) << des_pos[j][3]) )

/*
 * The round function f(R, K).
 * The expansion E gives S-box j the bits 4j..4j+5 of R (in FIPS
 * numbering, where bit 0 is bit 32), that is, R rotated right by 27-4j.
 */
static inline uint32_t des_f(uint32_t r, const uint8_t k[8])
{
    return SBOX(0, (ROTR32(r, 27) & 0x3F) ^ k[0]) |
           SBOX(1, (ROTR32(r, 23) & 0x3F) ^ k[1]) |
           SBOX(2, (ROTR32(r, 19) & 0x3F) ^ k[2]) |
           SBOX(3, (ROTR32(r, 15) & 0x3F) ^ k[3]) |
           SBOX(4, (ROTR32(r, 11) & 0x3F) ^ k[4]) |
           SBOX(5, (ROTR32(r,  7) & 0x3F) ^ k[5]) |
           SBOX(6, (ROTR32(r,  3) & 0x3F) ^ k[6]) |
           SBOX(7, (ROTR32(r, 31) & 0x3F) ^ k[7]);
}

/*
 * The 16 rounds of DES, in between the initial and final permutations,
 * including the final swap of the two halves.
 * For decryption, the subkeys are used in reverse order.
 */
static void des_rounds(uint32_t *l, uint32_t *r, const des_ks *ks, int decrypt)
{
    unsigned i, rev;
    uint32_t t;

    rev = decrypt ? 15 : 0;
    for (i=0; i<16; i+=2) {
        *l ^= des_f(*r, ks->k[i ^ rev]);
        *r ^= des_f(*l, ks->k[(i + 1) ^ rev]);
    }

    t = *l;
    *l = *r;
    *r = t;
}

static void des_process(const struct block_state *self, const uint8_t *in, uint8_t *out, int decrypt)
{
    uint32_t l, r;

    l = LOAD_U32_BIG(in);
    r = LOAD_U32_BIG(in + 4);

    des_ip(&l, &r);
#ifndef PCT_DES3_MODULE
    des_rounds(&l, &r, &self->ks[0], decrypt);
#else
    /** EDE: the final and initial permutations between stages cancel out **/
    if (!decrypt) {
        des_rounds(&l, &r, &self->ks[0], 0);
        des_rounds(&l, &r, &self->ks[1], 1);
        des_rounds(&l, &r, &self->ks[2], 0);
    } else {
        des_rounds(&l, &r, &self->ks[2], 1);
        des_rounds(&l, &r, &self->ks[1], 0);
        des_rounds(&l, &r, &self->ks[0], 1);
    }
#endif
    des_fp(&l, &r);

    STORE_U32_BIG(out, l);
    STORE_U32_BIG(out + 4, r);
}

static int block_init(struct block_state *self, const uint8_t *key, size_t keylen)
{
#ifndef PCT_DES3_MODULE
    if (keylen != 8)
        return ERR_KEY_SIZE;
    des_key_schedule(&self->ks[0], key);
#else
    if (keylen != 16 && keylen != 24)
        return ERR_KEY_SIZE;
    des_key_schedule(&self->ks[0], key);
    des_key_schedule(&self->ks[1], key + 8);
    /** With 2-key TDES, K3 is K1 **/
    des_key_schedule(&self->ks[2], keylen == 24 ? key + 16 : key);
#endif
    return 0;
}

static void block_finalize(struct block_state *self)
{
}

static void block_encrypt(struct block_state *self, const uint8_t *in, uint8_t *out)
{
    des_process(self, in, out, 0);
}

static void block_decrypt(struct block_state *self, const uint8_t *in, uint8_t *out)
{
    des_process(self, in, out, 1);
}

#include "block_common.c"
