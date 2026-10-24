/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/**
 * AES with the instructions of the ARMv8 Cryptography Extensions
 * (AESE, AESD, AESMC and AESIMC), for AArch64 CPUs.
 *
 * On other targets (such as the x86-64 half of a macOS universal2 build),
 * the module is empty: the Python code only loads it after checking
 * that the CPU has the extensions.
 */

#include <stdlib.h>
#include "common.h"
#include "endianess.h"
#include "block_base.h"

FAKE_INIT(raw_aes_armv8)

#if defined(__aarch64__) || defined(_M_ARM64)

#include <arm_neon.h>

#define MODULE_NAME AES_ARMV8
#define BLOCK_SIZE 16

struct block_state {
    uint8x16_t *erk;    /** Round keys for encryption (11, 13 or 15 elements) **/
    uint8x16_t *drk;    /** Round keys for decryption **/
    unsigned rounds;
};

typedef struct {
    BlockBase  base_state;
    struct block_state algo_state;
} AES_ARMV8_State;

/**
 * Return SubWord(w), with the bytes of w in little-endian order.
 *
 * AESE with a zero round key computes ShiftRows(SubBytes(x)):
 * with the same word in all four columns, ShiftRows changes nothing.
 */
STATIC uint32_t sub_word(uint32_t w)
{
    uint8x16_t x;

    x = vreinterpretq_u8_u32(vdupq_n_u32(w));
    x = vaeseq_u8(x, vdupq_n_u8(0));
    return vgetq_lane_u32(vreinterpretq_u32_u8(x), 0);
}

STATIC int expand_key(uint8x16_t *erk, uint8x16_t *drk, const uint8_t *key, unsigned Nk, unsigned Nr)
{
    static const uint8_t rcon[11] = { 0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
    uint32_t rk[4*(14+1)];
    uint8_t rk_bytes[16];
    unsigned tot_words;
    unsigned i, j;

    assert(
            ((Nk==4) && (Nr==10)) ||    /** AES-128 **/
            ((Nk==6) && (Nr==12)) ||    /** AES-192 **/
            ((Nk==8) && (Nr==14))       /** AES-256 **/
    );

    tot_words = 4*(Nr+1);

    for (i=0; i<Nk; i++) {
        rk[i] = LOAD_U32_LITTLE(key);
        key += 4;
    }

    for (i=Nk; i<tot_words; i++) {
        uint32_t tmp;

        tmp = rk[i-1];
        if (i % Nk == 0) {
            /** RotWord(SubWord(W)) xor RCON **/
            tmp = sub_word(tmp);
            tmp = ((tmp >> 8) | (tmp << 24)) ^ rcon[i/Nk];
        } else {
            if ((i % Nk == 4) && (Nk == 8)) {  /* AES-256 only */
                tmp = sub_word(tmp);
            }
        }
        rk[i] = rk[i-Nk] ^ tmp;
    }

    for (i=0; i<=Nr; i++) {
        for (j=0; j<4; j++) {
            STORE_U32_LITTLE(&rk_bytes[4*j], rk[4*i+j]);
        }
        erk[i] = vld1q_u8(rk_bytes);
    }

    /** Round keys for the Equivalent Inverse Cipher (FIPS 197, 5.3.5) **/
    drk[0] = erk[Nr];
    for (i=1; i<Nr; i++) {
        drk[i] = vaesimcq_u8(erk[Nr-i]);
    }
    drk[Nr] = erk[0];

    return 0;
}

/**
 * One AES round on 8 blocks: AESE (AddRoundKey, SubBytes and ShiftRows)
 * and AESMC (MixColumns). The blocks are independent, so the CPU can
 * execute the instructions in parallel.
 */
#define ENC_ROUND_8(d, k) do {                      \
        d[0] = vaesmcq_u8(vaeseq_u8(d[0], k));      \
        d[1] = vaesmcq_u8(vaeseq_u8(d[1], k));      \
        d[2] = vaesmcq_u8(vaeseq_u8(d[2], k));      \
        d[3] = vaesmcq_u8(vaeseq_u8(d[3], k));      \
        d[4] = vaesmcq_u8(vaeseq_u8(d[4], k));      \
        d[5] = vaesmcq_u8(vaeseq_u8(d[5], k));      \
        d[6] = vaesmcq_u8(vaeseq_u8(d[6], k));      \
        d[7] = vaesmcq_u8(vaeseq_u8(d[7], k));      \
    } while (0)

#define DEC_ROUND_8(d, k) do {                      \
        d[0] = vaesimcq_u8(vaesdq_u8(d[0], k));     \
        d[1] = vaesimcq_u8(vaesdq_u8(d[1], k));     \
        d[2] = vaesimcq_u8(vaesdq_u8(d[2], k));     \
        d[3] = vaesimcq_u8(vaesdq_u8(d[3], k));     \
        d[4] = vaesimcq_u8(vaesdq_u8(d[4], k));     \
        d[5] = vaesimcq_u8(vaesdq_u8(d[5], k));     \
        d[6] = vaesimcq_u8(vaesdq_u8(d[6], k));     \
        d[7] = vaesimcq_u8(vaesdq_u8(d[7], k));     \
    } while (0)

/**
 * The last round: AESE or AESD with the second-to-last round key,
 * without (Inv)MixColumns, and then AddRoundKey with the last one.
 */
#define LAST_ROUND_8(d, op, k, last) do {           \
        d[0] = veorq_u8(op(d[0], k), last);         \
        d[1] = veorq_u8(op(d[1], k), last);         \
        d[2] = veorq_u8(op(d[2], k), last);         \
        d[3] = veorq_u8(op(d[3], k), last);         \
        d[4] = veorq_u8(op(d[4], k), last);         \
        d[5] = veorq_u8(op(d[5], k), last);         \
        d[6] = veorq_u8(op(d[6], k), last);         \
        d[7] = veorq_u8(op(d[7], k), last);         \
    } while (0)

STATIC int internal_AES_ARMV8_encrypt(const uint8x16_t r[], unsigned rounds, const uint8_t *in, uint8_t *out, size_t data_len)
{
    /** Encrypt 8 blocks (128 bytes) in parallel, when possible **/
    for (; data_len >= 8*16; data_len -= 8*16) {
        uint8x16_t data[8];
        unsigned i, j;

        for (i=0; i<8; i++) {
            data[i] = vld1q_u8(in + 16*i);
        }

        for (j=0; j<9; j++) {
            ENC_ROUND_8(data, r[j]);
        }
        for (; j<rounds-1; j++) {
            ENC_ROUND_8(data, r[j]);
        }
        LAST_ROUND_8(data, vaeseq_u8, r[rounds-1], r[rounds]);

        for (i=0; i<8; i++) {
            vst1q_u8(out + 16*i, data[i]);
        }
        in += 8*16;
        out += 8*16;
    }

    /** There are 7 blocks or fewer left **/
    for (;data_len>=BLOCK_SIZE; data_len-=BLOCK_SIZE, in+=BLOCK_SIZE, out+=BLOCK_SIZE) {
        uint8x16_t data;
        unsigned i;

        data = vld1q_u8(in);
        for (i=0; i<rounds-1; i++) {
            data = vaesmcq_u8(vaeseq_u8(data, r[i]));
        }
        data = veorq_u8(vaeseq_u8(data, r[rounds-1]), r[rounds]);
        vst1q_u8(out, data);
    }

    if (data_len) {
        return ERR_NOT_ENOUGH_DATA;
    }

    return 0;
}

static int AES_ARMV8_encrypt(const BlockBase *bb, const uint8_t *in, uint8_t *out, size_t data_len)
{
    unsigned rounds;
    uint8x16_t r[14+1];
    const struct block_state *state;
    unsigned k;

    if ((bb == NULL) || (in == NULL) || (out == NULL))
        return ERR_NULL;

    state = &((AES_ARMV8_State*)bb)->algo_state;
    rounds = state->rounds;

    if (rounds > 14)
        return ERR_NR_ROUNDS;

    for (k=0; k<=rounds; k++) {
        r[k] = state->erk[k];
    }

    return internal_AES_ARMV8_encrypt(r, rounds, in, out, data_len);
}

STATIC int internal_AES_ARMV8_decrypt(const uint8x16_t r[], unsigned rounds, const uint8_t *in, uint8_t *out, size_t data_len)
{
    /** Decrypt 8 blocks (128 bytes) in parallel, when possible **/
    for (; data_len >= 8*16; data_len -= 8*16) {
        uint8x16_t data[8];
        unsigned i, j;

        for (i=0; i<8; i++) {
            data[i] = vld1q_u8(in + 16*i);
        }

        for (j=0; j<9; j++) {
            DEC_ROUND_8(data, r[j]);
        }
        for (; j<rounds-1; j++) {
            DEC_ROUND_8(data, r[j]);
        }
        LAST_ROUND_8(data, vaesdq_u8, r[rounds-1], r[rounds]);

        for (i=0; i<8; i++) {
            vst1q_u8(out + 16*i, data[i]);
        }
        in += 8*16;
        out += 8*16;
    }

    /** There are 7 blocks or fewer left **/
    for (;data_len>=BLOCK_SIZE; data_len-=BLOCK_SIZE, in+=BLOCK_SIZE, out+=BLOCK_SIZE) {
        uint8x16_t data;
        unsigned i;

        data = vld1q_u8(in);
        for (i=0; i<rounds-1; i++) {
            data = vaesimcq_u8(vaesdq_u8(data, r[i]));
        }
        data = veorq_u8(vaesdq_u8(data, r[rounds-1]), r[rounds]);
        vst1q_u8(out, data);
    }

    if (data_len) {
        return ERR_NOT_ENOUGH_DATA;
    }

    return 0;
}

static int AES_ARMV8_decrypt(const BlockBase *bb, const uint8_t *in, uint8_t *out, size_t data_len)
{
    unsigned rounds;
    uint8x16_t r[14+1];
    const struct block_state *state;
    unsigned k;

    if ((bb == NULL) || (in == NULL) || (out == NULL))
        return ERR_NULL;

    state = &((AES_ARMV8_State*)bb)->algo_state;
    rounds = state->rounds;

    if (rounds > 14)
        return ERR_NR_ROUNDS;

    for (k=0; k<=rounds; k++) {
        r[k] = state->drk[k];
    }

    return internal_AES_ARMV8_decrypt(r, rounds, in, out, data_len);
}

EXPORT_SYM int AES_ARMV8_stop_operation(BlockBase *bb)
{
    AES_ARMV8_State *state;

    if (NULL == bb)
        return ERR_NULL;

    state = (AES_ARMV8_State*)bb;
    align_free(state->algo_state.erk);
    align_free(state->algo_state.drk);
    free(state);
    return 0;
}

EXPORT_SYM int AES_ARMV8_start_operation(const uint8_t key[], size_t key_len, AES_ARMV8_State **pResult)
{
    unsigned Nr;
    int result;
    struct block_state *state;
    BlockBase *block_base;

    if ((NULL == key) || (NULL == pResult))
        return ERR_NULL;

    switch (key_len) {
        case 16: Nr = 10; break;
        case 24: Nr = 12; break;
        case 32: Nr = 14; break;
        default: return ERR_KEY_SIZE;
    }

    *pResult= calloc(1, sizeof(AES_ARMV8_State));
    if (NULL == *pResult)
        return ERR_MEMORY;

    block_base = &((*pResult)->base_state);
    block_base->encrypt = &AES_ARMV8_encrypt;
    block_base->decrypt = &AES_ARMV8_decrypt;
    block_base->destructor = &AES_ARMV8_stop_operation;
    block_base->block_len = BLOCK_SIZE;

    state = &((*pResult)->algo_state);
    state->rounds = Nr;
    state->erk = align_alloc((Nr+1)*sizeof(uint8x16_t), 16);
    if (state->erk == NULL) {
        result = ERR_MEMORY;
        goto error;
    }

    state->drk = align_alloc((Nr+1)*sizeof(uint8x16_t), 16);
    if (state->drk == NULL) {
        result = ERR_MEMORY;
        goto error;
    }

    result = expand_key(state->erk, state->drk, key, (unsigned)key_len/4, Nr);
    if (result) {
        goto error;
    }
    return 0;

error:
    align_free(state->erk);
    align_free(state->drk);
    free(*pResult);
    return result;
}

#endif /* __aarch64__ || _M_ARM64 */
