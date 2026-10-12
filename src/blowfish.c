/*
 * SPDX-FileCopyrightText: 2019 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"
#include "endianess.h"
#include "block_base.h"

#include "blowfish_init.c"

#ifdef EKS
#define NON_STANDARD_START_OPERATION
#define MODULE_NAME EKSBlowfish
FAKE_INIT(raw_eksblowfish)
#else
#define MODULE_NAME Blowfish
FAKE_INIT(raw_blowfish)
#endif

#define BLOCK_SIZE  8
#define KEY_SIZE    0

struct block_state {
    uint32_t S[4][256];
    uint32_t P[18];
};

static inline void swap(uint32_t *L, uint32_t *R)
{
    uint32_t tmp;

    tmp = *L;
    *L = *R;
    *R = tmp;
}

static inline uint32_t F(const struct block_state *ctx, uint32_t x)
{
    uint8_t a, b, c, d;
    uint32_t res;

    a = (uint8_t)(x >> 24);
    b = (uint8_t)(x >> 16);
    c = (uint8_t)(x >> 8);
    d = (uint8_t)(x >> 0);

    res =  ctx->S[0][a] + ctx->S[1][b];
    res ^= ctx->S[2][c];
    res += ctx->S[3][d];

    return res;
}

static void bf_encrypt(const struct block_state *state, uint32_t *Lx, uint32_t *Rx)
{
    unsigned i;
    uint32_t L, R;

    L = *Lx;
    R = *Rx;

    for (i=0; i<16; i++) {
        L ^= state->P[i];
        R ^= F(state, L);
        swap(&L, &R);
    }

    swap(&L, &R);
    R ^= state->P[16];
    L ^= state->P[17];

    *Lx = L;
    *Rx = R;
}

static void bf_decrypt(const struct block_state *state, uint32_t *Lx, uint32_t *Rx)
{
    unsigned i;
    uint32_t L, R;

    L = *Lx;
    R = *Rx;

    L ^= state->P[17];
    R ^= state->P[16];
    swap(&L, &R);

    for (i=0; i<16; i++) {
        swap(&L, &R);
        R ^= F(state, L);
        L ^= state->P[15-i];
    }

    *Lx = L;
    *Rx = R;
}

static inline void xorP(uint32_t P[18], const uint8_t *key, size_t keylength)
{
    uint8_t P_buf[4*18];
    size_t P_idx;
    unsigned i;

    P_idx = 0;
    while (P_idx < sizeof(P_buf)) {
        size_t tc;

        tc = MIN(keylength, sizeof(P_buf) - P_idx);
        memcpy(P_buf + P_idx, key, tc);

        P_idx += tc;
    }

    P_idx = 0;
    for (i=0; i<18; i++) {
        P[i] ^= LOAD_U32_BIG(P_buf + P_idx);
        P_idx += 4;
    }
}

static inline void encryptState(struct block_state *state, const uint8_t *key, size_t keylength)
{
    unsigned i, j;
    uint32_t L, R;

    xorP(state->P, key, keylength);

    L = R = 0;
    for (i=0; i<18; i+=2) {
        bf_encrypt(state, &L, &R);
        state->P[i] = L;
        state->P[i+1] = R;
    }
    for (j=0; j<4; j++) {
        for (i=0; i<256; i+=2) {
            bf_encrypt(state, &L, &R);
            state->S[j][i] = L;
            state->S[j][i+1] = R;
        }
    }
}

#ifndef EKS

static int block_init(struct block_state *state, const uint8_t *key, size_t keylength)
{
    /* Allowed key length: 32 to 448 bits */
    if (keylength < 4 || keylength > 56) {
        return ERR_KEY_SIZE;
    }

    memcpy(state->S, S_init, sizeof S_init);
    memcpy(state->P, P_init, sizeof P_init);

    encryptState(state, key, keylength);

    return 0;
}

#else

static inline uint32_t read_u32_circ(const uint8_t *base, size_t len, size_t *idx)
{
    uint8_t buf[4];
    unsigned i;

    for (i=0; i<4; i++) {
        buf[i] = base[*idx];
        (*idx)++;
        if (len == *idx)
            *idx = 0;
    }

    return LOAD_U32_BIG(buf);
}

static int encryptStateWithSalt(struct block_state *state, const uint8_t *key, size_t keylength, const uint8_t *salt, size_t saltlength)
{
    uint32_t L, R;
    unsigned i, j;
    size_t idx;

    xorP(state->P, key, keylength);

    L = R = 0;
    idx = 0;
    for (i=0; i<18; i+=2) {
        L ^= read_u32_circ(salt, saltlength, &idx);
        R ^= read_u32_circ(salt, saltlength, &idx);
        bf_encrypt(state, &L, &R);
        state->P[i] = L;
        state->P[i+1] = R;
    }

    for (j=0; j<4; j++) {
        for (i=0; i<256; i+=2) {
            L ^= read_u32_circ(salt, saltlength, &idx);
            R ^= read_u32_circ(salt, saltlength, &idx);
            bf_encrypt(state, &L, &R);
            state->S[j][i] = L;
            state->S[j][i+1] = R;
        }
    }

    return 0;
}

/**
 * Two independent Blowfish encryptions, with the rounds interleaved:
 * each one is a chain of dependent table lookups, so the CPU can
 * run the two at the same time (twice the throughput on one core).
 */
static inline void bf_encrypt2(const struct block_state *a, uint32_t *La, uint32_t *Ra,
                               const struct block_state *b, uint32_t *Lb, uint32_t *Rb)
{
    uint32_t l1, r1, l2, r2;
    unsigned i;

    l1 = *La;
    r1 = *Ra;
    l2 = *Lb;
    r2 = *Rb;

    for (i=0; i<16; i+=2) {
        l1 ^= a->P[i];
        l2 ^= b->P[i];
        r1 ^= F(a, l1);
        r2 ^= F(b, l2);
        r1 ^= a->P[i+1];
        r2 ^= b->P[i+1];
        l1 ^= F(a, r1);
        l2 ^= F(b, r2);
    }

    *La = r1 ^ a->P[17];
    *Ra = l1 ^ a->P[16];
    *Lb = r2 ^ b->P[17];
    *Rb = l2 ^ b->P[16];
}

/** Like encryptState(), on two states at once (each one with its own key) **/
static void encryptState2(struct block_state *a, const uint8_t *keya, size_t keyalength,
                          struct block_state *b, const uint8_t *keyb, size_t keyblength)
{
    unsigned i, j;
    uint32_t La, Ra, Lb, Rb;

    xorP(a->P, keya, keyalength);
    xorP(b->P, keyb, keyblength);

    La = Ra = Lb = Rb = 0;
    for (i=0; i<18; i+=2) {
        bf_encrypt2(a, &La, &Ra, b, &Lb, &Rb);
        a->P[i] = La;
        a->P[i+1] = Ra;
        b->P[i] = Lb;
        b->P[i+1] = Rb;
    }
    for (j=0; j<4; j++) {
        for (i=0; i<256; i+=2) {
            bf_encrypt2(a, &La, &Ra, b, &Lb, &Rb);
            a->S[j][i] = La;
            a->S[j][i+1] = Ra;
            b->S[j][i] = Lb;
            b->S[j][i+1] = Rb;
        }
    }
}

static int block_init(struct block_state *state, const uint8_t *key, size_t keylength, const uint8_t *salt, size_t saltlength, unsigned cost, unsigned invert)
{
    unsigned i;
    unsigned iterations;

    /* An empty key or salt cannot fill the state (see xorP and read_u32_circ) */
    if (keylength == 0 || keylength > 72) {
        return ERR_KEY_SIZE;
    }
    if (saltlength == 0) {
        return ERR_VALUE;
    }
    if (cost > 31) {
        return ERR_NR_ROUNDS;
    }

    /* InitState */
    memcpy(state->S, S_init, sizeof S_init);
    memcpy(state->P, P_init, sizeof P_init);

    encryptStateWithSalt(state, key, keylength, salt, saltlength);

    iterations = 1U << cost;
    if (!invert) {
        for (i=0; i<iterations; i++) {
            encryptState(state, salt, saltlength);
            encryptState(state, key, keylength);
        }
    } else {
        for (i=0; i<iterations; i++) {
            encryptState(state, key, keylength);
            encryptState(state, salt, saltlength);
        }
    }

    return 0;
}

#endif

static void block_finalize(struct block_state* state)
{
}

static inline void block_encrypt(struct block_state *state, const uint8_t *in, uint8_t *out)
{
    uint32_t L, R;

    L = LOAD_U32_BIG(in);
    R = LOAD_U32_BIG(in + 4);
    bf_encrypt(state, &L, &R);
    STORE_U32_BIG(out, L);
    STORE_U32_BIG(out + 4, R);
}

static inline void block_decrypt(struct block_state *state, const uint8_t *in, uint8_t *out)
{
    uint32_t L, R;

    L = LOAD_U32_BIG(in);
    R = LOAD_U32_BIG(in + 4);
    bf_decrypt(state, &L, &R);
    STORE_U32_BIG(out, L);
    STORE_U32_BIG(out + 4, R);
}

#include "block_common.c"

#ifdef EKS
EXPORT_SYM int CIPHER_START_OPERATION(const uint8_t key[], size_t key_len, const uint8_t salt[], size_t salt_len, unsigned cost, unsigned invert, CIPHER_STATE_TYPE **pResult)
{
    BlockBase *block_base;

    if ((key == NULL) || (salt == NULL) || (pResult == NULL))
        return ERR_NULL;

    *pResult = calloc(1, sizeof(CIPHER_STATE_TYPE));
    if (NULL == *pResult)
        return ERR_MEMORY;

    block_base = &((*pResult)->base_state);
    block_base->encrypt = &CIPHER_ENCRYPT;
    block_base->decrypt = &CIPHER_DECRYPT;
    block_base->destructor = &CIPHER_STOP_OPERATION;
    block_base->block_len = BLOCK_SIZE;

    return block_init(&(*pResult)->algo_state, (unsigned char*)key, key_len, salt, salt_len, cost, invert);
}

/**
 * Encrypt the constant 64 times in ECB mode (the end of bcrypt), with two states at once
 * (@b may be NULL, for one state only).
 */
static void bcrypt_encrypt_constant(const struct block_state *a, uint8_t *outa,
                                    const struct block_state *b, uint8_t *outb,
                                    const uint8_t *ctext, size_t ctext_len)
{
    size_t k;
    unsigned i;

    for (k=0; k<ctext_len; k+=8) {
        uint32_t La, Ra, Lb, Rb;

        La = Lb = LOAD_U32_BIG(ctext + k);
        Ra = Rb = LOAD_U32_BIG(ctext + k + 4);
        for (i=0; i<64; i++) {
            if (b != NULL) {
                bf_encrypt2(a, &La, &Ra, b, &Lb, &Rb);
            } else {
                bf_encrypt(a, &La, &Ra);
            }
        }
        STORE_U32_BIG(outa + k, La);
        STORE_U32_BIG(outa + k + 4, Ra);
        if (b != NULL) {
            STORE_U32_BIG(outb + k, Lb);
            STORE_U32_BIG(outb + k + 4, Rb);
        }
    }
}

static int bcrypt_check_params(size_t key_len, size_t salt_len, unsigned cost, size_t ctext_len)
{
    /* An empty key or salt cannot fill the state (see xorP and read_u32_circ) */
    if (key_len == 0 || key_len > 72) {
        return ERR_KEY_SIZE;
    }
    if (salt_len == 0) {
        return ERR_VALUE;
    }
    if (cost < 4 || cost > 31) {
        return ERR_NR_ROUNDS;
    }
    if (ctext_len == 0 || ctext_len % 8 != 0 || ctext_len > 64) {
        return ERR_BLOCK_SIZE;
    }
    return 0;
}

/**
 * The bcrypt hash: the expensive key setup of EKSBlowfish, followed by the
 * encryption of @ctext (a multiple of 8 bytes) 64 times in ECB mode.
 * The output @out is as long as @ctext.
 */
EXPORT_SYM int EKSBlowfish_bcrypt(const uint8_t key[], size_t key_len,
                                  const uint8_t salt[], size_t salt_len,
                                  unsigned cost, unsigned invert,
                                  const uint8_t ctext[], size_t ctext_len,
                                  uint8_t out[])
{
    struct block_state *state;
    int result;

    if (NULL == key || NULL == salt || NULL == ctext || NULL == out) {
        return ERR_NULL;
    }
    result = bcrypt_check_params(key_len, salt_len, cost, ctext_len);
    if (result) {
        return result;
    }

    state = calloc(1, sizeof *state);
    if (NULL == state) {
        return ERR_MEMORY;
    }

    result = block_init(state, key, key_len, salt, salt_len, cost, invert);
    if (0 == result) {
        bcrypt_encrypt_constant(state, out, NULL, NULL, ctext, ctext_len);
    }

    /* The state depends on the password */
    memset(state, 0, sizeof *state);
    free(state);
    return result;
}

/**
 * Two bcrypt hashes of the same @key, with two salts of the same length,
 * computed together twice as fast (see bf_encrypt2()).
 * This is what bcrypt_pbkdf (OpenSSH) needs at every round.
 */
EXPORT_SYM int EKSBlowfish_bcrypt2(const uint8_t key[], size_t key_len,
                                   const uint8_t salt1[], const uint8_t salt2[], size_t salt_len,
                                   unsigned cost, unsigned invert,
                                   const uint8_t ctext[], size_t ctext_len,
                                   uint8_t out1[], uint8_t out2[])
{
    struct block_state *states;
    struct block_state *a, *b;
    uint64_t i, iterations;
    int result;

    if (NULL == key || NULL == salt1 || NULL == salt2 || NULL == ctext || NULL == out1 || NULL == out2) {
        return ERR_NULL;
    }
    result = bcrypt_check_params(key_len, salt_len, cost, ctext_len);
    if (result) {
        return result;
    }

    states = calloc(2, sizeof *states);
    if (NULL == states) {
        return ERR_MEMORY;
    }
    a = &states[0];
    b = &states[1];

    /* As block_init(), for both states */
    memcpy(a->S, S_init, sizeof S_init);
    memcpy(a->P, P_init, sizeof P_init);
    encryptStateWithSalt(a, key, key_len, salt1, salt_len);
    memcpy(b->S, S_init, sizeof S_init);
    memcpy(b->P, P_init, sizeof P_init);
    encryptStateWithSalt(b, key, key_len, salt2, salt_len);

    iterations = (uint64_t)1 << cost;
    for (i=0; i<iterations; i++) {
        if (!invert) {
            encryptState2(a, salt1, salt_len, b, salt2, salt_len);
            encryptState2(a, key, key_len, b, key, key_len);
        } else {
            encryptState2(a, key, key_len, b, key, key_len);
            encryptState2(a, salt1, salt_len, b, salt2, salt_len);
        }
    }

    bcrypt_encrypt_constant(a, out1, b, out2, ctext, ctext_len);

    /* The states depend on the password */
    memset(states, 0, 2 * sizeof *states);
    free(states);
    return 0;
}
#endif
