/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * AEGIS-128L and AEGIS-256 (RFC 10032, Sections 3 and 4), on top of an AES round.
 *
 * This file is not a module: it is included by aegis_portable.c, aegis_aesni.c
 * and aegis_armv8.c, which first define:
 *  - AEGIS_PREFIX, the prefix of the names of the exported functions;
 *  - aes_block, the type of an AES block, with blk_load(), blk_store(),
 *    blk_xor() and blk_and();
 *  - either aes_rounds(out, in, rk, n), which sets out[i] = AESRound(in[i], rk[i])
 *    for i < n, or AEGIS_CORE and their own state (aegis_core) with the
 *    functions core_load(), core_store(), core_absorb(), core_crypt() and
 *    core_keystream(), described below.
 * They can also define UPDATE_INLINE, the declaration of the update functions
 * (static inline by default), to force their inlining.
 *
 * The associated data and the message can be passed in pieces of any length.
 * The bytes of an incomplete input block are kept until the block is complete:
 * associated data, or plaintext (the state absorbs the plaintext,
 * when encrypting and when decrypting), together with the keystream of the block.
 */

#include <stdlib.h>
#include <string.h>
#include "errors.h"
#include "aegis.h"

#define FUNC(name) PASTE2(AEGIS_PREFIX, name)

/* P_MAX and A_MAX: 2^61 - 1 bytes */
#define MAX_LEN     ((((uint64_t)1) << 61) - 1)

static const uint8_t C0[16] = {
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
    0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62
};

static const uint8_t C1[16] = {
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
    0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
};

enum Phase { ASSOCIATED_DATA, MESSAGE, DONE };


#ifndef AEGIS_CORE

#ifndef UPDATE_INLINE
#define UPDATE_INLINE static inline
#endif

/*
 * Update(M0, M1) of AEGIS-128L (3.3).
 * The statements are written out (no loops), so that the compiler can keep
 * the state in registers.
 */
UPDATE_INLINE void update_128l(aes_block S[8], aes_block m0, aes_block m1)
{
    aes_block in[8], rk[8];

    in[0] = S[7];
    in[1] = S[0];
    in[2] = S[1];
    in[3] = S[2];
    in[4] = S[3];
    in[5] = S[4];
    in[6] = S[5];
    in[7] = S[6];
    rk[0] = blk_xor(S[0], m0);
    rk[1] = S[1];
    rk[2] = S[2];
    rk[3] = S[3];
    rk[4] = blk_xor(S[4], m1);
    rk[5] = S[5];
    rk[6] = S[6];
    rk[7] = S[7];
    aes_rounds(S, in, rk, 8);
}

/* Update(M) of AEGIS-256 (4.3) */
UPDATE_INLINE void update_256(aes_block S[6], aes_block m)
{
    aes_block in[6], rk[6];

    in[0] = S[5];
    in[1] = S[0];
    in[2] = S[1];
    in[3] = S[2];
    in[4] = S[3];
    in[5] = S[4];
    rk[0] = blk_xor(S[0], m);
    rk[1] = S[1];
    rk[2] = S[2];
    rk[3] = S[3];
    rk[4] = S[4];
    rk[5] = S[5];
    aes_rounds(S, in, rk, 6);
}

/* z0 and z1 of Enc (3.6) */
#define Z0_128L(S)  blk_xor(blk_xor(S[1], S[6]), blk_and(S[2], S[3]))
#define Z1_128L(S)  blk_xor(blk_xor(S[2], S[5]), blk_and(S[6], S[7]))

/* z of Enc (4.6) */
#define Z_256(S)    blk_xor(blk_xor(S[1], S[4]), blk_xor(S[5], blk_and(S[2], S[3])))

/* The state: 8 blocks for AEGIS-128L, 6 for AEGIS-256 */
typedef struct {
    aes_block S[8];
} aegis_core;

/* Set the state from the blocks in S */
static void core_load(aegis_core *c, enum AegisVariant variant, const aes_block S[8])
{
    (void)variant;
    memcpy(c->S, S, sizeof c->S);
}

/* Get the blocks of the state into S */
static void core_store(aes_block S[8], const aegis_core *c, enum AegisVariant variant)
{
    (void)variant;
    memcpy(S, c->S, sizeof c->S);
}

/* Absorb(ai) (3.5 and 4.5): the input block (32 or 16 bytes) is at p */
static void core_absorb(aegis_core *c, enum AegisVariant variant, const uint8_t *p)
{
    if (variant == AEGIS_128L)
        update_128l(c->S, blk_load(p), blk_load(p + 16));
    else
        update_256(c->S, blk_load(p));
}

/* The keystream of the next message block (32 or 16 bytes), into ks */
static void core_keystream(const aegis_core *c, enum AegisVariant variant, uint8_t *ks)
{
    const aes_block *S = c->S;

    if (variant == AEGIS_128L) {
        blk_store(ks, Z0_128L(S));
        blk_store(ks + 16, Z1_128L(S));
    } else {
        blk_store(ks, Z_256(S));
    }
}

/*
 * Enc (3.6 and 4.6) or Dec (3.7 and 4.7) of the whole blocks in the len bytes at in,
 * or only Absorb (3.5 and 4.5) if out is NULL.
 * Return the number of bytes processed. in and out may be the same buffer.
 */
static size_t core_crypt(aegis_core *c, enum AegisVariant variant,
                         const uint8_t *in, uint8_t *out, size_t len, int decrypt)
{
    aes_block S[8];
    size_t done = 0;

    /* A local copy of the state */
    memcpy(S, c->S, sizeof S);
    if (variant == AEGIS_128L) {
        for (; len - done >= 32; done += 32) {
            aes_block t0, t1, out0, out1;

            t0 = blk_load(in + done);
            t1 = blk_load(in + done + 16);
            out0 = blk_xor(t0, Z0_128L(S));
            out1 = blk_xor(t1, Z1_128L(S));
            if (NULL != out) {
                blk_store(out + done, out0);
                blk_store(out + done + 16, out1);
            }
            if (decrypt)
                update_128l(S, out0, out1);
            else
                update_128l(S, t0, t1);
        }
    } else {
        for (; len - done >= 16; done += 16) {
            aes_block t, o;

            t = blk_load(in + done);
            o = blk_xor(t, Z_256(S));
            if (NULL != out)
                blk_store(out + done, o);
            update_256(S, decrypt ? o : t);
        }
    }
    memcpy(c->S, S, sizeof S);
    wipe(S, sizeof S);
    return done;
}

#endif /* AEGIS_CORE */

typedef struct {
    aegis_core core;
    enum AegisVariant variant;
    unsigned rate;          /* The size of an input block: 32 or 16 bytes */
    enum Phase phase;
    uint64_t ad_len;
    uint64_t msg_len;
    uint8_t buf[32];        /* The bytes of an incomplete input block */
    uint8_t ks[32];         /* The keystream of an incomplete message block */
    unsigned buf_len;
} aegis_state;

/* Absorb an input block (32 or 16 bytes) */
static void absorb(aegis_state *st, const uint8_t *p)
{
    core_absorb(&st->core, st->variant, p);
}

/* Init(key, nonce) (3.4 and 4.4) */
EXPORT_SYM int FUNC(init)(unsigned variant,
                          const uint8_t *key, size_t key_len,
                          const uint8_t *nonce, size_t nonce_len,
                          aegis_state **pState)
{
    aegis_state *st;
    aes_block S[8];
    aes_block c0, c1;
    uint8_t m[64];
    unsigned i, j;

    if (NULL == key || NULL == nonce || NULL == pState)
        return ERR_NULL;

    if (variant != AEGIS_128L && variant != AEGIS_256)
        return ERR_VALUE;
    if (key_len != (variant == AEGIS_128L ? 16u : 32u))
        return ERR_KEY_SIZE;
    if (nonce_len != key_len)
        return ERR_NONCE_SIZE;

    *pState = st = (aegis_state*)align_alloc(sizeof(aegis_state), 16);
    if (NULL == st)
        return ERR_MEMORY;
    memset(st, 0, sizeof(aegis_state));
    st->variant = variant;
    st->phase = ASSOCIATED_DATA;

    c0 = blk_load(C0);
    c1 = blk_load(C1);
    memset(S, 0, sizeof S);

    if (variant == AEGIS_128L) {
        aes_block k, n;

        st->rate = 32;
        k = blk_load(key);
        n = blk_load(nonce);
        S[0] = blk_xor(k, n);
        S[1] = c1;
        S[2] = c0;
        S[3] = c1;
        S[4] = blk_xor(k, n);
        S[5] = blk_xor(k, c0);
        S[6] = blk_xor(k, c1);
        S[7] = blk_xor(k, c0);
        core_load(&st->core, variant, S);

        /* Update(nonce, key), 10 times */
        memcpy(m, nonce, 16);
        memcpy(m + 16, key, 16);
        for (i = 0; i < 10; i++)
            core_absorb(&st->core, variant, m);
    } else {
        aes_block k0, k1, n0, n1;

        st->rate = 16;
        k0 = blk_load(key);
        k1 = blk_load(key + 16);
        n0 = blk_load(nonce);
        n1 = blk_load(nonce + 16);
        S[0] = blk_xor(k0, n0);
        S[1] = blk_xor(k1, n1);
        S[2] = c1;
        S[3] = c0;
        S[4] = blk_xor(k0, c0);
        S[5] = blk_xor(k1, c1);
        core_load(&st->core, variant, S);

        /* Update(k0), Update(k1), Update(k0 ^ n0), Update(k1 ^ n1), 4 times */
        memcpy(m, key, 32);
        for (i = 0; i < 32; i++)
            m[32 + i] = key[i] ^ nonce[i];
        for (i = 0; i < 4; i++)
            for (j = 0; j < 4; j++)
                core_absorb(&st->core, variant, m + 16*j);
    }

    wipe(S, sizeof S);
    wipe(m, sizeof m);
    return 0;
}

EXPORT_SYM int FUNC(destroy)(aegis_state *st)
{
    if (NULL == st)
        return ERR_NULL;
    wipe(st, sizeof(aegis_state));
    align_free(st);
    return 0;
}

/* Absorb the associated data (ZeroPad(ad) is completed by start_message()) */
EXPORT_SYM int FUNC(update_ad)(aegis_state *st, const uint8_t *in, size_t len)
{
    if (NULL == st || NULL == in)
        return ERR_NULL;
    if (st->phase != ASSOCIATED_DATA)
        return ERR_STATE;
    if (len > MAX_LEN - st->ad_len)
        return ERR_MAX_DATA;
    st->ad_len += len;

    while (len > 0) {
        size_t n;

        if (st->buf_len == 0 && len >= st->rate) {
            /* Absorb only (no output): the input is the plaintext */
            size_t done = core_crypt(&st->core, st->variant, in, NULL, len, 0);

            in += done;
            len -= done;
            continue;
        }
        n = st->rate - st->buf_len;
        n = len < n ? len : n;
        memcpy(st->buf + st->buf_len, in, n);
        st->buf_len += (unsigned)n;
        in += n;
        len -= n;
        if (st->buf_len == st->rate) {
            absorb(st, st->buf);
            st->buf_len = 0;
        }
    }

    return 0;
}

/* Absorb the last block of associated data, padded with zeros */
static void start_message(aegis_state *st)
{
    if (st->phase != ASSOCIATED_DATA)
        return;
    if (st->buf_len > 0) {
        memset(st->buf + st->buf_len, 0, st->rate - st->buf_len);
        absorb(st, st->buf);
        st->buf_len = 0;
    }
    st->phase = MESSAGE;
}

/*
 * Enc (3.6 and 4.6) and Dec (3.7 and 4.7) of whole blocks;
 * for the last partial block, Enc of ZeroPad(msg) and DecPartial (3.8 and 4.8),
 * completed by FUNC(digest)().
 * in and out may be the same buffer.
 */
static int crypt(aegis_state *st, const uint8_t *in, uint8_t *out, size_t len, int decrypt)
{
    size_t i, done;

    if (NULL == st || NULL == in || NULL == out)
        return ERR_NULL;
    if (st->phase == DONE)
        return ERR_STATE;
    start_message(st);
    if (len > MAX_LEN - st->msg_len)
        return ERR_MAX_DATA;
    st->msg_len += len;

    /* Complete an incomplete block */
    while (len > 0 && st->buf_len > 0) {
        uint8_t x = *in++;
        uint8_t y = x ^ st->ks[st->buf_len];

        *out++ = y;
        st->buf[st->buf_len++] = decrypt ? y : x;
        len--;
        if (st->buf_len == st->rate) {
            absorb(st, st->buf);
            st->buf_len = 0;
        }
    }

    /* Whole blocks */
    done = core_crypt(&st->core, st->variant, in, out, len, decrypt);
    in += done;
    out += done;
    len -= done;

    /* Start an incomplete block */
    if (len > 0) {
        core_keystream(&st->core, st->variant, st->ks);
        for (i = 0; i < len; i++) {
            uint8_t x = in[i];
            uint8_t y = x ^ st->ks[i];

            out[i] = y;
            st->buf[i] = decrypt ? y : x;
        }
        st->buf_len = (unsigned)len;
    }

    return 0;
}

EXPORT_SYM int FUNC(encrypt)(aegis_state *st, const uint8_t *in, uint8_t *out, size_t len)
{
    return crypt(st, in, out, len, 0);
}

EXPORT_SYM int FUNC(decrypt)(aegis_state *st, const uint8_t *in, uint8_t *out, size_t len)
{
    return crypt(st, in, out, len, 1);
}

/* S[0] ^ S[1] ^ ... ^ S[n - 1] */
static aes_block xor_blocks(const aes_block *S, unsigned n)
{
    aes_block t = S[0];
    unsigned i;

    for (i = 1; i < n; i++)
        t = blk_xor(t, S[i]);
    return t;
}

/* Finalize(ad_len_bits, msg_len_bits) (3.9 and 4.9), for a tag of 16 or 32 bytes */
EXPORT_SYM int FUNC(digest)(aegis_state *st, uint8_t *tag, size_t tag_len)
{
    aes_block S[8];
    aes_block t;
    uint8_t lens[16], tt[32];
    uint64_t bits;
    unsigned i, nb;

    if (NULL == st || NULL == tag)
        return ERR_NULL;
    if (tag_len != 16 && tag_len != 32)
        return ERR_TAG_SIZE;
    if (st->phase == DONE)
        return ERR_STATE;
    start_message(st);

    /* The last message block, padded with zeros */
    if (st->buf_len > 0) {
        memset(st->buf + st->buf_len, 0, st->rate - st->buf_len);
        absorb(st, st->buf);
        st->buf_len = 0;
    }

    bits = st->ad_len * 8;
    STORE_U64_LITTLE(lens, bits);
    bits = st->msg_len * 8;
    STORE_U64_LITTLE(lens + 8, bits);

    /* Update(t, t) or Update(t), 7 times */
    core_store(S, &st->core, st->variant);
    t = blk_xor(S[st->variant == AEGIS_128L ? 2 : 3], blk_load(lens));
    blk_store(tt, t);
    blk_store(tt + 16, t);
    for (i = 0; i < 7; i++)
        core_absorb(&st->core, st->variant, tt);
    core_store(S, &st->core, st->variant);

    nb = st->variant == AEGIS_128L ? 8 : 6;         /* The state blocks */
    if (tag_len == 16) {
        /* S0 ^ ... ^ S6 (AEGIS-128L: without S7) or S0 ^ ... ^ S5 (AEGIS-256) */
        blk_store(tag, xor_blocks(S, st->variant == AEGIS_128L ? 7 : 6));
    } else {
        /* One half of the state in each 16 bytes */
        blk_store(tag, xor_blocks(S, nb / 2));
        blk_store(tag + 16, xor_blocks(S + nb / 2, nb / 2));
    }

    /* The state is not needed anymore */
    wipe(S, sizeof S);
    wipe(tt, sizeof tt);
    wipe(&st->core, sizeof st->core);
    wipe(st->ks, sizeof st->ks);
    wipe(st->buf, sizeof st->buf);
    st->phase = DONE;
    return 0;
}
