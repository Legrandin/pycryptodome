/* ===================================================================
 *
 * Copyright (c) 2026, Legrandin <helderijs@gmail.com>
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

/*
 * KangarooTwelve (RFC 9861), in a separate module from the generic Keccak sponge.
 */

/* The K12 code needs the internals of keccak_state and keccak_function() */
#define KECCAK_EMBEDDED
#include "keccak.c"

FAKE_INIT(k12)

#define K12_LEAF_SIZE   8192
#define K12_CV_SIZE     32

/*
 * Hash n_leaves complete 8192-byte leaves with TurboSHAKE128
 * (domain 0x0B) and write their 32-byte chaining values to cvs
 * (n_leaves * 32 bytes).
 *
 * It only uses a local state on the stack, so it is reentrant
 * and it can be called from several threads at the same time.
 */
EXPORT_SYM int k12_leaves(const uint8_t *in, size_t n_leaves, uint8_t *cvs)
{
    keccak_state ks;
    size_t i;

    if (NULL == in || NULL == cvs)
        return ERR_NULL;

    memset(&ks, 0, sizeof ks);
    ks.capacity = 32;
    ks.rate = KECCAK_F1600_STATE - ks.capacity;
    ks.rounds = 12;

    for (i=0; i<n_leaves; i++) {
        keccak_reset(&ks);
        keccak_absorb(&ks, in, K12_LEAF_SIZE);
        keccak_squeeze(&ks, cvs, K12_CV_SIZE, 0x0B);
        in += K12_LEAF_SIZE;
        cvs += K12_CV_SIZE;
    }

    return 0;
}

/*
 * State of a KangarooTwelve computation.
 * The message is S = M || C || length_encode(|C|).
 */
typedef struct
{
    keccak_state final;     /* S_0 and then the final node */
    keccak_state leaf;      /* The current leaf S_i (i > 0) */
    size_t len0;            /* Bytes of S_0 absorbed so far (up to 8192) */
    size_t len_leaf;        /* Bytes of the current leaf absorbed so far */
    size_t n_cvs;           /* Chaining values absorbed into the final node */
    int tree;               /* Whether S is longer than 8192 bytes */
} k12_state;

static void turboshake128_init(keccak_state *ks)
{
    memset(ks, 0, sizeof *ks);
    ks->capacity = 32;
    ks->rate = KECCAK_F1600_STATE - ks->capacity;
    ks->rounds = 12;
}

static void k12_add_cv(k12_state *k12, const uint8_t *cv)
{
    keccak_absorb(&k12->final, cv, K12_CV_SIZE);
    k12->n_cvs++;
}

static void k12_absorb(k12_state *k12, const uint8_t *in, size_t length)
{
    static const uint8_t s0_divider[8] = { 3, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t cv[K12_CV_SIZE];
    size_t tc;

    while (length > 0) {

        if (k12->len0 < K12_LEAF_SIZE) {
            tc = MIN(length, K12_LEAF_SIZE - k12->len0);
            keccak_absorb(&k12->final, in, tc);
            k12->len0 += tc;
            in        += tc;
            length    -= tc;
            continue;
        }

        /* S is longer than 8192 bytes: switch to tree hashing */
        if (!k12->tree) {
            keccak_absorb(&k12->final, s0_divider, sizeof s0_divider);
            k12->tree = 1;
        }

        /* Fast path for whole leaves */
        if (k12->len_leaf == 0 && length >= K12_LEAF_SIZE) {
            k12_leaves(in, 1, cv);
            k12_add_cv(k12, cv);
            in     += K12_LEAF_SIZE;
            length -= K12_LEAF_SIZE;
            continue;
        }

        tc = MIN(length, K12_LEAF_SIZE - k12->len_leaf);
        keccak_absorb(&k12->leaf, in, tc);
        k12->len_leaf += tc;
        in            += tc;
        length        -= tc;

        if (k12->len_leaf == K12_LEAF_SIZE) {
            keccak_squeeze(&k12->leaf, cv, K12_CV_SIZE, 0x0B);
            k12_add_cv(k12, cv);
            keccak_reset(&k12->leaf);
            k12->len_leaf = 0;
        }
    }
}

/*
 * Big-endian encoding of x with the minimum number of bytes,
 * followed by that number of bytes (out must be 9 bytes or more).
 */
static unsigned k12_length_encode(size_t x, uint8_t *out)
{
    unsigned n, i;

    for (n=0; n<sizeof(size_t) && (x >> (8*n)) != 0; n++);
    for (i=0; i<n; i++) {
        out[i] = (uint8_t)(x >> (8*(n-1-i)));
    }
    out[n] = (uint8_t)n;
    return n + 1;
}

/*
 * Compute out_len bytes of KangarooTwelve output for message 'in'
 * and customization string 'custom', in a single call.
 *
 * Like k12_leaves(), it only uses a local state on the stack.
 */
EXPORT_SYM int k12_oneshot(const uint8_t *in, size_t in_len,
                           const uint8_t *custom, size_t custom_len,
                           uint8_t *out, size_t out_len)
{
    k12_state k12;
    uint8_t enc[sizeof(size_t) + 3];
    uint8_t cv[K12_CV_SIZE];
    unsigned enc_len;

    if ((NULL == in && in_len > 0) || (NULL == custom && custom_len > 0) || NULL == out)
        return ERR_NULL;

    turboshake128_init(&k12.final);
    turboshake128_init(&k12.leaf);
    k12.len0 = 0;
    k12.len_leaf = 0;
    k12.n_cvs = 0;
    k12.tree = 0;

    if (in_len > 0)
        k12_absorb(&k12, in, in_len);
    if (custom_len > 0)
        k12_absorb(&k12, custom, custom_len);
    enc_len = k12_length_encode(custom_len, enc);
    k12_absorb(&k12, enc, enc_len);

    if (!k12.tree) {
        return keccak_squeeze(&k12.final, out, out_len, 0x07);
    }

    if (k12.len_leaf > 0) {
        keccak_squeeze(&k12.leaf, cv, K12_CV_SIZE, 0x0B);
        k12_add_cv(&k12, cv);
    }

    enc_len = k12_length_encode(k12.n_cvs, enc);
    enc[enc_len++] = 0xFF;
    enc[enc_len++] = 0xFF;
    keccak_absorb(&k12.final, enc, enc_len);

    return keccak_squeeze(&k12.final, out, out_len, 0x06);
}
