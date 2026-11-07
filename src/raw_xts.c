/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/**
 * XTS mode (IEEE 1619, NIST SP 800-38E), for one data unit.
 *
 * The caller encrypts the tweak with the second AES key,
 * and gives us the result, with the cipher for the first key.
 */

#include "common.h"
#include "endianess.h"

FAKE_INIT(raw_xts)

#include "block_base.h"

#define BLOCK_LEN       16

/** How many blocks to pass in one go to the cipher, which may process them in parallel **/
#define BATCH_BLOCKS    64

/** A data unit cannot exceed 2^20 blocks (NIST SP 800-38E, IEEE 1619-2018) **/
#define MAX_DATA_LEN    ((uint64_t)1 << 24)

typedef struct {
    BlockBase   *cipher;

    /** The tweak for the next block, as a little-endian 128-bit integer (low word first) **/
    uint64_t    tweak[2];

    uint64_t    processed;

    /** The last call was not aligned to the block length, so it ended the data unit **/
    unsigned    finished;
} XtsModeState;

EXPORT_SYM int XTS_start_operation(BlockBase *cipher,
                                   const uint8_t *encrypted_tweak,
                                   size_t tweak_len,
                                   XtsModeState **pResult)
{
    XtsModeState *state;

    if ((NULL == cipher) || (NULL == encrypted_tweak) || (NULL == pResult))
        return ERR_NULL;

    if ((BLOCK_LEN != cipher->block_len) || (BLOCK_LEN != tweak_len))
        return ERR_BLOCK_SIZE;

    state = calloc(1, sizeof(XtsModeState));
    if (NULL == state)
        return ERR_MEMORY;

    state->cipher = cipher;
    state->tweak[0] = LOAD_U64_LITTLE(encrypted_tweak);
    state->tweak[1] = LOAD_U64_LITTLE(encrypted_tweak + 8);

    *pResult = state;
    return 0;
}

/**
 * Store the tweaks for the next blocks (len is a multiple of the block length).
 * After each one, multiply the tweak by alpha in GF(2^128), in constant time.
 */
static void next_tweaks(XtsModeState *state, uint8_t *out, size_t len)
{
    uint64_t lo = state->tweak[0];
    uint64_t hi = state->tweak[1];

    for (; len > 0; len -= BLOCK_LEN) {
        uint64_t carry;

        STORE_U64_LITTLE(out, lo);
        STORE_U64_LITTLE(out + 8, hi);
        out += BLOCK_LEN;

        carry = hi >> 63;
        hi = (hi << 1) | (lo >> 63);
        lo = (lo << 1) ^ (0x87 & (0 - carry));
    }

    state->tweak[0] = lo;
    state->tweak[1] = hi;
}

/** out = a XOR b, where the length is a multiple of the block length and out can be the same as a **/
static void xor_blocks(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len)
{
    /** Compilers usually turn this into one vector operation (such as with NEON) **/
    for (; len > 0; len -= BLOCK_LEN) {
        uint64_t x[2], y[2];

        memcpy(x, a, BLOCK_LEN);
        memcpy(y, b, BLOCK_LEN);
        x[0] ^= y[0];
        x[1] ^= y[1];
        memcpy(out, x, BLOCK_LEN);
        out += BLOCK_LEN;
        a += BLOCK_LEN;
        b += BLOCK_LEN;
    }
}

/** Process len bytes (a multiple of the block length, at most one batch) with their tweaks **/
static int process_batch(const BlockBase *cipher,
                         CipherOperation operation,
                         const uint8_t *tweaks,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t len)
{
    int result;

    xor_blocks(out, in, tweaks, len);
    result = operation(cipher, out, out, len);
    if (result)
        return result;
    xor_blocks(out, out, tweaks, len);
    return 0;
}

/**
 * Process a block and the partial block that follows it (ciphertext stealing).
 *
 * When encrypting, the full block uses the tweak of its own position first,
 * and the second operation uses the next tweak. Decrypting is the same
 * algorithm with the two tweaks in the opposite order.
 */
static int process_final(XtsModeState *state,
                         CipherOperation operation,
                         unsigned decrypting,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t partial_len)
{
    uint8_t tweaks[2][BLOCK_LEN];
    uint8_t block[BLOCK_LEN];
    uint8_t partial[BLOCK_LEN];
    int result;

    next_tweaks(state, tweaks[decrypting ? 1 : 0], BLOCK_LEN);
    next_tweaks(state, tweaks[decrypting ? 0 : 1], BLOCK_LEN);

    /** in and out may be the same buffer **/
    memcpy(partial, in + BLOCK_LEN, partial_len);

    result = process_batch(state->cipher, operation, tweaks[0], in, block, BLOCK_LEN);
    if (result)
        return result;

    memcpy(out + BLOCK_LEN, block, partial_len);
    memcpy(block, partial, partial_len);

    return process_batch(state->cipher, operation, tweaks[1], block, out, BLOCK_LEN);
}

static int process(XtsModeState *state,
                   CipherOperation operation,
                   unsigned decrypting,
                   const uint8_t *in,
                   uint8_t *out,
                   size_t data_len)
{
    uint8_t tweaks[BATCH_BLOCKS * BLOCK_LEN];
    size_t partial_len;
    size_t remaining;
    int result;

    if (0 == data_len)
        return 0;

    if (state->finished)
        return ERR_STATE;

    partial_len = data_len % BLOCK_LEN;

    /** Stealing takes bytes from a full block in the same call **/
    if (data_len < BLOCK_LEN)
        return ERR_NOT_ENOUGH_DATA;

    if ((uint64_t)data_len > MAX_DATA_LEN - state->processed)
        return ERR_MAX_DATA;

    state->processed += data_len;

    /** With a partial block at the end, the last full block is processed with it **/
    remaining = data_len - partial_len - (partial_len ? BLOCK_LEN : 0);

    while (remaining > 0) {
        size_t batch_len = MIN(remaining, sizeof tweaks);

        next_tweaks(state, tweaks, batch_len);

        result = process_batch(state->cipher, operation, tweaks, in, out, batch_len);
        if (result)
            return result;

        in += batch_len;
        out += batch_len;
        remaining -= batch_len;
    }

    if (partial_len) {
        state->finished = 1;
        return process_final(state, operation, decrypting, in, out, partial_len);
    }

    return 0;
}

EXPORT_SYM int XTS_encrypt(XtsModeState *state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    if ((NULL == state) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    return process(state, state->cipher->encrypt, 0, in, out, data_len);
}

EXPORT_SYM int XTS_decrypt(XtsModeState *state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    if ((NULL == state) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    return process(state, state->cipher->decrypt, 1, in, out, data_len);
}

EXPORT_SYM int XTS_stop_operation(XtsModeState *state)
{
    if (NULL == state)
        return ERR_NULL;

    state->cipher->destructor(state->cipher);
    free(state);
    return 0;
}
