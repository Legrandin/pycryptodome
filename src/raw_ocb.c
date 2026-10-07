/* ===================================================================
 *
 * Copyright (c) 2014, Legrandin <helderijs@gmail.com>
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

#include "common.h"

FAKE_INIT(raw_ocb)

#include "block_base.h"
#include <assert.h>
#include <stdio.h>

#define BLOCK_SIZE 16

typedef uint8_t DataBlock[BLOCK_SIZE];

typedef struct {
    BlockBase   *cipher;

    DataBlock   L_star;
    DataBlock   L_dollar;
    DataBlock   L[65];  /** 0..64 **/

    /** Associated data **/
    uint64_t    counter_A;
    DataBlock   offset_A;
    DataBlock   sum;

    /** Ciphertext/plaintext **/
    uint64_t    counter_P;
    DataBlock   offset_P;
    DataBlock   checksum;
} OcbModeState;

static void double_L(DataBlock *out, DataBlock *in)
{
    unsigned carry;
    int i;

    carry = 0;
    for (i=BLOCK_SIZE-1; i>=0; i--) {
        unsigned t;

        t = ((unsigned)(*in)[i] << 1) | carry;
        carry = t >> 8;
        (*out)[i] = (uint8_t)t;
    }
    carry |= 0x100;
    carry |= carry << 1;
    carry |= carry << 2;
    carry |= carry << 4;
    (*out)[BLOCK_SIZE-1] = (uint8_t)((*out)[BLOCK_SIZE-1] ^ (carry & 0x87));
}

static unsigned ntz(uint64_t counter)
{
    unsigned i;
    for (i=0; i<65; i++) {
        if (counter & 1)
            return i;
        counter >>= 1;
    }
    return 64;
}

/** Blocks are processed in batches of NR_BLOCKS, with one call to the cipher **/
#define NR_BLOCKS 8

/**
 * Move offset from Offset_from to Offset_to (block numbers).
 *
 * Since Offset_i = Offset_{i-1} ^ L[ntz(i)], Offset_to is Offset_from
 * XORed with L[ntz(j)] for j = from+1..to.
 * Among 1..i, the number of j with ntz(j) = k is odd if and only if
 * bit k of the Gray code of i (i ^ (i >> 1)) is set. So, the XOR of
 * L[ntz(j)] for j = 1..i is the XOR of the L[k] selected by the Gray code
 * of i, and the one for j = from+1..to by the XOR of two Gray codes.
 */
static void move_offset(const OcbModeState *state, DataBlock offset, uint64_t from, uint64_t to)
{
    uint64_t bits;
    unsigned i, k;

    bits = (from ^ (from >> 1)) ^ (to ^ (to >> 1));
    for (k=0; bits != 0; k++, bits >>= 1) {
        if (bits & 1) {
            for (i=0; i<BLOCK_SIZE; i++)
                offset[i] ^= state->L[k][i];
        }
    }
}

/**
 * Check that n_blocks blocks can be processed from block number first:
 * the counter never wraps around to 0.
 */
static int check_blocks(uint64_t first, uint64_t n_blocks)
{
    if (n_blocks > UINT64_MAX - first)
        return ERR_MAX_DATA;
    return 0;
}

enum OcbDirection { OCB_ENCRYPT, OCB_DECRYPT };

/**
 * Encrypt or decrypt n_blocks full blocks, the first one being block
 * number first. On entry, offset is Offset_{first-1}; on exit, it is
 * the offset of the last block. The plaintext blocks are XORed into checksum.
 * in and out can be the same buffer.
 */
static int transcrypt_blocks(const OcbModeState *state,
                             enum OcbDirection direction,
                             const uint8_t *in,
                             uint8_t *out,
                             size_t n_blocks,
                             uint64_t first,
                             DataBlock offset,
                             DataBlock checksum)
{
    CipherOperation process;
    uint8_t pre[NR_BLOCKS*BLOCK_SIZE];
    uint8_t offsets[NR_BLOCKS*BLOCK_SIZE];
    int result;

    process = OCB_ENCRYPT==direction ? state->cipher->encrypt : state->cipher->decrypt;

    while (n_blocks > 0) {
        size_t n, len, j;
        unsigned i;

        n = MIN(n_blocks, NR_BLOCKS);
        len = n * BLOCK_SIZE;

        for (j=0; j<n; j++) {
            unsigned idx;

            idx = ntz(first + j);
            for (i=0; i<BLOCK_SIZE; i++) {
                offset[i] ^= state->L[idx][i];
                offsets[j*BLOCK_SIZE + i] = offset[i];
            }
        }

        /** Read all of in[] before out[] is written (they can overlap) **/
        for (j=0; j<len; j++) {
            pre[j] = in[j] ^ offsets[j];
            if (OCB_ENCRYPT==direction)
                checksum[j % BLOCK_SIZE] ^= in[j];
        }

        result = process(state->cipher, pre, out, len);
        if (result)
            return result;

        for (j=0; j<len; j++) {
            out[j] ^= offsets[j];
            if (OCB_DECRYPT==direction)
                checksum[j % BLOCK_SIZE] ^= out[j];
        }

        first += n;
        n_blocks -= n;
        in += len;
        out += len;
    }

    return 0;
}

/**
 * Process n_blocks full blocks of associated data, the first one being
 * block number first. On entry, offset is Offset_{first-1}; on exit, it is
 * the offset of the last block. The encrypted blocks are XORed into sum.
 */
static int hash_blocks(const OcbModeState *state,
                       const uint8_t *in,
                       size_t n_blocks,
                       uint64_t first,
                       DataBlock offset,
                       DataBlock sum)
{
    uint8_t pre[NR_BLOCKS*BLOCK_SIZE];
    uint8_t ct[NR_BLOCKS*BLOCK_SIZE];
    int result;

    while (n_blocks > 0) {
        size_t n, len, j;
        unsigned i;

        n = MIN(n_blocks, NR_BLOCKS);
        len = n * BLOCK_SIZE;

        for (j=0; j<n; j++) {
            unsigned idx;

            idx = ntz(first + j);
            for (i=0; i<BLOCK_SIZE; i++) {
                offset[i] ^= state->L[idx][i];
                pre[j*BLOCK_SIZE + i] = in[j*BLOCK_SIZE + i] ^ offset[i];
            }
        }

        result = state->cipher->encrypt(state->cipher, pre, ct, len);
        if (result)
            return result;

        for (j=0; j<len; j++)
            sum[j % BLOCK_SIZE] ^= ct[j];

        first += n;
        n_blocks -= n;
        in += len;
    }

    return 0;
}

/**
 * Encrypt or decrypt the last piece, of in_len bytes (1..15).
 * On entry, offset is the offset of the last full block; on exit, it is
 * Offset_* (offset ^ L_*). The piece, padded, is XORed into checksum.
 */
static int transcrypt_tail(const OcbModeState *state,
                           enum OcbDirection direction,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t in_len,
                           DataBlock offset,
                           DataBlock checksum)
{
    DataBlock pad;
    unsigned i;
    int result;

    for (i=0; i<BLOCK_SIZE; i++)
        offset[i] ^= state->L_star[i];

    result = state->cipher->encrypt(state->cipher, offset, pad, BLOCK_SIZE);
    if (result)
        return result;

    for (i=0; i<in_len; i++) {
        uint8_t in_byte = in[i];

        out[i] = in_byte ^ pad[i];
        checksum[i] ^= OCB_ENCRYPT==direction ? in_byte : out[i];
    }
    checksum[in_len] ^= 0x80;

    return 0;
}

/**
 * Find the first block of the range of data_len bytes at the given offset
 * (both multiple of the block size), after the data processed so far
 * (up to block number counter-1). Check that the range can be processed.
 */
static int range_start(uint64_t counter, size_t offset, size_t data_len, uint64_t *first)
{
    uint64_t skipped;

    if ((offset % BLOCK_SIZE) || (data_len % BLOCK_SIZE))
        return ERR_NOT_ENOUGH_DATA;

    skipped = offset / BLOCK_SIZE;
    if (skipped > UINT64_MAX - counter)
        return ERR_MAX_DATA;
    *first = counter + skipped;

    return check_blocks(*first, data_len / BLOCK_SIZE);
}

/**
 * Compute Offset_0 from the nonce (RFC 7253, section 4.2).
 *
 * The nonce is formatted into a block, with the tag length (in bits, modulo 128)
 * in the top 7 bits, then zeroes, a single 1 bit, and the nonce itself.
 * Ktop is the encryption of that block, with the bottom 6 bits cleared.
 * Stretch is Ktop || (Ktop[0..63] xor Ktop[8..71]), 192 bits.
 * Offset_0 is made of the 128 bits of Stretch that start at bit "bottom"
 * (the 6 bits cleared before, counting from the most significant bit).
 */
static int compute_offset_0(const OcbModeState *state,
                            const uint8_t *nonce,
                            size_t nonce_len,
                            size_t tag_len,
                            DataBlock offset_0)
{
    DataBlock formatted;
    uint8_t stretch[BLOCK_SIZE + 8];
    unsigned bottom, byte_shift, bit_shift, i;
    int result;

    memset(formatted, 0, BLOCK_SIZE);
    formatted[0] = (uint8_t)(((tag_len * 8) % 128) << 1);
    formatted[BLOCK_SIZE - 1 - nonce_len] |= 1;
    memcpy(formatted + BLOCK_SIZE - nonce_len, nonce, nonce_len);

    bottom = formatted[BLOCK_SIZE - 1] & 0x3F;
    formatted[BLOCK_SIZE - 1] &= 0xC0;

    result = state->cipher->encrypt(state->cipher, formatted, stretch, BLOCK_SIZE);
    if (result)
        return result;
    for (i=0; i<8; i++)
        stretch[BLOCK_SIZE + i] = stretch[i] ^ stretch[i + 1];

    byte_shift = bottom / 8;
    bit_shift = bottom % 8;
    for (i=0; i<BLOCK_SIZE; i++) {
        unsigned two_bytes;

        /** byte_shift + i + 1 is at most 7 + 15 + 1, within stretch **/
        two_bytes = (unsigned)stretch[byte_shift + i] << 8 | stretch[byte_shift + i + 1];
        offset_0[i] = (uint8_t)(two_bytes >> (8 - bit_shift));
    }

    return 0;
}

/**
 * Create the state for an OCB encryption or decryption.
 *
 * @cipher     The block cipher (with 16 byte blocks), which the state then owns.
 * @nonce      The nonce (1 to 15 bytes).
 * @tag_len    The length of the tag, in bytes (1 to 16).
 * @pState     Where to store the new state.
 */
EXPORT_SYM int OCB_start_operation(BlockBase *cipher,
                                   const uint8_t *nonce,
                                   size_t nonce_len,
                                   size_t tag_len,
                                   OcbModeState **pState)
{
    OcbModeState *state;
    DataBlock zero;
    int result;
    unsigned i;

    if ((NULL == cipher) || (NULL == nonce) || (NULL == pState)) {
        return ERR_NULL;
    }

    if (BLOCK_SIZE != cipher->block_len) {
        return ERR_BLOCK_SIZE;
    }

    if ((nonce_len == 0) || (nonce_len >= BLOCK_SIZE)) {
        return ERR_NONCE_SIZE;
    }

    if ((tag_len == 0) || (tag_len > BLOCK_SIZE)) {
        return ERR_TAG_SIZE;
    }

    state = calloc(1, sizeof(OcbModeState));
    if (NULL == state) {
        return ERR_MEMORY;
    }

    state->cipher = cipher;

    memset(zero, 0, BLOCK_SIZE);
    result = state->cipher->encrypt(state->cipher, zero, state->L_star, BLOCK_SIZE);
    if (result)
        goto error;

    double_L(&state->L_dollar, &state->L_star);
    double_L(&state->L[0], &state->L_dollar);
    for (i=1; i<=64; i++)
        double_L(&state->L[i], &state->L[i-1]);

    result = compute_offset_0(state, nonce, nonce_len, tag_len, state->offset_P);
    if (result)
        goto error;

    state->counter_A = state->counter_P = 1;

    *pState = state;
    return 0;

error:
    /** The caller still owns the cipher **/
    free(state);
    return result;
}

EXPORT_SYM int OCB_transcrypt(OcbModeState *state,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t in_len,
                              enum OcbDirection direction)
{
    size_t n_blocks;
    int result;

    if ((NULL == state) || (NULL == out) || (NULL == in))
        return ERR_NULL;

    assert(OCB_ENCRYPT==direction || OCB_DECRYPT==direction);

    /** Process nothing if the counter would wrap around **/
    n_blocks = in_len / BLOCK_SIZE;
    result = check_blocks(state->counter_P, n_blocks);
    if (result)
        return result;

    result = transcrypt_blocks(state, direction, in, out, n_blocks, state->counter_P,
                               state->offset_P, state->checksum);
    if (result)
        return result;
    state->counter_P += n_blocks;

    in += n_blocks * BLOCK_SIZE;
    out += n_blocks * BLOCK_SIZE;
    in_len -= n_blocks * BLOCK_SIZE;

    /** Process last piece (if any) **/
    if (in_len>0)
        return transcrypt_tail(state, direction, in, out, in_len, state->offset_P, state->checksum);

    return 0;
}

/**
 * Encrypt or decrypt the data_len bytes at offset in in[] into the same
 * offset in out[], as if all data before offset had been processed already.
 * offset must be a multiple of 16 bytes. If data_len is not, the range
 * ends with the last piece of the message (shorter than a block),
 * like with OCB_encrypt() and OCB_decrypt().
 * The state is not changed: the checksum of the range goes into checksum[].
 *
 * Several threads can call it at the same time on the same state,
 * for instance each one on a different range of the same buffers,
 * as long as no other function changes the state in the meantime.
 * Afterwards, OCB_skip() moves the state past all the ranges.
 */
static int transcrypt_at(const OcbModeState *state,
                         const uint8_t *in,
                         uint8_t *out,
                         size_t offset,
                         size_t data_len,
                         uint8_t checksum[BLOCK_SIZE],
                         enum OcbDirection direction)
{
    DataBlock offset_P;
    uint64_t first;
    size_t whole_len;
    int result;

    if ((NULL == state) || (NULL == in) || (NULL == out) || (NULL == checksum))
        return ERR_NULL;

    if (offset + data_len < offset)
        return ERR_MAX_DATA;

    whole_len = data_len - data_len % BLOCK_SIZE;
    result = range_start(state->counter_P, offset, whole_len, &first);
    if (result)
        return result;

    memset(checksum, 0, BLOCK_SIZE);
    memcpy(offset_P, state->offset_P, BLOCK_SIZE);
    move_offset(state, offset_P, state->counter_P - 1, first - 1);

    in += offset;
    out += offset;
    result = transcrypt_blocks(state, direction, in, out, whole_len / BLOCK_SIZE, first, offset_P, checksum);
    if (result)
        return result;

    if (data_len > whole_len)
        return transcrypt_tail(state, direction, in + whole_len, out + whole_len,
                               data_len - whole_len, offset_P, checksum);

    return 0;
}

EXPORT_SYM int OCB_encrypt_at(const OcbModeState *state,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t offset,
                              size_t data_len,
                              uint8_t checksum[BLOCK_SIZE])
{
    return transcrypt_at(state, in, out, offset, data_len, checksum, OCB_ENCRYPT);
}

EXPORT_SYM int OCB_decrypt_at(const OcbModeState *state,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t offset,
                              size_t data_len,
                              uint8_t checksum[BLOCK_SIZE])
{
    return transcrypt_at(state, in, out, offset, data_len, checksum, OCB_DECRYPT);
}

/**
 * Move the state data_len bytes forward in the plaintext/ciphertext,
 * as if OCB_encrypt() or OCB_decrypt() had processed them: if data_len is
 * not a multiple of 16, they end with the last piece of the message.
 * checksum[] is the checksum of those bytes (the XOR of the checksums
 * computed by OCB_encrypt_at() or OCB_decrypt_at() for all ranges).
 */
EXPORT_SYM int OCB_skip(OcbModeState *state, size_t data_len, const uint8_t checksum[BLOCK_SIZE])
{
    uint64_t first;
    int result;
    unsigned i;

    if ((NULL == state) || (NULL == checksum))
        return ERR_NULL;

    result = range_start(state->counter_P, 0, data_len - data_len % BLOCK_SIZE, &first);
    if (result)
        return result;

    state->counter_P += data_len / BLOCK_SIZE;
    move_offset(state, state->offset_P, first - 1, state->counter_P - 1);

    /** The last piece uses Offset_* (see transcrypt_tail()) **/
    if (data_len % BLOCK_SIZE) {
        for (i=0; i<BLOCK_SIZE; i++)
            state->offset_P[i] ^= state->L_star[i];
    }

    for (i=0; i<BLOCK_SIZE; i++)
        state->checksum[i] ^= checksum[i];

    return 0;
}

/**
 * Encrypt a piece of plaintext.
 *
 * @state   The block cipher state.
 * @in      A pointer to the plaintext. It is aligned to the 16 byte boundary
 *          unless it is the last block.
 * @out     A pointer to an output buffer, that will hold the ciphertext.
 *          The caller must allocate an area of memory as big as the plaintext.
 * @in_len  The size of the plaintext pointed to by @in.
 *
 * @return  0 in case of success, otherwise the relevant error code.
 */
EXPORT_SYM int OCB_encrypt(OcbModeState *state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t in_len)
{
    return OCB_transcrypt(state, in, out, in_len, OCB_ENCRYPT);
}

/**
 * Decrypt a piece of ciphertext.
 *
 * @state   The block cipher state.
 * @in      A pointer to the ciphertext. It is aligned to the 16 byte boundary
 *          unless it is the last block.
 * @out     A pointer to an output buffer, that will hold the plaintext.
 *          The caller must allocate an area of memory as big as the ciphertext.
 * @in_len  The size of the ciphertext pointed to by @in.
 *
 * @return  0 in case of success, otherwise the relevant error code.
 */
EXPORT_SYM int OCB_decrypt(OcbModeState *state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t in_len)
{
    return OCB_transcrypt(state, in, out, in_len, OCB_DECRYPT);
}

/**
 * Process a piece of authenticated data.
 *
 * @state   The block cipher state.
 * @in      A pointer to the authenticated data.
 *          It must be aligned to the 16 byte boundary, unless it is
 *          the last piece.
 * @in_len  The size of the authenticated data pointed to by @in.
 */
EXPORT_SYM int OCB_update(OcbModeState *state,
                          const uint8_t *in,
                          size_t in_len)
{
    int result;
    unsigned i;
    size_t n_blocks;
    DataBlock pt;
    DataBlock ct;

    if ((NULL == state) || (NULL == in))
        return ERR_NULL;

    /** Process nothing if the counter would wrap around **/
    n_blocks = in_len / BLOCK_SIZE;
    result = check_blocks(state->counter_A, n_blocks);
    if (result)
        return result;

    result = hash_blocks(state, in, n_blocks, state->counter_A, state->offset_A, state->sum);
    if (result)
        return result;
    state->counter_A += n_blocks;

    in += n_blocks * BLOCK_SIZE;
    in_len -= n_blocks * BLOCK_SIZE;

    /** Process last piece (if any) **/
    if (in_len>0) {
        memset(pt, 0, sizeof pt);
        memcpy(pt, in, in_len);
        pt[in_len] = 0x80;

        for (i=0; i<BLOCK_SIZE; i++)
            pt[i] ^= state->offset_A[i] ^ state->L_star[i];

        result = state->cipher->encrypt(state->cipher, pt, ct, BLOCK_SIZE);
        if (result)
            return result;

        for (i=0; i<BLOCK_SIZE; i++)
            state->sum[i] ^= ct[i];
    }

    return 0;
}

EXPORT_SYM int OCB_digest(OcbModeState *state,
                          uint8_t *tag,
                          size_t tag_len)
{
    DataBlock pt;
    unsigned i;
    int result;

    if ((NULL == state) || (NULL == tag))
        return ERR_NULL;

    if (BLOCK_SIZE != tag_len)
        return ERR_TAG_SIZE;

    for (i=0; i<BLOCK_SIZE; i++)
        pt[i] = state->checksum[i] ^ state->offset_P[i] ^ state->L_dollar[i];

    result = state->cipher->encrypt(state->cipher, pt, tag, BLOCK_SIZE);
    if (result)
        return result;

    /** state->sum is HASH(K, A) **/
    for (i=0; i<BLOCK_SIZE; i++)
        tag[i] ^= state->sum[i];

    return 0;
}

EXPORT_SYM int OCB_stop_operation(OcbModeState *state)
{
    if (NULL == state)
        return ERR_NULL;
    state->cipher->destructor(state->cipher);
    free(state);
    return 0;
}
