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

FAKE_INIT(raw_ctr)

#include "block_base.h"

#define ERR_CTR_COUNTER_BLOCK_LEN   ((6 << 16) | 1)
#define ERR_CTR_REPEATED_KEY_STREAM ((6 << 16) | 2)

/** The key stream is computed in batches of NR_BLOCKS cipher blocks. **/
#define NR_BLOCKS 16

/** Memory alignment for counter blocks and key stream (any block size works) **/
#define KS_ALIGNMENT 64

/** Add an amount to a counter of counter_len bytes, modulo 2^(8*counter_len) **/
typedef void (*Add)(uint8_t *pCounter, size_t counter_len, uint64_t amount);

typedef struct {
    BlockBase *cipher;
    size_t block_len;

    /**
     *  A counter block is always as big as a cipher block.
     *  It is made up by three areas:
     *  1) Prefix  - immutable - can be empty
     *  2) Counter - mutable (+1 per block) - at least 1 byte
     *  3) Postfix - immutable - can be empty
     */
    uint8_t *counter_blocks;    /** The NR_BLOCKS counter blocks of the current batch **/
    size_t  counter_offset;     /** Position of the counter in a counter block (prefix length) **/
    size_t  counter_len;
    Add     add;                /** add_le() or add_be() **/

    uint8_t *keystream;         /** Key stream of the current batch (block_len * NR_BLOCKS bytes) **/
    size_t  used_ks;            /** Bytes already used in the key stream of the current batch **/
    /**
     * Index of the current batch (0 for the first one). A batch is a group
     * of NR_BLOCKS consecutive cipher blocks of key stream: the current batch
     * starts at block batch * NR_BLOCKS, and at byte batch * NR_BLOCKS * block_len.
     */
    uint64_t batch;

    /** Number of counter values available (0 if 2^64 or more) **/
    uint64_t max_blocks;
} CtrModeState;

static void add_le(uint8_t *pCounter, size_t counter_len, uint64_t amount) {
    size_t i;
    unsigned carry = 0;

    for (i=0; i<counter_len && (amount>0 || carry>0); i++, pCounter++) {
        unsigned sum = *pCounter + (unsigned)(amount & 0xFF) + carry;
        *pCounter = (uint8_t)sum;
        carry = sum >> 8;
        amount >>= 8;
    }
}

static void add_be(uint8_t *pCounter, size_t counter_len, uint64_t amount) {
    size_t i;
    unsigned carry = 0;

    pCounter += counter_len - 1;
    for (i=0; i<counter_len && (amount>0 || carry>0); i++, pCounter--) {
        unsigned sum = *pCounter + (unsigned)(amount & 0xFF) + carry;
        *pCounter = (uint8_t)sum;
        carry = sum >> 8;
        amount >>= 8;
    }
}

/** Add amount to the counter of each of the NR_BLOCKS counter blocks in blocks[] **/
static void advance_counters(const CtrModeState *ctr_state, uint8_t *blocks, uint64_t amount)
{
    unsigned i;

    for (i=0; i<NR_BLOCKS; i++) {
        ctr_state->add(blocks + i*ctr_state->block_len + ctr_state->counter_offset,
                       ctr_state->counter_len,
                       amount);
    }
}

/** Compute the key stream for the counter blocks in blocks[] **/
static void compute_keystream(const CtrModeState *ctr_state, const uint8_t *blocks, uint8_t *keystream)
{
    ctr_state->cipher->encrypt(ctr_state->cipher, blocks, keystream, ctr_state->block_len * NR_BLOCKS);
}

/*
 * Check that the next 'extra' bytes can be encrypted without using any
 * counter value twice. Reusing a counter value means reusing key stream,
 * which breaks confidentiality.
 *
 * 'batch' and 'used_ks' give the current position in the key stream
 * (byte 'used_ks' of batch 'batch'), as read once from the state by the caller.
 * 'used_ks' is 0 only before the first byte; a fully used batch is ks_size.
 *
 * Each cipher block of key stream takes one counter value, even if only some
 * of its bytes are used. So the function counts the blocks from the start of
 * the key stream up to the end of the extra bytes, rounding up, and compares
 * them with max_blocks: the 2^(8*counter_len) values of the counter. When
 * max_blocks is 0 (a counter of 8 bytes or more), the only limit is the 64-bit
 * block count itself.
 *
 * The state is not changed. Callers check before processing anything, so that
 * either all data is processed, or nothing is (ERR_CTR_REPEATED_KEY_STREAM).
 */
static int check_limit(const CtrModeState *ctr_state, uint64_t batch, size_t used_ks, uint64_t extra)
{
    uint64_t ks_size, end_batch, end_used, blocks;

    ks_size = ctr_state->block_len * NR_BLOCKS;

    /**
     * The position just after the extra bytes (the first byte not used),
     * in the same form as the current one:
     * - end_batch: index of the batch that position falls into
     * - end_used:  bytes of that batch used up to that position (0..ks_size-1)
     * The key stream up to there is end_batch * ks_size + end_used bytes long.
     **/
    end_batch = batch + (extra / ks_size);
    end_used = used_ks + (extra % ks_size);
    end_batch += end_used / ks_size;
    end_used %= ks_size;
    /** Unreachable in practice (2^64 batches), but a wrap would undercount **/
    if (end_batch < batch)
        return ERR_CTR_REPEATED_KEY_STREAM;

    /**
     * Counter values used by all bytes before that position, up to and
     * including the last extra byte: the cipher blocks they fall into, rounded
     * up. The byte at that position is not counted (it may never be used).
     **/
    /** Unreachable in practice (2^64 blocks), but blocks must not overflow **/
    if (end_batch > (UINT64_MAX - NR_BLOCKS) / NR_BLOCKS)
        return ERR_CTR_REPEATED_KEY_STREAM;
    blocks = end_batch * NR_BLOCKS + (end_used + ctr_state->block_len - 1) / ctr_state->block_len;

    if (ctr_state->max_blocks != 0 && blocks > ctr_state->max_blocks)
        return ERR_CTR_REPEATED_KEY_STREAM;

    return 0;
}

EXPORT_SYM int CTR_start_operation(BlockBase *cipher,
                                   uint8_t   counter_block0[],
                                   size_t    counter_block0_len,
                                   size_t    prefix_len,
                                   unsigned  counter_len,
                                   unsigned  little_endian,
                                   CtrModeState **pResult)
{
    CtrModeState *ctr_state;
    size_t block_len, ks_size;
    unsigned i;

    if (NULL == cipher || NULL == counter_block0 || NULL == pResult) {
        return ERR_NULL;
    }

    block_len = cipher->block_len;
    if (block_len == 0 || block_len > SIZE_MAX / NR_BLOCKS) {
        return ERR_BLOCK_SIZE;
    }
    ks_size = block_len * NR_BLOCKS;

    if (block_len != counter_block0_len ||
        counter_len == 0 || counter_len > block_len ||
        block_len < (prefix_len + counter_len)) {
        return ERR_CTR_COUNTER_BLOCK_LEN;
    }

    ctr_state = calloc(1, sizeof(CtrModeState));
    if (NULL == ctr_state) {
        return ERR_MEMORY;
    }

    ctr_state->cipher = cipher;
    ctr_state->block_len = block_len;
    ctr_state->counter_offset = prefix_len;
    ctr_state->counter_len = counter_len;
    ctr_state->add = little_endian ? add_le : add_be;

    ctr_state->counter_blocks = align_alloc(ks_size, KS_ALIGNMENT);
    ctr_state->keystream = align_alloc(ks_size, KS_ALIGNMENT);
    if (NULL == ctr_state->counter_blocks || NULL == ctr_state->keystream) {
        align_free(ctr_state->keystream);
        align_free(ctr_state->counter_blocks);
        free(ctr_state);
        return ERR_MEMORY;
    }

    /** The first batch: counter_block0, counter_block0 + 1, ... **/
    for (i=0; i<NR_BLOCKS; i++) {
        uint8_t *block = ctr_state->counter_blocks + i*block_len;

        memcpy(block, counter_block0, block_len);
        ctr_state->add(block + prefix_len, counter_len, i);
    }
    compute_keystream(ctr_state, ctr_state->counter_blocks, ctr_state->keystream);
    ctr_state->used_ks = 0;
    ctr_state->batch = 0;

    /** With a counter of 8 bytes or more, no data can exhaust its values **/
    if (counter_len < 8)
        ctr_state->max_blocks = (uint64_t)1 << (counter_len*8);
    else
        ctr_state->max_blocks = 0;

    *pResult = ctr_state;
    return 0;
}

/*
 * Check that the key stream does not run out in the next data_len bytes.
 */
EXPORT_SYM int CTR_check(const CtrModeState *ctr_state, size_t data_len)
{
    size_t used_ks;

    if (NULL == ctr_state)
        return ERR_NULL;

    used_ks = ctr_state->used_ks;
    if (used_ks > ctr_state->block_len * NR_BLOCKS)
        return ERR_STATE;

    return check_limit(ctr_state, ctr_state->batch, used_ks, data_len);
}

EXPORT_SYM int CTR_encrypt(CtrModeState *ctr_state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    size_t ks_size, used_ks;
    uint64_t batch;
    int result;

    if (NULL == ctr_state || NULL == in || NULL == out)
        return ERR_NULL;

    ks_size = ctr_state->block_len * NR_BLOCKS;

    /*
     * Read the position in the key stream only once, and check it:
     * if several threads used the object at once (not supported),
     * the state could be inconsistent, but the key stream must never
     * be read out of bounds.
     */
    used_ks = ctr_state->used_ks;
    batch = ctr_state->batch;
    if (used_ks > ks_size)
        return ERR_STATE;

    /** Never use a counter value twice: check before processing anything **/
    result = check_limit(ctr_state, batch, used_ks, data_len);
    if (result)
        return result;

    while (data_len > 0) {
        size_t ks_to_use, j;

        if (used_ks == ks_size) {
            advance_counters(ctr_state, ctr_state->counter_blocks, NR_BLOCKS);
            compute_keystream(ctr_state, ctr_state->counter_blocks, ctr_state->keystream);
            batch++;
            used_ks = 0;
        }

        ks_to_use = MIN(data_len, ks_size - used_ks);
        for (j=0; j<ks_to_use; j++) {
            *out++ = *in++ ^ ctr_state->keystream[j + used_ks];
        }

        data_len -= ks_to_use;
        used_ks += ks_to_use;
    }

    ctr_state->used_ks = used_ks;
    ctr_state->batch = batch;
    return 0;
}

/*
 * Encrypt (or decrypt) the data_len bytes at offset in[] into the
 * same offset in out[], with the key stream that starts offset bytes
 * after the current position. The state is not changed.
 *
 * Several threads can call it at the same time on the same state,
 * for instance each one on a different range of the same buffers,
 * as long as no other function changes the state in the meantime.
 * Afterwards, CTR_skip() moves the state past all the ranges.
 */
EXPORT_SYM int CTR_encrypt_at(const CtrModeState *ctr_state,
                              const uint8_t *in,
                              uint8_t *out,
                              size_t offset,
                              size_t data_len)
{
    uint8_t *counter_blocks, *keystream;
    size_t ks_size, used_ks;
    uint64_t pos;
    int result;

    if (NULL == ctr_state || NULL == in || NULL == out)
        return ERR_NULL;

    if (offset + data_len < offset)
        return ERR_MAX_DATA;

    ks_size = ctr_state->block_len * NR_BLOCKS;

    /** Read once and check (see CTR_encrypt) **/
    used_ks = ctr_state->used_ks;
    if (used_ks > ks_size)
        return ERR_STATE;

    result = check_limit(ctr_state, ctr_state->batch, used_ks, (uint64_t)offset + data_len);
    if (result || 0 == data_len)
        return result;

    counter_blocks = align_alloc(ks_size, KS_ALIGNMENT);
    keystream = align_alloc(ks_size, KS_ALIGNMENT);
    if (NULL == counter_blocks || NULL == keystream) {
        result = ERR_MEMORY;
        goto cleanup;
    }

    /** Move a private copy of the counter blocks to the batch where this range starts **/
    pos = (uint64_t)used_ks + offset;
    memcpy(counter_blocks, ctr_state->counter_blocks, ks_size);
    advance_counters(ctr_state, counter_blocks, pos / ks_size * NR_BLOCKS);
    used_ks = (size_t)(pos % ks_size);

    /** Write only out[offset..offset+data_len-1]: the key stream is private, and
     *  a block shared with another range is computed twice but used for different bytes **/
    in += offset;
    out += offset;
    while (data_len > 0) {
        size_t ks_to_use, j;

        compute_keystream(ctr_state, counter_blocks, keystream);

        ks_to_use = MIN(data_len, ks_size - used_ks);
        for (j=0; j<ks_to_use; j++) {
            *out++ = *in++ ^ keystream[j + used_ks];
        }
        data_len -= ks_to_use;
        used_ks = 0;

        if (data_len > 0) {
            advance_counters(ctr_state, counter_blocks, NR_BLOCKS);
        }
    }

cleanup:
    align_free(keystream);
    align_free(counter_blocks);
    return result;
}

/*
 * Move the state data_len bytes forward in the key stream,
 * as if CTR_encrypt() had processed them.
 */
EXPORT_SYM int CTR_skip(CtrModeState *ctr_state, size_t data_len)
{
    size_t ks_size, used_ks;
    uint64_t batch, pos;
    int result;

    if (NULL == ctr_state)
        return ERR_NULL;

    ks_size = ctr_state->block_len * NR_BLOCKS;

    /** Read once and check (see CTR_encrypt) **/
    used_ks = ctr_state->used_ks;
    batch = ctr_state->batch;
    if (used_ks > ks_size)
        return ERR_STATE;

    result = check_limit(ctr_state, batch, used_ks, data_len);
    if (result)
        return result;

    /** Like CTR_encrypt(), only update the key stream when more is needed **/
    pos = (uint64_t)used_ks + data_len;
    if (pos > ks_size) {
        uint64_t batches = (pos - 1) / ks_size;

        advance_counters(ctr_state, ctr_state->counter_blocks, batches * NR_BLOCKS);
        compute_keystream(ctr_state, ctr_state->counter_blocks, ctr_state->keystream);
        pos -= batches * ks_size;
        batch += batches;
    }

    ctr_state->used_ks = (size_t)pos;
    ctr_state->batch = batch;
    return 0;
}

EXPORT_SYM int CTR_decrypt(CtrModeState *ctr_state,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    return CTR_encrypt(ctr_state, in, out, data_len);
}

EXPORT_SYM int CTR_stop_operation(CtrModeState *ctr_state)
{
    if (NULL == ctr_state)
        return ERR_NULL;
    ctr_state->cipher->destructor(ctr_state->cipher);
    align_free(ctr_state->keystream);
    align_free(ctr_state->counter_blocks);
    free(ctr_state);
    return 0;
}
