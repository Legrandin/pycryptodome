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

#include "pycrypto_common.h"

FAKE_INIT(raw_ctr)

#include "block_base.h"

#define ERR_CTR_COUNTER_BLOCK_LEN   ((6 << 16) | 1)
#define ERR_CTR_REPEATED_KEY_STREAM ((6 << 16) | 2)

typedef struct {
    BlockBase *cipher;

    /** How many bytes at the beginning of the key stream
      * have already been used.
      */
    uint8_t usedKeyStream;

    /**
      * The counter is an area within the counter block.
      */
    uint8_t *counter;
    size_t  counter_len;

    void (*increment)(uint8_t *counter, size_t counter_len);

    /**
      * originalCounterBlock - block_len bytes
      * counterBlock - block_len bytes
      * keyStream - block_len bytes
      */
    uint8_t buffer[0];
} CtrModeState;

static inline unsigned min_ab(unsigned a, unsigned b) {
    return a < b ? a : b;
}

static void increment_le(uint8_t *pCounter, size_t counter_len) {
    size_t i;

    for (i=0; i<counter_len; i++, pCounter++) {
        if (++(*pCounter) != 0)
            break;
    }
}

static void increment_be(uint8_t *pCounter, size_t counter_len) {
    size_t i;

    pCounter += counter_len - 1;
    for (i=0; i<counter_len; i++, pCounter--) {
        if (++(*pCounter) != 0)
            break;
    }
}

EXPORT_SYM int CTR_start_operation(BlockBase *cipher,
                                   uint8_t   initialCounterBlock[],
                                   size_t    initialCounterBlock_len,
                                   size_t    prefix_len,
                                   unsigned  counter_len,
                                   unsigned  littleEndian,
                                   CtrModeState **pResult)
{
    CtrModeState *ctrState = NULL;
    size_t block_len;

    if ((NULL == cipher) || (NULL == initialCounterBlock) || (NULL == pResult)) {
        return ERR_NULL;
    }

    block_len = cipher->block_len;

    if ((block_len != initialCounterBlock_len) ||
        (counter_len == 0) ||
        (block_len < (prefix_len + counter_len))) {
        return ERR_CTR_COUNTER_BLOCK_LEN;
    }

    ctrState = calloc(1, sizeof(CtrModeState) + block_len*3);
    if (NULL == ctrState) {
        return ERR_MEMORY;
    }
    memcpy(&ctrState->buffer[0], initialCounterBlock, block_len);
    memcpy(&ctrState->buffer[block_len], initialCounterBlock, block_len);

    ctrState->cipher = cipher;
    ctrState->usedKeyStream = block_len;
    ctrState->counter = ctrState->buffer + block_len + prefix_len;
    ctrState->counter_len = counter_len;
    ctrState->increment = littleEndian ? &increment_le : &increment_be;

    *pResult = ctrState;
    return 0;
}

EXPORT_SYM int CTR_encrypt(CtrModeState *ctrState,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    size_t block_len;
    uint8_t *keyStream;
    uint8_t *counterBlock;
    uint8_t *originalCounterBlock;

    if ((NULL == ctrState) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    block_len = ctrState->cipher->block_len;
    originalCounterBlock = &ctrState->buffer[0];
    counterBlock = &ctrState->buffer[block_len];
    keyStream = &ctrState->buffer[2*block_len];

    while (data_len > 0) {
        unsigned j;
        size_t keyStreamToUse;

        if (ctrState->usedKeyStream == block_len) {

            ctrState->cipher->encrypt(ctrState->cipher,
                                      counterBlock,
                                      keyStream,
                                      block_len);
            ctrState->usedKeyStream = 0;

            /* Prepare next counter block */
            ctrState->increment(ctrState->counter, ctrState->counter_len);

            /* Fail if key stream is ever reused **/
            if (0 == memcmp(originalCounterBlock,
                            counterBlock,
                            block_len))
                return ERR_CTR_REPEATED_KEY_STREAM;
        }

        keyStreamToUse = min_ab(data_len, block_len - ctrState->usedKeyStream);
        for (j=0; j<keyStreamToUse; j++)
            *out++ = *in++ ^ keyStream[j + ctrState->usedKeyStream];

        data_len -= keyStreamToUse;
        ctrState->usedKeyStream += keyStreamToUse;
    }

    return 0;
}

EXPORT_SYM int CTR_decrypt(CtrModeState *ctrState,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    return CTR_encrypt(ctrState, in, out, data_len);
}

EXPORT_SYM int CTR_stop_operation(CtrModeState *ctrState)
{
    if (NULL == ctrState)
        return ERR_NULL;
    ctrState->cipher->destructor(ctrState->cipher);
    free(ctrState);
    return 0;
}
