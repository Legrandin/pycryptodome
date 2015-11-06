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

FAKE_INIT(raw_cfb)

#include "block_base.h"

#define ERR_CFB_IV_LEN           ((2 << 16) | 1)
#define ERR_CFB_INVALID_SEGMENT  ((2 << 16) | 2)

typedef struct {
    BlockBase *cipher;
    size_t segment_len;
    uint8_t iv[0];
} CfbModeState;

EXPORT_SYM int CFB_start_operation(BlockBase *cipher,
                                   const uint8_t iv[],
                                   size_t iv_len,
                                   size_t segment_len, /* In bytes */
                                   CfbModeState **pResult)
{
    if ((NULL == cipher) || (NULL == iv) || (NULL == pResult)) {
        return ERR_NULL;
    }

    if (cipher->block_len != iv_len) {
        return ERR_CFB_IV_LEN;
    }

    if ((segment_len == 0) || (segment_len > cipher->block_len)) {
        return ERR_CFB_INVALID_SEGMENT;
    }

    *pResult = calloc(1, sizeof(CfbModeState) + iv_len);
    if (NULL == *pResult) {
        return ERR_MEMORY;
    }

    (*pResult)->cipher = cipher;
    (*pResult)->segment_len = segment_len;
    memcpy((*pResult)->iv, iv, iv_len);

    return 0;
}

EXPORT_SYM int CFB_encrypt(CfbModeState *cfbState,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    uint8_t *keyStream, *iv;
    size_t block_len;
    size_t segment_len;

    if ((NULL == cfbState) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    block_len = cfbState->cipher->block_len;
    segment_len = cfbState->segment_len;

    keyStream = (uint8_t *) alloca(block_len);
    iv = (uint8_t *) alloca(block_len);

    memcpy(iv, cfbState->iv, block_len);
    while (data_len > 0) {
        size_t i;
        int result;

        if (data_len < segment_len)
            return ERR_NOT_ENOUGH_DATA;

        result = cfbState->cipher->encrypt(cfbState->cipher, iv, keyStream, block_len);
        if (result)
            return result;

        for (i=0; i<segment_len; i++)
            out[i] = keyStream[i] ^ in[i];

        for (i=0; i<block_len - segment_len; i++)
            iv[i] = iv[i + segment_len];
        memcpy(&iv[i], out, segment_len);

        data_len -= segment_len;
        in += segment_len;
        out += segment_len;
    }
    memcpy(cfbState->iv, iv, block_len);

    return 0;
}

EXPORT_SYM int CFB_decrypt(CfbModeState *cfbState,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    uint8_t *keyStream, *iv;
    size_t block_len;
    size_t segment_len;

    if ((NULL == cfbState) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    block_len = cfbState->cipher->block_len;
    segment_len = cfbState->segment_len;

    keyStream = (uint8_t *) alloca(block_len);
    iv = (uint8_t *) alloca(block_len);

    memcpy(iv, cfbState->iv, block_len);
    while (data_len > 0) {
        size_t i;
        int result;

        if (data_len < segment_len)
            return ERR_NOT_ENOUGH_DATA;

        result = cfbState->cipher->encrypt(cfbState->cipher, iv, keyStream, block_len);
        if (result)
            return result;

        for (i=0; i<segment_len; i++)
            out[i] = keyStream[i] ^ in[i];

        for (i=0; i<block_len - segment_len; i++)
            iv[i] = iv[i + segment_len];
        memcpy(&iv[i], in, segment_len);

        data_len -= segment_len;
        in += segment_len;
        out += segment_len;
    }
    memcpy(cfbState->iv, iv, block_len);

    return 0;
}

EXPORT_SYM int CFB_stop_operation(CfbModeState *state)
{
    if (NULL == state)
        return ERR_NULL;

    state->cipher->destructor(state->cipher);
    free(state);
    return 0;
}
