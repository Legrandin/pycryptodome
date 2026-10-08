/*
 * SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"

FAKE_INIT(raw_ofb)

#include "block_base.h"

#define ERR_OFB_IV_LEN  ((3 << 16) | 1)

#define MAX_BLOCK_LEN   16

typedef struct {
    BlockBase *cipher;

    /** How many bytes at the beginning of the key stream
      * have already been used.
      */
    size_t usedKeyStream;

    uint8_t keyStream[MAX_BLOCK_LEN];
} OfbModeState;

EXPORT_SYM int OFB_start_operation(BlockBase *cipher,
                                   const uint8_t iv[],
                                   size_t iv_len,
                                   OfbModeState **pResult)
{
    if ((NULL == cipher) || (NULL == iv) || (NULL == pResult))
        return ERR_NULL;

    if (cipher->block_len > MAX_BLOCK_LEN)
        return ERR_BLOCK_SIZE;

    if (cipher->block_len != iv_len)
        return ERR_OFB_IV_LEN;

    *pResult = calloc(1, sizeof(OfbModeState));
    if (NULL == *pResult)
        return ERR_MEMORY;

    (*pResult)->cipher = cipher;
    (*pResult)->usedKeyStream = cipher->block_len;
    memcpy((*pResult)->keyStream, iv, iv_len);

    return 0;
}

EXPORT_SYM int OFB_encrypt(OfbModeState *ofbState,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    size_t block_len;
    size_t used;
    uint8_t oldKeyStream[MAX_BLOCK_LEN];

    if ((NULL == ofbState) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    block_len = ofbState->cipher->block_len;
    if (block_len > MAX_BLOCK_LEN)
        return ERR_BLOCK_SIZE;

    /*
     * Read the position in the key stream only once, and check it:
     * if several threads used the object at once (not supported),
     * the state could be inconsistent, but memory must never be
     * accessed out of bounds.
     */
    used = ofbState->usedKeyStream;
    if (used > block_len)
        return ERR_STATE;

    while (data_len > 0) {
        size_t i;
        size_t keyStreamToUse;

        if (used == block_len) {
            int result;

            memcpy(oldKeyStream, ofbState->keyStream, block_len);
            result = ofbState->cipher->encrypt(ofbState->cipher,
                                               oldKeyStream,
                                               ofbState->keyStream,
                                               block_len);
            if (0 != result) {
                ofbState->usedKeyStream = used;
                return result;
            }

            used = 0;
        }

        keyStreamToUse = MIN(data_len, block_len - used);
        for (i=0; i<keyStreamToUse; i++)
            *out++ = *in++ ^ ofbState->keyStream[i + used];

        data_len -= keyStreamToUse;
        used += keyStreamToUse;
    }

    ofbState->usedKeyStream = used;
    return 0;
}

EXPORT_SYM int OFB_decrypt(OfbModeState *ofbState,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    return OFB_encrypt(ofbState, in, out, data_len);
}

EXPORT_SYM int OFB_stop_operation(OfbModeState *state)
{
    if (NULL == state)
        return ERR_NULL;
    state->cipher->destructor(state->cipher);
    free(state);
    return 0;
}
