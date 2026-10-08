/*
 * SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>

#include "block_base.h"

#define CIPHER_STATE_TYPE       _PASTE2(MODULE_NAME, _State)
#define CIPHER_ENCRYPT          _PASTE2(MODULE_NAME, _encrypt)
#define CIPHER_DECRYPT          _PASTE2(MODULE_NAME, _decrypt)
#define CIPHER_STOP_OPERATION   _PASTE2(MODULE_NAME, _stop_operation)
#define CIPHER_START_OPERATION  _PASTE2(MODULE_NAME, _start_operation)

typedef struct {
    BlockBase  base_state;
    struct block_state algo_state;
} CIPHER_STATE_TYPE;

static int CIPHER_ENCRYPT
           (const BlockBase *state, const uint8_t *in, uint8_t *out, size_t data_len)
{
    size_t block_len;

    if ((state == NULL) || (in == NULL) || (out == NULL))
        return ERR_NULL;

    block_len = state->block_len;

    for (; data_len>=block_len; data_len-=block_len) {
        block_encrypt(&((CIPHER_STATE_TYPE*)state)->algo_state, (uint8_t*)in, out);
        in += block_len;
        out += block_len;
    }

    if (data_len)
        return ERR_NOT_ENOUGH_DATA;

    return 0;
}

static int CIPHER_DECRYPT
           (const BlockBase *state, const uint8_t *in, uint8_t *out, size_t data_len)
{
    size_t block_len;

    if ((state == NULL) || (in == NULL) || (out == NULL))
        return ERR_NULL;

    block_len = state->block_len;

    for (; data_len>=block_len; data_len-=block_len) {
        block_decrypt(&((CIPHER_STATE_TYPE*)state)->algo_state, (uint8_t*)in, out);
        in += block_len;
        out += block_len;
    }

    if (data_len)
        return ERR_NOT_ENOUGH_DATA;
    
    return 0;
}

EXPORT_SYM int CIPHER_STOP_OPERATION(BlockBase *state)
{
    if (NULL == state)
        return ERR_NULL;

    block_finalize(&((CIPHER_STATE_TYPE*)state)->algo_state);
    free(state);
    return 0;
}

#ifndef NON_STANDARD_START_OPERATION
EXPORT_SYM int CIPHER_START_OPERATION(const uint8_t key[], size_t key_len, CIPHER_STATE_TYPE **pResult)
{
    BlockBase *block_base;
    int res;

    if ((key == NULL) || (pResult == NULL))
        return ERR_NULL;

    *pResult = calloc(1, sizeof(CIPHER_STATE_TYPE));
    if (NULL == *pResult)
        return ERR_MEMORY;

    block_base = &((*pResult)->base_state);
    block_base->encrypt = &CIPHER_ENCRYPT;
    block_base->decrypt = &CIPHER_DECRYPT;
    block_base->destructor = &CIPHER_STOP_OPERATION;
    block_base->block_len = BLOCK_SIZE;

    res = block_init(&(*pResult)->algo_state, (unsigned char*)key, key_len);
    if (res) {
        free(*pResult);
        *pResult = NULL;
    }

    return res;
}
#endif
