#include <stdlib.h>
#include <string.h>

#include "block_base.h"

#define ERR_CFB_IV_LEN           ((2 << 16) | 1)
#define ERR_CFB_INVALID_SEGMENT  ((2 << 16) | 2)

typedef struct {
    BlockBase *cipher;
    size_t segment_len;
    uint8_t iv[0];
} CfbModeState;

int CFB_start_operation(BlockBase *cipher,
                    const uint8_t iv[],
                    size_t iv_len,
                    size_t segment_len, /* In bytes */
                    CfbModeState **pResult) {

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

int CFB_encrypt(CfbModeState *cfbState,
            const uint8_t *in,
            uint8_t *out,
            size_t data_len) {

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

int CFB_decrypt(CfbModeState *cfbState,
            const uint8_t *in,
            uint8_t *out,
            size_t data_len) {

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

int CFB_stop_operation(CfbModeState *state)
{
    state->cipher->destructor(state->cipher);
    free(state);
    return 0;
}
