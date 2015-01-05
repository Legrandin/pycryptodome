#include <stdlib.h>
#include <string.h>

#include "block_base.h"

#define ERR_OFB_IV_LEN           ((3 << 16) | 1)

typedef struct {
    BlockBase *cipher;

    /** How many bytes at the beginning of the key stream
      * have already been used.
      */
    uint8_t usedKeyStream;

    uint8_t keyStream[0];
} OfbModeState;

static unsigned min(unsigned a, unsigned b) {
    return a < b ? a : b;
}

int OFB_start_operation(BlockBase *cipher,
                    const uint8_t iv[],
                    size_t iv_len,
                    OfbModeState **pResult) {

    if ((NULL == cipher) || (NULL == iv) || (NULL == pResult)) {
        return ERR_NULL;
    }

    if (cipher->block_len != iv_len) {
        return ERR_OFB_IV_LEN;
    }

    *pResult = calloc(1, sizeof(OfbModeState) + iv_len);
    if (NULL == *pResult) {
        return ERR_MEMORY;
    }

    (*pResult)->cipher = cipher;
    (*pResult)->usedKeyStream = cipher->block_len;
    memcpy((*pResult)->keyStream, iv, iv_len);

    return 0;
}

int OFB_encrypt(OfbModeState *ofbState,
            const uint8_t *in,
            uint8_t *out,
            size_t data_len) {

    size_t block_len;
    uint8_t *oldKeyStream;

    if ((NULL == ofbState) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    block_len = ofbState->cipher->block_len;

    oldKeyStream = (uint8_t*) alloca(block_len);

    while (data_len > 0) {
        size_t i;
        size_t keyStreamToUse;

        if (ofbState->usedKeyStream == block_len) {
            int result;

            memcpy(oldKeyStream, ofbState->keyStream, block_len);
            result = ofbState->cipher->encrypt(ofbState->cipher,
                                               oldKeyStream,
                                               ofbState->keyStream,
                                               block_len);
            if (0 != result)
                return result;

            ofbState->usedKeyStream = 0;
        }

        keyStreamToUse = min(data_len, block_len - ofbState->usedKeyStream);
        for (i=0; i<keyStreamToUse; i++)
            *out++ = *in++ ^ ofbState->keyStream[i + ofbState->usedKeyStream];

        data_len -= keyStreamToUse;
        ofbState->usedKeyStream += keyStreamToUse;
    }

    return 0;
}

int OFB_decrypt(OfbModeState *ofbState,
            const uint8_t *in,
            uint8_t *out,
            size_t data_len) {
    return OFB_encrypt(ofbState, in, out, data_len);
}

int OFB_stop_operation(OfbModeState *state)
{
    state->cipher->destructor(state->cipher);
    free(state);
    return 0;
}
