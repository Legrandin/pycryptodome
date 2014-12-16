#include <stdlib.h>
#include <string.h>

#include "block_base.h"

typedef BlockBase EcbModeState;

int ECB_start_operation(BlockBase *cipher,
                    EcbModeState **pResult) {

    if ((NULL == cipher) || (NULL == pResult)) {
        return ERR_NULL;
    }

    *pResult = (EcbModeState*)cipher;
    return 0;
}

int ECB_encrypt(EcbModeState *ecbState,
            const uint8_t *in,
            uint8_t *out,
            size_t data_len) {

    size_t block_len;

    if ((NULL == ecbState) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    block_len = ecbState->block_len;

    while (data_len > 0) {
        int result;

        if (data_len < block_len)
            return ERR_NOT_ENOUGH_DATA;

        result = ecbState->encrypt((BlockBase*)ecbState, in, out, block_len);
        if (result)
            return result;

        data_len -= block_len;
        in += block_len;
        out += block_len;
    }

    return 0;
}

int ECB_decrypt(EcbModeState *ecbState,
            const uint8_t *in,
            uint8_t *out,
            size_t data_len) {

    size_t block_len;

    if ((NULL == ecbState) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    block_len = ecbState->block_len;

    while (data_len > 0) {
        int result;

        if (data_len < block_len)
            return ERR_NOT_ENOUGH_DATA;

        result = ecbState->decrypt((BlockBase*)ecbState, in, out, block_len);
        if (result)
            return result;

        data_len -= block_len;
        in += block_len;
        out += block_len;
    }

    return 0;
}


int ECB_stop_operation(EcbModeState *state)
{
    state->destructor((BlockBase*)state);
    return 0;
}
