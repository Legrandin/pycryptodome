/*
 * SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"

FAKE_INIT(raw_ecb)

#include "block_base.h"

typedef BlockBase EcbModeState;

EXPORT_SYM int ECB_start_operation(BlockBase *cipher,
                                   EcbModeState **pResult)
{
    if ((NULL == cipher) || (NULL == pResult)) {
        return ERR_NULL;
    }

    *pResult = (EcbModeState*)cipher;
    return 0;
}

EXPORT_SYM int ECB_encrypt(EcbModeState *ecbState,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    if ((NULL == ecbState) || (NULL == in) || (NULL == out))
        return ERR_NULL;

    return ecbState->encrypt((BlockBase*)ecbState, in, out, data_len);
}

EXPORT_SYM int ECB_decrypt(EcbModeState *ecbState,
                           const uint8_t *in,
                           uint8_t *out,
                           size_t data_len)
{
    if ((NULL == ecbState) || (NULL == in) || (NULL == out))
        return ERR_NULL;
    
    return ecbState->decrypt((BlockBase*)ecbState, in, out, data_len);
}


EXPORT_SYM int ECB_stop_operation(EcbModeState *state)
{
    if (NULL == state)
        return ERR_NULL;
    state->destructor((BlockBase*)state);
    return 0;
}
