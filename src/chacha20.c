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

FAKE_INIT(chacha20)

#define KEY_SIZE   32

typedef struct {
    /** Initial state for the next iteration **/
    uint32_t h[16];
    size_t nonceSize;  /** in bytes **/

    /** How many bytes at the beginning of the key stream
      * have already been used.
      */
    unsigned usedKeyStream;

    uint8_t keyStream[sizeof(uint32_t)*16];
} stream_state;

#define ROTL(q, n)  (((q) << (n)) | ((q) >> (32 - (n))))

#define QR(a, b, c, d) {\
    a+=b; d^=a; d=ROTL(d,16); \
    c+=d; b^=c; b=ROTL(b,12); \
    a+=b; d^=a; d=ROTL(d,8);  \
    c+=d; b^=c; b=ROTL(b,7);  \
}

EXPORT_SYM int chacha20_init(stream_state **pState,
                             const uint8_t *key,
                             size_t keySize,
                             const uint8_t *nonce,
                             size_t nonceSize)
{
    stream_state *hs;
    unsigned i;

    if (NULL == pState || NULL == nonce)
        return ERR_NULL;

    if (NULL == key || keySize != KEY_SIZE)
        return ERR_KEY_SIZE;

    if (nonceSize != 8 && nonceSize != 12)
        return ERR_NONCE_SIZE;

    *pState = hs = (stream_state*) calloc(1, sizeof(stream_state));
    if (NULL == hs)
        return ERR_MEMORY;

    hs->h[0] = 0x61707865;
    hs->h[1] = 0x3320646e;
    hs->h[2] = 0x79622d32;
    hs->h[3] = 0x6b206574;
    
    /** Move 256-bit/32-byte key into h[4..11] **/
    for (i=0; i<32/4; i++) {
        hs->h[4+i] = LOAD_U32_LITTLE(key + 4*i);
    }
    /** h[12] remains 0 (offset) **/
    if (nonceSize == 8) {
        /** h[13] remains 0 (offset) **/
        hs->h[14] = LOAD_U32_LITTLE(nonce + 0);
        hs->h[15] = LOAD_U32_LITTLE(nonce + 4);
    } else {
        hs->h[13] = LOAD_U32_LITTLE(nonce + 0);
        hs->h[14] = LOAD_U32_LITTLE(nonce + 4);
        hs->h[15] = LOAD_U32_LITTLE(nonce + 8);
    }

    hs->nonceSize = nonceSize;
    hs->usedKeyStream = sizeof hs->keyStream;

    return 0;
}

EXPORT_SYM int chacha20_destroy(stream_state *state)
{
    if (NULL == state)
        return ERR_NULL;
    free(state);
    return 0;
}

static int chacha20_core(stream_state *state)
{
    unsigned i;
    uint32_t h[16];

    memcpy(h, state->h, sizeof h);

    for (i=0; i<10; i++) {
        /** Column round **/
        QR(h[0], h[4], h[ 8], h[12]);
        QR(h[1], h[5], h[ 9], h[13]);
        QR(h[2], h[6], h[10], h[14]);
        QR(h[3], h[7], h[11], h[15]);
        /** Diagonal round **/
        QR(h[0], h[5], h[10], h[15]);
        QR(h[1], h[6], h[11], h[12]);
        QR(h[2], h[7], h[ 8], h[13]);
        QR(h[3], h[4], h[ 9], h[14]);
    }

    for (i=0; i<16; i++)
        h[i] += state->h[i];

    for (i=0; i<16; i++) {
        STORE_U32_LITTLE(state->keyStream + 4*i, h[i]);
    }

    state->usedKeyStream = 0;

    if (state->nonceSize == 8) {
        /** Nonce is 64 bits, counter is two words **/
        if (++state->h[12] == 0) {
            if (++state->h[13] == 0) {
                return ERR_MAX_DATA;
            }
        }
    } else {
        /** Nonce is 96 bits, counter is one word **/
        if (++state->h[12] == 0) {
            return ERR_MAX_DATA;
        }
    }

    return 0;
}

EXPORT_SYM int chacha20_encrypt(stream_state *state,
                                const uint8_t in[],
                                uint8_t out[],
                                size_t len)
{
    if (NULL == state || NULL == in || NULL == out)
        return ERR_NULL;

    while (len>0) {
        unsigned keyStreamToUse;
        unsigned i;

        if (state->usedKeyStream == sizeof state->keyStream) {
            int result;

            result = chacha20_core(state);
            if (result)
                return result;
        }

        keyStreamToUse = (unsigned)MIN(len, sizeof state->keyStream - state->usedKeyStream);
        for (i=0; i<keyStreamToUse; i++)
            *out++ = *in++ ^ state->keyStream[i + state->usedKeyStream];

        len -= keyStreamToUse;
        state->usedKeyStream += keyStreamToUse;
    }

    return 0;
}

EXPORT_SYM int chacha20_seek(stream_state *state,
                             unsigned long block_high,
                             unsigned long block_low,
                             unsigned offset)
{
    int result;

    if (NULL == state)
        return ERR_NULL;

    if (offset >= sizeof state->keyStream)
        return ERR_MAX_OFFSET;

    if (state->nonceSize == 8) {
        /** Nonce is 64 bits, counter is two words **/
        state->h[12] = (uint32_t)block_low;
        state->h[13] = (uint32_t)block_high;
    } else {
        /** Nonce is 96 bits, counter is one word **/
        if (block_high > 0) {
            return ERR_MAX_OFFSET;
        }
        state->h[12] = (uint32_t)block_low;
    }

    result = chacha20_core(state);
    if (result)
        return result;
    state->usedKeyStream = offset;

    return 0;
}
