/*
 * SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"
#include "endianess.h"

FAKE_INIT(chacha20)

#define KEY_SIZE   32

typedef struct {
    /** Initial state for the next iteration (with the counter of the block after keyStream) **/
    uint32_t h[16];
    size_t nonceSize;  /** in bytes **/

    /** How many bytes at the beginning of the key stream
      * have already been used.
      */
    unsigned usedKeyStream;

    /** Always computed (the block before the counter) **/
    uint8_t keyStream[sizeof(uint32_t)*16];
} stream_state;

/*
 * The block counter has 64 bits with a nonce of 8 bytes (h[12] and h[13]),
 * and 32 bits with a nonce of 12 bytes (h[12]). The key stream ends with
 * the block whose counter is the largest value: using the blocks after it
 * would mean reusing the key stream from block 0, so that must fail.
 *
 * keyStream[] always holds the block before the counter in h[]:
 * after the last block, the counter has wrapped around to 0.
 */

#define ROTL(q, n)  (((q) << (n)) | ((q) >> (32 - (n))))

#define QR(a, b, c, d) {\
    a+=b; d^=a; d=ROTL(d,16); \
    c+=d; b^=c; b=ROTL(b,12); \
    a+=b; d^=a; d=ROTL(d,8);  \
    c+=d; b^=c; b=ROTL(b,7);  \
}

static void chacha20_core(stream_state *state, uint32_t h[16]);
static void advance_counter(stream_state *state);

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

    if (nonceSize != 8 && nonceSize != 12 && nonceSize != 16)
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

    switch (nonceSize) {
    case 8: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                bbbbbbbb  BBBBBBBB  nnnnnnnn  nnnnnnnn

                c=constant k=key b=blockcount(low) B=blockcount(high) n=nonce
                */

                /** h[12] remains 0 (offset) **/
                /** h[13] remains 0 (offset) **/
                hs->h[14] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 4);
                break;
                }
    case 12: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

                c=constant k=key b=blockcount n=nonce
                */

                /** h[12] remains 0 (offset) **/
                hs->h[13] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[14] = LOAD_U32_LITTLE(nonce + 4);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 8);
                break;
            }
    case 16: {
                /*
                cccccccc  cccccccc  cccccccc  cccccccc
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
                nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn

                c=constant k=key n=nonce
                */

                hs->h[12] = LOAD_U32_LITTLE(nonce + 0);
                hs->h[13] = LOAD_U32_LITTLE(nonce + 4);
                hs->h[14] = LOAD_U32_LITTLE(nonce + 8);
                hs->h[15] = LOAD_U32_LITTLE(nonce + 12);
                break;
            }
    default:
             return ERR_NONCE_SIZE;
    }

    hs->nonceSize = nonceSize;

    if (nonceSize == 16) {
        /*
         * HChaCha20: h[12..15] hold the input, and there is no block counter.
         * hchacha20() only calls chacha20_core(), and the state cannot be used
         * to encrypt (the key stream stays empty).
         */
        hs->usedKeyStream = sizeof hs->keyStream;
    } else {
        /** The key stream from block 0 on **/
        uint32_t h[16];

        chacha20_core(hs, h);
        advance_counter(hs);
        hs->usedKeyStream = 0;
    }

    return 0;
}

EXPORT_SYM int chacha20_destroy(stream_state *state)
{
    if (NULL == state)
        return ERR_NULL;
    free(state);
    return 0;
}

/** Compute keyStream[] from h[] (the counter is not advanced) **/
static void chacha20_core(stream_state *state, uint32_t h[16])
{
    unsigned i;

    memcpy(h, state->h, sizeof state->h);

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

    for (i=0; i<16; i++) {
        uint32_t sum;

        sum = h[i] + state->h[i];
        STORE_U32_LITTLE(state->keyStream + 4*i, sum);
    }
}

/** Block counter after keyStream[] **/
static uint64_t get_next_counter(const stream_state *state)
{
    if (state->nonceSize == 8)
        return ((uint64_t)state->h[13] << 32) | state->h[12];
    return state->h[12];
}

static void set_next_counter(stream_state *state, uint64_t next_counter)
{
    state->h[12] = (uint32_t)next_counter;
    if (state->nonceSize == 8)
        state->h[13] = (uint32_t)(next_counter >> 32);
}

/** Move the block counter past the block just computed in keyStream[] (it may wrap around to 0) **/
static void advance_counter(stream_state *state)
{
    set_next_counter(state, get_next_counter(state) + 1);
}

/**
 * Return 0 if len more bytes of key stream are available,
 * when ks_avail bytes are left in keyStream[].
 **/
static int check_length(const stream_state *state, unsigned ks_avail, size_t len)
{
    uint64_t next_counter, left;

    if (len <= ks_avail)
        return 0;

    /* Blocks after keyStream[] (none if the counter is 0, after the last block) */
    next_counter = get_next_counter(state);
    if (state->nonceSize == 8) {
        left = 0 - next_counter;
        /* With 2^58 blocks or more, any len fits */
        if (left >= ((uint64_t)1 << 58))
            return 0;
    } else {
        left = (uint32_t)(0 - (uint32_t)next_counter);
    }

    if ((uint64_t)(len - ks_avail) > 64 * left)
        return ERR_MAX_DATA;
    return 0;
}

EXPORT_SYM int chacha20_encrypt(stream_state *state,
                                const uint8_t in[],
                                uint8_t out[],
                                size_t len)
{
    unsigned used;
    int result;

    if (NULL == state || NULL == in || NULL == out)
        return ERR_NULL;

    if ((state->nonceSize != 8) && (state->nonceSize != 12))
        return ERR_NONCE_SIZE;

    /*
     * Read the position in the key stream only once, and check it:
     * if several threads used the object at once (not supported),
     * the state could be inconsistent, but the key stream must never
     * be read out of bounds.
     */
    used = state->usedKeyStream;
    if (used > sizeof state->keyStream)
        return ERR_STATE;

    /* Fail before encrypting anything if the key stream would run out */
    result = check_length(state, (unsigned)(sizeof state->keyStream - used), len);
    if (result)
        return result;

    while (len>0) {
        unsigned keyStreamToUse;
        unsigned i;
        uint32_t h[16];

        if (used == sizeof state->keyStream) {
            chacha20_core(state, h);
            advance_counter(state);
            used = 0;
        }

        keyStreamToUse = (unsigned)MIN(len, sizeof state->keyStream - used);
        for (i=0; i<keyStreamToUse; i++)
            *out++ = *in++ ^ state->keyStream[i + used];

        len -= keyStreamToUse;
        used += keyStreamToUse;
    }

    state->usedKeyStream = used;
    return 0;
}

EXPORT_SYM int chacha20_seek(stream_state *state,
                             unsigned long block_high,
                             unsigned long block_low,
                             unsigned offset)
{
    stream_state tmp;
    uint32_t h[16];
    uint64_t block;

    if (NULL == state)
        return ERR_NULL;

    if ((state->nonceSize != 8) && (state->nonceSize != 12))
        return ERR_NONCE_SIZE;

    if (offset >= sizeof state->keyStream)
        return ERR_MAX_OFFSET;

    if (block_high > 0xFFFFFFFFUL || block_low > 0xFFFFFFFFUL)
        return ERR_MAX_OFFSET;

    /** With a nonce of 12 bytes, the counter is one word **/
    if (state->nonceSize == 12 && block_high > 0)
        return ERR_MAX_OFFSET;

    block = ((uint64_t)block_high << 32) | block_low;

    /*
     * Compute the block in a copy of the state, so that the state never
     * holds its counter: if several threads used the object at once
     * (not supported), a counter of 0 would look like the end of the key stream
     */
    memcpy(tmp.h, state->h, sizeof tmp.h);
    tmp.nonceSize = state->nonceSize;
    set_next_counter(&tmp, block);
    chacha20_core(&tmp, h);
    memcpy(state->keyStream, tmp.keyStream, sizeof state->keyStream);
    set_next_counter(state, block + 1);
    state->usedKeyStream = offset;

    return 0;
}

/*
 * Based on https://tools.ietf.org/html/draft-arciszewski-xchacha-03
 */
EXPORT_SYM int hchacha20(const uint8_t key[KEY_SIZE],
                         const uint8_t nonce16[16],                 /* First 16 bytes of the 24 byte nonce */
                         uint8_t subkey[KEY_SIZE])
{
    stream_state *pState;
    uint32_t h[16];

    if (NULL == key || NULL == nonce16 || NULL == subkey) {
        return ERR_NULL;
    }

    chacha20_init(&pState, key, KEY_SIZE, nonce16, 16);
    if (NULL == pState)
        return ERR_MEMORY;

    chacha20_core(pState, h);
    /* We only keep first and last row from the new state */
    STORE_U32_LITTLE(subkey + 0,  h[0]);
    STORE_U32_LITTLE(subkey + 4,  h[1]);
    STORE_U32_LITTLE(subkey + 8,  h[2]);
    STORE_U32_LITTLE(subkey + 12, h[3]);
    STORE_U32_LITTLE(subkey + 16, h[12]);
    STORE_U32_LITTLE(subkey + 20, h[13]);
    STORE_U32_LITTLE(subkey + 24, h[14]);
    STORE_U32_LITTLE(subkey + 28, h[15]);
    chacha20_destroy(pState);

    return 0;
}

#ifdef PROFILE
int main(void)
{
    const unsigned data_size = 1024*1024;
    const uint8_t key[32] = "12345678901234561234567890123456";
    const uint8_t nonce[8] = "12345678";
    stream_state *state;
    uint8_t *data;

    data = malloc(data_size);
    for (int i=0; i<data_size; i++) {
        data[i] = (uint8_t) i;
    }

    chacha20_init(&state, key, 32, nonce, 8);

    for (int i=0; i<1024; i++)
        chacha20_encrypt(state, data, data, data_size);

    chacha20_destroy(state);
    free(data);
}
#endif
