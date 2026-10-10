/*
 * SPDX-FileCopyrightText: 2018 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef ENDIANESS_H
#define ENDIANESS_H

#include "common.h"

static inline void u32to8_little(uint8_t *p, const uint32_t *w)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(p, w, 4);
#else
    p[0] = (uint8_t)*w;
    p[1] = (uint8_t)(*w >> 8);
    p[2] = (uint8_t)(*w >> 16);
    p[3] = (uint8_t)(*w >> 24);
#endif
}

static inline void u8to32_little(uint32_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(w, p, 4);
#else
    *w = (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
#endif
}

static inline void u32to8_big(uint8_t *p, const uint32_t *w)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(p, w, 4);
#else
    p[0] = (uint8_t)(*w >> 24);
    p[1] = (uint8_t)(*w >> 16);
    p[2] = (uint8_t)(*w >> 8);
    p[3] = (uint8_t)*w;
#endif
}

static inline void u8to32_big(uint32_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(w, p, 4);
#else
    *w = (uint32_t)p[3] | (uint32_t)p[2]<<8 | (uint32_t)p[1]<<16 | (uint32_t)p[0]<<24;
#endif
}

static inline uint32_t load_u8to32_little(const uint8_t *p)
{
    uint32_t w;

    u8to32_little(&w, p);
    return w;
}

static inline uint32_t load_u8to32_big(const uint8_t *p)
{
    uint32_t w;

    u8to32_big(&w, p);
    return w;
}

#define LOAD_U32_LITTLE(p) load_u8to32_little(p)
#define LOAD_U32_BIG(p) load_u8to32_big(p)

#define STORE_U32_LITTLE(p, w) u32to8_little((p), &(w))
#define STORE_U32_BIG(p, w) u32to8_big((p), &(w))

static inline void u64to8_little(uint8_t *p, const uint64_t *w)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(p, w, 8);
#else
    p[0] = (uint8_t)*w;
    p[1] = (uint8_t)(*w >> 8);
    p[2] = (uint8_t)(*w >> 16);
    p[3] = (uint8_t)(*w >> 24);
    p[4] = (uint8_t)(*w >> 32);
    p[5] = (uint8_t)(*w >> 40);
    p[6] = (uint8_t)(*w >> 48);
    p[7] = (uint8_t)(*w >> 56);
#endif
}

static inline void u8to64_little(uint64_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_LITTLE_ENDIAN
    memcpy(w, p, 8);
#else
    *w = (uint64_t)p[0]       |
         (uint64_t)p[1] << 8  |
         (uint64_t)p[2] << 16 |
         (uint64_t)p[3] << 24 |
         (uint64_t)p[4] << 32 |
         (uint64_t)p[5] << 40 |
         (uint64_t)p[6] << 48 |
         (uint64_t)p[7] << 56;
#endif
}

static inline void u64to8_big(uint8_t *p, const uint64_t *w)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(p, w, 8);
#else
    p[0] = (uint8_t)(*w >> 56);
    p[1] = (uint8_t)(*w >> 48);
    p[2] = (uint8_t)(*w >> 40);
    p[3] = (uint8_t)(*w >> 32);
    p[4] = (uint8_t)(*w >> 24);
    p[5] = (uint8_t)(*w >> 16);
    p[6] = (uint8_t)(*w >> 8);
    p[7] = (uint8_t)*w;
#endif
}

static inline void u8to64_big(uint64_t *w, const uint8_t *p)
{
#ifdef PYCRYPTO_BIG_ENDIAN
    memcpy(w, p, 8);
#else
    *w = (uint64_t)p[0] << 56 |
         (uint64_t)p[1] << 48 |
         (uint64_t)p[2] << 40 |
         (uint64_t)p[3] << 32 |
         (uint64_t)p[4] << 24 |
         (uint64_t)p[5] << 16 |
         (uint64_t)p[6] << 8  |
         (uint64_t)p[7];
#endif
}

static inline uint64_t load_u8to64_little(const uint8_t *p)
{
    uint64_t w;

    u8to64_little(&w, p);
    return w;
}

static inline uint64_t load_u8to64_big(const uint8_t *p)
{
    uint64_t w;

    u8to64_big(&w, p);
    return w;
}

#define LOAD_U64_LITTLE(p) load_u8to64_little(p)
#define LOAD_U64_BIG(p) load_u8to64_big(p)

#define STORE_U64_LITTLE(p, w) u64to8_little((p), &(w))
#define STORE_U64_BIG(p, w) u64to8_big((p), &(w))

/**
 * Convert a big endian-encoded number in[] into a little-endian
 * 64-bit word array x[]. There must be enough words to contain the entire
 * number (ERR_MAX_DATA otherwise).
 *
 * The number can be secret: all bytes are processed, whatever their value
 * (leading zeros are not skipped), and only the fact that the number does
 * not fit can leak.
 */
static inline int bytes_to_words(uint64_t *x, size_t words, const uint8_t *in, size_t len)
{
    uint8_t overflow = 0;
    size_t k;

    if (0 == words || 0 == len)
        return ERR_NOT_ENOUGH_DATA;
    if (NULL == x || NULL == in)
        return ERR_NULL;

    memset(x, 0, words*sizeof(uint64_t));

    /* k is the position of the byte, from the least significant one */
    for (k=0; k<len; k++) {
        uint8_t byte = in[len - 1 - k];

        if (k/8 < words)
            x[k/8] |= (uint64_t)byte << (8*(k%8));
        else
            overflow |= byte;
    }

    return overflow ? ERR_MAX_DATA : 0;
}

/**
 * Convert a little-endian 64-bit word array x[] into a big endian-encoded
 * number out[]. The number is left-padded with zeroes if required, and
 * it must fit into len bytes (ERR_MAX_DATA otherwise).
 *
 * The number can be secret: all words are processed, whatever their value
 * (leading zeros are not skipped), and only the fact that the number does
 * not fit can leak.
 */
static inline int words_to_bytes(uint8_t *out, size_t len, const uint64_t *x, size_t words)
{
    uint8_t overflow = 0;
    size_t k;

    if (0 == words || 0 == len)
        return ERR_NOT_ENOUGH_DATA;
    if (NULL == x || NULL == out)
        return ERR_NULL;

    memset(out, 0, len);

    /* k is the position of the byte, from the least significant one */
    for (k=0; k<8*words; k++) {
        uint8_t byte = (uint8_t)(x[k/8] >> (8*(k%8)));

        if (k < len)
            out[len - 1 - k] = byte;
        else
            overflow |= byte;
    }

    return overflow ? ERR_MAX_DATA : 0;
}

#endif
