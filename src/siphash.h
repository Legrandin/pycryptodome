/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * SipHash-2-4 (Aumasson and Bernstein, "SipHash: a fast short-input PRF",
 * 2012) in counter mode: the elliptic curves use it to expand the random
 * seed of a scalar multiplication (the blinding of the scalar, the
 * randomization of the coordinates) into as many random words as needed.
 * The seed comes from the RNG of the caller, and is the key of the PRF:
 * the outputs reveal nothing about the seed, nor about each other.
 * It runs in constant time.
 */

#ifndef SIPHASH_H
#define SIPHASH_H

#include "common.h"

#define SIP_ROTL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

#define SIP_ROUND(v0, v1, v2, v3) do {                                      \
        v0 += v1; v1 = SIP_ROTL(v1, 13); v1 ^= v0; v0 = SIP_ROTL(v0, 32);   \
        v2 += v3; v3 = SIP_ROTL(v3, 16); v3 ^= v2;                          \
        v0 += v3; v3 = SIP_ROTL(v3, 21); v3 ^= v0;                          \
        v2 += v1; v1 = SIP_ROTL(v1, 17); v1 ^= v2; v2 = SIP_ROTL(v2, 32);   \
    } while (0)

/** SipHash-2-4 with the key (k0, k1) of the 8-byte message m (little-endian) **/
static inline uint64_t siphash24_u64(uint64_t k0, uint64_t k1, uint64_t m)
{
    uint64_t v0 = k0 ^ 0x736F6D6570736575ULL;
    uint64_t v1 = k1 ^ 0x646F72616E646F6DULL;
    uint64_t v2 = k0 ^ 0x6C7967656E657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;
    const uint64_t b = (uint64_t)8 << 56;    /* The length, no bytes left */

    v3 ^= m;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    v0 ^= m;

    v3 ^= b;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xFF;
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    SIP_ROUND(v0, v1, v2, v3);
    return v0 ^ v1 ^ v2 ^ v3;
}

#undef SIP_ROUND
#undef SIP_ROTL

/** The generator: SipHash-2-4 keyed with the seed, of a counter **/
typedef struct {
    uint64_t key;
    uint64_t counter;
} BlindPrf;

static inline void blind_prf_init(BlindPrf *prf, uint64_t seed)
{
    prf->key = seed;
    prf->counter = 0;
}

/** The next random word **/
static inline uint64_t blind_prf_next(BlindPrf *prf)
{
    return siphash24_u64(prf->key, 0, prf->counter++);
}

#endif
