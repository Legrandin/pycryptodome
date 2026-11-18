/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * AEGIS-128L and AEGIS-256 (RFC 10032), for x86 CPUs with AES-NI:
 * AESRound is exactly the AESENC instruction.
 */

#include <wmmintrin.h>
#include "sse2_unaligned.h"
#include "common.h"
#include "endianess.h"

FAKE_INIT(raw_aegis_aesni)

#define AEGIS_PREFIX AEGIS_AESNI_

typedef __m128i aes_block;

#define blk_load(p)         LOADU_128(p)
#define blk_store(p, x)     STOREU_128(p, x)
#define blk_xor(a, b)       _mm_xor_si128(a, b)
#define blk_and(a, b)       _mm_and_si128(a, b)

/* out[i] = AESRound(in[i], rk[i]) for i < n (6 or 8), without a loop */
static inline void aes_rounds(aes_block *out, const aes_block *in, const aes_block *rk, unsigned n)
{
#define ROUND(i) out[i] = _mm_aesenc_si128(in[i], rk[i])
    ROUND(0); ROUND(1); ROUND(2); ROUND(3); ROUND(4); ROUND(5);
    if (n == 8) {
        ROUND(6); ROUND(7);
    }
#undef ROUND
}

#include "aegis.c"
