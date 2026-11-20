/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * AEGIS-128L and AEGIS-256 (RFC 10032), for AArch64 CPUs with the ARMv8
 * Cryptography Extensions.
 *
 * AESE adds the round key before SubBytes and ShiftRows: with a zero key,
 * AESE and AESMC compute the AES round without AddRoundKey, which follows.
 *
 * On other targets (such as the x86-64 half of a macOS universal2 build),
 * the module is empty: the Python code only loads it after checking
 * that the CPU has the extensions.
 */

#include "common.h"
#include "endianess.h"

FAKE_INIT(raw_aegis_armv8)

#if defined(__aarch64__) || defined(_M_ARM64)

#include <arm_neon.h>

#define AEGIS_PREFIX AEGIS_ARMV8_

typedef uint8x16_t aes_block;

#define blk_load(p)         vld1q_u8(p)
#define blk_store(p, x)     vst1q_u8(p, x)
#define blk_xor(a, b)       veorq_u8(a, b)
#define blk_and(a, b)       vandq_u8(a, b)

/* out[i] = AESRound(in[i], rk[i]) for i < n (6 or 8), without a loop */
static inline void aes_rounds(aes_block *out, const aes_block *in, const aes_block *rk, unsigned n)
{
    const uint8x16_t zero = vdupq_n_u8(0);

#define ROUND(i) out[i] = veorq_u8(vaesmcq_u8(vaeseq_u8(in[i], zero)), rk[i])
    ROUND(0); ROUND(1); ROUND(2); ROUND(3); ROUND(4); ROUND(5);
    if (n == 8) {
        ROUND(6); ROUND(7);
    }
#undef ROUND
}

#include "aegis.c"

#endif
