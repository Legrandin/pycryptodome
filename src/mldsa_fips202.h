/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The Keccak-f[1600] permutation of pycryptodome, for mldsa-native,
 * as a FIPS 202 "native backend" (MLD_CONFIG_FIPS202_BACKEND_FILE,
 * see mldsa_config.h).
 *
 * mldsa-native keeps its own sponge construction (src/mldsa-native/src/fips202),
 * and it calls these functions for the permutation:
 *
 *  - always, for one state: keccak_function() of keccak.c;
 *  - if MLDSA_AVX2 is defined (module _mldsa_avx2_bmi2), also for four
 *    states at once: keccak_function_x4() of keccak_x4_avx2.c.
 *
 * mldsa-native includes this file once per compilation unit (from its
 * src/common.h), but it may undefine the MLD_USE_NATIVE_* macros at the end
 * of each parameter set: they are defined every time, the functions only once.
 */

#define MLD_NATIVE_FUNC_SUCCESS 0
#define MLD_NATIVE_FUNC_FALLBACK -1

#define MLD_USE_NATIVE_FIPS202_X1
#ifdef MLDSA_AVX2
#define MLD_USE_NATIVE_FIPS202_X4
#define MLD_USE_NATIVE_FIPS202_X4_XOR_BYTES
#define MLD_USE_NATIVE_FIPS202_X4_EXTRACT_BYTES
#endif

#ifndef MLDSA_FIPS202_H
#define MLDSA_FIPS202_H

/*
 * keccak.c, private to this module (KECCAK_EMBEDDED).
 * mldsa-native has static functions with the same names as some
 * in keccak.c (keccak_init(), keccak_absorb(), ...): ours are renamed.
 */
#define keccak_reset                pyc_keccak_reset
#define keccak_init                 pyc_keccak_init
#define keccak_destroy              pyc_keccak_destroy
#define keccak_absorb               pyc_keccak_absorb
#define keccak_squeeze              pyc_keccak_squeeze
#define keccak_digest               pyc_keccak_digest
#define keccak_oneshot              pyc_keccak_oneshot
#define keccak_copy                 pyc_keccak_copy
#define keccak_pbkdf2_hmac_assist   pyc_keccak_pbkdf2_hmac_assist
#define keccak_finish               pyc_keccak_finish

#define KECCAK_EMBEDDED
#include "keccak.c"

#undef keccak_reset
#undef keccak_init
#undef keccak_destroy
#undef keccak_absorb
#undef keccak_squeeze
#undef keccak_digest
#undef keccak_oneshot
#undef keccak_copy
#undef keccak_pbkdf2_hmac_assist
#undef keccak_finish

static inline int mld_keccak_f1600_x1_native(uint64_t *state)
{
    keccak_function(state, 24);
    return MLD_NATIVE_FUNC_SUCCESS;
}

#ifdef MLDSA_AVX2

#include <immintrin.h>

/* keccak_absorb_x4() and keccak_extract_x4() are not used here */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#include "keccak_x4_avx2.c"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

/*
 * The 4 states of mldsa-native (uint64_t[100]) are kept in the layout of
 * keccak_function_x4(): lane i of state j is word 4*i + j, so that the
 * 4 copies of a lane form one __m256i.
 * That is fine, because mldsa-native only accesses the 4 states with the
 * three functions below (and it zeroes them, which does not depend on the layout).
 * AVX2 is only on x86, which is little-endian: byte k of lane i of state j
 * is byte 8*(4*i + j) + k of the array.
 */
#define X4_BYTE(b, j)   ((((b) >> 3) * 4 + (j)) * 8 + ((b) & 7))

static inline int mld_keccak_f1600_x4_native(uint64_t *state)
{
    __m256i A[25];
    unsigned i;

    for (i = 0; i < 25; i++)
        A[i] = _mm256_loadu_si256((const __m256i *)(state + 4 * i));
    keccak_function_x4(A, 24);
    for (i = 0; i < 25; i++)
        _mm256_storeu_si256((__m256i *)(state + 4 * i), A[i]);
    return MLD_NATIVE_FUNC_SUCCESS;
}

/* XOR length bytes of each dj into state j, starting from byte offset */
static inline int mld_keccakf1600_xor_bytes_x4_native(uint64_t *state,
                                                      const unsigned char *d0,
                                                      const unsigned char *d1,
                                                      const unsigned char *d2,
                                                      const unsigned char *d3,
                                                      unsigned offset,
                                                      unsigned length)
{
    const unsigned char *d[4];
    uint8_t *s = (uint8_t *)state;
    unsigned b, end, j;

    d[0] = d0; d[1] = d1; d[2] = d2; d[3] = d3;
    end = offset + length;

    /* Byte by byte up to the next lane, then lane by lane, then the rest */
    for (b = offset; b < end && (b & 7); b++)
        for (j = 0; j < 4; j++)
            s[X4_BYTE(b, j)] ^= d[j][b - offset];
    for (; b + 8 <= end; b += 8)
        for (j = 0; j < 4; j++)
            state[(b >> 3) * 4 + j] ^= LOAD_U64_LITTLE(d[j] + (b - offset));
    for (; b < end; b++)
        for (j = 0; j < 4; j++)
            s[X4_BYTE(b, j)] ^= d[j][b - offset];

    return MLD_NATIVE_FUNC_SUCCESS;
}

/* Copy length bytes of state j into dj, starting from byte offset */
static inline int mld_keccakf1600_extract_bytes_x4_native(uint64_t *state,
                                                          unsigned char *d0,
                                                          unsigned char *d1,
                                                          unsigned char *d2,
                                                          unsigned char *d3,
                                                          unsigned offset,
                                                          unsigned length)
{
    unsigned char *d[4];
    const uint8_t *s = (const uint8_t *)state;
    unsigned b, end, j;

    d[0] = d0; d[1] = d1; d[2] = d2; d[3] = d3;
    end = offset + length;

    for (b = offset; b < end && (b & 7); b++)
        for (j = 0; j < 4; j++)
            d[j][b - offset] = s[X4_BYTE(b, j)];
    for (; b + 8 <= end; b += 8)
        for (j = 0; j < 4; j++)
            STORE_U64_LITTLE(d[j] + (b - offset), state[(b >> 3) * 4 + j]);
    for (; b < end; b++)
        for (j = 0; j < 4; j++)
            d[j][b - offset] = s[X4_BYTE(b, j)];

    return MLD_NATIVE_FUNC_SUCCESS;
}

#undef X4_BYTE

#endif /* MLDSA_AVX2 */

#endif /* MLDSA_FIPS202_H */
