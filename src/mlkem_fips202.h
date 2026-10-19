/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * The Keccak-f[1600] permutation of pycryptodome, for mlkem-native,
 * as a FIPS 202 "native backend" (MLK_CONFIG_FIPS202_BACKEND_FILE,
 * see mlkem_config.h).
 *
 * The functions are in pq_fips202.h (shared with mldsa-native):
 *
 *  - always, for one state: keccak_function() of keccak.c;
 *  - if MLKEM_AVX2 is defined (module _mlkem_avx2_bmi2), also for four
 *    states at once: keccak_function_x4() of keccak_x4_avx2.c.
 *
 * mlkem-native includes this file once per compilation unit (from its
 * src/common.h), but it may undefine the MLK_USE_NATIVE_* macros at the end
 * of each parameter set: they are defined every time, the functions only once.
 */

#define MLK_NATIVE_FUNC_SUCCESS 0
#define MLK_NATIVE_FUNC_FALLBACK -1

#define MLK_USE_NATIVE_FIPS202_X1
#ifdef MLKEM_AVX2
#define MLK_USE_NATIVE_FIPS202_X4
#define MLK_USE_NATIVE_FIPS202_X4_XOR_BYTES
#define MLK_USE_NATIVE_FIPS202_X4_EXTRACT_BYTES
#endif

#ifndef MLKEM_FIPS202_H
#define MLKEM_FIPS202_H

#ifdef MLKEM_AVX2
#define PQ_FIPS202_AVX2
#endif
#include "pq_fips202.h"

static inline int mlk_keccak_f1600_x1_native(uint64_t *state)
{
    return pq_keccak_f1600_x1(state);
}

#ifdef MLKEM_AVX2

static inline int mlk_keccak_f1600_x4_native(uint64_t *state)
{
    return pq_keccak_f1600_x4(state);
}

static inline int mlk_keccakf1600_xor_bytes_x4_native(uint64_t *state,
                                                      const unsigned char *d0,
                                                      const unsigned char *d1,
                                                      const unsigned char *d2,
                                                      const unsigned char *d3,
                                                      unsigned offset,
                                                      unsigned length)
{
    return pq_keccakf1600_xor_bytes_x4(state, d0, d1, d2, d3, offset, length);
}

static inline int mlk_keccakf1600_extract_bytes_x4_native(uint64_t *state,
                                                          unsigned char *d0,
                                                          unsigned char *d1,
                                                          unsigned char *d2,
                                                          unsigned char *d3,
                                                          unsigned offset,
                                                          unsigned length)
{
    return pq_keccakf1600_extract_bytes_x4(state, d0, d1, d2, d3, offset, length);
}

#endif /* MLKEM_AVX2 */

#endif /* MLKEM_FIPS202_H */
