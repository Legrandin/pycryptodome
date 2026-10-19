/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Configuration of mlkem-native (src/mlkem-native) for pycryptodome,
 * used in place of mlkem-native/mlkem_native_config.h (via MLK_CONFIG_FILE).
 *
 * See mlkem-native/mlkem_native_config.h for the meaning of each option.
 *
 * src/mlkem-native is the directory mlkem/ of mlkem-native v2.0.0
 * (https://github.com/pq-code-package/mlkem-native,
 * commit d1b2fe782888bdb761a50336012923180be7f502), plus its LICENSE,
 * without any change, except that the native backends were left out:
 * mlkem_native_asm.S, src/native/ and src/fips202/native/
 * (but for the 4 files under src/fips202/native that mlkem_native.c includes
 * when a FIPS 202 backend is used: they are empty without the upstream backends).
 */

#ifndef MLKEM_CONFIG_H
#define MLKEM_CONFIG_H

/*
 * The three parameter sets (ML-KEM-512, ML-KEM-768 and ML-KEM-1024)
 * are built in the same compilation unit (see mlkem.c).
 * MLK_CONFIG_PARAMETER_SET is set there.
 */
#define MLK_CONFIG_MULTILEVEL_BUILD

/* The functions become mlkem512_*, mlkem768_* and mlkem1024_* */
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem

/*
 * Neither the internal functions nor the mlkem-native API are visible
 * outside mlkem.c, which only exports its own functions.
 */
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static
#define MLK_CONFIG_EXTERNAL_API_QUALIFIER static

/*
 * The randomness (the key seed and the encapsulation coins) always comes
 * from Python, so we only need the deterministic API
 * (*_keypair_derand, *_enc_derand and *_dec) and no randombytes().
 */
#define MLK_CONFIG_NO_RANDOMIZED_API

/*
 * Arithmetic: only the portable C code. The native backends of mlkem-native
 * (AVX2, Neon, ...) are not part of src/mlkem-native, so
 * MLK_CONFIG_USE_NATIVE_BACKEND_ARITH must not be set.
 * In the module _mlkem_avx2_bmi2, the same C code is just compiled
 * for AVX2 and BMI2.
 */

/*
 * SHA-3 / SHAKE: the sponge of mlkem-native (src/mlkem-native/src/fips202),
 * on top of the Keccak-f[1600] permutation of pycryptodome (src/keccak.c,
 * and src/keccak_x4_avx2.c for 4 states at once in _mlkem_avx2_bmi2),
 * through the FIPS 202 backend interface of mlkem-native.
 */
#define MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLK_CONFIG_FIPS202_BACKEND_FILE "mlkem_fips202.h"

#endif /* MLKEM_CONFIG_H */
