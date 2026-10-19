/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Configuration of mldsa-native (src/mldsa-native) for pycryptodome,
 * used in place of mldsa-native/mldsa_native_config.h (via MLD_CONFIG_FILE).
 *
 * See mldsa-native/mldsa_native_config.h for the meaning of each option.
 *
 * src/mldsa-native is the directory mldsa/ of mldsa-native v2.0.0
 * (https://github.com/pq-code-package/mldsa-native,
 * commit 834a90d5e846ffa1e1611bd24e160bb2e9b86d35), plus its LICENSE,
 * without any change, except that the native backends were left out:
 * mldsa_native_asm.S, src/native/ and src/fips202/native/
 * (but for the 4 files under src/fips202/native that mldsa_native.c includes
 * when a FIPS 202 backend is used: they are empty without the upstream backends).
 */

#ifndef MLDSA_CONFIG_H
#define MLDSA_CONFIG_H

/*
 * The three parameter sets (ML-DSA-44, ML-DSA-65 and ML-DSA-87)
 * are built in the same compilation unit (see mldsa.c).
 * MLD_CONFIG_PARAMETER_SET is set there.
 */
#define MLD_CONFIG_MULTILEVEL_BUILD

/* The functions become mldsa44_*, mldsa65_* and mldsa87_* */
#define MLD_CONFIG_NAMESPACE_PREFIX mldsa

/*
 * The internal functions are not visible outside mldsa.c.
 * The mldsa-native API keeps the default linkage (but it is not exported
 * on Windows): with static, the functions we don't use would trigger warnings.
 */
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static

/*
 * The randomness (the key seed and the signing nonce rnd) always comes
 * from Python, so we only need the deterministic API
 * (*_keypair_internal, *_signature_internal, ...) and no randombytes().
 */
#define MLD_CONFIG_NO_RANDOMIZED_API

/*
 * Arithmetic: only the portable C code. The native backends of mldsa-native
 * (AVX2, Neon, ...) are not part of src/mldsa-native, so
 * MLD_CONFIG_USE_NATIVE_BACKEND_ARITH must not be set.
 * In the module _mldsa_avx2_bmi2, the same C code is just compiled
 * for AVX2 and BMI2.
 */

/*
 * SHA-3 / SHAKE: the sponge of mldsa-native (src/mldsa-native/src/fips202),
 * on top of the Keccak-f[1600] permutation of pycryptodome (src/keccak.c,
 * and src/keccak_x4_avx2.c for 4 states at once in _mldsa_avx2_bmi2),
 * through the FIPS 202 backend interface of mldsa-native.
 */
#define MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202
#define MLD_CONFIG_FIPS202_BACKEND_FILE "mldsa_fips202.h"

#endif /* MLDSA_CONFIG_H */
