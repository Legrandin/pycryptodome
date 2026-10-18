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
 * mldsa_native_asm.S, src/native/ and src/fips202/native/.
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
 * Only the portable C code: the native backends (AVX2, Neon, ...)
 * of mldsa-native are not part of src/mldsa-native.
 * In other words, MLD_CONFIG_USE_NATIVE_BACKEND_ARITH and
 * MLD_CONFIG_USE_NATIVE_BACKEND_FIPS202 must not be set.
 */

/*
 * SHA-3 / SHAKE
 *
 * For now, we use the FIPS 202 code that comes with mldsa-native
 * (src/mldsa-native/src/fips202).
 *
 * To use the Keccak code of pycryptodome instead (src/keccak.c),
 * define MLD_CONFIG_FIPS202_CUSTOM_HEADER and MLD_CONFIG_FIPS202X4_CUSTOM_HEADER
 * to point to two headers that implement the API in
 * src/mldsa-native/src/fips202/fips202.h and fips202x4.h on top of it
 * (see FIPS202.md in the mldsa-native repository).
 * mldsa-native/mldsa_native.c will then stop including its own FIPS 202 code.
 */
/* #define MLD_CONFIG_FIPS202_CUSTOM_HEADER "mldsa_fips202.h" */
/* #define MLD_CONFIG_FIPS202X4_CUSTOM_HEADER "mldsa_fips202x4.h" */

#endif /* MLDSA_CONFIG_H */
