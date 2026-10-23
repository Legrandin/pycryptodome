/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * ML-KEM (FIPS 203), on top of mlkem-native (src/mlkem-native).
 *
 * The three parameter sets are compiled here, as a single compilation unit
 * (see examples/monolithic_build_multilevel in mlkem-native).
 * The configuration is in mlkem_config.h.
 *
 * Each function takes the parameter set (512, 768 or 1024) as first argument.
 * The randomness (key seed and encapsulation coins) is always provided by the caller.
 *
 * SHA-3 and SHAKE use the Keccak permutation of pycryptodome (mlkem_fips202.h).
 * mlkem_avx2_bmi2.c compiles this file again for AVX2 and BMI2
 * (module _mlkem_avx2_bmi2), with the 4-way AVX2 Keccak.
 */

#define MLK_CONFIG_FILE "mlkem_config.h"

/* ML-KEM-512, together with the code shared by all parameter sets */
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED
#define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 512
#include "mlkem-native/mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MULTILEVEL_WITH_SHARED

/* ML-KEM-768 */
#define MLK_CONFIG_MULTILEVEL_NO_SHARED
#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem-native/mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET

/* ML-KEM-1024, and clean up all the headers at the end */
#undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem-native/mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MULTILEVEL_NO_SHARED

/* The public constants (MLKEM512_PUBLICKEYBYTES, ...) */
#define MLK_CONFIG_CONSTANTS_ONLY
#include "mlkem-native/mlkem_native.h"

/* (common.h was already included by keccak.c, via mlkem_fips202.h) */
#include "common.h"
#include "errors.h"

/* mlkem_avx2_bmi2.c includes this file with another module name */
#ifndef MLKEM_MODULE
#define MLKEM_MODULE mlkem
#endif
FAKE_INIT(MLKEM_MODULE)

/* The seed (d || z) and the encapsulation randomness (m), in bytes */
#define MLKEM_SEEDBYTES     (2 * MLKEM_SYMBYTES)
#define MLKEM_COINSBYTES    MLKEM_SYMBYTES

typedef struct {
    size_t pk_len;
    size_t sk_len;
    size_t ct_len;
} ParamSet;

static const ParamSet param_sets[] = {
    { MLKEM512_PUBLICKEYBYTES, MLKEM512_SECRETKEYBYTES, MLKEM512_CIPHERTEXTBYTES },
    { MLKEM768_PUBLICKEYBYTES, MLKEM768_SECRETKEYBYTES, MLKEM768_CIPHERTEXTBYTES },
    { MLKEM1024_PUBLICKEYBYTES, MLKEM1024_SECRETKEYBYTES, MLKEM1024_CIPHERTEXTBYTES },
};

static const ParamSet *get_param_set(unsigned level)
{
    switch (level) {
        case 512: return &param_sets[0];
        case 768: return &param_sets[1];
        case 1024: return &param_sets[2];
        default: return NULL;
    }
}

/*
 * Generate a key pair from a 64-byte seed d || z (FIPS 203, Algorithm 16).
 *
 * The encapsulation key goes into pk (pk_len bytes), the expanded
 * decapsulation key into sk (sk_len bytes).
 */
EXPORT_SYM int mlkem_keypair(unsigned level,
                             uint8_t *pk, size_t pk_len,
                             uint8_t *sk, size_t sk_len,
                             const uint8_t *seed, size_t seed_len)
{
    const ParamSet *ps;
    int res;

    if (NULL == pk || NULL == sk || NULL == seed)
        return ERR_NULL;

    ps = get_param_set(level);
    if (NULL == ps)
        return ERR_VALUE;

    if (pk_len != ps->pk_len || sk_len != ps->sk_len || seed_len != MLKEM_SEEDBYTES)
        return ERR_KEY_SIZE;

    switch (level) {
        case 512: res = mlkem512_keypair_derand(pk, sk, seed); break;
        case 768: res = mlkem768_keypair_derand(pk, sk, seed); break;
        default: res = mlkem1024_keypair_derand(pk, sk, seed); break;
    }

    return res == 0 ? 0 : ERR_UNKNOWN;
}

/*
 * Check an encapsulation key (FIPS 203, Section 7.2, modulus check).
 *
 * Return ERR_VALUE if it is not valid.
 */
EXPORT_SYM int mlkem_check_pk(unsigned level, const uint8_t *pk, size_t pk_len)
{
    const ParamSet *ps;
    int res;

    if (NULL == pk)
        return ERR_NULL;

    ps = get_param_set(level);
    if (NULL == ps)
        return ERR_VALUE;

    if (pk_len != ps->pk_len)
        return ERR_KEY_SIZE;

    switch (level) {
        case 512: res = mlkem512_check_pk(pk); break;
        case 768: res = mlkem768_check_pk(pk); break;
        default: res = mlkem1024_check_pk(pk); break;
    }

    switch (res) {
        case 0: return 0;
        case MLK_ERR_INVALID_PK: return ERR_VALUE;
        default: return ERR_UNKNOWN;
    }
}

/*
 * Check an expanded decapsulation key (FIPS 203, Section 7.3, hash check).
 *
 * Return ERR_VALUE if it is not valid.
 */
EXPORT_SYM int mlkem_check_sk(unsigned level, const uint8_t *sk, size_t sk_len)
{
    const ParamSet *ps;
    int res;

    if (NULL == sk)
        return ERR_NULL;

    ps = get_param_set(level);
    if (NULL == ps)
        return ERR_VALUE;

    if (sk_len != ps->sk_len)
        return ERR_KEY_SIZE;

    switch (level) {
        case 512: res = mlkem512_check_sk(sk); break;
        case 768: res = mlkem768_check_sk(sk); break;
        default: res = mlkem1024_check_sk(sk); break;
    }

    switch (res) {
        case 0: return 0;
        case MLK_ERR_INVALID_SK: return ERR_VALUE;
        default: return ERR_UNKNOWN;
    }
}

/*
 * Encapsulate a shared secret with an encapsulation key
 * (FIPS 203, Algorithm 17), with the 32-byte randomness m in coins.
 *
 * The ciphertext goes into ct (ct_len bytes), the 32-byte shared secret into ss.
 *
 * Return ERR_VALUE if the encapsulation key is not valid.
 */
EXPORT_SYM int mlkem_encaps(unsigned level,
                            uint8_t *ct, size_t ct_len,
                            uint8_t *ss, size_t ss_len,
                            const uint8_t *pk, size_t pk_len,
                            const uint8_t *coins, size_t coins_len)
{
    const ParamSet *ps;
    int res;

    if (NULL == ct || NULL == ss || NULL == pk || NULL == coins)
        return ERR_NULL;

    ps = get_param_set(level);
    if (NULL == ps)
        return ERR_VALUE;

    if (pk_len != ps->pk_len)
        return ERR_KEY_SIZE;

    if (ct_len != ps->ct_len || ss_len != MLKEM_BYTES || coins_len != MLKEM_COINSBYTES)
        return ERR_NOT_ENOUGH_DATA;

    switch (level) {
        case 512: res = mlkem512_enc_derand(ct, ss, pk, coins); break;
        case 768: res = mlkem768_enc_derand(ct, ss, pk, coins); break;
        default: res = mlkem1024_enc_derand(ct, ss, pk, coins); break;
    }

    switch (res) {
        case 0: return 0;
        case MLK_ERR_INVALID_PK: return ERR_VALUE;
        default: return ERR_UNKNOWN;
    }
}

/*
 * Decapsulate the shared secret from a ciphertext with an expanded
 * decapsulation key (FIPS 203, Algorithm 18).
 *
 * The 32-byte shared secret goes into ss. An invalid ciphertext of the right
 * length is not an error: the shared secret is then pseudorandom
 * (implicit rejection).
 *
 * Return ERR_VALUE if the decapsulation key is not valid.
 */
EXPORT_SYM int mlkem_decaps(unsigned level,
                            uint8_t *ss, size_t ss_len,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t *sk, size_t sk_len)
{
    const ParamSet *ps;
    int res;

    if (NULL == ss || NULL == ct || NULL == sk)
        return ERR_NULL;

    ps = get_param_set(level);
    if (NULL == ps)
        return ERR_VALUE;

    if (sk_len != ps->sk_len)
        return ERR_KEY_SIZE;

    if (ct_len != ps->ct_len || ss_len != MLKEM_BYTES)
        return ERR_NOT_ENOUGH_DATA;

    switch (level) {
        case 512: res = mlkem512_dec(ss, ct, sk); break;
        case 768: res = mlkem768_dec(ss, ct, sk); break;
        default: res = mlkem1024_dec(ss, ct, sk); break;
    }

    switch (res) {
        case 0: return 0;
        case MLK_ERR_INVALID_SK: return ERR_VALUE;
        default: return ERR_UNKNOWN;
    }
}
