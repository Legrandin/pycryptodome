/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * ML-DSA (FIPS 204), on top of mldsa-native (src/mldsa-native).
 *
 * The three parameter sets are compiled here, as a single compilation unit
 * (see examples/monolithic_build_multilevel in mldsa-native).
 * The configuration is in mldsa_config.h.
 *
 * Each function takes the parameter set (44, 65 or 87) as first argument.
 * The randomness (key seed and signing nonce) is always provided by the caller.
 */

#define MLD_CONFIG_FILE "mldsa_config.h"

/* ML-DSA-44, together with the code shared by all parameter sets */
#define MLD_CONFIG_MULTILEVEL_WITH_SHARED
#define MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa-native/mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_CONFIG_MULTILEVEL_WITH_SHARED

/* ML-DSA-65 */
#define MLD_CONFIG_MULTILEVEL_NO_SHARED
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa-native/mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET

/* ML-DSA-87, and clean up all the headers at the end */
#undef MLD_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa-native/mldsa_native.c"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_CONFIG_MULTILEVEL_NO_SHARED

/* The public constants (MLDSA44_PUBLICKEYBYTES, ...) */
#define MLD_CONFIG_CONSTANTS_ONLY
#include "mldsa-native/mldsa_native.h"

/* After mldsa-native, so that its macros don't leak into it */
#include "common.h"
#include "errors.h"

FAKE_INIT(mldsa)

typedef struct {
    size_t pk_len;
    size_t sk_len;
    size_t sig_len;
} ParamSet;

static const ParamSet param_sets[] = {
    { MLDSA44_PUBLICKEYBYTES, MLDSA44_SECRETKEYBYTES, MLDSA44_BYTES },
    { MLDSA65_PUBLICKEYBYTES, MLDSA65_SECRETKEYBYTES, MLDSA65_BYTES },
    { MLDSA87_PUBLICKEYBYTES, MLDSA87_SECRETKEYBYTES, MLDSA87_BYTES },
};

static const ParamSet *get_param_set(unsigned level)
{
    switch (level) {
        case 44: return &param_sets[0];
        case 65: return &param_sets[1];
        case 87: return &param_sets[2];
        default: return NULL;
    }
}

/*
 * Generate a key pair from a 32-byte seed (FIPS 204, Algorithm 6).
 *
 * The public key goes into pk (pk_len bytes), the expanded private key
 * into sk (sk_len bytes).
 */
EXPORT_SYM int mldsa_keypair(unsigned level,
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

    if (pk_len != ps->pk_len || sk_len != ps->sk_len || seed_len != MLDSA_SEEDBYTES)
        return ERR_KEY_SIZE;

    switch (level) {
        case 44: res = mldsa44_keypair_internal(pk, sk, seed); break;
        case 65: res = mldsa65_keypair_internal(pk, sk, seed); break;
        default: res = mldsa87_keypair_internal(pk, sk, seed); break;
    }

    return res == 0 ? 0 : ERR_UNKNOWN;
}

/*
 * Validate an expanded private key, and compute the matching public key.
 *
 * Return ERR_VALUE if the private key is not valid.
 */
EXPORT_SYM int mldsa_pk_from_sk(unsigned level,
                                uint8_t *pk, size_t pk_len,
                                const uint8_t *sk, size_t sk_len)
{
    const ParamSet *ps;
    int res;

    if (NULL == pk || NULL == sk)
        return ERR_NULL;

    ps = get_param_set(level);
    if (NULL == ps)
        return ERR_VALUE;

    if (pk_len != ps->pk_len || sk_len != ps->sk_len)
        return ERR_KEY_SIZE;

    switch (level) {
        case 44: res = mldsa44_pk_from_sk(pk, sk); break;
        case 65: res = mldsa65_pk_from_sk(pk, sk); break;
        default: res = mldsa87_pk_from_sk(pk, sk); break;
    }

    switch (res) {
        case 0: return 0;
        case MLD_ERR_INVALID_KEY: return ERR_VALUE;
        default: return ERR_UNKNOWN;
    }
}

/*
 * Sign a message with an expanded private key (FIPS 204, Algorithm 7).
 *
 * If external_mu is zero, the message is the concatenation of pre and m
 * (M' in FIPS 204).
 * Otherwise, m is the 64-byte message representative mu and pre is ignored.
 *
 * rnd is the 32-byte nonce (all zeroes for the deterministic variant).
 */
EXPORT_SYM int mldsa_sign(unsigned level,
                          uint8_t *sig, size_t sig_len,
                          const uint8_t *m, size_t m_len,
                          const uint8_t *pre, size_t pre_len,
                          const uint8_t *rnd, size_t rnd_len,
                          const uint8_t *sk, size_t sk_len,
                          int external_mu)
{
    const ParamSet *ps;
    int res;

    if (NULL == sig || NULL == m || NULL == pre || NULL == rnd || NULL == sk)
        return ERR_NULL;

    ps = get_param_set(level);
    if (NULL == ps)
        return ERR_VALUE;

    if (sk_len != ps->sk_len)
        return ERR_KEY_SIZE;

    if (sig_len != ps->sig_len || rnd_len != MLDSA_RNDBYTES)
        return ERR_VALUE;

    if (external_mu && m_len != MLDSA_CRHBYTES)
        return ERR_VALUE;

    switch (level) {
        case 44: res = mldsa44_signature_internal(sig, m, m_len, pre, pre_len, rnd, sk, external_mu); break;
        case 65: res = mldsa65_signature_internal(sig, m, m_len, pre, pre_len, rnd, sk, external_mu); break;
        default: res = mldsa87_signature_internal(sig, m, m_len, pre, pre_len, rnd, sk, external_mu); break;
    }

    return res == 0 ? 0 : ERR_UNKNOWN;
}

/*
 * Verify a signature with a public key (FIPS 204, Algorithm 8).
 *
 * The message is as for mldsa_sign().
 *
 * Return 0 if the signature is valid, ERR_VALUE if it is not.
 */
EXPORT_SYM int mldsa_verify(unsigned level,
                            const uint8_t *sig, size_t sig_len,
                            const uint8_t *m, size_t m_len,
                            const uint8_t *pre, size_t pre_len,
                            const uint8_t *pk, size_t pk_len,
                            int external_mu)
{
    const ParamSet *ps;
    int res;

    if (NULL == sig || NULL == m || NULL == pre || NULL == pk)
        return ERR_NULL;

    ps = get_param_set(level);
    if (NULL == ps)
        return ERR_VALUE;

    if (pk_len != ps->pk_len)
        return ERR_KEY_SIZE;

    if (sig_len != ps->sig_len)
        return ERR_VALUE;

    if (external_mu && m_len != MLDSA_CRHBYTES)
        return ERR_VALUE;

    switch (level) {
        case 44: res = mldsa44_verify_internal(sig, m, m_len, pre, pre_len, pk, external_mu); break;
        case 65: res = mldsa65_verify_internal(sig, m, m_len, pre, pre_len, pk, external_mu); break;
        default: res = mldsa87_verify_internal(sig, m, m_len, pre, pre_len, pk, external_mu); break;
    }

    switch (res) {
        case 0: return 0;
        case MLD_ERR_INVALID_SIGNATURE: return ERR_VALUE;
        default: return ERR_UNKNOWN;
    }
}
