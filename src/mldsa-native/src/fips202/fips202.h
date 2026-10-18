/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLD_FIPS202_FIPS202_H
#define MLD_FIPS202_FIPS202_H

#include <stddef.h>
#include "../cbmc.h"
#include "../common.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define MLD_KECCAK_LANES 25
#define SHA3_256_HASHBYTES 32
#define SHA3_512_HASHBYTES 64


/** Context for the incremental SHAKE128 XOF. */
typedef struct
{
  uint64_t s[MLD_KECCAK_LANES]; /**< Keccak state. */
  unsigned int pos; /**< Byte position within the current Keccak block. */
} mld_shake128ctx;

/** Context for the incremental SHAKE256 XOF. */
typedef struct
{
  uint64_t s[MLD_KECCAK_LANES]; /**< Keccak state. */
  unsigned int pos; /**< Byte position within the current Keccak block. */
} mld_shake256ctx;

#define mld_shake128_init MLD_NAMESPACE(shake128_init)
/**
 * Initializes state for use as SHAKE128 XOF.
 *
 * @param[out] state Pointer to (uninitialized) state.
 */
MLD_INTERNAL_API
void mld_shake128_init(mld_shake128ctx *state)
__contract__(
  requires(memory_no_alias(state, sizeof(mld_shake128ctx)))
  assigns(memory_slice(state, sizeof(mld_shake128ctx)))
  ensures(state->pos == 0)
);

#define mld_shake128_absorb MLD_NAMESPACE(shake128_absorb)
/**
 * Absorb step of the SHAKE128 XOF. Absorbs arbitrarily many bytes. Can be
 * called multiple times to absorb multiple chunks of data.
 *
 * @param[in,out] state Pointer to (initialized) output state.
 * @param[in]     in    Pointer to input to be absorbed into s.
 * @param         inlen Length of input in bytes.
 */
MLD_INTERNAL_API
void mld_shake128_absorb(mld_shake128ctx *state, const uint8_t *in,
                         size_t inlen)
__contract__(
  requires(inlen <= MLD_MAX_BUFFER_SIZE)
  requires(memory_no_alias(state, sizeof(mld_shake128ctx)))
  requires(memory_no_alias(in, inlen))
  requires(state->pos <= SHAKE128_RATE)
  assigns(memory_slice(state, sizeof(mld_shake128ctx)))
  ensures(state->pos <= SHAKE128_RATE)
);

#define mld_shake128_finalize MLD_NAMESPACE(shake128_finalize)
/**
 * Concludes the absorb phase of the SHAKE128 XOF.
 *
 * @param[in,out] state Pointer to state.
 */
MLD_INTERNAL_API
void mld_shake128_finalize(mld_shake128ctx *state)
__contract__(
  requires(memory_no_alias(state, sizeof(mld_shake128ctx)))
  requires(state->pos <= SHAKE128_RATE)
  assigns(memory_slice(state, sizeof(mld_shake128ctx)))
  ensures(state->pos <= SHAKE128_RATE)
);

#define mld_shake128_squeeze MLD_NAMESPACE(shake128_squeeze)
/**
 * Squeeze step of SHAKE128 XOF. Squeezes arbitrarily many bytes. Can be
 * called multiple times to keep squeezing.
 *
 * @param[out]    out    Pointer to output blocks.
 * @param         outlen Number of bytes to be squeezed (written to output).
 * @param[in,out] state  Pointer to input/output state.
 */
MLD_INTERNAL_API
void mld_shake128_squeeze(uint8_t *out, size_t outlen, mld_shake128ctx *state)
__contract__(
  requires(outlen <= 8 * SHAKE128_RATE /* somewhat arbitrary bound */)
  requires(memory_no_alias(state, sizeof(mld_shake128ctx)))
  requires(memory_no_alias(out, outlen))
  requires(state->pos <= SHAKE128_RATE)
  assigns(memory_slice(state, sizeof(mld_shake128ctx)))
  assigns(memory_slice(out, outlen))
  ensures(state->pos <= SHAKE128_RATE)
);

#define mld_shake128_release MLD_NAMESPACE(shake128_release)
/**
 * Release and securely zero the SHAKE128 state.
 *
 * @param[in,out] state Pointer to state.
 */
MLD_INTERNAL_API
void mld_shake128_release(mld_shake128ctx *state)
__contract__(
  requires(memory_no_alias(state, sizeof(mld_shake128ctx)))
  assigns(memory_slice(state, sizeof(mld_shake128ctx)))
);

#define mld_shake256_init MLD_NAMESPACE(shake256_init)
/**
 * Initializes state for use as SHAKE256 XOF.
 *
 * @param[out] state Pointer to (uninitialized) state.
 */
MLD_INTERNAL_API
void mld_shake256_init(mld_shake256ctx *state)
__contract__(
  requires(memory_no_alias(state, sizeof(mld_shake256ctx)))
  assigns(memory_slice(state, sizeof(mld_shake256ctx)))
  ensures(state->pos == 0)
);

#define mld_shake256_absorb MLD_NAMESPACE(shake256_absorb)
/**
 * Absorb step of the SHAKE256 XOF. Absorbs arbitrarily many bytes. Can be
 * called multiple times to absorb multiple chunks of data.
 *
 * @param[in,out] state Pointer to (initialized) output state.
 * @param[in]     in    Pointer to input to be absorbed into s.
 * @param         inlen Length of input in bytes.
 */
MLD_INTERNAL_API
void mld_shake256_absorb(mld_shake256ctx *state, const uint8_t *in,
                         size_t inlen)
__contract__(
  requires(inlen <= MLD_MAX_BUFFER_SIZE)
  requires(memory_no_alias(state, sizeof(mld_shake256ctx)))
  requires(memory_no_alias(in, inlen))
  requires(state->pos <= SHAKE256_RATE)
  assigns(memory_slice(state, sizeof(mld_shake256ctx)))
  ensures(state->pos <= SHAKE256_RATE)
);

#define mld_shake256_finalize MLD_NAMESPACE(shake256_finalize)
/**
 * Concludes the absorb phase of the SHAKE256 XOF.
 *
 * @param[in,out] state Pointer to state.
 */
MLD_INTERNAL_API
void mld_shake256_finalize(mld_shake256ctx *state)
__contract__(
  requires(memory_no_alias(state, sizeof(mld_shake256ctx)))
  requires(state->pos <= SHAKE256_RATE)
  assigns(memory_slice(state, sizeof(mld_shake256ctx)))
  ensures(state->pos <= SHAKE256_RATE)
);

#define mld_shake256_squeeze MLD_NAMESPACE(shake256_squeeze)
/**
 * Squeeze step of SHAKE256 XOF. Squeezes arbitrarily many bytes. Can be
 * called multiple times to keep squeezing.
 *
 * @param[out]    out    Pointer to output blocks.
 * @param         outlen Number of bytes to be squeezed (written to output).
 * @param[in,out] state  Pointer to input/output state.
 */
MLD_INTERNAL_API
void mld_shake256_squeeze(uint8_t *out, size_t outlen, mld_shake256ctx *state)
__contract__(
  requires(outlen <= 8 * SHAKE256_RATE /* somewhat arbitrary bound */)
  requires(memory_no_alias(state, sizeof(mld_shake256ctx)))
  requires(memory_no_alias(out, outlen))
  requires(state->pos <= SHAKE256_RATE)
  assigns(memory_slice(state, sizeof(mld_shake256ctx)))
  assigns(memory_slice(out, outlen))
  ensures(state->pos <= SHAKE256_RATE)
);

#define mld_shake256_release MLD_NAMESPACE(shake256_release)
/**
 * Release and securely zero the SHAKE256 state.
 *
 * @param[in,out] state Pointer to state.
 */
MLD_INTERNAL_API
void mld_shake256_release(mld_shake256ctx *state)
__contract__(
  requires(memory_no_alias(state, sizeof(mld_shake256ctx)))
  assigns(memory_slice(state, sizeof(mld_shake256ctx)))
);

#if !defined(MLD_CONFIG_NO_KEYPAIR_API) || !defined(MLD_CONFIG_CORE_API_ONLY)
#define mld_shake256 MLD_NAMESPACE(shake256)
/**
 * SHAKE256 XOF with non-incremental API.
 *
 * @param[out] out    Pointer to output.
 * @param      outlen Requested output length in bytes.
 * @param[in]  in     Pointer to input.
 * @param      inlen  Length of input in bytes.
 */
MLD_INTERNAL_API
void mld_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
__contract__(
  requires(inlen <= MLD_MAX_BUFFER_SIZE)
  requires(outlen <= 8 * SHAKE256_RATE /* somewhat arbitrary bound */)
  requires(memory_no_alias(in, inlen))
  requires(memory_no_alias(out, outlen))
  assigns(memory_slice(out, outlen))
);
#endif /* !MLD_CONFIG_NO_KEYPAIR_API || !MLD_CONFIG_CORE_API_ONLY */

#endif /* !MLD_FIPS202_FIPS202_H */
