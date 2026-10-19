/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS204]
 *   FIPS 204 Module-Lattice-Based Digital Signature Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/204/final
 */

#include "../common.h"
#if !defined(MLD_CONFIG_MULTILEVEL_NO_SHARED) && \
    !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)

#include "../ct.h"
#include "fips202.h"
#include "fips202x4.h"
#include "keccakf1600.h"

#if !defined(MLD_CONFIG_NO_KEYPAIR_API) || !defined(MLD_CONFIG_REDUCE_RAM) || \
    defined(MLD_UNIT_TEST)
static void mld_keccak_absorb_once_x4(uint64_t *s, unsigned r,
                                      const uint8_t *in0, const uint8_t *in1,
                                      const uint8_t *in2, const uint8_t *in3,
                                      size_t inlen, uint8_t p)
__contract__(
  requires(inlen <= MLD_MAX_BUFFER_SIZE)
  requires(memory_no_alias(s, sizeof(uint64_t) * MLD_KECCAK_LANES * MLD_KECCAK_WAY))
  requires(r > 0)
  requires(r <= sizeof(uint64_t) * MLD_KECCAK_LANES)
  requires(memory_no_alias(in0, inlen))
  requires(memory_no_alias(in1, inlen))
  requires(memory_no_alias(in2, inlen))
  requires(memory_no_alias(in3, inlen))
  assigns(memory_slice(s, sizeof(uint64_t) * MLD_KECCAK_LANES * MLD_KECCAK_WAY)))
{
  while (inlen >= r)
  __loop__(
    assigns(inlen, in0, in1, in2, in3, memory_slice(s, sizeof(uint64_t) * MLD_KECCAK_LANES * MLD_KECCAK_WAY))
    invariant(inlen <= loop_entry(inlen))
    invariant(in0 == loop_entry(in0) + (loop_entry(inlen) - inlen))
    invariant(in1 == loop_entry(in1) + (loop_entry(inlen) - inlen))
    invariant(in2 == loop_entry(in2) + (loop_entry(inlen) - inlen))
    invariant(in3 == loop_entry(in3) + (loop_entry(inlen) - inlen))
    decreases(inlen))
  {
    mld_keccakf1600x4_xor_bytes(s, in0, in1, in2, in3, 0, r);
    mld_keccakf1600x4_permute(s);

    in0 += r;
    in1 += r;
    in2 += r;
    in3 += r;
    inlen -= r;
  }

  /* Safety: At this point, inlen < r, so the truncations to unsigned are safe
   * below. */
  if (inlen > 0)
  {
    mld_keccakf1600x4_xor_bytes(s, in0, in1, in2, in3, 0, (unsigned)inlen);
  }

  if (inlen == r - 1)
  {
    p |= 128;
    mld_keccakf1600x4_xor_bytes(s, &p, &p, &p, &p, (unsigned)inlen, 1);
  }
  else
  {
    mld_keccakf1600x4_xor_bytes(s, &p, &p, &p, &p, (unsigned)inlen, 1);
    p = 128;
    mld_keccakf1600x4_xor_bytes(s, &p, &p, &p, &p, r - 1, 1);
  }
}

static void mld_keccak_squeezeblocks_x4(uint8_t *out0, uint8_t *out1,
                                        uint8_t *out2, uint8_t *out3,
                                        size_t nblocks, uint64_t *s, unsigned r)
__contract__(
    requires(r <= sizeof(uint64_t) * MLD_KECCAK_LANES)
    requires(nblocks <= 8 /* somewhat arbitrary bound */)
    requires(memory_no_alias(s, sizeof(uint64_t) * MLD_KECCAK_LANES * MLD_KECCAK_WAY))
    requires(memory_no_alias(out0, nblocks * r))
    requires(memory_no_alias(out1, nblocks * r))
    requires(memory_no_alias(out2, nblocks * r))
    requires(memory_no_alias(out3, nblocks * r))
    assigns(memory_slice(s, sizeof(uint64_t) * MLD_KECCAK_LANES * MLD_KECCAK_WAY))
    assigns(memory_slice(out0, nblocks * r))
    assigns(memory_slice(out1, nblocks * r))
    assigns(memory_slice(out2, nblocks * r))
    assigns(memory_slice(out3, nblocks * r)))
{
  size_t current_offset = 0;
  while (nblocks > 0)
  __loop__(
    assigns(nblocks, current_offset,
            memory_slice(s, sizeof(uint64_t) * MLD_KECCAK_LANES * MLD_KECCAK_WAY),
            memory_slice(out0, nblocks * r),
            memory_slice(out1, nblocks * r),
            memory_slice(out2, nblocks * r),
            memory_slice(out3, nblocks * r))
    invariant(nblocks <= loop_entry(nblocks))
    invariant(current_offset == (loop_entry(nblocks) - nblocks) * r)
    decreases(nblocks))
  {
    mld_keccakf1600x4_permute(s);
    mld_keccakf1600x4_extract_bytes(
        s, &out0[current_offset], &out1[current_offset], &out2[current_offset],
        &out3[current_offset], 0, r);
    current_offset += r;
    nblocks--;
  }
}
#endif /* !MLD_CONFIG_NO_KEYPAIR_API || !MLD_CONFIG_REDUCE_RAM || \
          MLD_UNIT_TEST */

#if !defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)
MLD_INTERNAL_API
void mld_shake128x4_absorb_once(mld_shake128x4ctx *state, const uint8_t *in0,
                                const uint8_t *in1, const uint8_t *in2,
                                const uint8_t *in3, size_t inlen)
{
  mld_memset(state, 0, sizeof(mld_shake128x4ctx));
  mld_keccak_absorb_once_x4(state->ctx, SHAKE128_RATE, in0, in1, in2, in3,
                            inlen, 0x1F);
}

MLD_INTERNAL_API
void mld_shake128x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                                  uint8_t *out3, size_t nblocks,
                                  mld_shake128x4ctx *state)
{
  mld_keccak_squeezeblocks_x4(out0, out1, out2, out3, nblocks, state->ctx,
                              SHAKE128_RATE);
}

MLD_INTERNAL_API
void mld_shake128x4_init(mld_shake128x4ctx *state) { (void)state; }
MLD_INTERNAL_API
void mld_shake128x4_release(mld_shake128x4ctx *state)
{
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(state, sizeof(mld_shake128x4ctx));
}
#endif /* !MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */

#if !defined(MLD_CONFIG_NO_KEYPAIR_API) ||                                  \
    (!defined(MLD_CONFIG_NO_SIGN_API) &&                                    \
     (!defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)))
MLD_INTERNAL_API
void mld_shake256x4_absorb_once(mld_shake256x4ctx *state, const uint8_t *in0,
                                const uint8_t *in1, const uint8_t *in2,
                                const uint8_t *in3, size_t inlen)
{
  mld_memset(state, 0, sizeof(mld_shake256x4ctx));
  mld_keccak_absorb_once_x4(state->ctx, SHAKE256_RATE, in0, in1, in2, in3,
                            inlen, 0x1F);
}

MLD_INTERNAL_API
void mld_shake256x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                                  uint8_t *out3, size_t nblocks,
                                  mld_shake256x4ctx *state)
{
  mld_keccak_squeezeblocks_x4(out0, out1, out2, out3, nblocks, state->ctx,
                              SHAKE256_RATE);
}

MLD_INTERNAL_API
void mld_shake256x4_init(mld_shake256x4ctx *state) { (void)state; }
MLD_INTERNAL_API
void mld_shake256x4_release(mld_shake256x4ctx *state)
{
  /* @[FIPS204, Section 3.6.3] Destruction of intermediate values. */
  mld_zeroize(state, sizeof(mld_shake256x4ctx));
}
#endif /* !MLD_CONFIG_NO_KEYPAIR_API || (!MLD_CONFIG_NO_SIGN_API && \
          (!MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST)) */

#endif /* !MLD_CONFIG_MULTILEVEL_NO_SHARED && !MLD_CONFIG_SERIAL_FIPS202_ONLY \
        */
