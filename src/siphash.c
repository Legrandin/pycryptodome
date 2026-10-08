/* ===================================================================
 *
 * Copyright (c) 2026, Helder Eijs <helderijs@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
 */

/**
 * SipHash-2-4, a keyed hash function by J.-P. Aumasson and D. J. Bernstein,
 * as specified in "SipHash: a fast short-input PRF" (2012), with the
 * 128-bit output variant described at https://github.com/veorq/SipHash
 */

#include "common.h"
#include "endianess.h"
#include "siphash.h"

/** Compression rounds per message word, and finalization rounds **/
#define C_ROUNDS 2
#define D_ROUNDS 4

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

typedef struct {
    uint64_t v0, v1, v2, v3;
} SipState;

static void sip_round(SipState *s)
{
    s->v0 += s->v1;
    s->v1 = ROTL64(s->v1, 13);
    s->v1 ^= s->v0;
    s->v0 = ROTL64(s->v0, 32);

    s->v2 += s->v3;
    s->v3 = ROTL64(s->v3, 16);
    s->v3 ^= s->v2;

    s->v0 += s->v3;
    s->v3 = ROTL64(s->v3, 21);
    s->v3 ^= s->v0;

    s->v2 += s->v1;
    s->v1 = ROTL64(s->v1, 17);
    s->v1 ^= s->v2;
    s->v2 = ROTL64(s->v2, 32);
}

static void absorb(SipState *s, uint64_t m)
{
    unsigned i;

    s->v3 ^= m;
    for (i=0; i<C_ROUNDS; i++)
        sip_round(s);
    s->v0 ^= m;
}

static uint64_t squeeze(SipState *s)
{
    unsigned i;

    for (i=0; i<D_ROUNDS; i++)
        sip_round(s);
    return s->v0 ^ s->v1 ^ s->v2 ^ s->v3;
}

/**
 * Compute SipHash-2-4 of a message.
 *
 * @in      The message.
 * @inlen   The length of the message, in bytes.
 * @k       The 16-byte key.
 * @out     The buffer for the output.
 * @outlen  The length of the output: 8 bytes (SipHash-2-4),
 *          or 16 bytes (SipHash-2-4 with 128-bit output).
 *
 * @return  0 in case of success, ERR_VALUE if outlen is not 8 or 16.
 */
int siphash(const uint8_t *in, const size_t inlen, const uint8_t *k, uint8_t *out, const size_t outlen)
{
    SipState s;
    uint64_t k0, k1, w;
    uint8_t last[8];
    size_t i, left;

    if (outlen != 8 && outlen != 16)
        return ERR_VALUE;

    /** Initialization: the key, XORed with "somepseudorandomlygeneratedbytes" **/
    k0 = LOAD_U64_LITTLE(k);
    k1 = LOAD_U64_LITTLE(k + 8);
    s.v0 = k0 ^ 0x736f6d6570736575ULL;
    s.v1 = k1 ^ 0x646f72616e646f6dULL;
    s.v2 = k0 ^ 0x6c7967656e657261ULL;
    s.v3 = k1 ^ 0x7465646279746573ULL;
    if (outlen == 16)
        s.v1 ^= 0xee;

    /** Compression: the message as 64-bit little endian words **/
    for (i=0; i+8<=inlen; i+=8)
        absorb(&s, LOAD_U64_LITTLE(in + i));

    /** The last word: the remaining bytes, padded with zeroes,
     *  and the message length (modulo 256) as its top byte **/
    left = inlen - i;
    memset(last, 0, sizeof last);
    memcpy(last, in + i, left);
    last[7] = (uint8_t)inlen;
    absorb(&s, LOAD_U64_LITTLE(last));

    /** Finalization **/
    s.v2 ^= (outlen == 16) ? 0xee : 0xff;
    w = squeeze(&s);
    STORE_U64_LITTLE(out, w);

    if (outlen == 16) {
        s.v1 ^= 0xdd;
        w = squeeze(&s);
        STORE_U64_LITTLE(out + 8, w);
    }

    return 0;
}
