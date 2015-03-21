/* ===================================================================
 *
 * Copyright (c) 2014, Legrandin <helderijs@gmail.com>
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

#include "pycrypto_common.h"

#define F_ROUNDS 12
#define MAX_DIGEST_BYTES 64
#define MAX_KEY_BYTES    64
#define BLAKE2_WORD_SIZE 64
#define G_R1 32
#define G_R2 24
#define G_R3 16
#define G_R4 63

typedef uint64_t blake2_word;

static const uint64_t iv[8] = {
    0x6A09E667F3BCC908ull,
    0xBB67AE8584CAA73Bull,
    0x3C6EF372FE94F82Bull,
    0xA54FF53A5F1D36F1ull,
    0x510E527FADE682D1ull,
    0x9B05688C2B3E6C1Full,
    0x1F83D9ABFB41BD6Bull,
    0x5BE0CD19137E2179ull
};

static void byteswap(uint64_t *v)
{
    union {
        uint64_t w;
        uint8_t b[8];
    } x, y;

    x.w = *v;
    y.b[0] = x.b[7];
    y.b[1] = x.b[6];
    y.b[2] = x.b[5];
    y.b[3] = x.b[4];
    y.b[4] = x.b[3];
    y.b[5] = x.b[2];
    y.b[6] = x.b[1];
    y.b[7] = x.b[0];
    *v = y.w;
}

#define blake2_init blake2b_init
#define blake2_copy blake2b_copy
#define blake2_destroy blake2b_destroy
#define blake2_digest blake2b_digest
#define blake2_update blake2b_update

FAKE_INIT(BLAKE2b)

#include "blake2.c"

