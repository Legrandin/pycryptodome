/*
 * SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"

#define F_ROUNDS 12
#define MAX_DIGEST_BYTES 64
#define MAX_KEY_BYTES    64
#define BLAKE2_WORD_SIZE 64
#define G_R1 32
#define G_R2 24
#define G_R3 16
#define G_R4 63

typedef uint64_t blake2_word;

#define STORE_WORD_LITTLE(p, w)     STORE_U64_LITTLE(p, w)
#define LOAD_WORD_LITTLE(p)         LOAD_U64_LITTLE(p)

static const uint64_t iv[8] = {
    0x6A09E667F3BCC908ULL,
    0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL,
    0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL,
    0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL,
    0x5BE0CD19137E2179ULL
};

#define blake2_init blake2b_init
#define blake2_copy blake2b_copy
#define blake2_destroy blake2b_destroy
#define blake2_digest blake2b_digest
#define blake2_update blake2b_update

FAKE_INIT(BLAKE2b)

#include "blake2.c"

