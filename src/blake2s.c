/*
 * SPDX-FileCopyrightText: 2014 Legrandin <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "common.h"

#define F_ROUNDS 10
#define MAX_DIGEST_BYTES 32
#define MAX_KEY_BYTES    32
#define BLAKE2_WORD_SIZE 32
#define G_R1 16
#define G_R2 12
#define G_R3 8
#define G_R4 7

typedef uint32_t blake2_word;

#define STORE_WORD_LITTLE(p, w)     STORE_U32_LITTLE(p, w)
#define LOAD_WORD_LITTLE(p)         LOAD_U32_LITTLE(p)

static const uint32_t iv[8] = {
    0x6A09E667U,
    0xBB67AE85U,
    0x3C6EF372U,
    0xA54FF53AU,
    0x510E527FU,
    0x9B05688CU,
    0x1F83D9ABU,
    0x5BE0CD19U
};

#define blake2_init blake2s_init
#define blake2_copy blake2s_copy
#define blake2_destroy blake2s_destroy
#define blake2_digest blake2s_digest
#define blake2_update blake2s_update

FAKE_INIT(BLAKE2s)

#include "blake2.c"

