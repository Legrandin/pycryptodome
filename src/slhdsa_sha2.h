/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * SHA-256 and SHA-512 of pycryptodome (SHA256.c and SHA512.c),
 * private to the SLH-DSA module (see hash_SHA2_template.c for SHA2_EMBEDDED).
 *
 * Both come from the same template, so they use the same internal names:
 * each copy gets its own prefix (sha256_ or sha512_), and the macros
 * of the template are removed after each copy.
 *
 * The functions are SHA256_init(), SHA256_update(), ... as in SHA256.c,
 * on a sha256_hash_state (and the same for SHA-512).
 *
 * If SLHDSA_SHA_NI is defined, SHA-256 uses the Intel SHA extensions
 * (SHA256_shani.c).
 */

#ifndef SLHDSA_SHA2_H
#define SLHDSA_SHA2_H

#define SHA2_EMBEDDED

/* SHA-256 */

#define sha2_word_t         sha256_word_t
#define t_hash_state        sha256_t_hash_state
#define hash_state          sha256_hash_state
#define K                   sha256_K
#define H                   sha256_H
#define put_be              sha256_put_be
#define add_bits            sha256_add_bits
#define sha_compress_words  sha256_compress_words
#define sha_compress_block  sha256_compress_block
#define sha_compress        sha256_compress
#define sha_init_state      sha256_init_state
#define sha_finalize        sha256_finalize

#ifdef SLHDSA_SHA_NI
#include "SHA256_shani.c"
#undef SHA2_MODULE
#undef SHA2_SHA_NI
#undef SHANI_ROUNDS
#undef SHANI_SCHEDULE
#else
#include "SHA256.c"
#endif

#undef sha2_word_t
#undef t_hash_state
#undef hash_state
#undef K
#undef H
#undef put_be
#undef add_bits
#undef sha_compress_words
#undef sha_compress_block
#undef sha_compress
#undef sha_init_state
#undef sha_finalize

/* The macros of SHA256.c and of the template, which SHA512.c defines again */
#undef MODULE_NAME
#undef DIGEST_SIZE
#undef WORD_SIZE
#undef FUNC_NAME
#undef SCHEDULE_SIZE
#undef BLOCK_SIZE
#undef SCHEDULE
#undef CYCLE
#undef LOAD_WORD_BIG
#undef STORE_WORD_BIG

/* SHA-512 */

#define sha2_word_t         sha512_word_t
#define t_hash_state        sha512_t_hash_state
#define hash_state          sha512_hash_state
#define K                   sha512_K
#define put_be              sha512_put_be
#define add_bits            sha512_add_bits
#define sha_compress_words  sha512_compress_words
#define sha_compress_block  sha512_compress_block
#define sha_compress        sha512_compress
#define sha_init_state      sha512_init_state
#define sha_finalize        sha512_finalize

#include "SHA512.c"

#undef sha2_word_t
#undef t_hash_state
#undef hash_state
#undef K
#undef put_be
#undef add_bits
#undef sha_compress_words
#undef sha_compress_block
#undef sha_compress
#undef sha_init_state
#undef sha_finalize

#undef MODULE_NAME
#undef DIGEST_SIZE
#undef WORD_SIZE
#undef FUNC_NAME
#undef SCHEDULE_SIZE
#undef BLOCK_SIZE
#undef SCHEDULE
#undef CYCLE
#undef LOAD_WORD_BIG
#undef STORE_WORD_BIG

#undef SHA2_EMBEDDED
#undef SHA2_API

#endif
