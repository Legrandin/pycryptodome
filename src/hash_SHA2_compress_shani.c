/*
 * SPDX-FileCopyrightText: 2018 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/**
 * The SHA-2 compression function with the Intel SHA extensions
 * (SHA-224 and SHA-256 only), for hash_SHA2_template.c.
 *
 * This file is not a module: it is included by hash_SHA2_template.c
 * when SHA2_SHA_NI is defined (see SHA256_shani.c), after the definitions
 * of sha2_word_t, SCHEDULE_SIZE and K[].
 */

#if WORD_SIZE != 4
#error SHA-NI is only available for SHA-224 and SHA-256
#endif

#include <immintrin.h>
#include "sse2_unaligned.h"

/** Rounds 4g to 4g+3, with message words w = W[4g..4g+3] **/
#define SHANI_ROUNDS(g, w) do { \
    wk = _mm_add_epi32(w, LOADU_128(&K[(g)*4])); \
    cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk); \
    wk = _mm_shuffle_epi32(wk, 0x0E); \
    abef = _mm_sha256rnds2_epu32(abef, cdgh, wk); \
    } while (0)

/** With m0..m3 = W[t-16..t-1], replace m0 with W[t..t+3] **/
#define SHANI_SCHEDULE(m0, m1, m2, m3) do { \
    m0 = _mm_sha256msg1_epu32(m0, m1); \
    m0 = _mm_add_epi32(m0, _mm_alignr_epi8(m3, m2, 4)); \
    m0 = _mm_sha256msg2_epu32(m0, m3); \
    } while (0)

/**
 * Compress one block, already decoded into sixteen words,
 * with the Intel SHA extensions.
 * h_out[] may be the same array as h_in[] or M[].
 */
static void sha_compress_words(const sha2_word_t h_in[8], sha2_word_t h_out[8], const sha2_word_t M[16])
{
    __m128i abef, cdgh, abef_save, cdgh_save;
    __m128i m0, m1, m2, m3, wk, tmp;

    /** The SHA-NI instructions want the state as {A,B,E,F} and {C,D,G,H} **/
    tmp  = LOADU_128(&h_in[0]);                         /** D C B A (lane 3..0) **/
    cdgh = LOADU_128(&h_in[4]);                         /** H G F E **/
    tmp  = _mm_shuffle_epi32(tmp, 0xB1);                /** C D A B **/
    cdgh = _mm_shuffle_epi32(cdgh, 0x1B);               /** E F G H **/
    abef = _mm_alignr_epi8(tmp, cdgh, 8);               /** A B E F **/
    cdgh = _mm_blend_epi16(cdgh, tmp, 0xF0);            /** C D G H **/

    abef_save = abef;
    cdgh_save = cdgh;

    /** m0..m3 are a rolling window of the last 16 words of the message schedule **/
    m0 = LOADU_128(&M[0]);
    m1 = LOADU_128(&M[4]);
    m2 = LOADU_128(&M[8]);
    m3 = LOADU_128(&M[12]);

    SHANI_ROUNDS( 0, m0);
    SHANI_ROUNDS( 1, m1);
    SHANI_ROUNDS( 2, m2);
    SHANI_ROUNDS( 3, m3);
    SHANI_SCHEDULE(m0, m1, m2, m3); SHANI_ROUNDS( 4, m0);
    SHANI_SCHEDULE(m1, m2, m3, m0); SHANI_ROUNDS( 5, m1);
    SHANI_SCHEDULE(m2, m3, m0, m1); SHANI_ROUNDS( 6, m2);
    SHANI_SCHEDULE(m3, m0, m1, m2); SHANI_ROUNDS( 7, m3);
    SHANI_SCHEDULE(m0, m1, m2, m3); SHANI_ROUNDS( 8, m0);
    SHANI_SCHEDULE(m1, m2, m3, m0); SHANI_ROUNDS( 9, m1);
    SHANI_SCHEDULE(m2, m3, m0, m1); SHANI_ROUNDS(10, m2);
    SHANI_SCHEDULE(m3, m0, m1, m2); SHANI_ROUNDS(11, m3);
    SHANI_SCHEDULE(m0, m1, m2, m3); SHANI_ROUNDS(12, m0);
    SHANI_SCHEDULE(m1, m2, m3, m0); SHANI_ROUNDS(13, m1);
    SHANI_SCHEDULE(m2, m3, m0, m1); SHANI_ROUNDS(14, m2);
    SHANI_SCHEDULE(m3, m0, m1, m2); SHANI_ROUNDS(15, m3);

    abef = _mm_add_epi32(abef, abef_save);
    cdgh = _mm_add_epi32(cdgh, cdgh_save);

    /** Back to {A,B,C,D} and {E,F,G,H} **/
    tmp  = _mm_shuffle_epi32(abef, 0x1B);               /** F E B A **/
    cdgh = _mm_shuffle_epi32(cdgh, 0xB1);               /** D C H G **/
    abef = _mm_blend_epi16(tmp, cdgh, 0xF0);            /** D C B A **/
    cdgh = _mm_alignr_epi8(cdgh, tmp, 8);               /** H G F E **/

    STOREU_128(&h_out[0], abef);
    STOREU_128(&h_out[4], cdgh);
}
