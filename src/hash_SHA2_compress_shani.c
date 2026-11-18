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
 *
 * With SHA2_SHANI_X4 defined, it also has sha_compress_blocks_x4(),
 * which compresses four independent blocks at once (see slhdsa_sha2.h).
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

#ifdef SHA2_SHANI_X4

/** The state {A..D}, {E..H} in h[] as {A,B,E,F} and {C,D,G,H} **/
static inline void shani_load_state(const sha2_word_t h[8], __m128i *abef, __m128i *cdgh)
{
    __m128i tmp;

    tmp   = LOADU_128(&h[0]);
    *cdgh = LOADU_128(&h[4]);
    tmp   = _mm_shuffle_epi32(tmp, 0xB1);
    *cdgh = _mm_shuffle_epi32(*cdgh, 0x1B);
    *abef = _mm_alignr_epi8(tmp, *cdgh, 8);
    *cdgh = _mm_blend_epi16(*cdgh, tmp, 0xF0);
}

/** The inverse of shani_load_state() **/
static inline void shani_store_state(sha2_word_t h[8], __m128i abef, __m128i cdgh)
{
    __m128i tmp;

    tmp  = _mm_shuffle_epi32(abef, 0x1B);
    cdgh = _mm_shuffle_epi32(cdgh, 0xB1);
    abef = _mm_blend_epi16(tmp, cdgh, 0xF0);
    cdgh = _mm_alignr_epi8(cdgh, tmp, 8);
    STOREU_128(&h[0], abef);
    STOREU_128(&h[4], cdgh);
}

/** SHANI_ROUNDS() for the four blocks a, b, c and d, with message words m<x><p> **/
#define SHANI_ROUNDS_X4(g, p) do { \
    k4 = LOADU_128(&K[(g)*4]); \
    wka = _mm_add_epi32(ma##p, k4); \
    wkb = _mm_add_epi32(mb##p, k4); \
    wkc = _mm_add_epi32(mc##p, k4); \
    wkd = _mm_add_epi32(md##p, k4); \
    cdgha = _mm_sha256rnds2_epu32(cdgha, abefa, wka); \
    cdghb = _mm_sha256rnds2_epu32(cdghb, abefb, wkb); \
    cdghc = _mm_sha256rnds2_epu32(cdghc, abefc, wkc); \
    cdghd = _mm_sha256rnds2_epu32(cdghd, abefd, wkd); \
    wka = _mm_shuffle_epi32(wka, 0x0E); \
    wkb = _mm_shuffle_epi32(wkb, 0x0E); \
    wkc = _mm_shuffle_epi32(wkc, 0x0E); \
    wkd = _mm_shuffle_epi32(wkd, 0x0E); \
    abefa = _mm_sha256rnds2_epu32(abefa, cdgha, wka); \
    abefb = _mm_sha256rnds2_epu32(abefb, cdghb, wkb); \
    abefc = _mm_sha256rnds2_epu32(abefc, cdghc, wkc); \
    abefd = _mm_sha256rnds2_epu32(abefd, cdghd, wkd); \
    } while (0)

/** SHANI_SCHEDULE() and SHANI_ROUNDS_X4() for the next 4 rounds of a, b, c and d **/
#define SHANI_STEP_X4(g, p0, p1, p2, p3) do { \
    SHANI_SCHEDULE(ma##p0, ma##p1, ma##p2, ma##p3); \
    SHANI_SCHEDULE(mb##p0, mb##p1, mb##p2, mb##p3); \
    SHANI_SCHEDULE(mc##p0, mc##p1, mc##p2, mc##p3); \
    SHANI_SCHEDULE(md##p0, md##p1, md##p2, md##p3); \
    SHANI_ROUNDS_X4(g, p0); \
    } while (0)

/**
 * Compress four independent blocks of 64 bytes at once (block[j] from
 * the state h_in[j] into h_out[j], which may be the same array).
 * Each SHA-NI round depends on the previous one: interleaving the rounds
 * of four blocks keeps the SHA unit busy while each of them waits.
 */
static void sha_compress_blocks_x4(const sha2_word_t *h_in[4], sha2_word_t *h_out[4],
                                   const uint8_t *block[4])
{
    const __m128i bswap = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    __m128i abefa, cdgha, abefa_save, cdgha_save, wka, ma0, ma1, ma2, ma3;
    __m128i abefb, cdghb, abefb_save, cdghb_save, wkb, mb0, mb1, mb2, mb3;
    __m128i abefc, cdghc, abefc_save, cdghc_save, wkc, mc0, mc1, mc2, mc3;
    __m128i abefd, cdghd, abefd_save, cdghd_save, wkd, md0, md1, md2, md3;
    __m128i k4;

    shani_load_state(h_in[0], &abefa, &cdgha);
    shani_load_state(h_in[1], &abefb, &cdghb);
    shani_load_state(h_in[2], &abefc, &cdghc);
    shani_load_state(h_in[3], &abefd, &cdghd);
    abefa_save = abefa;
    cdgha_save = cdgha;
    abefb_save = abefb;
    cdghb_save = cdghb;
    abefc_save = abefc;
    cdghc_save = cdghc;
    abefd_save = abefd;
    cdghd_save = cdghd;

    ma0 = _mm_shuffle_epi8(LOADU_128(block[0] + 4*0), bswap);
    ma1 = _mm_shuffle_epi8(LOADU_128(block[0] + 4*4), bswap);
    ma2 = _mm_shuffle_epi8(LOADU_128(block[0] + 4*8), bswap);
    ma3 = _mm_shuffle_epi8(LOADU_128(block[0] + 4*12), bswap);
    mb0 = _mm_shuffle_epi8(LOADU_128(block[1] + 4*0), bswap);
    mb1 = _mm_shuffle_epi8(LOADU_128(block[1] + 4*4), bswap);
    mb2 = _mm_shuffle_epi8(LOADU_128(block[1] + 4*8), bswap);
    mb3 = _mm_shuffle_epi8(LOADU_128(block[1] + 4*12), bswap);
    mc0 = _mm_shuffle_epi8(LOADU_128(block[2] + 4*0), bswap);
    mc1 = _mm_shuffle_epi8(LOADU_128(block[2] + 4*4), bswap);
    mc2 = _mm_shuffle_epi8(LOADU_128(block[2] + 4*8), bswap);
    mc3 = _mm_shuffle_epi8(LOADU_128(block[2] + 4*12), bswap);
    md0 = _mm_shuffle_epi8(LOADU_128(block[3] + 4*0), bswap);
    md1 = _mm_shuffle_epi8(LOADU_128(block[3] + 4*4), bswap);
    md2 = _mm_shuffle_epi8(LOADU_128(block[3] + 4*8), bswap);
    md3 = _mm_shuffle_epi8(LOADU_128(block[3] + 4*12), bswap);

    SHANI_ROUNDS_X4( 0, 0);
    SHANI_ROUNDS_X4( 1, 1);
    SHANI_ROUNDS_X4( 2, 2);
    SHANI_ROUNDS_X4( 3, 3);
    SHANI_STEP_X4( 4, 0, 1, 2, 3);
    SHANI_STEP_X4( 5, 1, 2, 3, 0);
    SHANI_STEP_X4( 6, 2, 3, 0, 1);
    SHANI_STEP_X4( 7, 3, 0, 1, 2);
    SHANI_STEP_X4( 8, 0, 1, 2, 3);
    SHANI_STEP_X4( 9, 1, 2, 3, 0);
    SHANI_STEP_X4(10, 2, 3, 0, 1);
    SHANI_STEP_X4(11, 3, 0, 1, 2);
    SHANI_STEP_X4(12, 0, 1, 2, 3);
    SHANI_STEP_X4(13, 1, 2, 3, 0);
    SHANI_STEP_X4(14, 2, 3, 0, 1);
    SHANI_STEP_X4(15, 3, 0, 1, 2);

    abefa = _mm_add_epi32(abefa, abefa_save);
    cdgha = _mm_add_epi32(cdgha, cdgha_save);
    abefb = _mm_add_epi32(abefb, abefb_save);
    cdghb = _mm_add_epi32(cdghb, cdghb_save);
    abefc = _mm_add_epi32(abefc, abefc_save);
    cdghc = _mm_add_epi32(cdghc, cdghc_save);
    abefd = _mm_add_epi32(abefd, abefd_save);
    cdghd = _mm_add_epi32(cdghd, cdghd_save);

    shani_store_state(h_out[0], abefa, cdgha);
    shani_store_state(h_out[1], abefb, cdghb);
    shani_store_state(h_out[2], abefc, cdghc);
    shani_store_state(h_out[3], abefd, cdghd);
}

#endif /* SHA2_SHANI_X4 */
