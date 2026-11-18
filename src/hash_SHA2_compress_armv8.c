/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/**
 * The SHA-2 compression function with the ARMv8 Cryptography Extensions,
 * for hash_SHA2_template.c:
 * - SHA256H, SHA256H2, SHA256SU0 and SHA256SU1 for SHA-224 and SHA-256;
 * - SHA512H, SHA512H2, SHA512SU0 and SHA512SU1 (ARMv8.2) for SHA-384 and SHA-512.
 *
 * This file is not a module: it is included by hash_SHA2_template.c
 * when SHA2_ARMV8 is defined, on 64-bit ARM only (see SHA256_armv8.c),
 * after the definitions of sha2_word_t, SCHEDULE_SIZE and K[].
 *
 * With SHA2_ARMV8_X4 defined, it also has sha_compress_blocks_x4() for SHA-256,
 * which compresses four independent blocks at once (see slhdsa_sha2.h).
 */

#include <arm_neon.h>

#if WORD_SIZE == 4

/** Rounds 4g to 4g+3, with message words w = W[4g..4g+3] **/
#define ARMV8_ROUNDS(g, w) do { \
    uint32x4_t wk = vaddq_u32(w, vld1q_u32(&K[(g)*4])); \
    uint32x4_t abcd_prev = abcd; \
    abcd = vsha256hq_u32(abcd, efgh, wk); \
    efgh = vsha256h2q_u32(efgh, abcd_prev, wk); \
    } while (0)

/** With m0..m3 = W[t-16..t-1], replace m0 with W[t..t+3] **/
#define ARMV8_SCHEDULE(m0, m1, m2, m3) do { \
    m0 = vsha256su1q_u32(vsha256su0q_u32(m0, m1), m2, m3); \
    } while (0)

/**
 * Compress one block, already decoded into sixteen words,
 * with the SHA-256 instructions of the ARMv8 Cryptography Extensions.
 * h_out[] may be the same array as h_in[] or M[].
 */
static void sha_compress_words(const sha2_word_t h_in[8], sha2_word_t h_out[8], const sha2_word_t M[16])
{
    uint32x4_t abcd, efgh;
    uint32x4_t m0, m1, m2, m3;
    unsigned g;

    /** The instructions want the state as {A,B,C,D} and {E,F,G,H}, as in h_in[] **/
    abcd = vld1q_u32(&h_in[0]);
    efgh = vld1q_u32(&h_in[4]);

    /** m0..m3 are a rolling window of the last 16 words of the message schedule **/
    m0 = vld1q_u32(&M[0]);
    m1 = vld1q_u32(&M[4]);
    m2 = vld1q_u32(&M[8]);
    m3 = vld1q_u32(&M[12]);

    ARMV8_ROUNDS(0, m0);
    ARMV8_ROUNDS(1, m1);
    ARMV8_ROUNDS(2, m2);
    ARMV8_ROUNDS(3, m3);
    for (g=4; g<SCHEDULE_SIZE/4; g+=4) {
        ARMV8_SCHEDULE(m0, m1, m2, m3); ARMV8_ROUNDS(g,   m0);
        ARMV8_SCHEDULE(m1, m2, m3, m0); ARMV8_ROUNDS(g+1, m1);
        ARMV8_SCHEDULE(m2, m3, m0, m1); ARMV8_ROUNDS(g+2, m2);
        ARMV8_SCHEDULE(m3, m0, m1, m2); ARMV8_ROUNDS(g+3, m3);
    }

    vst1q_u32(&h_out[0], vaddq_u32(abcd, vld1q_u32(&h_in[0])));
    vst1q_u32(&h_out[4], vaddq_u32(efgh, vld1q_u32(&h_in[4])));
}

#ifdef SHA2_ARMV8_X4

/** ARMV8_ROUNDS() for the four blocks a, b, c and d, with message words m<x><p> **/
#define ARMV8_ROUNDS_X4(g, p) do { \
    uint32x4_t k4 = vld1q_u32(&K[(g)*4]); \
    uint32x4_t wka = vaddq_u32(ma##p, k4); \
    uint32x4_t wkb = vaddq_u32(mb##p, k4); \
    uint32x4_t wkc = vaddq_u32(mc##p, k4); \
    uint32x4_t wkd = vaddq_u32(md##p, k4); \
    uint32x4_t preva = abcda, prevb = abcdb, prevc = abcdc, prevd = abcdd; \
    abcda = vsha256hq_u32(abcda, efgha, wka); \
    abcdb = vsha256hq_u32(abcdb, efghb, wkb); \
    abcdc = vsha256hq_u32(abcdc, efghc, wkc); \
    abcdd = vsha256hq_u32(abcdd, efghd, wkd); \
    efgha = vsha256h2q_u32(efgha, preva, wka); \
    efghb = vsha256h2q_u32(efghb, prevb, wkb); \
    efghc = vsha256h2q_u32(efghc, prevc, wkc); \
    efghd = vsha256h2q_u32(efghd, prevd, wkd); \
    } while (0)

/** ARMV8_SCHEDULE() and ARMV8_ROUNDS_X4() for the next 4 rounds of a, b, c and d **/
#define ARMV8_STEP_X4(g, p0, p1, p2, p3) do { \
    ARMV8_SCHEDULE(ma##p0, ma##p1, ma##p2, ma##p3); \
    ARMV8_SCHEDULE(mb##p0, mb##p1, mb##p2, mb##p3); \
    ARMV8_SCHEDULE(mc##p0, mc##p1, mc##p2, mc##p3); \
    ARMV8_SCHEDULE(md##p0, md##p1, md##p2, md##p3); \
    ARMV8_ROUNDS_X4(g, p0); \
    } while (0)

/** Load the 4 big-endian words at p **/
#define ARMV8_LOAD_BE(p)    vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p)))

/**
 * Compress four independent blocks of 64 bytes at once (block[j] from
 * the state h_in[j] into h_out[j], which may be the same array).
 * Each round depends on the previous one: interleaving the rounds
 * of four blocks keeps the SHA-256 unit busy while each of them waits.
 */
static void sha_compress_blocks_x4(const sha2_word_t *h_in[4], sha2_word_t *h_out[4],
                                   const uint8_t *block[4])
{
    uint32x4_t abcda, efgha, ma0, ma1, ma2, ma3;
    uint32x4_t abcdb, efghb, mb0, mb1, mb2, mb3;
    uint32x4_t abcdc, efghc, mc0, mc1, mc2, mc3;
    uint32x4_t abcdd, efghd, md0, md1, md2, md3;

    abcda = vld1q_u32(&h_in[0][0]);
    efgha = vld1q_u32(&h_in[0][4]);
    abcdb = vld1q_u32(&h_in[1][0]);
    efghb = vld1q_u32(&h_in[1][4]);
    abcdc = vld1q_u32(&h_in[2][0]);
    efghc = vld1q_u32(&h_in[2][4]);
    abcdd = vld1q_u32(&h_in[3][0]);
    efghd = vld1q_u32(&h_in[3][4]);

    ma0 = ARMV8_LOAD_BE(block[0]);
    ma1 = ARMV8_LOAD_BE(block[0] + 16);
    ma2 = ARMV8_LOAD_BE(block[0] + 32);
    ma3 = ARMV8_LOAD_BE(block[0] + 48);
    mb0 = ARMV8_LOAD_BE(block[1]);
    mb1 = ARMV8_LOAD_BE(block[1] + 16);
    mb2 = ARMV8_LOAD_BE(block[1] + 32);
    mb3 = ARMV8_LOAD_BE(block[1] + 48);
    mc0 = ARMV8_LOAD_BE(block[2]);
    mc1 = ARMV8_LOAD_BE(block[2] + 16);
    mc2 = ARMV8_LOAD_BE(block[2] + 32);
    mc3 = ARMV8_LOAD_BE(block[2] + 48);
    md0 = ARMV8_LOAD_BE(block[3]);
    md1 = ARMV8_LOAD_BE(block[3] + 16);
    md2 = ARMV8_LOAD_BE(block[3] + 32);
    md3 = ARMV8_LOAD_BE(block[3] + 48);

    ARMV8_ROUNDS_X4( 0, 0);
    ARMV8_ROUNDS_X4( 1, 1);
    ARMV8_ROUNDS_X4( 2, 2);
    ARMV8_ROUNDS_X4( 3, 3);
    ARMV8_STEP_X4( 4, 0, 1, 2, 3);
    ARMV8_STEP_X4( 5, 1, 2, 3, 0);
    ARMV8_STEP_X4( 6, 2, 3, 0, 1);
    ARMV8_STEP_X4( 7, 3, 0, 1, 2);
    ARMV8_STEP_X4( 8, 0, 1, 2, 3);
    ARMV8_STEP_X4( 9, 1, 2, 3, 0);
    ARMV8_STEP_X4(10, 2, 3, 0, 1);
    ARMV8_STEP_X4(11, 3, 0, 1, 2);
    ARMV8_STEP_X4(12, 0, 1, 2, 3);
    ARMV8_STEP_X4(13, 1, 2, 3, 0);
    ARMV8_STEP_X4(14, 2, 3, 0, 1);
    ARMV8_STEP_X4(15, 3, 0, 1, 2);

    /* Read all of h_in[] before writing h_out[] */
    abcda = vaddq_u32(abcda, vld1q_u32(&h_in[0][0]));
    efgha = vaddq_u32(efgha, vld1q_u32(&h_in[0][4]));
    abcdb = vaddq_u32(abcdb, vld1q_u32(&h_in[1][0]));
    efghb = vaddq_u32(efghb, vld1q_u32(&h_in[1][4]));
    abcdc = vaddq_u32(abcdc, vld1q_u32(&h_in[2][0]));
    efghc = vaddq_u32(efghc, vld1q_u32(&h_in[2][4]));
    abcdd = vaddq_u32(abcdd, vld1q_u32(&h_in[3][0]));
    efghd = vaddq_u32(efghd, vld1q_u32(&h_in[3][4]));

    vst1q_u32(&h_out[0][0], abcda);
    vst1q_u32(&h_out[0][4], efgha);
    vst1q_u32(&h_out[1][0], abcdb);
    vst1q_u32(&h_out[1][4], efghb);
    vst1q_u32(&h_out[2][0], abcdc);
    vst1q_u32(&h_out[2][4], efghc);
    vst1q_u32(&h_out[3][0], abcdd);
    vst1q_u32(&h_out[3][4], efghd);
}

#endif /* SHA2_ARMV8_X4 */

#elif WORD_SIZE == 8

/**
 * Rounds 2g and 2g+1, with message words w = W[2g..2g+1].
 *
 * SHA512H returns T1 of both rounds (the sum without A..D), from:
 * - H + K[2g] + W[2g] (high lane) and G + K[2g+1] + W[2g+1] (low lane)
 * - {F,G} and {D,E} (low lane first)
 * SHA512H2 returns the new A of both rounds, from T1, {C,D} and {A,B}.
 * After the two rounds, the new {E,F} is {C,D} plus T1, and
 * {A,B}, {C,D} and {E,F} move to {C,D}, {E,F} and {G,H}.
 */
#define ARMV8_ROUNDS(g, w) do { \
    uint64x2_t wk = vaddq_u64(w, vld1q_u64(&K[(g)*2])); \
    uint64x2_t t1, a_new; \
    wk = vaddq_u64(vextq_u64(wk, wk, 1), gh); \
    t1 = vsha512hq_u64(wk, vextq_u64(ef, gh, 1), vextq_u64(cd, ef, 1)); \
    a_new = vsha512h2q_u64(t1, cd, ab); \
    gh = ef; \
    ef = vaddq_u64(cd, t1); \
    cd = ab; \
    ab = a_new; \
    } while (0)

/** With m0..m7 = W[t-16..t-1], replace m0 with W[t..t+1] **/
#define ARMV8_SCHEDULE(m0, m1, m4, m5, m7) do { \
    m0 = vsha512su1q_u64(vsha512su0q_u64(m0, m1), m7, vextq_u64(m4, m5, 1)); \
    } while (0)

/**
 * Compress one block, already decoded into sixteen words,
 * with the SHA-512 instructions of the ARMv8 Cryptography Extensions.
 * h_out[] may be the same array as h_in[] or M[].
 */
static void sha_compress_words(const sha2_word_t h_in[8], sha2_word_t h_out[8], const sha2_word_t M[16])
{
    uint64x2_t ab, cd, ef, gh;
    uint64x2_t m0, m1, m2, m3, m4, m5, m6, m7;
    unsigned g;

    /** The state as {A,B}, {C,D}, {E,F} and {G,H} (low lane first) **/
    ab = vld1q_u64(&h_in[0]);
    cd = vld1q_u64(&h_in[2]);
    ef = vld1q_u64(&h_in[4]);
    gh = vld1q_u64(&h_in[6]);

    /** m0..m7 are a rolling window of the last 16 words of the message schedule **/
    m0 = vld1q_u64(&M[0]);
    m1 = vld1q_u64(&M[2]);
    m2 = vld1q_u64(&M[4]);
    m3 = vld1q_u64(&M[6]);
    m4 = vld1q_u64(&M[8]);
    m5 = vld1q_u64(&M[10]);
    m6 = vld1q_u64(&M[12]);
    m7 = vld1q_u64(&M[14]);

    ARMV8_ROUNDS(0, m0);
    ARMV8_ROUNDS(1, m1);
    ARMV8_ROUNDS(2, m2);
    ARMV8_ROUNDS(3, m3);
    ARMV8_ROUNDS(4, m4);
    ARMV8_ROUNDS(5, m5);
    ARMV8_ROUNDS(6, m6);
    ARMV8_ROUNDS(7, m7);
    for (g=8; g<SCHEDULE_SIZE/2; g+=8) {
        ARMV8_SCHEDULE(m0, m1, m4, m5, m7); ARMV8_ROUNDS(g,   m0);
        ARMV8_SCHEDULE(m1, m2, m5, m6, m0); ARMV8_ROUNDS(g+1, m1);
        ARMV8_SCHEDULE(m2, m3, m6, m7, m1); ARMV8_ROUNDS(g+2, m2);
        ARMV8_SCHEDULE(m3, m4, m7, m0, m2); ARMV8_ROUNDS(g+3, m3);
        ARMV8_SCHEDULE(m4, m5, m0, m1, m3); ARMV8_ROUNDS(g+4, m4);
        ARMV8_SCHEDULE(m5, m6, m1, m2, m4); ARMV8_ROUNDS(g+5, m5);
        ARMV8_SCHEDULE(m6, m7, m2, m3, m5); ARMV8_ROUNDS(g+6, m6);
        ARMV8_SCHEDULE(m7, m0, m3, m4, m6); ARMV8_ROUNDS(g+7, m7);
    }

    vst1q_u64(&h_out[0], vaddq_u64(ab, vld1q_u64(&h_in[0])));
    vst1q_u64(&h_out[2], vaddq_u64(cd, vld1q_u64(&h_in[2])));
    vst1q_u64(&h_out[4], vaddq_u64(ef, vld1q_u64(&h_in[4])));
    vst1q_u64(&h_out[6], vaddq_u64(gh, vld1q_u64(&h_in[6])));
}

#endif /** WORD_SIZE **/
