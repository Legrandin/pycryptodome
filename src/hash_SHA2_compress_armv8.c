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
