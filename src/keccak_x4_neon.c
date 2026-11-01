/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Four independent Keccak-p[1600] states, permuted at the same time
 * on 64-bit ARM (AArch64): two states with the general-purpose registers
 * and the other two with NEON, which is always available on AArch64.
 *
 * Why both: on a core like Neoverse-V1 (AWS Graviton3), NEON alone is not
 * faster than scalar code, even with two states per register
 * (and also with the EOR3/BCAX/XAR/RAX1 instructions of ARMv8.2 SHA3,
 * which have a low throughput), but the integer and the NEON pipelines
 * work in parallel: mixing a scalar and a NEON instruction stream
 * permutes 4 states in about the time of 2 scalar ones (on Graviton3).
 *
 * This relies on a wide out-of-order core. On a simple in-order core,
 * the two instruction streams compete for the same issue slots instead
 * of overlapping, and the 4-way code can be SLOWER than 4 calls to the
 * scalar keccak_function(). On a Raspberry Pi 3 (Cortex-A53), K12 over
 * 4 MiB was 10% slower with gcc 10 and 17% slower with clang 21
 * (5% faster with gcc 15). Cortex-A55 and similar in-order cores
 * probably behave the same way (not measured).
 * Today the code is always used on AArch64 (it is chosen at compile time):
 * a better approach would be to also build the scalar-only version and
 * select one at runtime from the CPU type (e.g. MIDR_EL1).
 *
 * Since a NEON round takes about the time of two scalar rounds, the
 * permutation runs in two passes, each one with all the rounds of
 * one scalar state and half the rounds of the two NEON states
 * (with the steps of the two kinds of rounds interleaved in the code):
 *
 *   pass 0:  state 0 (scalar), rounds 0..R-1   states 2+3 (NEON), rounds 0..R/2-1
 *   pass 1:  state 1 (scalar), rounds 0..R-1   states 2+3 (NEON), rounds R/2..R-1
 *
 * This way, only one scalar state is in the 31 general-purpose registers,
 * and the NEON state (two states, one per 64-bit half) stays in 25 of
 * the 32 vector registers.
 *
 * The 4 states are 4 consecutive arrays of 25 words: lane (x, y) of
 * state j is state[25*j + x + 5*y], the same layout as 4 separate calls
 * to keccak_function().
 *
 * This file is not a module: it must be included after keccak.c,
 * whose round constants it uses.
 *
 * See KECCAK_K12.txt for which file includes which, and the resulting modules.
 */

#include <arm_neon.h>

/*
 * One round of Keccak-p[1600] from the lanes a0..a24 to e0..e24 is
 * THETA, then PLANE_0 to PLANE_4, as in keccak_function(): the 5 lanes
 * of each output plane go through Theta, Rho and Pi, and then Chi,
 * before the next plane.
 *
 * The macros are used for scalar (uint64_t) and NEON (uint64x2_t) lanes:
 * the prefix p (s or v) selects both the variables (sa0, ..., or va0, ...)
 * and the operations: pXOR, pROL (rotation to the left by a constant,
 * 1 to 63 bits), pANDN (~x & y) and pRC (the round constant as a lane).
 */

/* Theta: the parities of the columns (c), and what each column gets (d) */
#define THETA(p, a)                                                         \
    do {                                                                    \
        p##c0 = p##XOR(p##XOR(p##XOR(p##a##0, p##a##5), p##XOR(p##a##10, p##a##15)), p##a##20); \
        p##c1 = p##XOR(p##XOR(p##XOR(p##a##1, p##a##6), p##XOR(p##a##11, p##a##16)), p##a##21); \
        p##c2 = p##XOR(p##XOR(p##XOR(p##a##2, p##a##7), p##XOR(p##a##12, p##a##17)), p##a##22); \
        p##c3 = p##XOR(p##XOR(p##XOR(p##a##3, p##a##8), p##XOR(p##a##13, p##a##18)), p##a##23); \
        p##c4 = p##XOR(p##XOR(p##XOR(p##a##4, p##a##9), p##XOR(p##a##14, p##a##19)), p##a##24); \
        p##d0 = p##XOR(p##c4, p##ROL(p##c1, 1));                            \
        p##d1 = p##XOR(p##c0, p##ROL(p##c2, 1));                            \
        p##d2 = p##XOR(p##c1, p##ROL(p##c3, 1));                            \
        p##d3 = p##XOR(p##c2, p##ROL(p##c4, 1));                            \
        p##d4 = p##XOR(p##c3, p##ROL(p##c0, 1));                            \
    } while (0)

/* Chi on b0..b4, into the lanes o0..o4 of e */
#define CHI(p, e, o0, o1, o2, o3, o4)                                       \
    do {                                                                    \
        p##e##o0 = p##XOR(p##b0, p##ANDN(p##b1, p##b2));                    \
        p##e##o1 = p##XOR(p##b1, p##ANDN(p##b2, p##b3));                    \
        p##e##o2 = p##XOR(p##b2, p##ANDN(p##b3, p##b4));                    \
        p##e##o3 = p##XOR(p##b3, p##ANDN(p##b4, p##b0));                    \
        p##e##o4 = p##XOR(p##b4, p##ANDN(p##b0, p##b1));                    \
    } while (0)

/*
 * Theta, Rho and Pi for the 5 lanes that move to one output plane
 * (the lanes o0..o4 of e), then Chi: b0 is lane i0 of a, XOR-ed with
 * d##j0 and rotated by r0 bits; and so on for b1..b4.
 */
#define PLANE(p, a, e, o0, o1, o2, o3, o4, i0, j0, r0, i1, j1, r1,          \
              i2, j2, r2, i3, j3, r3, i4, j4, r4)                           \
    do {                                                                    \
        p##b0 = p##ROL(p##XOR(p##a##i0, p##d##j0), r0);                     \
        p##b1 = p##ROL(p##XOR(p##a##i1, p##d##j1), r1);                     \
        p##b2 = p##ROL(p##XOR(p##a##i2, p##d##j2), r2);                     \
        p##b3 = p##ROL(p##XOR(p##a##i3, p##d##j3), r3);                     \
        p##b4 = p##ROL(p##XOR(p##a##i4, p##d##j4), r4);                     \
        CHI(p, e, o0, o1, o2, o3, o4);                                      \
    } while (0)

/* Plane 0 has the lane that is not rotated (a0), and gets Iota */
#define PLANE_0(p, a, e, rc)                                                \
    do {                                                                    \
        p##b0 = p##XOR(p##a##0, p##d0);                                     \
        p##b1 = p##ROL(p##XOR(p##a##6, p##d1), 44);                         \
        p##b2 = p##ROL(p##XOR(p##a##12, p##d2), 43);                        \
        p##b3 = p##ROL(p##XOR(p##a##18, p##d3), 21);                        \
        p##b4 = p##ROL(p##XOR(p##a##24, p##d4), 14);                        \
        CHI(p, e, 0, 1, 2, 3, 4);                                           \
        p##e##0 = p##XOR(p##e##0, p##RC(rc));                               \
    } while (0)

#define PLANE_1(p, a, e)                                                    \
    PLANE(p, a, e,  5,  6,  7,  8,  9,   3, 3, 28,   9, 4, 20,  10, 0,  3,  16, 1, 45,  22, 2, 61)
#define PLANE_2(p, a, e)                                                    \
    PLANE(p, a, e, 10, 11, 12, 13, 14,   1, 1,  1,   7, 2,  6,  13, 3, 25,  19, 4,  8,  20, 0, 18)
#define PLANE_3(p, a, e)                                                    \
    PLANE(p, a, e, 15, 16, 17, 18, 19,   4, 4, 27,   5, 0, 36,  11, 1, 10,  17, 2, 15,  23, 3, 56)
#define PLANE_4(p, a, e)                                                    \
    PLANE(p, a, e, 20, 21, 22, 23, 24,   2, 2, 62,   8, 3, 55,  14, 4, 39,  15, 0, 41,  21, 1,  2)

/* Operations on scalar lanes */
#define sXOR(x, y)      ((x) ^ (y))
#define sROL(x, n)      ROL64(x, n)
#define sANDN(x, y)     (~(x) & (y))
#define sRC(rc)         (rc)

/* Operations on NEON lanes (two states at a time) */
#define vXOR(x, y)      veorq_u64(x, y)
#define vROL(x, n)      vsriq_n_u64(vshlq_n_u64(x, n), x, 64 - (n))
#define vANDN(x, y)     vbicq_u64(y, x)
#define vRC(rc)         vdupq_n_u64(rc)

/* Declare the 25 lanes of a state */
#define DECLARE_LANES(T, p, a)                                              \
    T p##a##0, p##a##1, p##a##2, p##a##3, p##a##4, p##a##5, p##a##6,        \
      p##a##7, p##a##8, p##a##9, p##a##10, p##a##11, p##a##12, p##a##13,    \
      p##a##14, p##a##15, p##a##16, p##a##17, p##a##18, p##a##19,           \
      p##a##20, p##a##21, p##a##22, p##a##23, p##a##24

/* Apply op(lane variable, index) to the 25 lanes */
#define FOR_EACH_LANE(op, p, a)                                             \
    do {                                                                    \
        op(p##a##0, 0);   op(p##a##1, 1);   op(p##a##2, 2);                 \
        op(p##a##3, 3);   op(p##a##4, 4);   op(p##a##5, 5);                 \
        op(p##a##6, 6);   op(p##a##7, 7);   op(p##a##8, 8);                 \
        op(p##a##9, 9);   op(p##a##10, 10); op(p##a##11, 11);               \
        op(p##a##12, 12); op(p##a##13, 13); op(p##a##14, 14);               \
        op(p##a##15, 15); op(p##a##16, 16); op(p##a##17, 17);               \
        op(p##a##18, 18); op(p##a##19, 19); op(p##a##20, 20);               \
        op(p##a##21, 21); op(p##a##22, 22); op(p##a##23, 23);               \
        op(p##a##24, 24);                                                   \
    } while (0)

/*
 * The Keccak-p[1600, rounds] permutation on the 4 states in state[100]
 * (state j is state[25*j] to state[25*j + 24]), for 24 or 12 rounds:
 * the number of rounds must be a multiple of 4.
 */
static void keccak_function_x4(uint64_t *state, unsigned rounds)
{
    DECLARE_LANES(uint64_t, s, a);
    DECLARE_LANES(uint64_t, s, e);
    DECLARE_LANES(uint64x2_t, v, a);
    DECLARE_LANES(uint64x2_t, v, e);
    uint64_t sb0, sb1, sb2, sb3, sb4, sc0, sc1, sc2, sc3, sc4, sd0, sd1, sd2, sd3, sd4;
    uint64x2_t vb0, vb1, vb2, vb3, vb4, vc0, vc1, vc2, vc3, vc4, vd0, vd1, vd2, vd3, vd4;
    const uint64_t *rc = roundconstants + KECCAK_ROUNDS - rounds;
    const uint64_t *vrc;
    uint64_t *s;
    unsigned pass, i;

    /* Lane i of state 2 in the low half, of state 3 in the high half */
#define LOAD_V(lane, i)   lane = vcombine_u64(vld1_u64(state + 50 + (i)), vld1_u64(state + 75 + (i)))
#define LOAD_S(lane, i)   lane = s[i]
#define STORE_V(lane, i)  do { vst1_u64(state + 50 + (i), vget_low_u64(lane)); \
                               vst1_u64(state + 75 + (i), vget_high_u64(lane)); } while (0)
#define STORE_S(lane, i)  s[i] = lane

    FOR_EACH_LANE(LOAD_V, v, a);

    for (pass = 0; pass < 2; pass++) {
        s = state + 25*pass;
        vrc = rc + pass*(rounds/2);
        FOR_EACH_LANE(LOAD_S, s, a);

        /*
         * 4 rounds of the scalar state and 2 rounds of the NEON state,
         * with their steps interleaved: one NEON step every two scalar steps
         */
        for (i = 0; i < rounds; i += 4) {
            THETA(s, a);         THETA(v, a);
            PLANE_0(s, a, e, rc[i]);
            PLANE_1(s, a, e);    PLANE_0(v, a, e, vrc[i/2]);
            PLANE_2(s, a, e);
            PLANE_3(s, a, e);    PLANE_1(v, a, e);
            PLANE_4(s, a, e);
            THETA(s, e);         PLANE_2(v, a, e);
            PLANE_0(s, e, a, rc[i + 1]);
            PLANE_1(s, e, a);    PLANE_3(v, a, e);
            PLANE_2(s, e, a);
            PLANE_3(s, e, a);    PLANE_4(v, a, e);
            PLANE_4(s, e, a);

            THETA(s, a);         THETA(v, e);
            PLANE_0(s, a, e, rc[i + 2]);
            PLANE_1(s, a, e);    PLANE_0(v, e, a, vrc[i/2 + 1]);
            PLANE_2(s, a, e);
            PLANE_3(s, a, e);    PLANE_1(v, e, a);
            PLANE_4(s, a, e);
            THETA(s, e);         PLANE_2(v, e, a);
            PLANE_0(s, e, a, rc[i + 3]);
            PLANE_1(s, e, a);    PLANE_3(v, e, a);
            PLANE_2(s, e, a);
            PLANE_3(s, e, a);    PLANE_4(v, e, a);
            PLANE_4(s, e, a);
        }

        FOR_EACH_LANE(STORE_S, s, a);
    }

    FOR_EACH_LANE(STORE_V, v, a);

#undef LOAD_V
#undef LOAD_S
#undef STORE_V
#undef STORE_S
}

/* The files that include this one (pq_fips202.h) do not need these macros */
#undef THETA
#undef CHI
#undef PLANE
#undef PLANE_0
#undef PLANE_1
#undef PLANE_2
#undef PLANE_3
#undef PLANE_4
#undef sXOR
#undef sROL
#undef sANDN
#undef sRC
#undef vXOR
#undef vROL
#undef vANDN
#undef vRC
#undef DECLARE_LANES
#undef FOR_EACH_LANE

/*
 * XOR n 64-bit words (n <= 25) into each of the 4 states.
 *
 * in[j] is the input for state j: it points to at least 8*n bytes
 * (with any alignment), read as n little-endian 64-bit words.
 * Word i of in[j] is XOR-ed into lane i of state j.
 */
static void keccak_absorb_x4(uint64_t state[100], const uint8_t *in[4], unsigned n)
{
    unsigned i, j;

    for (j=0; j<4; j++) {
        for (i=0; i<n; i++) {
            state[25*j + i] ^= LOAD_U64_LITTLE(in[j] + 8*i);
        }
    }
}

/*
 * Write the first n 64-bit words (n <= 25) of each of the 4 states.
 *
 * out[j] is the output for state j: it points to at least 8*n bytes
 * (with any alignment), written as n little-endian 64-bit words.
 * Lane i of state j is written into word i of out[j].
 */
static void keccak_extract_x4(const uint64_t state[100], uint8_t *out[4], unsigned n)
{
    unsigned i, j;

    for (j=0; j<4; j++) {
        for (i=0; i<n; i++) {
            STORE_U64_LITTLE(out[j] + 8*i, state[25*j + i]);
        }
    }
}

/* XOR the word w into lane i of each of the 4 states */
static inline void keccak_xor_lane_x4(uint64_t state[100], unsigned i, uint64_t w)
{
    unsigned j;

    for (j=0; j<4; j++) {
        state[25*j + i] ^= w;
    }
}
