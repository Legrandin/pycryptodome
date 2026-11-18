/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * AEGIS-128L and AEGIS-256 (RFC 10032), for CPUs without AES instructions.
 *
 * The AES round is bitsliced (constant time, no table lookups), as described in
 * F. Denis, "Bitslicing the AEGIS", ePrint 2026/1338, with the barrel-shiftrows
 * layout of A. Adomnicai and T. Peyrin ("Fixslicing AES-like Ciphers", TCHES 2021):
 * 8 blocks are processed together, and each AES row has its own 32-bit words,
 * in which ShiftRows is a rotation.
 *
 * The terms of this file, aegis_simd.c and aegis_scalar.c:
 *
 *  - block: a 16-byte AES block (a state block S[i], or a message block);
 *
 *  - row r and column c: the AES layout of a block, with byte 4c + r
 *    in row r and column c;
 *
 *  - vector: a 128-bit value of a NEON register (Q or V) or of an SSE2 register
 *    (XMM), made of four 32-bit elements (which are not lanes);
 *
 *  - word: a value of the bitsliced form (type word), which holds one bit (k)
 *    of the bytes of 8 blocks (128 bytes in total). Each byte of a word has
 *    exactly one bit from each block, and each 32-bit part of a word holds
 *    one whole row (with NEON or SSE2, a word is a vector, and its element r
 *    is row r):
 *
 *                Word size   Words for   Held in           Rows per word
 *                            8 blocks
 *    =============================================================================
 *      NEON      128 bits       8        Q or V register   4 (elements)
 *      SSE2      128 bits       8        XMM register      4 (elements)
 *      Scalar     64 bits      16        64-bit integer    2 (halves)
 *
 *  - lane b: bit b of all the bytes of any word, contributed by block b (0..7).
 *
 *    Each byte in a word maps to a certain row(0..3)/column(0..3) across all
 *    blocks.
 *
 *    Take for instance byte j (j=0..15) of the 128-bit SIMD word k (k=0..7).
 *    Byte j will contain 8 bits, one from each of 8 blocks (bit b from block b).
 *    All bits in that byte map to row j/4 and column j%4 of each block.
 *    All bits in that byte will be bit k in row j/4 and column j%4.
 *
 *    For non-SIMD, take byte j (j=0..7) of the 64-bit word n (n=0..15).
 *    Byte j will again contain 8 bits, one from each of 8 blocks.
 *    The mapping of AES blocks rows to words follows the rule:
 *    - Word k of the first half of the words contains bit k for the even AES rows
 *      (row 0 in bytes 0..3, row 2 in bytes 4..7)
 *    - Word k of the second half of the words contains bit k for the odd AES rows
 *      (row 1 in bytes 0..3, row 3 in bytes 4..7)
 *    - Within a word, byte j refers to column j%4 (each column is referred to
 *      twice, since a word contains two 32-bit parts).
 *
 *    No operation moves a bit to another byte on its own (only whole bytes
 *    move), so the bits of a byte always come from the same position of the
 *    8 blocks. (The rows and columns above are those before ShiftRows, which
 *    moves whole bytes within each row.)
 *
 *    For AEGIS-256, which has 6 state blocks, lanes 6 and 7 of the state are not used.
 *
 * With NEON or SSE2, a 128-bit vector holds the four rows of a bit (Section 6.2
 * of the paper). The state is kept as plain blocks: each update converts its 8
 * blocks (6 for AEGIS-256) to the bitsliced form and back, so that only 8 vectors
 * are live in the round, and the keystream is a few XORs (aegis_simd.c).
 * Otherwise, a 64-bit word holds two rows (0 and 2, or 1 and 3), the state stays
 * bitsliced (the rotation of the blocks in an update is a rotation of each byte),
 * the keystream is computed in that form, and the input blocks are converted
 * 8 at a time (aegis_scalar.c).
 *
 * The S-box is the smallest circuit of A. Maximov and P. Ekdahl (TCHES 2019).
 */

#include <string.h>
#include "common.h"
#include "endianess.h"
#include "aegis.h"

FAKE_INIT(raw_aegis)

#define AEGIS_PREFIX AEGIS_

/*
 * A word holds bit k of the bytes of 8 blocks: lane b (bit b of each byte) is
 * from block b, and each 32-bit part holds one row, with byte c from column c.
 * With NEON or SSE2, a word is a 128-bit vector with the 4 rows (row r in
 * element r); otherwise, it is a 64-bit integer with 2 rows (0 and 2, or 1 and 3).
 */
#if (defined(__aarch64__) || defined(__ARM_NEON)) && defined(__GNUC__) && !defined(__ARM_BIG_ENDIAN)
#define AEGIS_NEON
#define AEGIS_SIMD
#include <arm_neon.h>
typedef uint64_t word __attribute__((vector_size(16)));
#elif defined(USE_SSE2)
#if !defined(__SSE2__) && !defined(_M_X64) && !(defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#error "USE_SSE2 is defined, but the compiler does not target SSE2 (add -msse2)"
#endif
#define AEGIS_SSE2
#define AEGIS_SIMD
#if defined(HAVE_INTRIN_H)
#include <intrin.h>
#elif defined(HAVE_X86INTRIN_H)
#include <x86intrin.h>
#elif defined(HAVE_EMMINTRIN_H)
#include <xmmintrin.h>
#include <emmintrin.h>
#endif
#include "sse2_unaligned.h"
typedef __m128i word;
#else
typedef uint64_t word;
#endif

/* Inline the functions of an update, so that the state stays in the registers */
#if defined(__GNUC__)
#define HOT static inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define HOT static __forceinline
#else
#define HOT static inline
#endif

/* Fully unroll a short loop, so that an in-order CPU can interleave the iterations */
#if defined(__GNUC__)
#define UNROLL  _Pragma("GCC unroll 16")
#else
#define UNROLL
#endif

/*
 * The layout of the bitsliced form: aegis_simd.c (NEON or SSE2) or aegis_scalar.c
 * (64-bit words).
 *
 * Each file first defines the operations on words, which the functions below
 * (the S-box, bit_stage() and mix_xtime()) use: XOR, AND, OR,
 * NOT, ANDN(a, b) is a & ~b, MUX(s, a, b) is s ? a : b,
 * XMUX(s, a, b) is s ? ~a : b, SHL and SHR shift the 64-bit integers
 * (both halves of a vector), and MASK(c) has the 32-bit constant c in every 32-bit part.
 *
 * Then it defines aes_block with blk_load(), blk_store() and blk_xor(), and
 * bitslice_aes_round() on its own layout, which calls the functions below:
 *  - aegis_simd.c also defines blk_and() and aes_rounds(): aegis.c then keeps
 *    the state as plain blocks (generic core);
 *  - aegis_scalar.c instead defines AEGIS_CORE: the state (aegis_core) stays
 *    bitsliced, with its own core_load(), core_store(), core_absorb(),
 *    core_keystream() and core_crypt().
 */
HOT void bitslice_Sbox(word bit[8]);
HOT void bit_stage(word x[8]);
HOT void mix_xtime(word bit[8], const word d[8]);

#ifdef AEGIS_SIMD
#include "aegis_simd.c"
#else
#include "aegis_scalar.c"
#endif

/*
 * The AES S-box on the 8 bits of the bytes (bit[k] holds bit k), with the circuit
 * of 102 gates of A. Maximov and P. Ekdahl, "New Circuit Minimization Techniques
 * for Smaller and Faster AES SBoxes", TCHES 2019(4), Appendix D.5 (Listing 7).
 * U0 and R0 are the most significant bits. The NOTs of the NAND, NOR, XNOR and
 * MUX gates of the circuit are moved into the following gates (AND to OR, AND
 * to ANDN, MUX to XMUX), which leaves 4 NOTs.
 */
HOT void bitslice_Sbox(word bit[8])
{
    const word U0 = bit[7];
    const word U1 = bit[6];
    const word U2 = bit[5];
    const word U3 = bit[4];
    const word U4 = bit[3];
    const word U5 = bit[2];
    const word U6 = bit[1];
    const word U7 = bit[0];

    /* Top linear layer */
    const word Z24 = XOR(U3, U4);
    const word Q17 = XOR(U1, U7);
    const word Q16 = XOR(U5, Q17);
    const word Q0 = XOR(Z24, Q16);
    const word Z66 = XOR(U1, U6);
    const word Q7 = XOR(Z24, Z66);
    const word Q2 = XOR(U2, Q0);
    const word Q1 = XOR(Q7, Q2);
    const word Q3 = XOR(U0, Q7);
    const word Q4 = XOR(U0, Q2);
    const word Q5 = XOR(U1, Q4);
    const word Q6 = XOR(U2, U3);
    const word Q10 = XOR(Q6, Q7);
    const word Q8 = XOR(U0, Q10);
    const word Q9 = XOR(Q8, Q2);
    const word Q12 = XOR(Z24, Q17);
    const word Q15 = XOR(U7, Q4);
    const word Q13 = XOR(Z24, Q15);
    const word Q14 = XOR(Q15, Q0);

    /* Inversion in GF(2^4) */
    const word T20 = AND(Q6, Q12);
    const word T21 = AND(Q3, Q14);
    const word T22 = AND(Q1, Q16);
    const word T10 = XOR(OR(Q3, Q14), AND(Q0, Q7));
    const word T11 = XOR(OR(Q4, Q13), AND(Q10, U5));
    const word T12 = XOR(OR(Q2, Q17), AND(Q5, Q9));
    const word T13 = XOR(OR(Q8, Q15), AND(Q2, Q17));
    const word X0 = XOR(T10, XOR(T20, T22));
    const word X1 = XOR(T11, XOR(T21, T20));
    const word X2 = XOR(T12, XOR(T21, T22));
    const word X3 = XOR(T13, XOR(T21, AND(Q4, Q13)));
    const word T0 = AND(X0, X2);
    const word T1 = OR(X1, X3);
    const word T2 = XOR(T0, T1);
    const word Y0 = XMUX(X2, T2, X3);
    const word Y2 = XMUX(X0, T2, X1);
    const word T3 = ANDN(X1, X2);
    const word Y1 = XMUX(T2, T3, X3);
    const word T4 = ANDN(X3, X0);
    const word Y3 = XMUX(T2, T4, X1);
    const word Y02 = XOR(Y2, Y0);
    const word Y13 = XOR(Y3, Y1);
    const word Y23 = XOR(Y3, Y2);
    const word Y01 = XOR(Y1, Y0);
    const word Y00 = XOR(Y02, Y13);

    /* Multiplications */
    const word N0 = AND(Y01, U5);
    const word N1 = AND(Y0, Q12);
    const word N2 = AND(Y1, Q0);
    const word N3 = AND(Y23, Q17);
    const word N4 = AND(Y2, Q5);
    const word N5 = AND(Y3, Q15);
    const word N6 = AND(Y13, Q14);
    const word N7 = AND(Y00, Q16);
    const word N8 = AND(Y02, Q13);
    const word N9 = AND(Y01, Q7);
    const word N10 = AND(Y0, Q10);
    const word N11 = AND(Y1, Q6);
    const word N12 = AND(Y23, Q2);
    const word N13 = AND(Y2, Q9);
    const word N14 = AND(Y3, Q8);
    const word N15 = AND(Y13, Q3);
    const word N16 = AND(Y00, Q1);
    const word N17 = AND(Y02, Q4);

    /* Bottom linear layer, with the affine constant */
    const word H0 = XOR(N1, N5);
    const word H1 = XOR(N4, H0);
    const word R2 = XOR(N2, H1);
    const word H2 = XOR(N9, N15);
    const word H3 = XOR(N11, N17);
    const word R6 = XOR(H2, H3);
    const word H4 = XOR(N11, N14);
    const word H5 = XOR(N9, N12);
    const word R5 = XOR(H4, H5);
    const word H6 = XOR(N16, H2);
    const word H7 = XOR(R2, R6);
    const word H8 = XOR(N10, H7);
    const word R7 = XOR(H6, H8);
    const word H9 = XOR(N8, H1);
    const word H10 = XOR(N13, H8);
    const word R3 = XOR(H5, H10);
    const word H11 = XOR(H9, H10);
    const word H12 = XOR(N7, H11);
    const word H13 = XOR(H4, H12);
    const word R4 = XOR(N1, H13);
    const word H14 = XOR(N0, R7);
    const word H15 = XOR(H9, H14);
    const word H16 = XOR(H7, H15);
    const word R1 = XOR(N6, H16);
    const word H17 = XOR(N4, H14);
    const word H18 = XOR(N3, H17);
    const word R0 = XOR(H13, H18);

    bit[7] = R0;
    bit[6] = NOT(R1);
    bit[5] = NOT(R2);
    bit[4] = R3;
    bit[3] = R4;
    bit[2] = R5;
    bit[1] = NOT(R6);
    bit[0] = NOT(R7);
}

/*
 * Exchange the bits of a in mask << n with the bits of b in mask:
 * bit i + n of a and bit i of b, for each bit i set in MASK(mask).
 * t_ has the bits where the two differ, so XORing it into both swaps them
 * (the bits outside the masks are unchanged). The shifts are on 64-bit integers,
 * so the mask must also clear the bits that a >> n brings across a byte.
 */
#define SWAPMOVE(a, b, mask, n) do {                            \
        word t_ = AND(XOR(b, SHR(a, n)), MASK(mask));           \
        b = XOR(b, t_);                                         \
        a = XOR(a, SHL(t_, n));                                 \
    } while (0)

/*
 * Convert 8 blocks to the bitsliced form, and back (it is its own inverse).
 * The input has the AES row form, for all 8 blocks.
 * The output will have the SIMD bitsliced form, for all 8 bits.
 *
 * For each byte position j, the bytes j of the 8 words are an 8x8 bit matrix,
 * which is transposed: bit b of byte j of x[k] becomes bit k of byte j of x[b].
 * Before, x[b] is block b (with its bytes already in place); after, x[k] holds
 * bit k of the bytes, with lane b from block b.
 * Bytes do not move: the three stages swap the 4x4, 2x2 and 1x1 sub-matrices
 * (words j and j + 4, j + 2, j + 1), with masks repeated in every byte.
 */
HOT void bit_stage(word x[8])
{
    unsigned j;

    /* Together, the 3 stages transpose an 8x8 matrix */

    /*
    For a byte position (row, column), take the 8 bytes
    at that position in x[0] … x[7].
    Bit b of the byte in x[w] is entry (w, b) of the matrix:
    one row per word, one column per bit.
    The goal is to move entry (w, b) to (b, w).

    In the trace below, each entry is labelled wb, its word and bit
    before the transpose. So 47 started as bit 7 of x[4].
    Bits are shown 0 to 7 from left to right.

    before                                      after stage 1
          bit: 0  1  2  3  4  5  6  7                 bit: 0  1  2  3  4  5  6  7
       x[0]:  00 01 02 03 04 05 06 07              x[0]:  00 01 02 03 40 41 42 43
       x[1]:  10 11 12 13 14 15 16 17              x[1]:  10 11 12 13 50 51 52 53
       x[2]:  20 21 22 23 24 25 26 27              x[2]:  20 21 22 23 60 61 62 63
       x[3]:  30 31 32 33 34 35 36 37              x[3]:  30 31 32 33 70 71 72 73
       x[4]:  40 41 42 43 44 45 46 47              x[4]:  04 05 06 07 44 45 46 47
       x[5]:  50 51 52 53 54 55 56 57              x[5]:  14 15 16 17 54 55 56 57
       x[6]:  60 61 62 63 64 65 66 67              x[6]:  24 25 26 27 64 65 66 67
       x[7]:  70 71 72 73 74 75 76 77              x[7]:  34 35 36 37 74 75 76 77

    after stage 2                               after stage 3
          bit: 0  1  2  3  4  5  6  7                 bit: 0  1  2  3  4  5  6  7
       x[0]:  00 01 20 21 40 41 60 61              x[0]:  00 10 20 30 40 50 60 70
       x[1]:  10 11 30 31 50 51 70 71              x[1]:  01 11 21 31 41 51 61 71
       x[2]:  02 03 22 23 42 43 62 63              x[2]:  02 12 22 32 42 52 62 72
       x[3]:  12 13 32 33 52 53 72 73              x[3]:  03 13 23 33 43 53 63 73
       x[4]:  04 05 24 25 44 45 64 65              x[4]:  04 14 24 34 44 54 64 74
       x[5]:  14 15 34 35 54 55 74 75              x[5]:  05 15 25 35 45 55 65 75
       x[6]:  06 07 26 27 46 47 66 67              x[6]:  06 16 26 36 46 56 66 76
       x[7]:  16 17 36 37 56 57 76 77              x[7]:  07 17 27 37 47 57 67 77

    At the end, x[k] holds bit k of every original word: x[1] = 01 11 21 … 71.
    Before, x[b] was block b.
    After, x[k] is bit k of all the blocks, with lane b from block b.
    */

    /* Stage 1: swaps the 4×4 sub-matrices */
    /* (0,4), (1,5), (2,6), (3,7) */
    UNROLL
    for (j = 0; j < 4; j++)
        SWAPMOVE(x[j], x[j + 4], 0x0F0F0F0F, 4);
    /* Stage 2: swaps the 2×2 sub-matrices inside each 4×4. */
    /* (0,2), (1,3), (4,6), (5,7) */
    UNROLL
    for (j = 0; j < 4; j++)                         /* 0, 1, 4, 5 */
        SWAPMOVE(x[j + (j & 2)], x[j + (j & 2) + 2], 0x33333333, 2);
    /* Stage 3: swaps the single bits inside each 2×2. */
    /* (0,1), (2,3), (4,5), (6,7) */
    UNROLL
    for (j = 0; j < 8; j += 2)
        SWAPMOVE(x[j], x[j + 1], 0x55555555, 1);
}

/*
 * AESRound without AddRoundKey, on the 8 blocks.
 * ShiftRows rotates row r by 8r bits towards the LSB.
 * MixColumns: a'[r] = xtime(d[r]) ^ s[r], with d[r] = a[r] ^ a[r+1] and
 * s[r] = a[r+1] ^ a[r+2] ^ a[r+3]; xtime(d) moves bit k-1 of d to bit k,
 * and bit 7 to bits 0, 1, 3 and 4.
 * mix_xtime() adds xtime(d) to bit[] (which holds s), d[k] holding bit k of d.
 */
HOT void mix_xtime(word bit[8], const word d[8])
{
    unsigned k;

    bit[0] = XOR(bit[0], d[7]);
    UNROLL
    for (k = 1; k < 8; k++)
        bit[k] = XOR(bit[k], d[k - 1]);
    bit[1] = XOR(bit[1], d[7]);
    bit[3] = XOR(bit[3], d[7]);
    bit[4] = XOR(bit[4], d[7]);
}

#include "aegis.c"
