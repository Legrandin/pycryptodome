/*
 * Test of the 4-state Keccak-p[1600] permutation for 64-bit ARM
 * (keccak_x4_neon.c), against the scalar one of keccak.c,
 * for 12 and 24 rounds, and of its functions to access the 4 states.
 *
 * On other CPUs, the test does nothing.
 */

#include <assert.h>
#include <stdio.h>

#define KECCAK_EMBEDDED
#include "keccak.c"

#if (defined(__aarch64__) && defined(__ARM_NEON)) || defined(_M_ARM64)

#include "keccak_x4_neon.c"

/* xorshift64: just to fill the states */
static uint64_t next(uint64_t *x)
{
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    return *x;
}

static void test_permutation(void)
{
    uint64_t x = 0x9E3779B97F4A7C15ULL;
    uint64_t state[100], expected[100];
    unsigned trial, rounds, i, j;

    for (trial = 0; trial < 100; trial++) {
        for (rounds = 12; rounds <= 24; rounds += 12) {
            for (i = 0; i < 100; i++)
                expected[i] = state[i] = next(&x);
            for (j = 0; j < 4; j++)
                keccak_function(expected + 25*j, rounds);
            keccak_function_x4(state, rounds);
            assert(0 == memcmp(state, expected, sizeof state));
        }
    }
}

static void test_access(void)
{
    uint64_t state[100];
    uint8_t in[4][200], out[4][200];
    const uint8_t *pin[4];
    uint8_t *pout[4];
    unsigned i, j;

    for (j = 0; j < 4; j++) {
        for (i = 0; i < 200; i++)
            in[j][i] = (uint8_t)(i*7 + j*61 + 1);
        pin[j] = in[j];
        pout[j] = out[j];
    }

    /* Absorbing into a zero state, then extracting, gives back the input */
    memset(state, 0, sizeof state);
    keccak_absorb_x4(state, pin, 21);
    memset(out, 0xAA, sizeof out);
    keccak_extract_x4(state, pout, 21);
    for (j = 0; j < 4; j++) {
        assert(0 == memcmp(out[j], in[j], 21*8));
        assert(out[j][21*8] == 0xAA);
        assert(LOAD_U64_LITTLE(in[j] + 8) == state[25*j + 1]);
        assert(0 == state[25*j + 21]);
    }

    /* The same word goes into one lane of each state */
    keccak_xor_lane_x4(state, 24, 0x8000000000000001ULL);
    for (j = 0; j < 4; j++)
        assert(0x8000000000000001ULL == state[25*j + 24]);
}

int main(void)
{
    test_permutation();
    test_access();
    return 0;
}

#else

int main(void)
{
    printf("Not a 64-bit ARM CPU with NEON: nothing to test\n");
    return 0;
}

#endif
