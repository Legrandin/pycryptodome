/*
 * Test of the 8-way SHA-256 compression function for AVX2
 * (sha256_x8_avx2.c), against the scalar one of SHA256.c,
 * with eight different states and blocks.
 *
 * On a CPU without AVX2, the test does nothing.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define SHA2_EMBEDDED
#include "SHA256.c"
#include "sha256_x8_avx2.c"

#include <cpuid.h>

static int have_avx2(void)
{
    unsigned eax, ebx, ecx, edx;

    if (__get_cpuid_max(0, NULL) < 7)
        return 0;
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx >> 5) & 1;
}

/* xorshift32: just to fill the states and the blocks */
static uint32_t next(uint32_t *x)
{
    *x ^= *x << 13;
    *x ^= *x >> 17;
    *x ^= *x << 5;
    return *x;
}

int main(void)
{
    uint32_t h[8][8], expected[8][8], out[8][8];
    uint8_t blocks[8][64];
    const uint32_t *h_in[8];
    uint32_t *h_out[8];
    const uint8_t *in[8];
    uint32_t x = 0x9E3779B9;
    unsigned round, j, t;

    if (!have_avx2()) {
        printf("No AVX2: test skipped\n");
        return 0;
    }

    for (round = 0; round < 100; round++) {
        for (j = 0; j < 8; j++) {
            for (t = 0; t < 8; t++)
                h[j][t] = next(&x);
            for (t = 0; t < 64; t++)
                blocks[j][t] = (uint8_t)next(&x);

            /* The scalar compression, on the same block */
            {
                uint32_t M[16];
                for (t = 0; t < 16; t++)
                    M[t] = LOAD_U32_BIG(blocks[j] + 4*t);
                sha_compress_words(h[j], expected[j], M);
            }
            h_in[j] = h[j];
            h_out[j] = (round % 2) ? h[j] : out[j];     /* in place, every other round */
            in[j] = blocks[j];
        }

        sha256_compress_x8_avx2(h_in, h_out, in);

        for (j = 0; j < 8; j++) {
            if (memcmp(h_out[j], expected[j], sizeof expected[j]) != 0) {
                printf("Mismatch in round %u, lane %u\n", round, j);
                return 1;
            }
        }
    }

    printf("SHA-256 x8: OK\n");
    return 0;
}
