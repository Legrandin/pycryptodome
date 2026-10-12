/*
 * Test of the Salsa20 stream cipher (Salsa20.c), in particular of
 * Salsa20_stream_seek(), against an independent reference implementation.
 *
 * The test is linked with each way of computing the key stream:
 * - Salsa20.c without SSE2 (one block at a time),
 * - Salsa20.c with SSE2 (4 blocks at a time),
 * - Salsa20_avx2_bmi2.c (8 blocks at a time; TEST_SALSA20_AVX2). On a CPU
 *   without AVX2 that test does nothing, unless SALSA20_REQUIRE_AVX2 is set.
 */

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

/** The Salsa20 functions, with an opaque state **/
typedef void stream_state;
int Salsa20_stream_init(uint8_t *key, size_t keylen, uint8_t *nonce, size_t nonce_len, stream_state **pSalsaState);
int Salsa20_stream_destroy(stream_state *salsaState);
int Salsa20_stream_encrypt(stream_state *salsaState, const uint8_t in[], uint8_t out[], size_t len);
int Salsa20_stream_seek(stream_state *salsaState, unsigned long block_high, unsigned long block_low, unsigned offset);

/** Reference Salsa20 (Bernstein's specification): one 64-byte block of key stream **/
#define R(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define QR(a, b, c, d) do {         \
        x[b] ^= R(x[a] + x[d], 7);  \
        x[c] ^= R(x[b] + x[a], 9);  \
        x[d] ^= R(x[c] + x[b], 13); \
        x[a] ^= R(x[d] + x[c], 18); \
    } while (0)

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void ref_block(uint8_t out[64], const uint8_t *key, size_t keylen,
                      const uint8_t nonce[8], uint64_t counter)
{
    const uint8_t *c = (const uint8_t*)(keylen == 32 ? "expand 32-byte k" : "expand 16-byte k");
    const uint8_t *k2 = keylen == 32 ? key + 16 : key;
    uint32_t in[16], x[16];
    unsigned i;

    in[0] = le32(c);
    for (i=0; i<4; i++) {
        in[1+i] = le32(key + 4*i);
        in[11+i] = le32(k2 + 4*i);
    }
    in[5] = le32(c + 4);
    in[6] = le32(nonce);
    in[7] = le32(nonce + 4);
    in[8] = (uint32_t)counter;
    in[9] = (uint32_t)(counter >> 32);
    in[10] = le32(c + 8);
    in[15] = le32(c + 12);

    memcpy(x, in, sizeof x);
    for (i=0; i<10; i++) {
        QR(0, 4, 8, 12); QR(5, 9, 13, 1); QR(10, 14, 2, 6); QR(15, 3, 7, 11);
        QR(0, 1, 2, 3); QR(5, 6, 7, 4); QR(10, 11, 8, 9); QR(15, 12, 13, 14);
    }
    for (i=0; i<16; i++) {
        uint32_t w = x[i] + in[i];

        out[4*i] = (uint8_t)w;
        out[4*i+1] = (uint8_t)(w >> 8);
        out[4*i+2] = (uint8_t)(w >> 16);
        out[4*i+3] = (uint8_t)(w >> 24);
    }
}

/** Reference key stream from block 'block' (wrapping around at 2^64) **/
static void ref_keystream(uint8_t *ks, size_t nblocks, const uint8_t *key, size_t keylen,
                          const uint8_t nonce[8], uint64_t block)
{
    size_t i;

    for (i=0; i<nblocks; i++) {
        ref_block(ks + 64*i, key, keylen, nonce, block + i);
    }
}

static const uint8_t nonce[8] = { 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
static uint8_t key[32];
static const uint8_t zeros[64*40];

/** Encrypt zeros (that is, read the key stream) in uneven pieces **/
static void read_keystream(stream_state *st, uint8_t *out, size_t len)
{
    static const size_t pieces[] = { 1, 63, 100, 7, 300, 64, 513 };
    size_t done = 0, i = 0;

    while (done < len) {
        size_t n = pieces[i++ % 7];

        n = MIN(n, len - done);
        assert(Salsa20_stream_encrypt(st, zeros, out + done, n) == 0);
        done += n;
    }
}

static void seek(stream_state *st, uint64_t block, unsigned offset)
{
    assert(Salsa20_stream_seek(st, (unsigned long)(block >> 32), (unsigned long)(block & 0xFFFFFFFF), offset) == 0);
}

static void test_stream(size_t keylen)
{
    stream_state *st;
    uint8_t out[64*30], ref[64*30];

    /** From position 0, without seek **/
    assert(Salsa20_stream_init(key, keylen, (uint8_t*)nonce, 8, &st) == 0);
    read_keystream(st, out, sizeof out);
    ref_keystream(ref, 30, key, keylen, nonce, 0);
    assert(memcmp(out, ref, sizeof out) == 0);
    Salsa20_stream_destroy(st);
}

static void test_seek_positions(size_t keylen)
{
    static const size_t positions[] = { 0, 1, 63, 64, 65, 64*4+1, 64*8+3, 64*9+7, 64*17+33 };
    stream_state *st;
    uint8_t out[300], ref[64*30];
    unsigned i;

    ref_keystream(ref, 30, key, keylen, nonce, 0);
    assert(Salsa20_stream_init(key, keylen, (uint8_t*)nonce, 8, &st) == 0);
    for (i=0; i<sizeof positions / sizeof positions[0]; i++) {
        size_t p = positions[i];

        seek(st, p / 64, (unsigned)(p % 64));
        read_keystream(st, out, sizeof out);
        assert(memcmp(out, ref + p, sizeof out) == 0);
    }

    /** Back to the start, after some use **/
    seek(st, 0, 0);
    read_keystream(st, out, sizeof out);
    assert(memcmp(out, ref, sizeof out) == 0);
    Salsa20_stream_destroy(st);
}

static void test_seek_counters(size_t keylen)
{
    /*
     * Across the carry into the high word of the counter,
     * for all the blocks computed at once
     */
    static const uint64_t blocks[] = {
        0xDE7A8B6883EEED8DULL,
        0xFFFFFFFDULL, 0xFFFFFFFFULL, 0x1FFFFFFFEULL,
        0xFFFFFFFFFFFFFFF0ULL
    };
    static const unsigned offsets[] = { 0, 5, 63 };
    stream_state *st;
    uint8_t out[64*10], ref[64*10];
    unsigned i, j;

    assert(Salsa20_stream_init(key, keylen, (uint8_t*)nonce, 8, &st) == 0);
    for (i=0; i<sizeof blocks / sizeof blocks[0]; i++) {
        ref_keystream(ref, 10, key, keylen, nonce, blocks[i]);
        for (j=0; j<sizeof offsets / sizeof offsets[0]; j++) {
            seek(st, blocks[i], offsets[j]);
            read_keystream(st, out, sizeof out - offsets[j]);
            assert(memcmp(out, ref + offsets[j], sizeof out - offsets[j]) == 0);
        }
    }
    Salsa20_stream_destroy(st);
}

/*
 * The key stream ends with block 2^64 - 1: it can be used up to its last
 * byte, but encrypting beyond fails, and leaves the state untouched.
 */
static void test_end_of_key_stream(size_t keylen)
{
    /* The last blocks, at different positions in the blocks computed at once */
    static const unsigned last_blocks[] = { 1, 2, 3, 4, 5, 7, 8, 9, 12, 17 };
    static const unsigned offsets[] = { 0, 5, 63 };
    stream_state *st;
    uint8_t out[64*17 + 1], ref[64*17];
    unsigned i, j;

    assert(Salsa20_stream_init(key, keylen, (uint8_t*)nonce, 8, &st) == 0);
    for (i=0; i<sizeof last_blocks / sizeof last_blocks[0]; i++) {
        uint64_t block = 0 - (uint64_t)last_blocks[i];

        ref_keystream(ref, last_blocks[i], key, keylen, nonce, block);
        for (j=0; j<sizeof offsets / sizeof offsets[0]; j++) {
            size_t to_end = 64*last_blocks[i] - offsets[j];

            /* Up to the last byte, in pieces */
            seek(st, block, offsets[j]);
            read_keystream(st, out, to_end);
            assert(memcmp(out, ref + offsets[j], to_end) == 0);

            /* Then no more */
            out[0] = 0xAA;
            assert(Salsa20_stream_encrypt(st, zeros, out, 1) == ERR_MAX_DATA);
            assert(out[0] == 0xAA);
            assert(Salsa20_stream_encrypt(st, zeros, out, 0) == 0);

            /* Beyond the end in one call: nothing is encrypted */
            seek(st, block, offsets[j]);
            memset(out, 0xAA, to_end + 1);
            assert(Salsa20_stream_encrypt(st, zeros, out, to_end + 1) == ERR_MAX_DATA);
            assert(out[0] == 0xAA && out[to_end] == 0xAA);
            assert(Salsa20_stream_encrypt(st, zeros, out, to_end) == 0);
            assert(memcmp(out, ref + offsets[j], to_end) == 0);
        }
    }

    /* Far from the end, with data longer than the key stream left (not accessed) */
    seek(st, 0 - ((uint64_t)1 << 20), 0);
    assert(Salsa20_stream_encrypt(st, zeros, out, ((size_t)1 << 26) + 1) == ERR_MAX_DATA);
#if SIZE_MAX > 0xFFFFFFFFUL
    seek(st, 0 - ((uint64_t)1 << 40), 0);
    assert(Salsa20_stream_encrypt(st, zeros, out, ((size_t)1 << 46) + 1) == ERR_MAX_DATA);
    seek(st, 0, 0);
    assert(Salsa20_stream_encrypt(st, zeros, out, 1) == 0);
#endif

    /* After the end, a seek makes the key stream usable again */
    seek(st, 0 - (uint64_t)1, 0);
    read_keystream(st, out, 64);
    assert(Salsa20_stream_encrypt(st, zeros, out, 1) == ERR_MAX_DATA);
    seek(st, 0, 0);
    read_keystream(st, out, 64*17);
    ref_keystream(ref, 17, key, keylen, nonce, 0);
    assert(memcmp(out, ref, 64*17) == 0);

    Salsa20_stream_destroy(st);
}

static void test_seek_errors(void)
{
    stream_state *st;

    assert(Salsa20_stream_seek(NULL, 0, 0, 0) == ERR_NULL);

    assert(Salsa20_stream_init(key, 32, (uint8_t*)nonce, 8, &st) == 0);
    assert(Salsa20_stream_seek(st, 0, 0, 64) == ERR_MAX_OFFSET);
#if ULONG_MAX > 0xFFFFFFFFUL
    assert(Salsa20_stream_seek(st, 0x100000000UL, 0, 0) == ERR_MAX_OFFSET);
    assert(Salsa20_stream_seek(st, 0, 0x100000000UL, 0) == ERR_MAX_OFFSET);
#endif
    Salsa20_stream_destroy(st);
}

int main(void)
{
    unsigned i;

#if defined(TEST_SALSA20_AVX2)
    if (!__builtin_cpu_supports("avx2")) {
        /* In CI on x86-64, the test must run (SALSA20_REQUIRE_AVX2 is set) */
        const char *required = getenv("SALSA20_REQUIRE_AVX2");

        if (required && *required) {
            printf("Failed: the CPU does not support AVX2, but SALSA20_REQUIRE_AVX2 is set\n");
            return 1;
        }
        printf("Skipped: the CPU does not support AVX2\n");
        return 0;
    }
#endif

    for (i=0; i<sizeof key; i++) {
        key[i] = (uint8_t)(i * 7 + 1);
    }

    test_stream(16);
    test_stream(32);
    test_seek_positions(16);
    test_seek_positions(32);
    test_seek_counters(16);
    test_seek_counters(32);
    test_end_of_key_stream(16);
    test_end_of_key_stream(32);
    test_seek_errors();

    return 0;
}
