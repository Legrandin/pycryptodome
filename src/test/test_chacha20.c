/*
 * Test of the ChaCha20 stream cipher (chacha20.c) against an independent
 * reference implementation: the key stream, seek(), the end of the key
 * stream, and the functions for encryption with several threads
 * (chacha20_check, chacha20_encrypt_at and chacha20_skip).
 *
 * The test is linked with each way of computing the key stream:
 * - chacha20.c without SSE2 (one block at a time),
 * - chacha20.c with SSE2 (4 blocks at a time),
 * - chacha20_avx2_bmi2.c (8 blocks at a time; TEST_CHACHA20_AVX2). On a CPU
 *   without AVX2 that test does nothing, unless CHACHA20_REQUIRE_AVX2 is set.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

/** The ChaCha20 functions, with an opaque state **/
typedef void stream_state;
int chacha20_init(stream_state **pState, const uint8_t *key, size_t keySize, const uint8_t *nonce, size_t nonceSize);
int chacha20_destroy(stream_state *state);
int chacha20_encrypt(stream_state *state, const uint8_t in[], uint8_t out[], size_t len);
int chacha20_seek(stream_state *state, unsigned long block_high, unsigned long block_low, unsigned offset);
int chacha20_check(const stream_state *state, size_t len);
int chacha20_encrypt_at(const stream_state *state, const uint8_t in[], uint8_t out[], size_t offset, size_t len);
int chacha20_skip(stream_state *state, size_t len);

/** Reference ChaCha20 (RFC 8439, and the original version with a 64-bit counter) **/
#define R(v, c) (((v) << (c)) | ((v) >> (32 - (c))))
#define QR(a, b, c, d) do {                         \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = R(x[d], 16); \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = R(x[b], 12); \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = R(x[d], 8);  \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = R(x[b], 7);  \
    } while (0)

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void ref_block(uint8_t out[64], const uint8_t key[32], const uint8_t *nonce, size_t nonce_len, uint64_t counter)
{
    static const uint8_t c[16] = "expand 32-byte k";
    uint32_t in[16], x[16];
    unsigned i;

    for (i=0; i<4; i++)
        in[i] = le32(c + 4*i);
    for (i=0; i<8; i++)
        in[4+i] = le32(key + 4*i);
    if (nonce_len == 8) {
        in[12] = (uint32_t)counter;
        in[13] = (uint32_t)(counter >> 32);
        in[14] = le32(nonce);
        in[15] = le32(nonce + 4);
    } else {
        in[12] = (uint32_t)counter;
        in[13] = le32(nonce);
        in[14] = le32(nonce + 4);
        in[15] = le32(nonce + 8);
    }

    memcpy(x, in, sizeof x);
    for (i=0; i<10; i++) {
        QR(0, 4, 8, 12); QR(1, 5, 9, 13); QR(2, 6, 10, 14); QR(3, 7, 11, 15);
        QR(0, 5, 10, 15); QR(1, 6, 11, 12); QR(2, 7, 8, 13); QR(3, 4, 9, 14);
    }
    for (i=0; i<16; i++) {
        uint32_t w = x[i] + in[i];

        out[4*i] = (uint8_t)w;
        out[4*i+1] = (uint8_t)(w >> 8);
        out[4*i+2] = (uint8_t)(w >> 16);
        out[4*i+3] = (uint8_t)(w >> 24);
    }
}

/** Reference key stream of nblocks blocks, from block (wrapping around like the counter) **/
static void ref_keystream(uint8_t *ks, size_t nblocks, const uint8_t *nonce, size_t nonce_len, uint64_t block)
{
    static uint8_t key[32];
    size_t i;

    for (i=0; i<32; i++)
        key[i] = (uint8_t)(i * 7 + 1);
    for (i=0; i<nblocks; i++) {
        uint64_t b = block + i;

        if (nonce_len == 12)
            b &= 0xFFFFFFFF;
        ref_block(ks + 64*i, key, nonce, nonce_len, b);
    }
}

static uint8_t key[32];
static const uint8_t nonce8[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
static const uint8_t nonce12[12] = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2 };
static uint8_t zeros[64*40];

static const uint8_t *nonce_of(size_t nonce_len)
{
    return nonce_len == 8 ? nonce8 : nonce12;
}

/** Encrypt zeros (that is, read the key stream) in uneven pieces **/
static void read_keystream(stream_state *st, uint8_t *out, size_t len)
{
    static const size_t pieces[] = { 1, 63, 100, 7, 300, 64, 513 };
    size_t done = 0, i = 0;

    while (done < len) {
        size_t n = pieces[i++ % 7];

        n = MIN(n, len - done);
        assert(chacha20_encrypt(st, zeros, out + done, n) == 0);
        done += n;
    }
}

static stream_state *new_state(size_t nonce_len)
{
    stream_state *st;

    assert(chacha20_init(&st, key, 32, nonce_of(nonce_len), nonce_len) == 0);
    return st;
}

static void seek(stream_state *st, uint64_t block, unsigned offset)
{
    assert(chacha20_seek(st, (unsigned long)(block >> 32), (unsigned long)(block & 0xFFFFFFFF), offset) == 0);
}

static void test_stream(size_t nonce_len)
{
    stream_state *st = new_state(nonce_len);
    uint8_t out[64*30], ref[64*30];

    read_keystream(st, out, sizeof out);
    ref_keystream(ref, 30, nonce_of(nonce_len), nonce_len, 0);
    assert(memcmp(out, ref, sizeof out) == 0);
    chacha20_destroy(st);
}

static void test_seek(size_t nonce_len)
{
    static const size_t positions[] = { 0, 1, 63, 64, 65, 64*3+1, 64*4+5, 64*7+63, 64*8+3, 64*9+7, 64*17+33 };
    stream_state *st = new_state(nonce_len);
    uint8_t out[300], ref[64*30];
    unsigned i;

    ref_keystream(ref, 30, nonce_of(nonce_len), nonce_len, 0);
    for (i=0; i<sizeof positions / sizeof positions[0]; i++) {
        size_t p = positions[i];

        seek(st, p / 64, (unsigned)(p % 64));
        read_keystream(st, out, sizeof out);
        assert(memcmp(out, ref + p, sizeof out) == 0);
    }
    chacha20_destroy(st);
}

/** The last blocks of the key stream, and nothing after them **/
static void test_end(size_t nonce_len)
{
    static const unsigned last_blocks[] = { 1, 2, 3, 4, 5, 7, 8, 9, 12, 17 };
    const uint64_t blocks_mod = nonce_len == 8 ? 0 : ((uint64_t)1 << 32);   /* 0 means 2^64 */
    stream_state *st = new_state(nonce_len);
    uint8_t out[64*17 + 1], ref[64*17];
    unsigned i;

    for (i=0; i<sizeof last_blocks / sizeof last_blocks[0]; i++) {
        uint64_t block = blocks_mod - last_blocks[i];
        size_t to_end = 64*last_blocks[i] - 5;

        ref_keystream(ref, last_blocks[i], nonce_of(nonce_len), nonce_len, block);
        seek(st, block, 5);
        read_keystream(st, out, to_end);
        assert(memcmp(out, ref + 5, to_end) == 0);
        assert(chacha20_encrypt(st, zeros, out, 1) == ERR_MAX_DATA);
        assert(chacha20_encrypt(st, zeros, out, 1) == ERR_MAX_DATA);

        /* Beyond the end in one call: nothing is encrypted */
        seek(st, block, 5);
        out[0] = 0xAA;
        assert(chacha20_encrypt(st, zeros, out, to_end + 1) == ERR_MAX_DATA);
        assert(out[0] == 0xAA);
        assert(chacha20_check(st, to_end) == 0);
        assert(chacha20_check(st, to_end + 1) == ERR_MAX_DATA);
        read_keystream(st, out, to_end);
        assert(memcmp(out, ref + 5, to_end) == 0);
    }
    chacha20_destroy(st);
}

/** chacha20_encrypt_at() and chacha20_skip(), from different starting positions **/
static void test_at_and_skip(size_t nonce_len)
{
    static const size_t starts[] = { 0, 1, 64, 100, 64*4, 64*8, 64*8+7, 64*13+63 };
    static const size_t offsets[] = { 0, 1, 63, 64, 65, 64*4-1, 64*8, 64*9+33 };
    uint8_t out[64*16], ref[64*40];
    unsigned i, j;

    ref_keystream(ref, 40, nonce_of(nonce_len), nonce_len, 0);
    for (i=0; i<sizeof starts / sizeof starts[0]; i++) {
        for (j=0; j<sizeof offsets / sizeof offsets[0]; j++) {
            stream_state *st = new_state(nonce_len);
            size_t start = starts[i], offset = offsets[j], len = 64*2 + 9;

            /* Position the state at start */
            if (start > 0)
                read_keystream(st, out, start);

            /* encrypt_at does not move the position */
            assert(chacha20_encrypt_at(st, zeros, out, offset, len) == 0);
            assert(memcmp(out + offset, ref + start + offset, len) == 0);
            assert(chacha20_encrypt_at(st, zeros, out, 0, 10) == 0);
            assert(memcmp(out, ref + start, 10) == 0);

            /* skip moves it */
            assert(chacha20_skip(st, offset) == 0);
            read_keystream(st, out, 100);
            assert(memcmp(out, ref + start + offset, 100) == 0);
            chacha20_destroy(st);
        }
    }
}

/** encrypt_at and skip near the end of the key stream **/
static void test_at_and_skip_end(size_t nonce_len)
{
    const uint64_t blocks_mod = nonce_len == 8 ? 0 : ((uint64_t)1 << 32);
    stream_state *st = new_state(nonce_len);
    uint8_t out[64*10], ref[64*10];
    uint64_t block = blocks_mod - 10;
    unsigned skips[] = { 0, 1, 64*8, 64*9, 64*10 - 1, 64*10 };
    unsigned i;

    ref_keystream(ref, 10, nonce_of(nonce_len), nonce_len, block);
    for (i=0; i<sizeof skips / sizeof skips[0]; i++) {
        size_t left = 64*10 - skips[i];

        seek(st, block, 0);
        assert(chacha20_encrypt_at(st, zeros, out, 0, 64*10) == 0);
        assert(memcmp(out, ref, 64*10) == 0);
        assert(chacha20_encrypt_at(st, zeros, out, 1, 64*10) == ERR_MAX_DATA);
        assert(chacha20_skip(st, skips[i]) == 0);
        assert(chacha20_check(st, left) == 0);
        assert(chacha20_check(st, left + 1) == ERR_MAX_DATA);
        assert(chacha20_skip(st, left + 1) == ERR_MAX_DATA);
        if (left > 0) {
            read_keystream(st, out, left);
            assert(memcmp(out, ref + skips[i], left) == 0);
        }
        assert(chacha20_encrypt(st, zeros, out, 1) == ERR_MAX_DATA);
    }
    assert(chacha20_encrypt_at(st, zeros, out, (size_t)-1, 2) == ERR_MAX_DATA);
    chacha20_destroy(st);
}

/** With a nonce of 8 bytes, the counter carries into its high word **/
static void test_carry(void)
{
    stream_state *st = new_state(8);
    uint8_t out[64*20], ref[64*20];
    uint64_t block = 0xFFFFFFFFULL - 9;

    ref_keystream(ref, 20, nonce8, 8, block);
    seek(st, block, 3);
    read_keystream(st, out, 64*20 - 3);
    assert(memcmp(out, ref + 3, 64*20 - 3) == 0);
    chacha20_destroy(st);
}

int main(void)
{
    unsigned i;

#if defined(TEST_CHACHA20_AVX2)
    if (!__builtin_cpu_supports("avx2")) {
        /* In CI on x86-64, the test must run (CHACHA20_REQUIRE_AVX2 is set) */
        const char *required = getenv("CHACHA20_REQUIRE_AVX2");

        if (required && *required) {
            printf("Failed: the CPU does not support AVX2, but CHACHA20_REQUIRE_AVX2 is set\n");
            return 1;
        }
        printf("Skipped: the CPU does not support AVX2\n");
        return 0;
    }
#endif

    for (i=0; i<sizeof key; i++) {
        key[i] = (uint8_t)(i * 7 + 1);
    }

    test_stream(8);
    test_stream(12);
    test_seek(8);
    test_seek(12);
    test_end(8);
    test_end(12);
    test_at_and_skip(8);
    test_at_and_skip(12);
    test_at_and_skip_end(8);
    test_at_and_skip_end(12);
    test_carry();

    return 0;
}
