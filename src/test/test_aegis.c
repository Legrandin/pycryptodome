/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Tests for AEGIS-128L and AEGIS-256 (RFC 10032) that the Python self-tests
 * cannot do: the AESRound and Update test vectors (Appendix A.1, A.2.1
 * and A.3.1), the error codes, and the AES round on its own:
 *  - the bitsliced S-box on all 256 bytes (aegis_portable.c only);
 *  - the round on 8 different blocks, against a table-based AES round:
 *    aes_rounds() for the backends with it, else (aegis_scalar.c, which keeps
 *    its own state) bitslice_aes_round() between bs_pack() and bs_unpack().
 * The A.1 test is only for the backends with aes_rounds().
 *
 * The file of the implementation is included, so that its internal functions
 * can be called: aegis_portable.c by default, aegis_aesni.c with TEST_AEGIS_AESNI,
 * aegis_armv8.c with TEST_AEGIS_ARMV8 (the CPU must have the instructions).
 */

#include <assert.h>
#include <string.h>

#if defined(TEST_AEGIS_AESNI)
#include "aegis_aesni.c"
#elif defined(TEST_AEGIS_ARMV8)
#include "aegis_armv8.c"
#else
#include "aegis_portable.c"
#endif

#define F(name) PASTE2(AEGIS_PREFIX, name)

static unsigned hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return (unsigned)(c - '0');
    assert(c >= 'a' && c <= 'f');
    return (unsigned)(c - 'a' + 10);
}

static void unhex(uint8_t *out, const char *hex)
{
    size_t i, len = strlen(hex) / 2;

    assert(strlen(hex) % 2 == 0);
    for (i = 0; i < len; i++)
        out[i] = (uint8_t)(hex_digit(hex[2*i]) << 4 | hex_digit(hex[2*i + 1]));
}

static aes_block block(const char *hex)
{
    uint8_t b[16];

    unhex(b, hex);
    return blk_load(b);
}

static int same(aes_block x, const char *hex)
{
    uint8_t b[16], e[16];

    blk_store(b, x);
    unhex(e, hex);
    return memcmp(b, e, 16) == 0;
}

/* The AES S-box (FIPS 197, Section 5.1.1) */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static uint8_t ref_xtime(uint8_t x)
{
    return (uint8_t)(x << 1 ^ (x & 0x80 ? 0x1b : 0));
}

/* AESRound (SubBytes, ShiftRows, MixColumns, AddRoundKey) with tables, as a reference */
static void ref_aes_round(uint8_t out[16], const uint8_t in[16], const uint8_t rk[16])
{
    uint8_t t[16];
    unsigned r, c;

    /* Byte 4c + r is row r, column c; ShiftRows moves column c + r of row r to column c */
    for (c = 0; c < 4; c++)
        for (r = 0; r < 4; r++)
            t[4*c + r] = sbox[in[4*((c + r) % 4) + r]];
    /* MixColumns: 2a[r] ^ 3a[r+1] ^ a[r+2] ^ a[r+3] */
    for (c = 0; c < 4; c++) {
        const uint8_t *a = t + 4*c;
        uint8_t x = a[0] ^ a[1] ^ a[2] ^ a[3];

        for (r = 0; r < 4; r++)
            out[4*c + r] = (uint8_t)(a[r] ^ x ^ ref_xtime(a[r] ^ a[(r + 1) % 4]) ^ rk[4*c + r]);
    }
}

static uint64_t rng = 0x0123456789ABCDEFULL;

static uint8_t rnd(void)
{
    /* xorshift64 */
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return (uint8_t)rng;
}

/* The reference round gives the result of A.1 */
static void test_ref_aes_round(void)
{
    uint8_t in[16], rk[16], out[16], exp[16];

    unhex(in, "000102030405060708090a0b0c0d0e0f");
    unhex(rk, "101112131415161718191a1b1c1d1e1f");
    unhex(exp, "7a7b4e5638782546a8c0477a3b813f43");
    ref_aes_round(out, in, rk);
    assert(memcmp(out, exp, 16) == 0);
}

#if !defined(TEST_AEGIS_AESNI) && !defined(TEST_AEGIS_ARMV8)
/*
 * bitslice_Sbox() on all 256 bytes: the S-box works on each bit position of the
 * words independently, so position p (bit p % 8 of byte p / 8 of each word)
 * gets byte base + p, with its bit k in word k.
 */
static void test_sbox(void)
{
    enum { P = 8 * sizeof(word) };      /* Bit positions in a word: 64 or 128 */
    uint8_t w[8][sizeof(word)];
    word bit[8];
    unsigned base, p, k;

    for (base = 0; base < 256; base += P) {
        memset(w, 0, sizeof w);
        for (p = 0; p < P; p++)
            for (k = 0; k < 8; k++)
                w[k][p / 8] |= (uint8_t)(((base + p) >> k & 1) << (p % 8));
        for (k = 0; k < 8; k++)
            memcpy(&bit[k], w[k], sizeof(word));
        bitslice_Sbox(bit);
        for (k = 0; k < 8; k++)
            memcpy(w[k], &bit[k], sizeof(word));
        for (p = 0; p < P; p++) {
            unsigned v = 0;

            for (k = 0; k < 8; k++)
                v |= (unsigned)(w[k][p / 8] >> (p % 8) & 1) << k;
            assert(v == sbox[base + p]);
        }
    }
}
#endif

#ifndef AEGIS_CORE
/* aes_rounds() on 8 (or 6) different blocks; it does not write the blocks after n */
static void test_round_blocks(void)
{
    uint8_t in[8][16], rk[8][16], b[16], exp[16], unused[16];
    aes_block bin[8], brk[8], out[8];
    unsigned n, i, j;

    memset(unused, 0xA5, 16);
    for (n = 6; n <= 8; n += 2) {
        for (i = 0; i < 8; i++) {
            for (j = 0; j < 16; j++) {
                in[i][j] = rnd();
                rk[i][j] = rnd();
            }
            bin[i] = blk_load(in[i]);
            brk[i] = blk_load(rk[i]);
            out[i] = blk_load(unused);
        }
        aes_rounds(out, bin, brk, n);
        for (i = 0; i < 8; i++) {
            blk_store(b, out[i]);
            if (i < n) {
                ref_aes_round(exp, in[i], rk[i]);
                assert(memcmp(b, exp, 16) == 0);
            } else {
                assert(memcmp(b, unused, 16) == 0);
            }
        }
    }
}
#else
/* The round of aegis_scalar.c (without AddRoundKey) on 8 different blocks */
static void test_round_blocks(void)
{
    static const uint8_t zero[16] = { 0 };
    uint8_t in[8][16], out[8][16], exp[16];
    const uint8_t *src[8];
    uint8_t *dst[8];
    sliced x;
    unsigned i, j;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 16; j++)
            in[i][j] = rnd();
        src[i] = in[i];
        dst[i] = out[i];
    }
    bs_pack(&x, src);
    bitslice_aes_round(&x);
    bs_unpack(dst, &x);
    for (i = 0; i < 8; i++) {
        ref_aes_round(exp, in[i], zero);
        assert(memcmp(out[i], exp, 16) == 0);
    }
}
#endif

#ifndef AEGIS_CORE
/* A.1 (in all the blocks: aes_rounds() computes 6 or 8 rounds) */
static void test_aes_round(void)
{
    aes_block in[8], rk[8], out[8];
    unsigned i;

    for (i = 0; i < 8; i++) {
        in[i] = block("000102030405060708090a0b0c0d0e0f");
        rk[i] = block("101112131415161718191a1b1c1d1e1f");
    }
    aes_rounds(out, in, rk, 8);
    for (i = 0; i < 8; i++)
        assert(same(out[i], "7a7b4e5638782546a8c0477a3b813f43"));
}
#endif

/* A.2.1 */
static void test_update_128l(void)
{
    static const char *before[8] = {
        "9b7e60b24cc873ea894ecc07911049a3", "330be08f35300faa2ebf9a7b0d274658",
        "7bbd5bd2b049f7b9b515cf26fbe7756c", "c35a00f55ea86c3886ec5e928f87db18",
        "9ebccafce87cab446396c4334592c91f", "58d83e31f256371e60fc6bb257114601",
        "1639b56ea322c88568a176585bc915de", "640818ffb57dc0fbc2e72ae93457e39a"
    };
    static const char *after[8] = {
        "596ab773e4433ca0127c73f60536769d", "790394041a3d26ab697bde865014652d",
        "38cf49e4b65248acd533041b64dd0611", "16d8e58748f437bfff1797f780337cee",
        "9689ecdf08228c74d7e3360cca53d0a5", "a21746bb193a569e331e1aa985d0d729",
        "09d714e6fcf9177a8ed1cde7e3d259a6", "61279ba73167f0ab76f0a11bf203bdff"
    };
    aes_block S[8];
    aegis_core c;
    uint8_t m[32];
    unsigned i;

    for (i = 0; i < 8; i++)
        S[i] = block(before[i]);
    unhex(m, "033e6975b94816879e42917650955aa0fcc1968a46b7e97861bd6e89af6aa55f");
    core_load(&c, AEGIS_128L, S);
    core_absorb(&c, AEGIS_128L, m);
    core_store(S, &c, AEGIS_128L);
    for (i = 0; i < 8; i++)
        assert(same(S[i], after[i]));
}

/* A.3.1 */
static void test_update_256(void)
{
    static const char *before[6] = {
        "1fa1207ed76c86f2c4bb40e8b395b43e", "b44c375e6c1e1978db64bcd12e9e332f",
        "0dab84bfa9f0226432ff630f233d4e5b", "d7ef65c9b93e8ee60c75161407b066e7",
        "a760bb3da073fbd92bdc24734b1f56fb", "a828a18d6a964497ac6e7e53c5f55c73"
    };
    static const char *after[6] = {
        "e6bc643bae82dfa3d991b1b323839dcd", "648578232ba0f2f0a3677f617dc052c3",
        "ea788e0e572044a46059212dd007a789", "2f1498ae19b80da13fba698f088a8590",
        "a54c2ee95e8c2a2c3dae2ec743ae6b86", "a3240fceb68e32d5d114df1b5363ab67"
    };
    aes_block S[8];
    aegis_core c;
    uint8_t m[16];
    unsigned i;

    memset(S, 0, sizeof S);
    for (i = 0; i < 6; i++)
        S[i] = block(before[i]);
    unhex(m, "b165617ed04ab738afb2612c6d18a1ec");
    core_load(&c, AEGIS_256, S);
    core_absorb(&c, AEGIS_256, m);
    core_store(S, &c, AEGIS_256);
    for (i = 0; i < 6; i++)
        assert(same(S[i], after[i]));
}

static void test_errors(void)
{
    uint8_t key[32] = { 0 }, nonce[32] = { 0 }, buf[32] = { 0 }, tag[32];
    aegis_state *st;

    assert(F(init)(AEGIS_128L, key, 16, nonce, 16, NULL) == ERR_NULL);
    assert(F(init)(AEGIS_128L, NULL, 16, nonce, 16, &st) == ERR_NULL);
    assert(F(init)(0, key, 16, nonce, 16, &st) == ERR_VALUE);
    assert(F(init)(3, key, 16, nonce, 16, &st) == ERR_VALUE);
    assert(F(init)(AEGIS_128L, key, 32, nonce, 32, &st) == ERR_KEY_SIZE);
    assert(F(init)(AEGIS_256, key, 16, nonce, 16, &st) == ERR_KEY_SIZE);
    assert(F(init)(AEGIS_128L, key, 16, nonce, 32, &st) == ERR_NONCE_SIZE);
    assert(F(init)(AEGIS_256, key, 32, nonce, 16, &st) == ERR_NONCE_SIZE);

    assert(F(init)(AEGIS_128L, key, 16, nonce, 16, &st) == 0);
    assert(F(update_ad)(st, buf, 5) == 0);
    assert(F(encrypt)(st, buf, buf, 5) == 0);
    /* No associated data after the message */
    assert(F(update_ad)(st, buf, 5) == ERR_STATE);
    assert(F(digest)(st, tag, 24) == ERR_TAG_SIZE);
    assert(F(digest)(st, tag, 16) == 0);
    /* Nothing after the tag */
    assert(F(digest)(st, tag, 16) == ERR_STATE);
    assert(F(encrypt)(st, buf, buf, 5) == ERR_STATE);
    assert(F(decrypt)(st, buf, buf, 5) == ERR_STATE);
    assert(F(destroy)(st) == 0);

    /* The lengths are limited to 2^61 - 1 bytes */
    assert(F(init)(AEGIS_256, key, 32, nonce, 32, &st) == 0);
    st->ad_len = MAX_LEN - 4;
    assert(F(update_ad)(st, buf, 5) == ERR_MAX_DATA);
    assert(F(update_ad)(st, buf, 4) == 0);
    st->msg_len = MAX_LEN - 4;
    assert(F(encrypt)(st, buf, buf, 5) == ERR_MAX_DATA);
    assert(F(encrypt)(st, buf, buf, 4) == 0);
    assert(F(destroy)(st) == 0);

    assert(F(destroy)(NULL) == ERR_NULL);
}

int main(void)
{
    test_ref_aes_round();
#if !defined(TEST_AEGIS_AESNI) && !defined(TEST_AEGIS_ARMV8)
    test_sbox();
#endif
    test_round_blocks();
#ifndef AEGIS_CORE
    test_aes_round();
#endif
    test_update_128l();
    test_update_256();
    test_errors();
    return 0;
}
