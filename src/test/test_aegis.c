/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Tests for AEGIS-128L and AEGIS-256 (RFC 10032) that the Python self-tests
 * cannot do: the AESRound and Update test vectors (Appendix A.1, A.2.1
 * and A.3.1), and the error codes. The AESRound test is only for the backends
 * with aes_rounds() (not for the bitsliced one, which has its own state).
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
#ifndef AEGIS_CORE
    test_aes_round();
#endif
    test_update_128l();
    test_update_256();
    test_errors();
    return 0;
}
