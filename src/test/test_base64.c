/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "common.h"

int base64_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size);

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** A plain encoder, with a newline every 'line' characters (0: none) **/
static size_t encode(const uint8_t *in, size_t len, char *out, size_t line)
{
    size_t i, o = 0, n = 0;
    char quad[4];
    unsigned j;

    for (i=0; i<len; i+=3) {
        uint32_t x = (uint32_t)in[i] << 16;
        size_t rem = len - i;

        if (rem > 1) x |= (uint32_t)in[i+1] << 8;
        if (rem > 2) x |= in[i+2];
        quad[0] = alphabet[(x >> 18) & 63];
        quad[1] = alphabet[(x >> 12) & 63];
        quad[2] = rem > 1 ? alphabet[(x >> 6) & 63] : '=';
        quad[3] = rem > 2 ? alphabet[x & 63] : '=';
        for (j=0; j<4; j++) {
            out[o++] = quad[j];
            if (line && ++n % line == 0)
                out[o++] = '\n';
        }
    }
    return o;
}

/** out has room for (len / 4) * 3 bytes, always enough **/
static int decode_str(const char *s, uint8_t *out)
{
    size_t len = strlen(s);

    return base64_decode((const uint8_t*)s, len, out, len / 4 * 3);
}

static void test_round_trip(void)
{
    uint8_t data[200], out[200];
    char text[400];
    size_t len, text_len, line;
    unsigned i;

    for (i=0; i<sizeof data; i++)
        data[i] = (uint8_t)(i * 37 + 11);

    for (line=0; line<=64; line+=16) {
        for (len=0; len<=sizeof data; len++) {
            text_len = encode(data, len, text, line);
            assert(base64_decode((uint8_t*)text, text_len, out, sizeof out) == (int)len);
            assert(base64_decode((uint8_t*)text, text_len, out, len) == (int)len);
            if (len > 0)
                assert(base64_decode((uint8_t*)text, text_len, out, len - 1) == -ERR_MAX_DATA);
            assert(memcmp(out, data, len) == 0);
        }
    }
}

/** Every byte value, in every position of a quad **/
static void test_all_characters(void)
{
    char text[5];
    uint8_t out[3];
    unsigned pos, c;

    for (pos=0; pos<4; pos++) {
        for (c=1; c<256; c++) {
            const char *p = memchr(alphabet, (int)c, 64);
            int is_space = (c == ' ' || (c >= '\t' && c <= '\r'));
            uint32_t x;
            int res;

            if (is_space || c == '=')
                continue;
            memcpy(text, "AAAA", 5);
            text[pos] = (char)c;
            res = decode_str(text, out);
            if (NULL == p) {
                assert(res == -ERR_VALUE);
                continue;
            }
            assert(res == 3);
            x = (uint32_t)(p - alphabet) << (6 * (3 - pos));
            assert(out[0] == (uint8_t)(x >> 16));
            assert(out[1] == (uint8_t)(x >> 8));
            assert(out[2] == (uint8_t)x);
        }
    }
}

static void test_whitespace_and_padding(void)
{
    uint8_t out[16];

    /* "Hello" */
    assert(decode_str(" SGVs\r\n\tbG8=\n \v\f", out) == 5);
    assert(memcmp(out, "Hello", 5) == 0);
    assert(decode_str("SGVsbA==", out) == 4);
    assert(memcmp(out, "Hell", 4) == 0);
    assert(decode_str("SGVsbA=\n=\n", out) == 4);
    assert(decode_str("", out) == 0);
    assert(decode_str(" \n ", out) == 0);

    /* Missing, wrong or excess padding */
    assert(decode_str("SGVsbA", out) == -ERR_VALUE);
    assert(decode_str("SGVsbA=", out) == -ERR_VALUE);
    assert(decode_str("SGVsbA===", out) == -ERR_VALUE);
    assert(decode_str("SGVsbG8", out) == -ERR_VALUE);
    assert(decode_str("SGVsbG8==", out) == -ERR_VALUE);
    assert(decode_str("SGVs=", out) == -ERR_VALUE);
    assert(decode_str("=", out) == -ERR_VALUE);
    assert(decode_str("S", out) == -ERR_VALUE);
    assert(decode_str("SGVsb", out) == -ERR_VALUE);
    assert(decode_str("SGVsb===", out) == -ERR_VALUE);

    /* Data after the padding */
    assert(decode_str("SGVsbA==SGVs", out) == -ERR_VALUE);
    assert(decode_str("SG=Vs", out) == -ERR_VALUE);

    /* Invalid characters */
    assert(decode_str("SGVs-A==", out) == -ERR_VALUE);
    assert(decode_str("SGVs\x80" "A==", out) == -ERR_VALUE);
    assert(base64_decode((const uint8_t*)"SG\0s", 4, out, sizeof out) == -ERR_VALUE);

    assert(base64_decode(NULL, 0, out, sizeof out) == -ERR_NULL);
    assert(base64_decode((const uint8_t*)"", 0, NULL, 0) == -ERR_NULL);
}

int main(void)
{
    test_round_trip();
    test_all_characters();
    test_whitespace_and_padding();
    return 0;
}
