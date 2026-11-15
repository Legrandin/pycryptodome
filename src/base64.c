/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/**
 * Constant-time base64 decoding (RFC 4648, section 4), for the body
 * of a PEM block, which may hold a private key.
 *
 * The usual decoders (such as binascii.a2b_base64() in CPython) map
 * each character through a 256-entry table: the address of each lookup
 * depends on the secret, and leaks it through the cache
 * (see "Util::Lookup", Sieck et al., USENIX Security 2021).
 *
 * Here, the value of each character is computed with masks only.
 * The code branches only on whether a character is whitespace
 * or the padding character '=': this reveals the layout of the text
 * (the length of the lines), and not the data.
 */

#include <limits.h>
#include "common.h"
#include "nat_ct.h"

FAKE_INIT(base64)

/** 1 if lo <= c <= hi, 0 otherwise **/
static inline uint64_t ct_in_range(uint64_t c, uint64_t lo, uint64_t hi)
{
    return ct_lt(c - lo, hi - lo + 1);
}

/**
 * Decode the base64 character c.
 * Return its value (0..63), and set *valid to 1 if c is in the
 * alphabet, or to 0 otherwise (and the value is then 0).
 */
static inline uint64_t ct_b64_value(uint64_t c, uint64_t *valid)
{
    uint64_t upper, lower, digit, plus, slash;

    upper = ct_in_range(c, 'A', 'Z');
    lower = ct_in_range(c, 'a', 'z');
    digit = ct_in_range(c, '0', '9');
    plus  = ct_eq(c, '+');
    slash = ct_eq(c, '/');

    *valid = upper | lower | digit | plus | slash;

    return (ct_mask(upper) & (c - 'A')) |
           (ct_mask(lower) & (c - 'a' + 26)) |
           (ct_mask(digit) & (c - '0' + 52)) |
           (ct_mask(plus)  & 62) |
           (ct_mask(slash) & 63);
}

/** 1 if c is whitespace (space, \t, \n, \v, \f, \r), 0 otherwise **/
static inline uint64_t ct_is_space(uint64_t c)
{
    return ct_eq(c, ' ') | ct_in_range(c, '\t', '\r');
}

/**
 * Decode base64 text, ignoring whitespace anywhere.
 *
 * The padding with '=' is mandatory, and it can only be followed by
 * whitespace. The unused bits of the last character are ignored.
 *
 * @param in        The base64 text
 * @param in_len    The length of the text, in bytes
 * @param out       The output buffer
 * @param out_size  The size of the output buffer, in bytes.
 *                  (in_len / 4) * 3 bytes are always enough.
 * @return The number of bytes written to out (success),
 *         or a negative error code: -ERR_VALUE if the text is not valid,
 *         -ERR_MAX_DATA if the output does not fit into out_size bytes
 */
EXPORT_SYM int base64_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size)
{
    size_t i, nchars, npad, o;
    uint64_t c, v, valid, invalid, acc;

    if (NULL == in || NULL == out)
        return -ERR_NULL;
    if (in_len > INT_MAX)
        return -ERR_MAX_DATA;

    nchars = 0;     /* data characters in the current group of 4 */
    npad = 0;       /* padding characters, so far */
    invalid = 0;    /* secret until the end: 1 if any character is not in the alphabet */
    acc = 0;
    o = 0;

    for (i=0; i<in_len; i++) {
        c = in[i];

        /* The layout of the text is public */
        if (ct_declassify(ct_is_space(c)))
            continue;
        if (ct_declassify(ct_eq(c, '='))) {
            npad++;
            continue;
        }
        if (npad > 0)
            return -ERR_VALUE;

        v = ct_b64_value(c, &valid);
        invalid |= 1 ^ valid;
        acc = (acc << 6) | v;
        nchars++;

        if (nchars == 4) {
            if (out_size - o < 3)
                return -ERR_MAX_DATA;
            out[o++] = (uint8_t)(acc >> 16);
            out[o++] = (uint8_t)(acc >> 8);
            out[o++] = (uint8_t)acc;
            acc = 0;
            nchars = 0;
        }
    }

    switch (nchars) {
        case 0:
            if (npad != 0)
                return -ERR_VALUE;
            break;
        case 1:
            return -ERR_VALUE;
        case 2:
            if (npad != 2)
                return -ERR_VALUE;
            if (out_size - o < 1)
                return -ERR_MAX_DATA;
            out[o++] = (uint8_t)(acc >> 4);
            break;
        case 3:
            if (npad != 1)
                return -ERR_VALUE;
            if (out_size - o < 2)
                return -ERR_MAX_DATA;
            out[o++] = (uint8_t)(acc >> 10);
            out[o++] = (uint8_t)(acc >> 2);
            break;
    }

    /* Whether the text is valid becomes public */
    if (ct_declassify(invalid))
        return -ERR_VALUE;

    return (int)o;
}
