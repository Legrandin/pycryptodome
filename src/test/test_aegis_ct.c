/*
 * SPDX-FileCopyrightText: 2026 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Constant-time check of AEGIS-128L and AEGIS-256 without AES instructions
 * (aegis_portable.c, a bitsliced AES round), with Valgrind memcheck,
 * like test_des_ct.c.
 *
 * The key, the nonce and the data are marked as undefined memory:
 * Valgrind then reports every conditional jump and every memory access
 * that depends on them. Run under:
 *     valgrind --error-exitcode=1 ./test_aegis_ct
 * The results are not checked here (see test_aegis.c and the Python self-tests).
 */

#include <assert.h>
#include <string.h>
#include <valgrind/memcheck.h>

#include "aegis_portable.c"

#define SECRET(p, len)  VALGRIND_MAKE_MEM_UNDEFINED(p, len)

static uint64_t state = 0x0123456789ABCDEFULL;

static uint8_t rnd(void)
{
    /* xorshift64 */
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return (uint8_t)state;
}

int main(void)
{
    static const unsigned variants[] = { AEGIS_128L, AEGIS_256 };
    uint8_t key[32], nonce[32], ad[45], in[100], out[100], tag[32];
    aegis_state *st;
    unsigned v, decrypt;
    size_t j, size;

    for (v = 0; v < 2; v++) {
        size = variants[v] == AEGIS_128L ? 16 : 32;
        for (decrypt = 0; decrypt < 2; decrypt++) {
            for (j = 0; j < sizeof key; j++)
                key[j] = nonce[j] = rnd();
            for (j = 0; j < sizeof ad; j++)
                ad[j] = rnd();
            for (j = 0; j < sizeof in; j++)
                in[j] = rnd();
            SECRET(key, sizeof key);
            SECRET(nonce, sizeof nonce);
            SECRET(ad, sizeof ad);
            SECRET(in, sizeof in);

            assert(AEGIS_init(variants[v], key, size, nonce, size, &st) == 0);
            /* Whole and partial blocks */
            assert(AEGIS_update_ad(st, ad, 40) == 0);
            assert(AEGIS_update_ad(st, ad + 40, 5) == 0);
            if (decrypt) {
                assert(AEGIS_decrypt(st, in, out, 3) == 0);
                assert(AEGIS_decrypt(st, in + 3, out + 3, 97) == 0);
            } else {
                assert(AEGIS_encrypt(st, in, out, 3) == 0);
                assert(AEGIS_encrypt(st, in + 3, out + 3, 97) == 0);
            }
            assert(AEGIS_digest(st, tag, 32) == 0);
            assert(AEGIS_destroy(st) == 0);
        }
    }

    return 0;
}
