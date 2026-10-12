/*
 * Constant-time check of DES and Triple DES (DES.c), with Valgrind
 * memcheck, like test_ed25519_ct.c.
 *
 * The key and the input blocks are marked as undefined memory:
 * Valgrind then reports every conditional jump and every memory access
 * that depends on them.
 *
 * Build with -DPCT_DES3_MODULE for Triple DES, and run under:
 *     valgrind --error-exitcode=1 ./test_des_ct
 * The results are not checked here (see the Python self-tests).
 */

#include <assert.h>
#include <string.h>
#include <valgrind/memcheck.h>

#include "DES.c"

#define SECRET(p, len)  VALGRIND_MAKE_MEM_UNDEFINED(p, len)

#ifdef PCT_DES3_MODULE
#define START   DES3_start_operation
#define STOP    DES3_stop_operation
#define STATE   DES3_State
static const size_t key_lens[] = { 16, 24 };
#else
#define START   DES_start_operation
#define STOP    DES_stop_operation
#define STATE   DES_State
static const size_t key_lens[] = { 8 };
#endif

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
    uint8_t key[24], in[8*16], out[8*16];
    STATE *ctx;
    unsigned i, t;
    size_t j;

    for (t=0; t<sizeof key_lens / sizeof key_lens[0]; t++) {
        for (i=0; i<4; i++) {
            for (j=0; j<sizeof key; j++)
                key[j] = rnd();
            for (j=0; j<sizeof in; j++)
                in[j] = rnd();

            SECRET(key, sizeof key);
            assert(START(key, key_lens[t], &ctx) == 0);

            SECRET(in, sizeof in);
            assert(ctx->base_state.encrypt(&ctx->base_state, in, out, sizeof in) == 0);
            SECRET(out, sizeof out);
            assert(ctx->base_state.decrypt(&ctx->base_state, out, in, sizeof out) == 0);

            STOP(&ctx->base_state);
        }
    }

    return 0;
}
