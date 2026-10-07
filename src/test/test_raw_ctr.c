#include "common.h"
#include "block_base.h"

/** The CTR functions, with an opaque state **/
int CTR_start_operation(BlockBase *cipher, uint8_t counter_block0[], size_t counter_block0_len,
                        size_t prefix_len, unsigned counter_len, unsigned little_endian, void **pResult);
int CTR_encrypt(void *ctrState, const uint8_t *in, uint8_t *out, size_t data_len);
int CTR_encrypt_at(const void *ctrState, const uint8_t *in, uint8_t *out, size_t offset, size_t data_len);
int CTR_skip(void *ctrState, size_t data_len);
int CTR_check(const void *ctrState, size_t data_len);
int CTR_stop_operation(void *ctrState);

#define ERR_CTR_REPEATED_KEY_STREAM ((6 << 16) | 2)

/** A dummy block cipher, for any block length: each output byte depends on two input bytes **/
static int dummy_encrypt(const BlockBase *bb, const uint8_t *in, uint8_t *out, size_t data_len)
{
    size_t i, j, L = bb->block_len;

    for (i=0; i<data_len; i+=L) {
        for (j=0; j<L; j++) {
            out[i+j] = (uint8_t)(in[i+j]*167 + in[i+(j+3)%L]*29 + j);
        }
    }
    return 0;
}

static int dummy_destructor(BlockBase *bb)
{
    free(bb);
    return 0;
}

static BlockBase *dummy_cipher(size_t block_len)
{
    BlockBase *bb = calloc(1, sizeof(BlockBase));

    bb->encrypt = dummy_encrypt;
    bb->decrypt = dummy_encrypt;
    bb->destructor = dummy_destructor;
    bb->block_len = block_len;
    return bb;
}

/** Reference: key stream of 'len' bytes, block by block **/
static void reference_keystream(size_t L, const uint8_t *block0, size_t prefix, size_t clen,
                                unsigned le, uint8_t *ks, size_t len)
{
    BlockBase *bb = dummy_cipher(L);
    uint8_t *ctr = malloc(L), *out = malloc(L);
    size_t done = 0;

    memcpy(ctr, block0, L);
    while (done < len) {
        size_t k, n = MIN(L, len - done);

        dummy_encrypt(bb, ctr, out, L);
        memcpy(ks + done, out, n);
        done += n;
        /** Increment the counter by one, modulo 2^(8*clen) **/
        for (k=0; k<clen; k++) {
            uint8_t *b = le ? &ctr[prefix + k] : &ctr[prefix + clen - 1 - k];
            if (++*b != 0)
                break;
        }
    }
    free(ctr);
    free(out);
    free(bb);
}

static void *start(size_t L, const uint8_t *block0, size_t prefix, size_t clen, unsigned le)
{
    void *state;
    int res = CTR_start_operation(dummy_cipher(L), (uint8_t*)block0, L, prefix, (unsigned)clen, le, &state);
    assert(res == 0);
    return state;
}

static void test_one(size_t L, size_t prefix, size_t clen, unsigned le)
{
    const size_t total = 50*L + 7;
    uint8_t *block0 = malloc(L), *ks = malloc(total), *zero = calloc(total, 1), *out = malloc(total);
    size_t i, first;
    void *state;

    /** Counter starts just below a carry over all its bytes **/
    for (i=0; i<L; i++)
        block0[i] = (uint8_t)(0x40 + i);
    for (i=0; i<clen; i++)
        block0[prefix + i] = 0xFF;
    block0[le ? prefix : prefix + clen - 1] = 0xF0;

    reference_keystream(L, block0, prefix, clen, le, ks, total);

    /** CTR_encrypt, in two pieces split anywhere **/
    for (first=0; first<total; first+=total/7) {
        state = start(L, block0, prefix, clen, le);
        assert(0 == CTR_encrypt(state, zero, out, first));
        assert(0 == CTR_encrypt(state, zero, out + first, total - first));
        assert(0 == memcmp(out, ks, total));
        CTR_stop_operation(state);
    }

    /** CTR_encrypt_at on three ranges, then CTR_skip and CTR_encrypt again **/
    for (first=1; first<total/2; first+=total/9) {
        /** Ranges [0, x), [x, y) and [y, total/2) after the first bytes, out of order **/
        size_t x = 3, y = total/4 + first/3;

        state = start(L, block0, prefix, clen, le);
        assert(0 == CTR_encrypt(state, zero, out, first));
        memset(out + first, 0x55, total - first);
        assert(0 == CTR_encrypt_at(state, zero, out + first, 0, x));
        assert(0 == CTR_encrypt_at(state, zero, out + first, y, total/2 - y));
        assert(0 == CTR_encrypt_at(state, zero, out + first, x, y - x));
        assert(0 == CTR_skip(state, total/2));
        assert(0 == CTR_encrypt(state, zero, out + first + total/2, total - first - total/2));
        assert(0 == memcmp(out, ks, total));
        CTR_stop_operation(state);
    }

    free(block0);
    free(ks);
    free(zero);
    free(out);
}

/** A 1-byte counter allows 256 blocks: one more byte must be rejected, without processing anything **/
static void test_limit(size_t L, unsigned le)
{
    const size_t max = 256*L;
    uint8_t *block0 = calloc(L, 1), *zero = calloc(max + 1, 1), *out = malloc(max + 1), *ks = malloc(max);
    void *state;

    reference_keystream(L, block0, L - 1, 1, le, ks, max);

    state = start(L, block0, L - 1, 1, le);
    assert(0 == CTR_check(state, max));
    assert(ERR_CTR_REPEATED_KEY_STREAM == CTR_check(state, max + 1));
    memset(out, 0x55, max + 1);
    assert(ERR_CTR_REPEATED_KEY_STREAM == CTR_encrypt(state, zero, out, max + 1));
    assert(out[0] == 0x55 && out[max] == 0x55);
    assert(ERR_CTR_REPEATED_KEY_STREAM == CTR_encrypt_at(state, zero, out, max - 3, 4));
    assert(ERR_CTR_REPEATED_KEY_STREAM == CTR_skip(state, max + 1));

    /** The state did not change **/
    assert(0 == CTR_encrypt(state, zero, out, 5));
    assert(0 == CTR_encrypt(state, zero, out + 5, max - 5));
    assert(0 == memcmp(out, ks, max));
    assert(ERR_CTR_REPEATED_KEY_STREAM == CTR_encrypt(state, zero, out, 1));
    assert(0 == CTR_encrypt(state, zero, out, 0));
    CTR_stop_operation(state);

    free(block0);
    free(zero);
    free(out);
    free(ks);
}

int main(void)
{
    static const size_t block_lens[] = { 1, 8, 16, 24, 64, 200 };
    unsigned i, le;

    for (i=0; i<sizeof block_lens / sizeof block_lens[0]; i++) {
        size_t L = block_lens[i];

        for (le=0; le<2; le++) {
            test_one(L, 0, L, le);                     /** Whole block is the counter **/
            test_one(L, L/3, MAX(1, L/2), le);         /** Prefix, counter, suffix **/
            test_one(L, L - 1, 1, le);                 /** 1-byte counter at the end **/
            if (L > 9)
                test_one(L, 1, 9, le);                 /** Counter longer than 8 bytes **/
            test_limit(L, le);
        }
    }

    {
        BlockBase *bb = dummy_cipher(0);
        uint8_t block0[1] = { 0 };
        void *state;

        assert(ERR_BLOCK_SIZE == CTR_start_operation(bb, block0, 0, 0, 1, 0, &state));
        free(bb);
    }

    return 0;
}
