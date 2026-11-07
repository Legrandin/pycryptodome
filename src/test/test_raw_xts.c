#include "common.h"
#include "block_base.h"

int XTS_start_operation(BlockBase *cipher, const uint8_t *encrypted_tweak, size_t tweak_len, void **pResult);
int XTS_encrypt(void *state, const uint8_t *in, uint8_t *out, size_t data_len);
int XTS_decrypt(void *state, const uint8_t *in, uint8_t *out, size_t data_len);
int XTS_stop_operation(void *state);

#define L 16

/** A dummy block cipher: each output byte depends on two input bytes **/
static int dummy_encrypt(const BlockBase *bb, const uint8_t *in, uint8_t *out, size_t data_len)
{
    size_t i;
    (void)bb;

    assert(data_len % L == 0);
    for (i=0; i<data_len; i+=L) {
        uint8_t block[L];
        unsigned j;

        for (j=0; j<L; j++) {
            block[j] = (uint8_t)(in[i+j] + in[i+(j+1)%L]*2 + j);
        }
        memcpy(out + i, block, L);
    }
    return 0;
}

static int dummy_decrypt(const BlockBase *bb, const uint8_t *in, uint8_t *out, size_t data_len)
{
    size_t i;
    (void)bb;

    assert(data_len % L == 0);
    /** Invert y[j] = x[j] + 2*x[j+1] + j modulo 256, with a series in powers of -2 **/
    for (i=0; i<data_len; i+=L) {
        uint8_t block[L];
        unsigned j, k;

        for (j=0; j<L; j++) {
            uint8_t acc = 0, coeff = 1;

            for (k=0; k<L; k++) {
                acc = (uint8_t)(acc + coeff * (in[i+(j+k)%L] - (j+k)%L));
                coeff = (uint8_t)(coeff * 254);
            }
            /** The series gives (1 - 2^16) x[j], which is x[j] modulo 256 **/
            block[j] = acc;
        }
        memcpy(out + i, block, L);
    }
    return 0;
}

static int dummy_destructor(BlockBase *bb)
{
    free(bb);
    return 0;
}

static BlockBase *dummy_cipher(void)
{
    BlockBase *bb = calloc(1, sizeof(BlockBase));

    bb->encrypt = dummy_encrypt;
    bb->decrypt = dummy_decrypt;
    bb->destructor = dummy_destructor;
    bb->block_len = L;
    return bb;
}

static void *new_state(const uint8_t *encrypted_tweak)
{
    void *state;
    int res = XTS_start_operation(dummy_cipher(), encrypted_tweak, L, &state);
    assert(res == 0);
    return state;
}

/** Exact allocations, so that the sanitizers catch any access out of bounds **/
static void test_lengths(void)
{
    const size_t max_len = 1100;
    uint8_t encrypted_tweak[L];
    size_t len, i;

    /** The top bit of each word is set, so that the carries are taken **/
    memset(encrypted_tweak, 0xA5, L);

    for (len=L; len<=max_len; len++) {
        uint8_t *pt = malloc(len), *ct = malloc(len), *ct2 = malloc(len), *back = malloc(len);
        void *state;

        for (i=0; i<len; i++)
            pt[i] = (uint8_t)(i*7 + len);

        state = new_state(encrypted_tweak);
        assert(XTS_encrypt(state, pt, ct, len) == 0);
        XTS_stop_operation(state);

        state = new_state(encrypted_tweak);
        assert(XTS_decrypt(state, ct, back, len) == 0);
        XTS_stop_operation(state);
        assert(memcmp(pt, back, len) == 0);

        /** In place **/
        memcpy(ct2, pt, len);
        state = new_state(encrypted_tweak);
        assert(XTS_encrypt(state, ct2, ct2, len) == 0);
        XTS_stop_operation(state);
        assert(memcmp(ct, ct2, len) == 0);

        state = new_state(encrypted_tweak);
        assert(XTS_decrypt(state, ct2, ct2, len) == 0);
        XTS_stop_operation(state);
        assert(memcmp(pt, ct2, len) == 0);

        /** In two pieces **/
        if (len > 2*L) {
            size_t first = (len/2) & ~(size_t)(L-1);

            state = new_state(encrypted_tweak);
            assert(XTS_encrypt(state, pt, ct2, first) == 0);
            assert(XTS_encrypt(state, pt + first, ct2 + first, len - first) == 0);
            XTS_stop_operation(state);
            assert(memcmp(ct, ct2, len) == 0);
        }

        free(pt);
        free(ct);
        free(ct2);
        free(back);
    }
}

static void test_tweak_update(void)
{
    uint8_t encrypted_tweak[L];
    uint8_t pt[2*L], ct[2*L], expected[L];
    void *state;

    /** The top bit of the 128-bit integer is set: the update gives 0x87 in the first byte **/
    memset(encrypted_tweak, 0, L);
    encrypted_tweak[L-1] = 0x80;
    memset(pt, 0, sizeof pt);

    state = new_state(encrypted_tweak);
    assert(XTS_encrypt(state, pt, ct, sizeof pt) == 0);
    XTS_stop_operation(state);

    memset(expected, 0, L);
    expected[0] = 0x87;
    dummy_encrypt(NULL, expected, expected, L);
    expected[0] ^= 0x87;
    assert(memcmp(ct + L, expected, L) == 0);
}

static void test_errors(void)
{
    uint8_t tweak[L], in[64], out[64];
    void *state;
    BlockBase *bb;

    memset(tweak, 0, L);
    memset(in, 0, sizeof in);

    assert(XTS_start_operation(NULL, tweak, L, &state) == ERR_NULL);
    bb = dummy_cipher();
    assert(XTS_start_operation(bb, NULL, L, &state) == ERR_NULL);
    assert(XTS_start_operation(bb, tweak, L, NULL) == ERR_NULL);
    assert(XTS_start_operation(bb, tweak, L-1, &state) == ERR_BLOCK_SIZE);
    bb->block_len = 8;
    assert(XTS_start_operation(bb, tweak, L, &state) == ERR_BLOCK_SIZE);
    free(bb);

    state = new_state(tweak);
    assert(XTS_encrypt(NULL, in, out, L) == ERR_NULL);
    assert(XTS_encrypt(state, NULL, out, L) == ERR_NULL);
    assert(XTS_encrypt(state, in, NULL, L) == ERR_NULL);
    assert(XTS_decrypt(NULL, in, out, L) == ERR_NULL);
    assert(XTS_decrypt(state, NULL, out, L) == ERR_NULL);
    assert(XTS_decrypt(state, in, NULL, L) == ERR_NULL);
    assert(XTS_encrypt(state, in, out, L-1) == ERR_NOT_ENOUGH_DATA);
    assert(XTS_encrypt(state, in, out, 0) == 0);
    assert(XTS_encrypt(state, in, out, L+1) == 0);
    assert(XTS_encrypt(state, in, out, 0) == 0);
    assert(XTS_encrypt(state, in, out, L) == ERR_STATE);
    XTS_stop_operation(state);

    assert(XTS_stop_operation(NULL) == ERR_NULL);
}

int main(void)
{
    test_lengths();
    test_tweak_update();
    test_errors();
    return 0;
}
