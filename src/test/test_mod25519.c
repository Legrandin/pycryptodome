#include "endianess.h"
#include <assert.h>

/** Test for multiplication are in a separate unit **/

void convert_le64_to_le25p5(uint32_t out[9], const uint64_t in[4]);
void convert_le25p5_to_le64(uint64_t out[4], const uint32_t in[9]);
int convert_behex_to_le25p5(uint32_t out[10], const char *in);
int convert_le25p5_to_behex(char **out, uint32_t in[10]);
void reduce_25519_le64(uint64_t x[4]);
void cswap(uint32_t a[10], uint32_t b[10], uint32_t c[10], uint32_t d[10], unsigned cond);
void invert_25519(uint32_t out[10], const uint32_t x[10]);
void add_25519(uint32_t out[10], const uint32_t f[10], const uint32_t g[10]);

static const uint64_t modulus[4] =  { 0xffffffffffffffedULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x7fffffffffffffffULL };
static const uint64_t modulus2[4] = { 0xffffffffffffffdaULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL };
static const uint64_t hundhund[4] = { 0xe08063f1e8753fb4ULL, 0x29e492f797f6605cULL, 0x1f6de7b30d1327efULL, 0x534a930de945ebf3ULL };

static const uint32_t modulus_32[10] = { 0x3ffffed, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff };
static const uint32_t hundhund_32[10] = { 0x753fb4, 0x18fc7a, 0xb9c10, 0x1bcbfb3, 0xa7924b, 0x11327ef, 0x2f3d986, 0x17e63ed, 0xde945e, 0x14d2a4c };

void test_le64_tole25p5(void)
{
    uint32_t out[10];
    uint64_t in[4];

    memset(out, 0xAA, sizeof out);
    memcpy(in, modulus, sizeof modulus);
    convert_le64_to_le25p5(out, in);

    assert(out[0] == 0x3ffffed);
    assert(out[1] == 0x1ffffff);
    assert(out[2] == 0x3ffffff);
    assert(out[3] == 0x1ffffff);
    assert(out[4] == 0x3ffffff);
    assert(out[5] == 0x1ffffff);
    assert(out[6] == 0x3ffffff);
    assert(out[7] == 0x1ffffff);
    assert(out[8] == 0x3ffffff);
    assert(out[9] == 0x1ffffff);

    memset(out, 0xAA, sizeof out);
    memcpy(in, hundhund, sizeof hundhund);
    convert_le64_to_le25p5(out, in);

    assert(out[0] == 0x753fb4);
    assert(out[1] == 0x18fc7a);
    assert(out[2] == 0xb9c10);
    assert(out[3] == 0x1bcbfb3);
    assert(out[4] == 0xa7924b);
    assert(out[5] == 0x11327ef);
    assert(out[6] == 0x2f3d986);
    assert(out[7] == 0x17e63ed);
    assert(out[8] == 0xde945e);
    assert(out[9] == 0x14d2a4c);

    in[0] = 0xAAAAAAAAAAAAAAAA;
    in[1] = 0xBBBBBBBBBBBBBBBB;
    in[2] = 0xCCCCCCCCCCCCCCCC;
    in[3] = 0xDDDDDDDDDDDDDDDD;
    convert_le64_to_le25p5(out, in);
    assert(out[0] == 0x2aaaaaa);
    assert(out[1] == 0xaaaaaa);
    assert(out[2] == 0x3777555);
    assert(out[3] == 0x1dddddd);
    assert(out[4] == 0x2eeeeee);
    assert(out[5] == 0xcccccc);
    assert(out[6] == 0x2666666);
    assert(out[7] == 0x1bbb999);
    assert(out[8] == 0x1dddddd);
    assert(out[9] == 0x3777777);
}

void test_le25p5_to_le64(void)
{
    uint64_t out[4];

    memset(out, 0xAA, sizeof out);
    convert_le25p5_to_le64(out, modulus_32);

    assert(out[0] == modulus[0]);
    assert(out[1] == modulus[1]);
    assert(out[2] == modulus[2]);
    assert(out[3] == modulus[3]);

    memset(out, 0xAA, sizeof out);
    convert_le25p5_to_le64(out, hundhund_32);

    assert(out[0] == hundhund[0]);
    assert(out[1] == hundhund[1]);
    assert(out[2] == hundhund[2]);
}

void test_behex_tole25p5(void)
{
    uint32_t out[10];
    char in1[] = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
    char in2[] = "534a930de945ebf31f6de7b30d1327ef29e492f797f6605ce08063f1e8753fb4";
    char in3[] = "DDDDDDDDDDDDDDDDCCCCCCCCCCCCCCCCBBBBBBBBBBBBBBBBAAAAAAAAAAAAAAAA";
    char in4[] = "AA";
    int ret;

    memset(out, 0xAA, sizeof out);
    ret = convert_behex_to_le25p5(out, in1);
    assert(ret == 0);

    assert(out[0] == 0x3ffffed);
    assert(out[1] == 0x1ffffff);
    assert(out[2] == 0x3ffffff);
    assert(out[3] == 0x1ffffff);
    assert(out[4] == 0x3ffffff);
    assert(out[5] == 0x1ffffff);
    assert(out[6] == 0x3ffffff);
    assert(out[7] == 0x1ffffff);
    assert(out[8] == 0x3ffffff);
    assert(out[9] == 0x1ffffff);

    memset(out, 0xAA, sizeof out);
    ret = convert_behex_to_le25p5(out, in2);
    assert(ret == 0);

    assert(out[0] == 0x753fb4);
    assert(out[1] == 0x18fc7a);
    assert(out[2] == 0xb9c10);
    assert(out[3] == 0x1bcbfb3);
    assert(out[4] == 0xa7924b);
    assert(out[5] == 0x11327ef);
    assert(out[6] == 0x2f3d986);
    assert(out[7] == 0x17e63ed);
    assert(out[8] == 0xde945e);
    assert(out[9] == 0x14d2a4c);

    memset(out, 0xAA, sizeof out);
    ret = convert_behex_to_le25p5(out, in3);
    assert(ret == 0);

    assert(out[0] == 0x2aaaaaa);
    assert(out[1] == 0xaaaaaa);
    assert(out[2] == 0x3777555);
    assert(out[3] == 0x1dddddd);
    assert(out[4] == 0x2eeeeee);
    assert(out[5] == 0xcccccc);
    assert(out[6] == 0x2666666);
    assert(out[7] == 0x1bbb999);
    assert(out[8] == 0x1dddddd);
    assert(out[9] == 0x3777777);

    memset(out, 0xAA, sizeof out);
    ret = convert_behex_to_le25p5(out, in4);
    assert(ret == 0);

    assert(out[0] == 0xaa);
    assert(out[1] == 0);
    assert(out[2] == 0);
    assert(out[3] == 0);
    assert(out[4] == 0);
    assert(out[5] == 0);
    assert(out[6] == 0);
    assert(out[7] == 0);
    assert(out[8] == 0);

    /* Negative test cases */
    ret = convert_behex_to_le25p5(out, "A");
    assert(ret != 0);
    ret = convert_behex_to_le25p5(out, NULL);
    assert(ret != 0);
    ret = convert_behex_to_le25p5(out, "te");
    assert(ret != 0);
}

void test_tole25p5_to_behex(void)
{
    char *out;
    uint32_t in[10];
    int res;

    in[0] = 0x3ffffed;
    in[1] = 0x1ffffff;
    in[2] = 0x3ffffff;
    in[3] = 0x1ffffff;
    in[4] = 0x3ffffff;
    in[5] = 0x1ffffff;
    in[6] = 0x3ffffff;
    in[7] = 0x1ffffff;
    in[8] = 0x3ffffff;
    in[9] = 0x1ffffff;

    convert_le25p5_to_behex(&out, in);
    res = strcmp(out, "0000000000000000000000000000000000000000000000000000000000000000");
    assert(res == 0);
}

void test_reduce(void)
{
    uint64_t x[4];

    /** 0 **/

    x[0] = x[1] = x[2] = x[3] = 0;
    reduce_25519_le64(x);
    assert(x[0] == 0);
    assert(x[1] == 0);
    assert(x[2] == 0);
    assert(x[3] == 0);

    memcpy(x, modulus, sizeof x);
    reduce_25519_le64(x);
    assert(x[0] == 0);
    assert(x[1] == 0);
    assert(x[2] == 0);
    assert(x[3] == 0);

    memcpy(x, modulus2, sizeof x);
    reduce_25519_le64(x);
    assert(x[0] == 0);
    assert(x[1] == 0);
    assert(x[2] == 0);
    assert(x[3] == 0);

    /** 1 **/

    x[0] = 1;
    x[1] = x[2] = x[3] = 0;
    reduce_25519_le64(x);
    assert(x[0] == 1);
    assert(x[1] == 0);
    assert(x[2] == 0);
    assert(x[3] == 0);

    memcpy(x, modulus, sizeof x);
    x[0]++;
    reduce_25519_le64(x);
    assert(x[0] == 1);
    assert(x[1] == 0);
    assert(x[2] == 0);
    assert(x[3] == 0);

    memcpy(x, modulus2, sizeof x);
    x[0]++;
    reduce_25519_le64(x);
    assert(x[0] == 1);
    assert(x[1] == 0);
    assert(x[2] == 0);
    assert(x[3] == 0);

    /** 38 **/

    x[0] = 38;
    x[1] = x[2] = x[3] = 0;
    reduce_25519_le64(x);
    assert(x[0] == 38);
    assert(x[1] == 0);
    assert(x[2] == 0);
    assert(x[3] == 0);

    x[0] = 0x13;
    x[1] = x[2] = 0;
    x[3] = 0x8000000000000000ULL;
    reduce_25519_le64(x);
    assert(x[0] == 38);
    assert(x[1] == 0);
    assert(x[2] == 0);
    assert(x[3] == 0);
}

int check(uint32_t x[10], uint32_t s)
{
    unsigned i;
    for (i=0; i<10; i++)
        if (x[i] != s) {
            return 0;
        }
    return 1;
}

void test_cswap(void)
{
    uint32_t a[10];
    uint32_t b[10];
    uint32_t c[10];
    uint32_t d[10];

    memset(a, 0xAA, sizeof a);
    memset(b, 0x55, sizeof b);
    memset(c, 0x77, sizeof c);
    memset(d, 0x11, sizeof d);
    cswap(a, b, c, d, 0);

    assert(check(a, 0xAAAAAAAA));
    assert(check(b, 0x55555555));
    assert(check(c, 0x77777777));
    assert(check(d, 0x11111111));

    cswap(a, b, c, d, 1);
    assert(check(a, 0x77777777));
    assert(check(b, 0x11111111));
    assert(check(c, 0xAAAAAAAA));
    assert(check(d, 0x55555555));
}

void test_invert(void)
{
    uint64_t in[4];
    uint32_t x[10];
    uint64_t out[4];

    in[0] = 1;
    in[1] = in[2] = in[3] = 0;
    convert_le64_to_le25p5(x, in);
    invert_25519(x, x);
    convert_le25p5_to_le64(out, x);
    reduce_25519_le64(out);
    assert(out[0] == 1);
    assert(out[1] == 0);
    assert(out[2] == 0);
    assert(out[3] == 0);

    in[0] = 2;
    in[1] = in[2] = in[3] = 0;
    convert_le64_to_le25p5(x, in);
    invert_25519(x, x);
    convert_le25p5_to_le64(out, x);
    reduce_25519_le64(out);
    assert(out[0] == 0xfffffffffffffff7);
    assert(out[1] == 0xffffffffffffffff);
    assert(out[2] == 0xffffffffffffffff);
    assert(out[3] == 0x3fffffffffffffff);

    in[0] = 0xAAAAAAAAAAAAAAAA;
    in[1] = 0xBBBBBBBBBBBBBBBB;
    in[2] = 0xCCCCCCCCCCCCCCCC;
    in[3] = 0xDDDDDDDDDDDDDDDD;
    convert_le64_to_le25p5(x, in);
    invert_25519(x, x);
    convert_le25p5_to_le64(out, x);
    reduce_25519_le64(out);
    assert(out[0] == 0x6cf8847ba332c4c7);
    assert(out[1] == 0x984028b39c0b5e92);
    assert(out[2] == 0x2404af2276fdd005);
    assert(out[3] == 0x22336ebc77628108);
}

void test_add(void)
{
    uint64_t in[4];
    uint32_t x[10];
    uint64_t out[4];

    in[0] = 0xFFFFFFFFFFFFFFFF;
    in[1] = 0xFFFFFFFFFFFFFFFF;
    in[2] = 0xFFFFFFFFFFFFFFFF;
    in[3] = 0xFFFFFFFFFFFFFFFF;
    convert_le64_to_le25p5(x, in);
    /* x[8] and x[9] have 26 bits set */
    add_25519(x, x, x);
    convert_le25p5_to_le64(out, x);
    assert(out[0] == 0x0000000000000037);
    assert(out[1] == 0x0000000000000000);
    assert(out[2] == 0x0000000000000000);
    assert(out[3] == 0x8000000000000000);
}

int main(void)
{
    test_le64_tole25p5();
    test_le25p5_to_le64();
    test_behex_tole25p5();
    test_tole25p5_to_behex();
    test_reduce();
    test_cswap();
    test_invert();
    test_add();
    return 0;
}
