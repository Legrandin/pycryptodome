#include <assert.h>
#include "common.h"
#include "mont.h"

int ge(const uint64_t *x, const uint64_t *y, size_t nw);
uint64_t sub(uint64_t *out, const uint64_t *a, const uint64_t *b, size_t nw);
void rsquare(uint64_t *r2, uint64_t *n, size_t nw);

void test_ge(void)
{
    int res;
    uint64_t x[2] = { 1, 2 };
    uint64_t y[2] = { 2, 1 };

    res = ge(x, y, 2);
    assert(res == 1);
    res = ge(x, x, 2);
    assert(res == 1);
    res = ge(y, x, 2);
    assert(res == 0);
}

void test_sub(void)
{
    uint64_t res;
    uint64_t x[2] = { 1, 2 };
    uint64_t y[2] = { 2, 1 };
    uint64_t out[2];

    memset(out, 0xFF, sizeof out);
    res = sub(out, x, x, 2);
    assert(res == 0);
    assert(out[0] == 0 && out[1] == 0);

    memset(out, 0xFF, sizeof out);
    x[0] = 1; x[1] = 2;
    res = sub(out, x, y, 2);
    assert(res == 0);
    assert(out[0] == 0xFFFFFFFFFFFFFFFFUL);
    assert(out[1] == 0);
    
    memset(out, 0xFF, sizeof out);
    x[0] = 1; x[1] = 2;
    res = sub(out, y, x, 2);
    assert(res == 1);
    assert(out[0] == 1);
    assert(out[1] == 0xFFFFFFFFFFFFFFFFUL);
}

void test_rsquare(void)
{
    uint64_t n1[2] = { 1, 0x89 };
    uint64_t r2[2];

    rsquare(r2, n1, 2);
    assert(r2[0] == 0x44169db8eb2b48d8L);
    assert(r2[1] == 0x18);
}

void test_mont_context_init(void)
{
    int res;
    MontContext *ctx;
    uint8_t modulus[] = { 1, 0, 0, 1 };
    uint8_t modulus_even[] = { 1, 0, 0, 2 };

    res = mont_context_init(NULL, modulus, 4);
    assert(res == ERR_NULL);
    
    res = mont_context_init(&ctx, 0, 4);
    assert(res == ERR_NULL);
    
    res = mont_context_init(&ctx, modulus, 0);
    assert(res == ERR_NOT_ENOUGH_DATA);
    
    res = mont_context_init(&ctx, modulus_even, 4);
    assert(res == ERR_VALUE);

    res = mont_context_init(&ctx, modulus, 4);
    assert(res == 0);

    mont_context_free(ctx);
}

void test_mont_from_bytes(void)
{
    int res;
    MontContext *ctx;
    uint8_t modulus[16] = { 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    uint8_t number[] = { 2, 2 };
    uint64_t *output;

    res = mont_context_init(&ctx, modulus, 16);
    assert(res == 0);

    res = mont_from_bytes(NULL, number, 2, ctx);
    assert(res == ERR_NULL);
    
    res = mont_from_bytes(&output, NULL, 2, ctx);
    assert(res == ERR_NULL);
    
    res = mont_from_bytes(&output, number, 2, NULL);
    assert(res == ERR_NULL);
    
    res = mont_from_bytes(&output, number, 0, ctx);
    assert(res == ERR_NOT_ENOUGH_DATA);
    
    res = mont_from_bytes(&output, number, 2, ctx);
    assert(res == 0);
    assert(output != NULL);
    assert(output[0] == 18446744073709420033UL);
    assert(output[1] == 71492449356218367L);
    free(output);
    
    mont_context_free(ctx);
}

void test_mont_to_bytes(void)
{
    int res;
    MontContext *ctx;
    uint8_t modulus[16] = { 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };   // 0x01000001000000000000000000000001
    uint64_t number_mont[2] = { 18446744073709420033UL, 71492449356218367L };
    uint8_t number[16];

    memset(number, 0xAA, 16);

    res = mont_context_init(&ctx, modulus, 16);
    assert(res == 0);
    assert(mont_bytes(ctx) == 16);

    res = mont_to_bytes(NULL, number_mont, ctx);
    assert(res == ERR_NULL);
    res = mont_to_bytes(number, NULL, ctx);
    assert(res == ERR_NULL);
    res = mont_to_bytes(number, number_mont, NULL);
    assert(res == ERR_NULL);

    res = mont_to_bytes(number, number_mont, ctx);
    assert(res == 0);
    assert(0 == memcmp(number, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02", 16));
    
    mont_context_free(ctx);
}

void test_mont_add(void)
{
    int res;
    MontContext *ctx;
    uint64_t *tmp;
    uint8_t modulus[16] = { 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };   // 0x01000001000000000000000000000001
    uint8_t modulus2[16];
    uint64_t a[2] = { -1, -1 };
    uint64_t b[2] = { 1, 0 };
    uint64_t out[2];

    mont_context_init(&ctx, modulus, 16);
    mont_number(&tmp, 2, ctx);
    
    res = mont_add(NULL, a, b, tmp, ctx);
    assert(res == ERR_NULL);
    res = mont_add(out, NULL, b, tmp, ctx);
    assert(res == ERR_NULL);
    res = mont_add(out, a, NULL, tmp, ctx);
    assert(res == ERR_NULL);
    res = mont_add(out, a, b, NULL, ctx);
    assert(res == ERR_NULL);
    res = mont_add(out, a, b, tmp, NULL);
    assert(res == ERR_NULL);
    
    // 0x100000200000100000000000000000L + 0x100000200000100000000000000000L
    a[0] = 0x10;
    a[1] = 0;
    b[0] = 0x100;
    b[1] = 0;
    res = mont_add(out, a, b, tmp, ctx);
    assert(res == 0);
    assert(out[0] == 0x110);
    assert(out[1] == 0);
 
    // 0xff0000fdffffff0000000000000001 + 0x100
    a[0] = 0x0;
    a[1] = 0x100000100000000UL;
    b[0] = 0xffffffffffff0001L;
    b[1] = 0xff0000ffffffffL;
    res = mont_add(out, a, b, tmp, ctx);
    assert(res == 0);
    assert(out[0] == 0xffffffffffff0000L);
    assert(out[1] == 0xff0000ffffffffL);

    // 0xff0000fdffffff0000000000000001L * 2
    a[0] = 0;
    a[1] = 0x100000100000000L;
    b[0] = 0;
    b[1] = 0x100000100000000L;
    res = mont_add(out, a, b, tmp, ctx);
    assert(res == 0);
    assert(out[0] == 0xffffffffffffffffL);
    assert(out[1] == 0x1000000ffffffffL);

    // Use modulus2, to trigger overflow over R
    mont_context_free(ctx);
    memset(modulus2, 0xFF, 16);
    mont_context_init(&ctx, modulus2, 16);

    // 0xfffffffffffffffffffffffffffffffe * 2
    // (same encoding in Montgomery domain)
    a[0] = 0xfffffffffffffffeL;
    a[1] = 0xffffffffffffffffL;
    b[0] = a[0];
    b[1] = a[1];
    res = mont_add(out, a, b, tmp, ctx);
    assert(res == 0);
    assert(out[0] == 0xfffffffffffffffdL);
    assert(out[1] == 0xffffffffffffffffL);

    free(tmp);
    mont_context_free(ctx);
}

void test_mont_sub(void)
{
    int res;
    MontContext *ctx;
    uint8_t modulus[16] = { 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };   // 0x01000001000000000000000000000001
    uint64_t a[2] = { 0, 0 };
    uint64_t b[2] = { 1, 0 };
    uint64_t out[3];
    uint64_t *tmp;

    mont_context_init(&ctx, modulus, 16);
    mont_number(&tmp, 2, ctx);
    
    res = mont_sub(NULL, a, b, tmp, ctx);
    assert(res == ERR_NULL);
    res = mont_sub(out, NULL, b, tmp, ctx);
    assert(res == ERR_NULL);
    res = mont_sub(out, a, NULL, tmp, ctx);
    assert(res == ERR_NULL);
    res = mont_sub(out, a, b, NULL, ctx);
    assert(res == ERR_NULL);
    res = mont_sub(out, a, b, tmp, NULL);
    assert(res == ERR_NULL);

    out[2] = 0xA;
    res = mont_sub(out, a, b, tmp, ctx);
    assert(res == 0);
    assert(out[0] == 0);
    assert(out[1] == 0x100000100000000);
    assert(out[2] == 0xA);

    res = mont_sub(out, b, a, tmp, ctx);
    assert(res == 0);
    assert(out[0] == 1);
    assert(out[1] == 0);

    free(tmp);
    mont_context_free(ctx);
}

void test_mont_inv_prime(void)
{
    int res;
    MontContext *ctx;
    uint8_t modulus_f6[9] = { 1, 0, 0, 0, 0, 0, 0, 0, 1 }; // F6 = 2^64 + 1
    uint64_t a[2] = { 1, 0 };
    uint64_t out[2];
    uint64_t *p;
    uint8_t buf[16];

    res = mont_context_init(&ctx, modulus_f6, sizeof modulus_f6);
    assert(res == 0);

    res = mont_inv_prime(NULL, a, ctx);
    assert(res == ERR_NULL);
    res = mont_inv_prime(out, NULL, ctx);
    assert(res == ERR_NULL);
    res = mont_inv_prime(out, a, NULL);
    assert(res == ERR_NULL);

    /* 1 == R mod N when N = F6 */
    a[0] = 1;   a[1] = 0;
    out[0] = 1; out[1] = 0;
    res = mont_inv_prime(out, a, ctx);
    assert(res == 0);
    assert(out[0] == 1);
    assert(out[1] == 0);

    assert(sizeof buf == mont_bytes(ctx));

    /* 2^{-1} mod N = 0x8000000000000001 */
    res = mont_from_bytes(&p, (uint8_t*)"\x00\x02", 2, ctx);
    assert(res == 0);
    res = mont_inv_prime(out, p, ctx);
    assert(res == 0);
    res = mont_to_bytes(buf, out, ctx);
    assert(res == 0);
    assert(0 == memcmp(buf, (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x01", 16));
    free(p);

    /* 3^{-1} mod N = 0x287cbedc41008ca6 */
    res = mont_from_bytes(&p, (uint8_t*)"\x00\x03", 2, ctx);
    assert(res == 0);
    res = mont_inv_prime(out, p, ctx);
    assert(res == 0);
    res = mont_to_bytes(buf, out, ctx);
    assert(res == 0);
    assert(0 == memcmp(buf, (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x28\x7c\xbe\xdc\x41\x00\x8c\xa6", 16));
    free(p);

    mont_context_free(ctx);
}

int main(void) {
    test_ge();
    test_sub();
    test_rsquare();
    test_mont_context_init();
    test_mont_from_bytes();
    test_mont_to_bytes();
    test_mont_add();
    test_mont_sub();
    test_mont_inv_prime();
    return 0;
}
