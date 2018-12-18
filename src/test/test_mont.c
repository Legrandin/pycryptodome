#include <assert.h>
#include "common.h"
#include "mont.h"

int ge(const uint64_t *x, const uint64_t *y, size_t nw);
uint64_t sub(uint64_t *a, const uint64_t *b, size_t nw);
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

    res = sub(x, x, 2);
    assert(res == 0);
    assert(x[0] == 0 && x[1] == 0);

    x[0] = 1; x[1] = 2;
    res = sub(x, y, 2);
    assert(res == 0);
    assert(x[0] == 0xFFFFFFFFFFFFFFFFUL);
    assert(x[1] == 0);
    
    x[0] = 1; x[1] = 2;
    res = sub(y, x, 2);
    assert(res == 1);
    assert(y[0] == 1);
    assert(y[1] == 0xFFFFFFFFFFFFFFFFUL);
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

    res = mont_from_bytes(NULL, ctx, number, 2);
    assert(res == ERR_NULL);
    
    res = mont_from_bytes(&output, NULL, number, 2);
    assert(res == ERR_NULL);
    
    res = mont_from_bytes(&output, ctx, NULL, 2);
    assert(res == ERR_NULL);
    
    res = mont_from_bytes(&output, ctx, number, 0);
    assert(res == ERR_NOT_ENOUGH_DATA);
    
    res = mont_from_bytes(&output, ctx, number, 2);
    assert(res == 0);
    assert(output != NULL);
    assert(output[0] == 18446744073709420033UL);
    assert(output[1] == 71492449356218367L);
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

    res = mont_to_bytes(NULL, ctx, number_mont);
    assert(res == ERR_NULL);
    
    res = mont_to_bytes(number, NULL, number_mont);
    assert(res == ERR_NULL);
    
    res = mont_to_bytes(number, ctx, NULL);
    assert(res == ERR_NULL);

    res = mont_to_bytes(number, ctx, number_mont);
    assert(res == 0);
    assert(0 == memcmp(number, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02", 16));
}

int main(void) {
    test_ge();
    test_sub();
    test_rsquare();
    test_mont_context_init();
    test_mont_from_bytes();
    test_mont_to_bytes();
    return 0;
}
