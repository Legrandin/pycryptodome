#include <assert.h>
#include "common.h"
#include "mont.h"

int ge(const uint64_t *x, const uint64_t *y, size_t nw);
unsigned sub(uint64_t *out, const uint64_t *a, const uint64_t *b, size_t nw);
void rsquare(uint64_t *r2, uint64_t *n, size_t nw);
int mont_select(uint64_t *out, const uint64_t *a, const uint64_t *b, unsigned cond, unsigned words);

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
    assert(res == ERR_MODULUS);
    
    res = mont_context_init(&ctx, modulus_even, 4);
    assert(res == ERR_MODULUS);

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

    number[0] = 0;
    number[1] = 0;
    res = mont_from_bytes(&output, number, 2, ctx);
    assert(res == 0);
    assert(output != NULL);
    assert(output[0] == 0);
    assert(output[1] == 0);
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

    res = mont_to_bytes(NULL, 16, number_mont, ctx);
    assert(res == ERR_NULL);
    res = mont_to_bytes(number, 16, NULL, ctx);
    assert(res == ERR_NULL);
    res = mont_to_bytes(number, 16, number_mont, NULL);
    assert(res == ERR_NULL);

    res = mont_to_bytes(number, 15, number_mont, ctx);
    assert(res == ERR_NOT_ENOUGH_DATA);

    res = mont_to_bytes(number, 16, number_mont, ctx);
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

    uint8_t modulus_p521[66] = "\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    uint64_t out_p521[9];
    uint8_t buf_p521[66];

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
    res = mont_to_bytes(buf, 16, out, ctx);
    assert(res == 0);
    assert(0 == memcmp(buf, (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x01", 16));
    free(p);

    /* 3^{-1} mod N = 0x287cbedc41008ca6 */
    res = mont_from_bytes(&p, (uint8_t*)"\x00\x03", 2, ctx);
    assert(res == 0);
    res = mont_inv_prime(out, p, ctx);
    assert(res == 0);
    res = mont_to_bytes(buf, 16, out, ctx);
    assert(res == 0);
    assert(0 == memcmp(buf, (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x28\x7c\xbe\xdc\x41\x00\x8c\xa6", 16));
    free(p);

    mont_context_free(ctx);

    /* --- */
    mont_context_init(&ctx, modulus_p521, sizeof modulus_p521);
    res = mont_from_bytes(&p, (uint8_t*)"\x01\xE9\xF3\x4F\x60\xAD\x5C\x4B\x98\x8A\xB4\x3A\x0C\x1C\x40\xFB\x5C\xB0\xFD\x1A\x1A\x6F\x4E\x81\xEB\x33\xDE\x7D\x95\x2E\xE2\x62\x0D\x76\x08\x3B\xA2\x28\xCC\x56\xA4\xFE\xD2\xF6\x08\xF3\x17\x1E\x59\x41\xB7\xE1\x6D\x20\x05\xEB\x9F\x55\x6B\x6B\xA1\x36\x0E\xC2\x35\x8C", 66, ctx);
    assert(res == 0);

    res = mont_inv_prime(out_p521, p, ctx);
    assert(res == 0);

    res = mont_to_bytes(buf_p521, 66, out_p521, ctx);
    assert(res == 0);
    assert(0 == memcmp(buf_p521, (uint8_t*)"\x01\xF5\xDD\xE7\xED\xB2\xAD\x9D\x06\x2F\x2C\xAE\x1B\x66\x95\xC0\x9B\xE6\x16\xDA\xEA\x07\x2A\xC8\x2A\xFB\x44\xF4\x21\x79\xE1\x38\x8B\x1C\xEF\x91\xBA\xD3\xEB\x1D\x81\xE5\x45\xEF\x54\x63\xD7\x0A\xED\x39\x70\xFC\xD5\x95\xFF\x1B\xA7\x52\x11\xD3\xC3\x3C\x2C\x14\x42\x51", 66));

    free(p);
    mont_context_free(ctx);
}


void test_mont_set(void)
{
    int res;
    MontContext *ctx;
    uint64_t *tmp;
    uint8_t modulus[16] = { 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };   // 0x01000001000000000000000000000001
    uint64_t out[2];

    mont_context_init(&ctx, modulus, 16);
    mont_number(&tmp, 5, ctx);
    
    res = mont_set(NULL, 0x1000, tmp, ctx);
    assert(res == ERR_NULL);
    res = mont_set(out, 0x1000, NULL, ctx);
    assert(res == ERR_NULL);
    res = mont_set(out, 0x1000, tmp, NULL);
    assert(res == ERR_NULL);

    res = mont_set(out, 0, tmp, ctx);
    assert(res == 0);
    assert(out[0] == 0);
    assert(out[1] == 0);
    
    res = mont_set(out, 0x1000, tmp, ctx);
    assert(res == 0);
    assert(out[0] == 0xfffffffffff00001UL);
    assert(out[1] == 0xf00000ffffffffUL);

    free(tmp);
    mont_context_free(ctx);
}

void test_mont_select()
{
    int res;
    MontContext *ctx;
    uint8_t modulusA[16] = { 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };      // 0x01000001000000000000000000000001
    uint8_t modulusB[17] = { 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3 };   // 0x0301000001000000000000000000000001
    uint64_t a[2] = { 0xFFFFFFFFFFFFFFFFU, 0xFFFFFFFFFFFFFFFFU };
    uint64_t b[2] = { 1, 1 };
    uint64_t c[2];
    uint64_t d[3] = { 0xFFFFFFFFFFFFFFFFU, 0xFFFFFFFFFFFFFFFFU, 3 };
    uint64_t e[3] = { 1, 1, 3 };
    uint64_t f[3];

    mont_context_init(&ctx, modulusA, 16);

    memset(c, 0, sizeof c);
    res = mont_select(c, a, b, 1, ctx->words);
    assert(res == 0);
    assert(memcmp(a, c, sizeof c) == 0);

    memset(c, 0, sizeof c);
    res = mont_select(c, a, b, 10, ctx->words);
    assert(res == 0);
    assert(memcmp(a, c, sizeof c) == 0);

    memset(c, 0, sizeof c);
    res = mont_select(c, a, b, 0, ctx->words);
    assert(res == 0);
    assert(memcmp(b, c, sizeof c) == 0);

    mont_context_free(ctx);

    /* --- */

    mont_context_init(&ctx, modulusB, 17);

    memset(f, 0, sizeof f);
    res = mont_select(f, d, e, 1, ctx->words);
    assert(res == 0);
    assert(memcmp(d, f, sizeof f) == 0);

    memset(f, 0, sizeof f);
    res = mont_select(f, d, e, 0, ctx->words);
    assert(res == 0);
    assert(memcmp(e, f, sizeof f) == 0);
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
    test_mont_set();
    test_mont_select();
    return 0;
}
