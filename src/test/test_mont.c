#include <assert.h>
#include "common.h"

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

int main(void) {
    test_ge();
    test_sub();
    test_rsquare();
    return 0;
}
