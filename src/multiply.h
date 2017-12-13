#include <inttypes.h>
#include <stddef.h>

/**
 * Double-precision multiplication
 */
#define DP_MULT(a,b,ol,oh) do { \
    __uint128_t pr;             \
    pr = (__uint128_t)(a)*(b);  \
    ol = (__uint128_t)pr;       \
    oh = pr >> 64;              \
    } while (0)

size_t square_w(uint64_t *t, const uint64_t *a, size_t words) __attribute__((optimize("-O3")));
uint64_t addmul128(uint64_t *t, const uint64_t *a, uint64_t b0, uint64_t b1, size_t words) __attribute__((optimize("-O3")));
