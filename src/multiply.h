#include "pycrypto_common.h"

/**
 * Double-precision multiplication
 */
#ifdef __GNUC__
#define DP_MULT(a,b,ol,oh) do { \
    __uint128_t pr;             \
    pr = (__uint128_t)(a)*(b);  \
    ol = (__uint128_t)pr;       \
    oh = pr >> 64;              \
    } while (0)
#elif defined(_MSC_VER)

#include <windows.h>
#define DP_MULT(a,b,ol,oh) do { ol = UnsignedMultiply128(a,b,&oh); } while (0)

#else
#error TODO
#endif

size_t square_w(uint64_t *t, const uint64_t *a, size_t words)
#ifdef __GNUC__
__attribute__((optimize("-O3")))
#endif
;

uint64_t addmul128(uint64_t * RESTRICT t, const uint64_t * RESTRICT a, uint64_t b0, uint64_t b1, size_t words)
#ifdef __GNUC__
__attribute__((optimize("-O3")))
#endif
;
