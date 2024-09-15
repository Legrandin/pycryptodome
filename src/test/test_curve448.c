#include "endianess.h"
#include "curve448.h"
#include "mont.h"
#include <assert.h>

#if 0
void print_point(Curve448Point *p)
{
    mont_printf("X=", p->x, p->ec_ctx->mont_ctx);
    mont_printf("Z=", p->z, p->ec_ctx->mont_ctx);
}
#endif

void test_ladder_1(void)
{
    Curve448Context *ec_ctx;
    Curve448Point *point;
    int res;

    const uint8_t x[56] = { 0x86, 0xa0, 0xf8, 0x4e, 0xfb, 0xa7, 0xa7, 0x8a,
                            0xa1, 0xad, 0x94, 0xdb, 0x29, 0x54, 0xfa, 0x83,
                            0x25, 0xda, 0xc6, 0x19, 0x8c, 0xc3, 0xbd, 0xdd,
                            0x31, 0xc0, 0x4d, 0x81, 0xf9, 0x08, 0x0f, 0x02,
                            0x7f, 0x43, 0x07, 0xbd, 0x4c, 0x33, 0x88, 0xad,
                            0x8a, 0x3f, 0x26, 0xd5, 0xf2, 0x6c, 0x5f, 0xda,
                            0xbf, 0x87, 0x34, 0xfa, 0x40, 0xe6, 0xfc, 0x06 };

    const uint8_t scalar[] = { 0xd3, 0x0a, 0x60, 0x1c, 0x4f, 0x9a, 0x25, 0x29,
                               0x4b, 0xf5, 0x68, 0xa3, 0xeb, 0x43, 0x49, 0xf4,
                               0xbf, 0x8f, 0xd7, 0xcd, 0xf8, 0x24, 0x4c, 0x98,
                               0x9c, 0x77, 0x0a, 0x70, 0x21, 0xe1, 0xaa, 0xd1,
                               0xd0, 0x04, 0x51, 0x04, 0xef, 0xac, 0x82, 0x88,
                               0xd2, 0x34, 0x9a, 0xa1, 0xfe, 0x66, 0x52, 0x49,
                               0x88, 0x8e, 0xec, 0xf9, 0xdd, 0x2f, 0x26, 0x3c };

    const uint8_t expected[56] = { 0x6f, 0x6b, 0xd9, 0x3d, 0xf7, 0x82, 0x62, 0x76,
                                   0x21, 0x1e, 0x11, 0x61, 0x39, 0x22, 0x98, 0x9d,
                                   0x77, 0xb0, 0x01, 0x6a, 0xc6, 0x5f, 0x44, 0xeb,
                                   0xad, 0xba, 0x4f, 0xe1, 0x9f, 0x23, 0x5f, 0x6d,
                                   0x54, 0xd7, 0x12, 0x24, 0x0a, 0xb5, 0x79, 0xdf,
                                   0xfb, 0x6a, 0x5e, 0xd8, 0xb1, 0x1d, 0xda, 0x97,
                                   0x66, 0xdc, 0x60, 0x5a, 0xf9, 0x4f, 0x3e, 0xce };

    uint8_t result_x[56];

    res = curve448_new_context(&ec_ctx);
    assert(res == 0);

    res = curve448_new_point(&point, x, sizeof(x), ec_ctx);
    assert(res == 0);

    res = curve448_scalar(point, scalar, sizeof(scalar), 0);

    assert(mont_is_one(point->z, point->ec_ctx->mont_ctx));
    res = mont_to_bytes(result_x, sizeof(result_x), point->x, point->ec_ctx->mont_ctx);
    assert(res == 0);
    assert(memcmp(expected, result_x, sizeof(expected)) == 0);

    curve448_free_point(point);
    curve448_free_context(ec_ctx);
}

void test_ladder_2(void)
{
    Curve448Context *ec_ctx;
    Curve448Point *point;
    int res;
    uint8_t x[] = { 5 };
    uint8_t scalar[] = { 0 };

    res = curve448_new_context(&ec_ctx);
    assert(res == 0);

    res = curve448_new_point(&point, x, sizeof(x), ec_ctx);
    assert(res == 0);

    res = curve448_scalar(point, scalar, sizeof(scalar), 0);

    /** PAI **/
    assert(mont_is_one(point->x, point->ec_ctx->mont_ctx));
    assert(mont_is_zero(point->z, point->ec_ctx->mont_ctx));

    curve448_free_point(point);
    curve448_free_context(ec_ctx);
}

void test_cmp_1(void)
{
    uint8_t c1[56] = { 0xd7, 0x41, 0x07, 0x7b, 0xae, 0x25, 0x76, 0x75,
                       0xdb, 0xb5, 0x43, 0x55, 0x0d, 0x6f, 0x27, 0xda,
                       0x32, 0x89, 0x21, 0xfd, 0xb9, 0x9b, 0xf5, 0x4e,
                       0xbe, 0x9d, 0x4d, 0x0b, 0xcc, 0x58, 0xe9, 0x67,
                       0xff, 0x6f, 0xd1, 0xe1, 0x18, 0x2b, 0x22, 0x0f,
                       0xa0, 0x05, 0x7f, 0x0b, 0x0d, 0x3b, 0xc8, 0x3f,
                       0x86, 0xae, 0x38, 0xef, 0xb3, 0x5f, 0x5a, 0x35 };

    Curve448Context *ec_ctx;
    Curve448Point *G, *P;
    int res;

    res = curve448_new_context(&ec_ctx);
    assert(res == 0);

    // G = (C1, 1)
    res = curve448_new_point(&G, c1, sizeof(c1), ec_ctx);
    assert(res == 0);

    // P = (C1*C2, C2)
    res = curve448_clone(&P, G);
    assert(res == 0);

    mont_set(P->z, 0x12345678U, P->ec_ctx->mont_ctx);
    mont_mult(P->x, G->x, P->z, P->wp->scratch, P->ec_ctx->mont_ctx);

    res = curve448_cmp(G, P);
    assert(res == 0);

    mont_set(G->z, 2, G->ec_ctx->mont_ctx);

    // G = (C1, 2)
    res = curve448_cmp(G, P);
    assert(res != 0);

    curve448_free_point(P);
    curve448_free_point(G);
    curve448_free_context(ec_ctx);
}

void test_cmp_2(void)
{
    const uint8_t c1[56] = { 0xd7, 0x41, 0x07, 0x7b, 0xae, 0x25, 0x76, 0x75,
                             0xdb, 0xb5, 0x43, 0x55, 0x0d, 0x6f, 0x27, 0xda,
                             0x32, 0x89, 0x21, 0xfd, 0xb9, 0x9b, 0xf5, 0x4e,
                             0xbe, 0x9d, 0x4d, 0x0b, 0xcc, 0x58, 0xe9, 0x67,
                             0xff, 0x6f, 0xd1, 0xe1, 0x18, 0x2b, 0x22, 0x0f,
                             0xa0, 0x05, 0x7f, 0x0b, 0x0d, 0x3b, 0xc8, 0x3f,
                             0x86, 0xae, 0x38, 0xef, 0xb3, 0x5f, 0x5a, 0x35 };
    const uint8_t scalar[] = { 0 };

    Curve448Context *ec_ctx;
    Curve448Point *G, *P, *Q;
    int res;

    res = curve448_new_context(&ec_ctx);
    assert(res == 0);

    /** 3 different ways to create API **/

    res = curve448_new_point(&G, 0, sizeof(c1), ec_ctx);
    assert(res == 0);

    res = curve448_new_point(&P, c1, 0, ec_ctx);
    assert(res == 0);

    res = curve448_new_point(&Q, c1, sizeof(c1), ec_ctx);
    assert(res == 0);
    res = curve448_scalar(Q, scalar, sizeof(scalar), 0);
    assert(res == 0);

    res = curve448_cmp(G, P);
    assert(res == 0);
    res = curve448_cmp(G, Q);
    assert(res == 0);

    curve448_free_point(Q);
    curve448_free_point(P);
    curve448_free_point(G);
    curve448_free_context(ec_ctx);
}

int main(void)
{
    test_ladder_1();
    test_ladder_2();
    test_cmp_1();
    test_cmp_2();
    return 0;
}
