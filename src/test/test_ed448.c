#include "ed448.h"
#include "mont.h"
#include <assert.h>

const uint8_t Gx[56] = {0x4F, 0x19, 0x70, 0xC6, 0x6B, 0xED, 0x0D, 0xED, 0x22, 0x1D, 0x15, 0xA6, 0x22, 0xBF, 0x36, 0xDA, 0x9E, 0x14, 0x65, 0x70, 0x47, 0x0F, 0x17, 0x67, 0xEA, 0x6D, 0xE3, 0x24, 0xA3, 0xD3, 0xA4, 0x64, 0x12, 0xAE, 0x1A, 0xF7, 0x2A, 0xB6, 0x65, 0x11, 0x43, 0x3B, 0x80, 0xE1, 0x8B, 0x00, 0x93, 0x8E, 0x26, 0x26, 0xA8, 0x2B, 0xC7, 0x0C, 0xC0, 0x5E};
const uint8_t Gy[56] = {0x69, 0x3F, 0x46, 0x71, 0x6E, 0xB6, 0xBC, 0x24, 0x88, 0x76, 0x20, 0x37, 0x56, 0xC9, 0xC7, 0x62, 0x4B, 0xEA, 0x73, 0x73, 0x6C, 0xA3, 0x98, 0x40, 0x87, 0x78, 0x9C, 0x1E, 0x05, 0xA0, 0xC2, 0xD7, 0x3A, 0xD3, 0xFF, 0x1C, 0xE6, 0x7C, 0x39, 0xC4, 0xFD, 0xBD, 0x13, 0x2C, 0x4E, 0xD7, 0xC8, 0xAD, 0x98, 0x08, 0x79, 0x5B, 0xF2, 0x30, 0xFA, 0x14};
const uint8_t PAIx[56] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t PAIy[56] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
const uint8_t G2x[56] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xA9, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
const uint8_t G2y[56] = {0xAE, 0x05, 0xE9, 0x63, 0x4A, 0xD7, 0x04, 0x8D, 0xB3, 0x59, 0xD6, 0x20, 0x50, 0x86, 0xC2, 0xB0, 0x03, 0x6E, 0xD7, 0xA0, 0x35, 0x88, 0x4D, 0xD7, 0xB7, 0xE3, 0x6D, 0x72, 0x8A, 0xD8, 0xC4, 0xB8, 0x0D, 0x65, 0x65, 0x83, 0x3A, 0x2A, 0x30, 0x98, 0xBB, 0xBC, 0xB2, 0xBE, 0xD1, 0xCD, 0xA0, 0x6B, 0xDA, 0xEA, 0xFB, 0xCD, 0xEA, 0x93, 0x86, 0xED};
const uint8_t G3x[56] = {0x08, 0x65, 0x88, 0x6B, 0x91, 0x08, 0xAF, 0x64, 0x55, 0xBD, 0x64, 0x31, 0x6C, 0xB6, 0x94, 0x33, 0x32, 0x24, 0x1B, 0x8B, 0x8C, 0xDA, 0x82, 0xC7, 0xE2, 0xBA, 0x07, 0x7A, 0x4A, 0x3F, 0xCF, 0xE8, 0xDA, 0xA9, 0xCB, 0xF7, 0xF6, 0x27, 0x1F, 0xD6, 0xE8, 0x62, 0xB7, 0x69, 0x46, 0x5D, 0xA8, 0x57, 0x57, 0x28, 0x17, 0x32, 0x86, 0xFF, 0x2F, 0x8F};
const uint8_t G3y[56] = {0xE0, 0x05, 0xA8, 0xDB, 0xD5, 0x12, 0x5C, 0xF7, 0x06, 0xCB, 0xDA, 0x7A, 0xD4, 0x3A, 0xA6, 0x44, 0x9A, 0x4A, 0x8D, 0x95, 0x23, 0x56, 0xC3, 0xB9, 0xFC, 0xE4, 0x3C, 0x82, 0xEC, 0x4E, 0x1D, 0x58, 0xBB, 0x3A, 0x33, 0x1B, 0xDB, 0x67, 0x67, 0xF0, 0xBF, 0xFA, 0x9A, 0x68, 0xFE, 0xD0, 0x2D, 0xAF, 0xB8, 0x22, 0xAC, 0x13, 0x58, 0x8E, 0xD6, 0xFC};

/** Double the generator **/
void test_point_double_1(void)
{
    uint8_t outx[56], outy[56];
    int res;

    EcContext *ec_ctx;
    PointEd448 *G, *G2;

    memset(outx, 0xFF, sizeof outx);
    memset(outy, 0xFF, sizeof outy);

    ed448_new_context(&ec_ctx);
    res = ed448_new_point(&G, Gx, Gy, 56, ec_ctx);
    assert(res == 0);

    res = ed448_clone(&G2, G);
    assert(res == 0);

    res = ed448_double(G2);
    assert(res == 0);

    res = ed448_get_xy(outx, outy, 56, G2);
    assert(res == 0);

    /* Check */
    assert(0 == memcmp(outx, G2x, 56));
    assert(0 == memcmp(outy, G2y, 56));

    ed448_free_point(G);
    ed448_free_point(G2);
    ed448_free_context(ec_ctx);
}

/** Double the PAI **/
void test_point_double_2(void)
{
    uint8_t outx[56], outy[56];
    int res;

    EcContext *ec_ctx;
    PointEd448 *PAI;

    memset(outx, 0xFF, sizeof outx);
    memset(outy, 0xFF, sizeof outy);

    ed448_new_context(&ec_ctx);
    res = ed448_new_point(&PAI, PAIx, PAIy, 56, ec_ctx);
    assert(res == 0);

    res = ed448_double(PAI);
    assert(res == 0);

    res = ed448_get_xy(outx, outy, 56, PAI);
    assert(res == 0);

    /* Check */
    assert(0 == memcmp(outx, PAIx, 56));
    assert(0 == memcmp(outy, PAIy, 56));

    ed448_free_point(PAI);
    ed448_free_context(ec_ctx);
}

/** Add the generator to PAI **/
void test_point_add_1(void)
{
    uint8_t outx[56], outy[56];
    int res;

    EcContext *ec_ctx;
    PointEd448 *G, *PAI, *P;

    memset(outx, 0xFF, sizeof outx);
    memset(outy, 0xFF, sizeof outy);

    ed448_new_context(&ec_ctx);
    res = ed448_new_point(&G, Gx, Gy, 56, ec_ctx);
    assert(res == 0);
    res = ed448_new_point(&PAI, PAIx, PAIy, 56, ec_ctx);
    assert(res == 0);

    res = ed448_clone(&P, G);
    assert(res == 0);

    res = ed448_add(P, PAI);
    assert(res == 0);

    res = ed448_get_xy(outx, outy, 56, P);
    assert(res == 0);

    /* Check */
    assert(0 == memcmp(outx, Gx, 56));
    assert(0 == memcmp(outy, Gy, 56));

    ed448_free_point(G);
    ed448_free_point(PAI);
    ed448_free_point(P);
    ed448_free_context(ec_ctx);
}

/** Add the generator to itself **/
void test_point_add_2(void)
{
    uint8_t outx[56], outy[56];
    int res;

    EcContext *ec_ctx;
    PointEd448 *G, *G2;

    memset(outx, 0xFF, sizeof outx);
    memset(outy, 0xFF, sizeof outy);

    ed448_new_context(&ec_ctx);
    res = ed448_new_point(&G, Gx, Gy, 56, ec_ctx);
    assert(res == 0);

    res = ed448_clone(&G2, G);
    assert(res == 0);

    res = ed448_add(G2, G);
    assert(res == 0);

    res = ed448_get_xy(outx, outy, 56, G2);
    assert(res == 0);

    /* Check */
    assert(0 == memcmp(outx, G2x, 56));
    assert(0 == memcmp(outy, G2y, 56));

    ed448_free_point(G);
    ed448_free_point(G2);
    ed448_free_context(ec_ctx);
}

static void scale(PointEd448 *P, uint64_t *scale, EcContext *ec_ctx)
{
    uint64_t *scratch = P->wp->scratch;

    mont_mult(P->x, P->x, scale, scratch, ec_ctx->mont_ctx);
    mont_mult(P->y, P->y, scale, scratch, ec_ctx->mont_ctx);
    mont_mult(P->z, P->z, scale, scratch, ec_ctx->mont_ctx);
}

/** Add G to 2G **/
void test_point_add_3(void)
{
    uint8_t outx[56], outy[56];
    int res;

    EcContext *ec_ctx;
    PointEd448 *G, *G2, *G3;

    uint64_t *scale1, *scale2;

    memset(outx, 0xFF, sizeof outx);
    memset(outy, 0xFF, sizeof outy);

    ed448_new_context(&ec_ctx);
    res = ed448_new_point(&G, Gx, Gy, 56, ec_ctx);
    assert(res == 0);
    res = ed448_new_point(&G2, G2x, G2y, 56, ec_ctx);
    assert(res == 0);

    /** Let's scale Z coords by different factors, so that they are not equal nor 1 **/
    mont_number(&scale1, 1, ec_ctx->mont_ctx);
    mont_number(&scale2, 1, ec_ctx->mont_ctx);
    mont_set(scale1, 0xAABBCCDDEEFF, ec_ctx->mont_ctx);
    mont_set(scale2, 0xFFEEDDCCBBAA, ec_ctx->mont_ctx);
    scale(G, scale1, ec_ctx);
    scale(G2, scale2, ec_ctx);

    res = ed448_clone(&G3, G);
    assert(res == 0);

    res = ed448_add(G3, G2);
    assert(res == 0);

    res = ed448_get_xy(outx, outy, 56, G3);
    assert(res == 0);

    /* Check */
    assert(0 == memcmp(outx, G3x, 56));
    assert(0 == memcmp(outy, G3y, 56));

    ed448_free_point(G);
    ed448_free_point(G2);
    ed448_free_point(G3);
    ed448_free_context(ec_ctx);
    free(scale1);
    free(scale2);
}

void test_scalar_1(void)
{
    EcContext *ec_ctx;
    PointEd448 *G, *P, *G259;

    uint8_t outx[56], outy[56];
    int res;

    ed448_new_context(&ec_ctx);
    res = ed448_new_point(&G, Gx, Gy, 56, ec_ctx);
    assert(res == 0);
    res = ed448_clone(&P, G);
    assert(res == 0);

    /* Multiply by zero */
    res = ed448_scalar(P, (uint8_t*)"\x00", 1, 0);
    assert(res == 0);
    res = ed448_get_xy(outx, outy, 56, P);
    assert(res == 0);
    assert(0 == memcmp(outx, PAIx, 56));
    assert(0 == memcmp(outy, PAIy, 56));

    /* Multiply by one */
    res = ed448_copy(P, G);
    assert(res == 0);
    res = ed448_scalar(P, (uint8_t*)"\x01", 1, 0);
    assert(res == 0);
    res = ed448_get_xy(outx, outy, 56, P);
    assert(res == 0);
    assert(0 == memcmp(outx, Gx, 56));
    assert(0 == memcmp(outy, Gy, 56));

    /* Multiply by three */
    ed448_copy(P, G);
    res = ed448_scalar(P, (uint8_t*)"\x03", 1, 0);
    assert(res == 0);
    res = ed448_get_xy(outx, outy, 56, P);
    assert(res == 0);
    assert(0 == memcmp(outx, G3x, 56));
    assert(0 == memcmp(outy, G3y, 56));

    /* Multiply by 259 */
    ed448_new_point(&G259, Gx, Gy, 56, ec_ctx);
    for (unsigned i=1; i<259; i++)
        ed448_add(G259, G);
    ed448_copy(P, G);
    res = ed448_scalar(P, (uint8_t*)"\x01\x03", 2, 0);
    assert(res == 0);
    res = ed448_cmp(P, G259);
    assert(res == 0);

    ed448_free_point(G);
    ed448_free_point(G259);
    ed448_free_point(P);
    ed448_free_context(ec_ctx);
}

void test_cmp_1(void)
{
    EcContext *ec_ctx;
    PointEd448 *G, *G2, *P;
    uint64_t *scale1, *scale2;
    int res;

    ed448_new_context(&ec_ctx);
    res = ed448_new_point(&G, Gx, Gy, 56, ec_ctx);
    assert(res == 0);
    res = ed448_clone(&P, G);
    assert(res == 0);
    res = ed448_new_point(&G2, G2x, G2y, 56, ec_ctx);
    assert(res == 0);

    mont_number(&scale1, 1, ec_ctx->mont_ctx);
    mont_number(&scale2, 1, ec_ctx->mont_ctx);
    mont_set(scale1, 0xAABBCCDDEEFF, ec_ctx->mont_ctx);
    mont_set(scale2, 0xFFEEDDCCBBAA, ec_ctx->mont_ctx);
    scale(G, scale1, ec_ctx);
    scale(P, scale2, ec_ctx);

    res = ed448_cmp(P, G);
    assert(res == 0);

    res = ed448_cmp(G2, G);
    assert(res != 0);

    ed448_free_point(G);
    ed448_free_point(G2);
    ed448_free_point(P);
    ed448_free_context(ec_ctx);
    free(scale1);
    free(scale2);
}

void test_neg_1(void)
{
    EcContext *ec_ctx;
    PointEd448 *G, *P, *PAI;
    int res;

    ed448_new_context(&ec_ctx);
    res = ed448_new_point(&G, Gx, Gy, 56, ec_ctx);
    assert(res == 0);
    res = ed448_clone(&P, G);
    assert(res == 0);
    res = ed448_new_point(&PAI, PAIx, PAIy, 56, ec_ctx);
    assert(res == 0);

    ed448_neg(P);
    ed448_add(P, G);
    res = ed448_cmp(P, PAI);
    assert(res == 0);

    ed448_free_point(G);
    ed448_free_point(P);
    ed448_free_point(PAI);
    ed448_free_context(ec_ctx);
}

int main(void)
{
    test_point_double_1();
    test_point_double_2();
    test_point_add_1();
    test_point_add_2();
    test_point_add_3();
    test_scalar_1();
    test_cmp_1();
    test_neg_1();
    return 0;
}
