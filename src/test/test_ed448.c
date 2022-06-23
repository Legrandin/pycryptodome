#include "ed448.h"
#include "mont.h"
#include <assert.h>

const uint8_t Gx[56] = "\x4f\x19\x70\xc6\x6b\xed\x0d\xed\x22\x1d\x15\xa6\x22\xbf\x36\xda\x9e\x14\x65\x70\x47\x0f\x17\x67\xea\x6d\xe3\x24\xa3\xd3\xa4\x64\x12\xae\x1a\xf7\x2a\xb6\x65\x11\x43\x3b\x80\xe1\x8b\x00\x93\x8e\x26\x26\xa8\x2b\xc7\x0c\xc0\x5e";
const uint8_t Gy[56] = "\x69\x3f\x46\x71\x6e\xb6\xbc\x24\x88\x76\x20\x37\x56\xc9\xc7\x62\x4b\xea\x73\x73\x6c\xa3\x98\x40\x87\x78\x9c\x1e\x05\xa0\xc2\xd7\x3a\xd3\xff\x1c\xe6\x7c\x39\xc4\xfd\xbd\x13\x2c\x4e\xd7\xc8\xad\x98\x08\x79\x5b\xf2\x30\xfa\x14";
const uint8_t PAIx[56] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
const uint8_t PAIy[56] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
const uint8_t G2x[56] = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xa9\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55";
const uint8_t G2y[56] = "\xae\x05\xe9\x63\x4a\xd7\x04\x8d\xb3\x59\xd6\x20\x50\x86\xc2\xb0\x03\x6e\xd7\xa0\x35\x88\x4d\xd7\xb7\xe3\x6d\x72\x8a\xd8\xc4\xb8\x0d\x65\x65\x83\x3a\x2a\x30\x98\xbb\xbc\xb2\xbe\xd1\xcd\xa0\x6b\xda\xea\xfb\xcd\xea\x93\x86\xed";
const uint8_t G3x[56] = "\x08\x65\x88\x6b\x91\x08\xaf\x64\x55\xbd\x64\x31\x6c\xb6\x94\x33\x32\x24\x1b\x8b\x8c\xda\x82\xc7\xe2\xba\x07\x7a\x4a\x3f\xcf\xe8\xda\xa9\xcb\xf7\xf6\x27\x1f\xd6\xe8\x62\xb7\x69\x46\x5d\xa8\x57\x57\x28\x17\x32\x86\xff\x2f\x8f";
const uint8_t G3y[56] = "\xe0\x05\xa8\xdb\xd5\x12\x5c\xf7\x06\xcb\xda\x7a\xd4\x3a\xa6\x44\x9a\x4a\x8d\x95\x23\x56\xc3\xb9\xfc\xe4\x3c\x82\xec\x4e\x1d\x58\xbb\x3a\x33\x1b\xdb\x67\x67\xf0\xbf\xfa\x9a\x68\xfe\xd0\x2d\xaf\xb8\x22\xac\x13\x58\x8e\xd6\xfc";

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
void test_point_double_2()
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
