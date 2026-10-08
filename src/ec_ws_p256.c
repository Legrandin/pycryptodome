/*
 * SPDX-FileCopyrightText: 2018 Helder Eijs <helderijs@gmail.com>
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>

#include "common.h"
#include "endianess.h"
#include "multiply.h"
#include "mont.h"
#include "ec.h"
#include "modexp_utils.h"

#include <sys/time.h>

#include "ec_ws.c"

int main(void)
{
    const uint8_t p256_mod[32] = "\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    const uint8_t  b[32] = "\x5a\xc6\x35\xd8\xaa\x3a\x93\xe7\xb3\xeb\xbd\x55\x76\x98\x86\xbc\x65\x1d\x06\xb0\xcc\x53\xb0\xf6\x3b\xce\x3c\x3e\x27\xd2\x60\x4b";
    const uint8_t order[32] = "\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51";
    const uint8_t p256_Gx[32] = "\x6b\x17\xd1\xf2\xe1\x2c\x42\x47\xf8\xbc\xe6\xe5\x63\xa4\x40\xf2\x77\x03\x7d\x81\x2d\xeb\x33\xa0\xf4\xa1\x39\x45\xd8\x98\xc2\x96";
    const uint8_t p256_Gy[32] = "\x4f\xe3\x42\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xeb\x4a\x7c\x0f\x9e\x16\x2b\xce\x33\x57\x6b\x31\x5e\xce\xcb\xb6\x40\x68\x37\xbf\x51\xf5";
    uint8_t x[32], y[32];
    uint8_t exp[32];
    EcContext *ec_ctx;
    EcPoint *ecp = NULL;
    EcPoint *gp = NULL;
    unsigned i;
    struct timeval start, stop;
    double duration_ms, rate;
    int res;

#define ITERATIONS 1000U

    /* Make almost-worst case exponent */
    for (i=0; i<32; i++) {
        exp[i] = (uint8_t)(0xFF - i);
    }

    res = ec_ws_new_context(&ec_ctx, p256_mod, b, order, 32, /* seed */ 4);
    assert(res == 0);

    res = ec_ws_new_point(&gp, p256_Gx, p256_Gy, 32, ec_ctx);
    assert(res == 0);

    res = ec_ws_clone(&ecp, gp);
    assert(res == 0);

    /** Scalar multiplications by G **/
    gettimeofday(&start, NULL);
    for (i=0; i<ITERATIONS; i++) {
        res = ec_ws_copy(ecp, gp);
        assert(res == 0);

        res = ec_ws_scalar(ecp, exp, 32, 0xFFF);
        assert(res == 0);

        res = ec_ws_get_xy(x, y, 32, ecp);
        assert(res == 0);
    }
    gettimeofday(&stop, NULL);
    duration_ms = (double)(stop.tv_sec - start.tv_sec) * 1000 + (double)(stop.tv_usec - start.tv_usec) / 1000;
    rate = ITERATIONS / (duration_ms/1000);
    printf("Speed (scalar mult by G) = %.0f op/s\n", rate);

    res = ec_ws_get_xy(x, y, 32, ecp);
    assert(res == 0);

    printf("X: ");
    for (i=0; i<32; i++)
        printf("%02X", x[i]);
    printf("\n");
    printf("Y: ");
    for (i=0; i<32; i++)
        printf("%02X", y[i]);
    printf("\n");

#if 1
    /** Scalar multiplications by arbitrary point **/
    res = ec_ws_double(ecp);
    assert(res == 0);

    gettimeofday(&start, NULL);
    for (i=0; i<ITERATIONS; i++) {
        res = ec_ws_scalar(ecp, exp, 32, 0xFFF);
        assert(res == 0);

        res = ec_ws_get_xy(x, y, 32, ecp);
        assert(res == 0);
    }
    gettimeofday(&stop, NULL);
    duration_ms = (double)(stop.tv_sec - start.tv_sec) * 1000 + (double)(stop.tv_usec - start.tv_usec) / 1000;
    rate = ITERATIONS / (duration_ms/1000);
    printf("Speed (scalar mult by P) = %.0f op/s\n", rate);

    res = ec_ws_get_xy(x, y, 32, ecp);
    assert(res == 0);
    printf("X: ");
    for (i=0; i<32; i++)
        printf("%02X", x[i]);
    printf("\n");
    printf("Y: ");
    for (i=0; i<32; i++)
        printf("%02X", y[i]);
    printf("\n");
#endif

    ec_ws_free_point(gp);
    ec_ws_free_point(ecp);
    ec_ws_free_context(ec_ctx);

    return 0;
}
