#include "common.h"
#include "ec.h"
#include "endianess.h"

#define BITS    256
#define BYTES   BITS/8
#define WORDS   BITS/64

int main(void)
{
    const uint8_t p256_mod[32] = "\xff\xff\xff\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    const uint8_t  b[32] = "\x5a\xc6\x35\xd8\xaa\x3a\x93\xe7\xb3\xeb\xbd\x55\x76\x98\x86\xbc\x65\x1d\x06\xb0\xcc\x53\xb0\xf6\x3b\xce\x3c\x3e\x27\xd2\x60\x4b";
    const uint8_t order[32] = "\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xbc\xe6\xfa\xad\xa7\x17\x9e\x84\xf3\xb9\xca\xc2\xfc\x63\x25\x51";
    const uint8_t p256_Gx[32] = "\x6b\x17\xd1\xf2\xe1\x2c\x42\x47\xf8\xbc\xe6\xe5\x63\xa4\x40\xf2\x77\x03\x7d\x81\x2d\xeb\x33\xa0\xf4\xa1\x39\x45\xd8\x98\xc2\x96";
    const uint8_t p256_Gy[32] = "\x4f\xe3\x42\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xeb\x4a\x7c\x0f\x9e\x16\x2b\xce\x33\x57\x6b\x31\x5e\xce\xcb\xb6\x40\x68\x37\xbf\x51\xf5";
    uint8_t xz[32] = { 0 }, yz[32] = { 0 };
    EcContext *ec_ctx;
    EcPoint *g = NULL;
    EcPoint **base_window = NULL;
    int i, j, k;
    unsigned n_tables, points_per_table, window_size;

    ec_ws_new_context(&ec_ctx, p256_mod, b, order, 32);
    ec_ws_new_point(&g, p256_Gx, p256_Gy, 32, ec_ctx, FALSE);

    /** TODO: accept this as input **/
    window_size = 5;

    points_per_table = 1 << window_size;
    n_tables = (256+window_size-1)/window_size;

    /** Create table with points 0, G, 2G, 3G, .. (2**window_size-1)G **/
    base_window = (EcPoint**)calloc(points_per_table, sizeof(EcPoint*));
    ec_ws_new_point(&base_window[0], xz, yz, 32, ec_ctx, FALSE);
    for (i=1; i<points_per_table; i++) {
        ec_ws_clone(&base_window[i], base_window[i-1]);
        ec_ws_add(base_window[i], g);
    }

    printf("/* This file was automatically generated, do not edit */\n");
    printf("#include <stdint.h>\n");
    printf("static const unsigned p256_n_tables = %d;\n", n_tables);
    printf("static const unsigned p256_window_size = %d;\n", window_size);
    printf("static const unsigned p256_points_per_table = %d;\n", points_per_table);
    printf("/* Affine coordinates in Montgomery form */\n");
    printf("static const uint64_t p256_tables[%d][%d][2][4] = {\n", n_tables, points_per_table);

    for (i=0; i<n_tables; i++) {

        printf(" { /* Table #%d */\n", i);
        for (j=0; j<points_per_table; j++) {
            uint64_t xw[4], yw[4];

            ec_ws_normalize(base_window[j]);
            if (ec_ws_is_pai(base_window[j])) {
                memset(xw, 0, sizeof xw);
                memset(yw, 0, sizeof yw);
            } else {
                memcpy(xw, base_window[j]->x, sizeof xw);
                memcpy(yw, base_window[j]->y, sizeof yw);
            }

            printf("  { /* Point #%d */\n", j);
            printf("    { ");
            for (k=0; k<4; k++) {
                printf("0x%016lX%s", xw[k], k==3 ? "" : ",");
            }
            printf(" },\n");
            printf("    { ");
            for (k=0; k<4; k++) {
                printf("0x%016lX%s", yw[k], k==3 ? "" : ",");
            }
            printf(" }\n");
            printf("  }%s\n", j==points_per_table-1 ? "" : ",");
        }
        printf(" }%s\n", i==n_tables-1 ? "" : ",");

        /* Multiply G by 2^window_size */
        for (j=0; j<window_size; j++)
            ec_ws_double(g);

        for (j=0; j<points_per_table; j++)
            ec_ws_add(base_window[j], g);
    }

    printf("};\n");

    for (i=0; i<points_per_table; i++) {
        ec_free_point(base_window[i]);
    }
    free(base_window);
    ec_free_point(g);
    ec_free_context(ec_ctx);

    return 0;
}
