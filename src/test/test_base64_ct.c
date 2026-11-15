/*
 * Constant-time check of the base64 decoding ("ctgrind").
 * The data characters are marked as undefined memory: Valgrind memcheck
 * then reports every conditional jump and every memory access that
 * depends on them. Whitespace and padding are public.
 * Run under:
 *     valgrind --error-exitcode=1 ./test_base64_ct
 * The results are not checked here (see test_base64.c and the Python tests).
 */

#include <string.h>
#include <valgrind/memcheck.h>
#include "common.h"

int base64_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_size);

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define LINE 64

/*
 * Lines of LINE characters, with a CRLF after each of them,
 * and n_data characters followed by the padding.
 * Only the data characters are secret.
 */
static void run(size_t n_data)
{
    static uint8_t text[4096], out[4096];
    size_t i, len;
    volatile int res;

    len = 0;
    for (i=0; i<n_data + (4 - n_data % 4) % 4; i++) {
        if (i > 0 && i % LINE == 0) {
            text[len++] = '\r';
            text[len++] = '\n';
        }
        if (i < n_data) {
            text[len] = (uint8_t)alphabet[(i * 29 + 3) % 64];
            VALGRIND_MAKE_MEM_UNDEFINED(&text[len], 1);
        } else {
            text[len] = '=';
        }
        len++;
    }
    text[len++] = '\n';

    res = base64_decode(text, len, out, sizeof out);
    (void)res;
}

int main(void)
{
    run(4 * 100);
    run(4 * 100 + 2);
    run(4 * 100 + 3);
    return 0;
}
