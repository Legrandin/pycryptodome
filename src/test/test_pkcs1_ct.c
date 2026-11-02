/*
 * Constant-time check of the PKCS#1 v1.5 and OAEP decoding ("ctgrind").
 * Secret inputs are marked as undefined memory: Valgrind memcheck then
 * reports every conditional jump and every memory access that depends
 * on them.
 * Run under:
 *     valgrind --error-exitcode=1 ./test_pkcs1_ct
 * The results are not checked here (see test_pkcs1.c and the Python tests).
 */

#include <string.h>
#include <valgrind/memcheck.h>
#include "common.h"

/* As in pkcs1_decode.c */
#define IR_NUM_LENGTHS 128

int pkcs1_decode(const uint8_t *em, size_t len_em_output,
                 const uint8_t *sentinel, size_t len_sentinel,
                 size_t expected_pt_len,
                 uint8_t *output);
int pkcs1_decode_implicit(const uint8_t *em, size_t len_em_output,
                          const uint8_t *am,
                          const uint8_t cl[IR_NUM_LENGTHS][2],
                          size_t expected_pt_len,
                          uint8_t *output);
int oaep_decode(const uint8_t *em, size_t em_len,
                const uint8_t *lHash, size_t hLen,
                const uint8_t *db, size_t db_len);

#define MAX_K 512

static void fill(uint8_t *p, size_t len, uint8_t seed)
{
    size_t i;

    for (i=0; i<len; i++)
        p[i] = (uint8_t)(seed + 7*i + 1);
}

static void secret(void *p, size_t len)
{
    VALGRIND_MAKE_MEM_UNDEFINED(p, len);
}

static void run(size_t k)
{
    static uint8_t em[MAX_K], am[MAX_K], out[MAX_K], db[MAX_K];
    static uint8_t cl[IR_NUM_LENGTHS][2];
    uint8_t sentinel[16], lhash[32];
    const size_t hlen = sizeof lhash;
    volatile int res;

    /* The values do not matter: Valgrind follows the secret data */
    fill(em, k, 3);
    em[0] = 0;
    em[1] = 2;
    em[k - 20] = 0;
    fill(am, k, 9);
    fill(&cl[0][0], sizeof cl, 5);
    fill(db, k - 1 - hlen, 6);
    fill(sentinel, sizeof sentinel, 1);
    fill(lhash, sizeof lhash, 4);

    /* The output of RSA decryption, and what is derived from it */
    secret(em, k);
    secret(am, k);
    secret(cl, sizeof cl);
    secret(db, k - 1 - hlen);

    /* PKCS#1 v1.5, with a sentinel (a byte string) */
    res = pkcs1_decode(em, k, sentinel, sizeof sentinel, 0, out);
    res = pkcs1_decode(em, k, sentinel, sizeof sentinel, 16, out);

    /* PKCS#1 v1.5, with implicit rejection */
    res = pkcs1_decode_implicit(em, k, am, (const uint8_t (*)[2])cl, 0, out);
    res = pkcs1_decode_implicit(em, k, am, (const uint8_t (*)[2])cl, 16, out);

    /* OAEP (the validity of the padding is public afterwards) */
    res = oaep_decode(em, k, lhash, hlen, db, k - 1 - hlen);

    (void)res;
}

int main(void)
{
    run(128);
    run(256);
    run(257);
    run(MAX_K);
    return 0;
}
