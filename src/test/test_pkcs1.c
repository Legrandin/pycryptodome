#include "common.h"

size_t propagate_ones(uint8_t x);
void set_if_match(uint8_t *flag, size_t term1, size_t term2);
void set_if_no_match(uint8_t *flag, size_t term1, size_t term2);
void safe_select(const uint8_t *in1, const uint8_t *in2, uint8_t *out, uint8_t choice, size_t len);
size_t safe_select_idx(size_t in1, size_t in2, uint8_t choice);
uint8_t safe_cmp_masks(const uint8_t *in1, const uint8_t *in2,
                 const uint8_t *eq_mask, const uint8_t *neq_mask,
                 size_t len);
int safe_search(const uint8_t *in1, uint8_t c, size_t len, size_t *pos);
/* As in pkcs1_decode.c */
#define IR_NUM_LENGTHS 128

size_t select_alt_length(const uint8_t cl[IR_NUM_LENGTHS][2], size_t max_len);
int pkcs1_decode_implicit(const uint8_t *em, size_t len_em_output,
                          const uint8_t *am,
                          const uint8_t cl[IR_NUM_LENGTHS][2],
                          size_t expected_pt_len,
                          uint8_t *output);

const uint8_t one[] = "1";
const uint8_t zero[] = "0";
const uint8_t onezero[] = "10";
const uint8_t oneone[] = "11";
const uint8_t zeroone[] = "01";
const uint8_t zerozero[] = "00";

void test_propagate_ones(void)
{
    unsigned i;

    assert(propagate_ones(0) == 0);
    for (i=0; i<8; i++) {
        size_t res;
        res = propagate_ones((size_t)1 << i);
        assert(res == (size_t)-1);
    }
}

void test_set_if_match(void)
{
    uint8_t x;

    x = 1;
    set_if_match(&x, 0, 0);
    assert(x == 0xFF);

    x = 1;
    set_if_match(&x, 1, 2);
    assert(x == 1);
}

void test_set_if_no_match(void)
{
    uint8_t x;

    x = 1;
    set_if_no_match(&x, 1, 2);
    assert(x == 0xFF);

    x = 1;
    set_if_no_match(&x, 0, 0);
    assert(x == 1);
}

void test_safe_select(void)
{
    uint8_t out[10];

    safe_select(one, zero, out, 0, 1);
    assert(memcmp(one, out, 1) == 0);

    safe_select(one, zero, out, 1, 1);
    assert(memcmp(zero, out, 1) == 0);

    safe_select(onezero, zerozero, out, 0, 2);
    assert(memcmp(onezero, out, 1) == 0);

    safe_select(onezero, zerozero, out, 01, 2);
    assert(memcmp(zerozero, out, 1) == 0);
}

void test_safe_select_idx(void)
{
    assert(safe_select_idx(0, 1, 0) == 0);
    assert(safe_select_idx(0, 1, 1) == 1);
    assert(safe_select_idx(0x100004, 0x223344, 0) == 0x100004);
    assert(safe_select_idx(0x100004, 0x223344, 1) == 0x223344);
}

void test_safe_cmp_masks(void)
{
    uint8_t res;

    res = safe_cmp_masks(onezero, onezero,
                   (uint8_t*)"\xFF\xFF",
                   (uint8_t*)"\x00\x00",
                   2);
    assert(res == 0);

    res = safe_cmp_masks(onezero, zerozero,
                   (uint8_t*)"\xFF\xFF",
                   (uint8_t*)"\x00\x00",
                   2);
    assert(res != 0);

    res = safe_cmp_masks(onezero, oneone,
                   (uint8_t*)"\xFF\xFF",
                   (uint8_t*)"\x00\x00",
                   2);
    assert(res != 0);

    res = safe_cmp_masks(onezero, oneone,
                   (uint8_t*)"\xFF\x00",
                   (uint8_t*)"\x00\x00",
                   2);
    assert(res == 0);

    /** -- **/

    res = safe_cmp_masks(onezero, onezero,
                   (uint8_t*)"\x00\x00",
                   (uint8_t*)"\xFF\xFF",
                   2);
    assert(res != 0);

    res = safe_cmp_masks(oneone, zerozero,
                   (uint8_t*)"\x00\x00",
                   (uint8_t*)"\xFF\xFF",
                   2);
    assert(res == 0);

    res = safe_cmp_masks(onezero, oneone,
                   (uint8_t*)"\x00\x00",
                   (uint8_t*)"\x00\xFF",
                   2);
    assert(res == 0);

    /** -- **/

    res = safe_cmp_masks(onezero, oneone,
                   (uint8_t*)"\xFF\x00",
                   (uint8_t*)"\x00\xFF",
                   2);
    assert(res == 0);
}

void test_safe_search(void)
{
    size_t pos;

    assert(safe_search((uint8_t*)"ABCDEFB", 0x41, 6, &pos) == 0);
    assert(pos == 0);

    assert(safe_search((uint8_t*)"ABCDEFB", 0x42, 6, &pos) == 0);
    assert(pos == 1);

    assert(safe_search((uint8_t*)"ABCDEFB", 0x47, 6, &pos) == 0);
    assert(pos == 6);

    /* Errors */
    assert(safe_search(NULL, 0x41, 6, &pos) == -1);
    assert(safe_search((uint8_t*)"ABCDEFB", 0x41, 0, &pos) == -1);
    assert(safe_search((uint8_t*)"ABCDEFB", 0x41, 6, NULL) == -1);
}

/*
 * Set the candidate length with index i (0..IR_NUM_LENGTHS-1) in cl[]
 * to value, encoded in big endian as the IRPRF output.
 */
static void set_cl(uint8_t cl[IR_NUM_LENGTHS][2], unsigned i, unsigned value)
{
    cl[i][0] = (uint8_t)(value >> 8);
    cl[i][1] = (uint8_t)value;
}

/*
 * Call select_alt_length() and pkcs1_decode_implicit() on a modifiable cl[]
 * (in C, there is no implicit conversion to a pointer to const arrays).
 */
static size_t alt_length(uint8_t cl[IR_NUM_LENGTHS][2], size_t max_len)
{
    return select_alt_length((const uint8_t (*)[2])cl, max_len);
}

static int decode_implicit(const uint8_t *em, size_t len_em, const uint8_t *am,
                           uint8_t cl[IR_NUM_LENGTHS][2],
                           size_t expected_pt_len, uint8_t *output)
{
    return pkcs1_decode_implicit(em, len_em, am, (const uint8_t (*)[2])cl,
                                 expected_pt_len, output);
}

void test_select_alt_length(void)
{
    uint8_t cl[IR_NUM_LENGTHS][2];

    /* All candidates too long: 0 */
    memset(cl, 0xFF, sizeof cl);
    assert(alt_length(cl, 245) == 0);

    /* The last candidate that fits wins */
    set_cl(cl, 3, 17);
    set_cl(cl, 100, 245);
    assert(alt_length(cl, 245) == 245);

    /* High bits are masked to the bit length of max_len (8 bits for 245) */
    set_cl(cl, IR_NUM_LENGTHS - 1, 0x1234);    /* 0x34 = 52 */
    assert(alt_length(cl, 245) == 52);

    /* After masking, 0xF6 = 246 is too long: the previous one is taken */
    set_cl(cl, IR_NUM_LENGTHS - 1, 0xAAF6);
    assert(alt_length(cl, 245) == 245);

    /* 9 bits for 256 */
    set_cl(cl, IR_NUM_LENGTHS - 1, 0xFF00);    /* 0x100 = 256 */
    assert(alt_length(cl, 256) == 256);

    memset(cl, 0, sizeof cl);
    assert(alt_length(cl, 1) == 0);
    set_cl(cl, 0, 0xFFFF);
    assert(alt_length(cl, 1) == 0);
    set_cl(cl, IR_NUM_LENGTHS - 1, 0xFFFF);
    assert(alt_length(cl, 1) == 1);
}

void test_pkcs1_decode_implicit(void)
{
    uint8_t em[32], am[32], cl[IR_NUM_LENGTHS][2], out[32];
    int res;
    unsigned i;

    for (i=0; i<sizeof am; i++)
        am[i] = (uint8_t)(0xA0 + i);
    memset(cl, 0, sizeof cl);
    set_cl(cl, IR_NUM_LENGTHS - 1, 5);

    /* Correct padding, 3 bytes of plaintext */
    memset(em, 0x11, sizeof em);
    em[0] = 0;
    em[1] = 2;
    em[28] = 0;
    res = decode_implicit(em, sizeof em, am, cl, 0, out);
    assert(res == 29);
    assert(memcmp(out, em, sizeof em) == 0);

    /* With the right expected length */
    res = decode_implicit(em, sizeof em, am, cl, 3, out);
    assert(res == 29);
    assert(memcmp(out, em, sizeof em) == 0);

    /* With the wrong expected length: the last 4 bytes of am */
    res = decode_implicit(em, sizeof em, am, cl, 4, out);
    assert(res == 28);
    assert(memcmp(out, am, sizeof am) == 0);

    /* Wrong padding: the last 5 bytes of am */
    em[1] = 1;
    res = decode_implicit(em, sizeof em, am, cl, 0, out);
    assert(res == 27);
    assert(memcmp(out, am, sizeof am) == 0);

    /* Bad parameters */
    assert(decode_implicit(NULL, sizeof em, am, cl, 0, out) == -1);
    assert(decode_implicit(em, sizeof em, NULL, cl, 0, out) == -1);
    assert(pkcs1_decode_implicit(em, sizeof em, am, NULL, 0, out) == -1);
    assert(decode_implicit(em, sizeof em, am, cl, 0, NULL) == -1);
    assert(decode_implicit(em, 11, am, cl, 0, out) == -1);
    assert(decode_implicit(em, sizeof em, am, cl, 22, out) == -1);
}

int main(void)
{
    test_propagate_ones();
    test_set_if_match();
    test_set_if_no_match();
    test_safe_select();
    test_safe_select_idx();
    test_safe_cmp_masks();
    test_safe_search();
    test_select_alt_length();
    test_pkcs1_decode_implicit();
    return 0;
}
