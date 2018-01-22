#include "montgomery_utils.h"
#include "siphash.h"

#if 0
static void print_words_w(const uint8_t *str, const uint64_t *x, unsigned words)
{
    int i;
    printf("%s = 0x", str);
    for (i=words-1; i>=0; i--) {
        printf("%016" PRIx64, x[i]);
    }
    printf("\n");
}
#endif

void bytes_to_words(uint64_t *x, const uint8_t *in, size_t len, size_t words)
{
    int i, j;
    size_t partial;

    if (words == 0 || len == 0) {
        return;
    }

    assert(len<=words*8);
    assert(len>(words-1)*8);

    memset(x, 0, words*8);

    partial = len % 8;
    if (partial == 0) {
        partial = 8;
    }

    for (j=0; j<partial; j++) {
        x[words-1] = (x[words-1] << 8) | *in++;
    }

    if (words == 1) {
        return;
    }

    for (i=words-2; i>=0; i--) {
        for (j=0; j<8; j++) {
            x[i] = (x[i] << 8) | *in++;
        }
    }
}

void words_to_bytes(uint8_t *out, const uint64_t *x, size_t len, size_t words)
{
    int i, j;
    size_t partial;

    if (words == 0 || len == 0) {
        return;
    }

    assert(len<=words*8);
    assert(len>(words-1)*8);

    partial = len % 8;
    if (partial == 0) {
        partial = 8;
    }

    for (j=partial-1; j>=0; j--) {
        *out++ = (uint8_t)(x[words-1] >> (8*j));
    }

    if (words == 1) {
        return;
    }

    for (i=words-2; i>=0; i--) {
        for (j=7; j>=0; j--) {
            *out++ = x[i] >> (8*j);
        }
    }
}

void expand_seed(uint64_t seed_in, uint8_t* seed_out, size_t out_len)
{
    uint8_t counter[4];
    int i;

#define SIPHASH_LEN 16
    
    for (i=0 ;; i++, out_len-=SIPHASH_LEN) {
        counter[0] = i;
        counter[1] = i>>8;
        counter[2] = i>>16;
        counter[3] = i>>24;
        if (out_len<SIPHASH_LEN)
            break;
        siphash(counter, 4, (const uint8_t*)&seed_in, seed_out, SIPHASH_LEN);
        seed_out += 16;
    }

    if (out_len>0) {
        uint8_t buffer[SIPHASH_LEN];
        siphash(counter, 4, (const uint8_t*)&seed_in, buffer, SIPHASH_LEN);
        memcpy(seed_out, buffer, out_len);
    }

#undef SIPHASH_LEN
}

struct BitWindow init_bit_window(int window_size, const uint8_t *exp, int exp_len)
{
    struct BitWindow bw;

    bw.window_size = window_size;
    bw.nr_windows = (exp_len*8+window_size-1)/window_size;

    bw.tg = (exp_len*8) % window_size;
    if (bw.tg == 0) {
        bw.tg = window_size;
    }

    bw.available = 8;
    bw.scan_exp = 0;
    bw.exp = exp;

    return bw;
}

#define MIN(a,b) (a<b?(a):(b))

int get_next_digit(struct BitWindow *bw)
{
    int tc, index;

    /** Possibly move to the next byte **/
    if (bw->available == 0) {
        bw->available = 8;
        bw->scan_exp++;
    }

    /** Try to consume as much as possible from the current byte **/
    tc = MIN(bw->tg, bw->available);
    
    index = (bw->exp[bw->scan_exp] >> (bw->available - tc)) & ((1 << tc) - 1);
    
    bw->available -= tc;
    bw->tg -= tc;
        
    /** A few bits (<8) might still be needed from the next byte **/
    if (bw->tg > 0) {
        bw->scan_exp++;
        index = (index << bw->tg) | (bw->exp[bw->scan_exp] >> (8 - bw->tg));
        bw->available = 8 - bw->tg;
    }

    bw->tg = bw->window_size;

    return index;
}

