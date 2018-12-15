#include "montgomery_utils.h"
#include "siphash.h"
#include "endianess.h"

void expand_seed(uint64_t seed_in, uint8_t* seed_out, size_t out_len)
{
    uint8_t counter[4];
    uint8_t seed_in_b[16];
    uint32_t i;

    for (i=0; i<8; i++) {
        seed_in_b[2*i] = seed_in_b[2*i+1] = (uint8_t)(seed_in >> (i*8));
    }

#define SIPHASH_LEN 16
    
    for (i=0 ;; i++, out_len-=SIPHASH_LEN) {
        STORE_U32_LITTLE(counter, i);
        if (out_len<SIPHASH_LEN)
            break;
        siphash(counter, 4, seed_in_b, seed_out, SIPHASH_LEN);
        seed_out += SIPHASH_LEN;
    }

    if (out_len>0) {
        uint8_t buffer[SIPHASH_LEN];
        siphash(counter, 4, seed_in_b, buffer, SIPHASH_LEN);
        memcpy(seed_out, buffer, out_len);
    }

#undef SIPHASH_LEN
}

struct BitWindow init_bit_window(unsigned window_size, const uint8_t *exp, size_t exp_len)
{
    struct BitWindow bw;

    bw.window_size = window_size;
    bw.nr_windows = (unsigned)((exp_len*8+window_size-1)/window_size);

    bw.tg = (unsigned)((exp_len*8) % window_size);
    if (bw.tg == 0) {
        bw.tg = window_size;
    }

    bw.available = 8;
    bw.scan_exp = 0;
    bw.exp = exp;

    return bw;
}

unsigned get_next_digit(struct BitWindow *bw)
{
    unsigned tc, index;

    /** Possibly move to the next byte **/
    if (bw->available == 0) {
        bw->available = 8;
        bw->scan_exp++;
    }

    /** Try to consume as much as possible from the current byte **/
    tc = MIN(bw->tg, bw->available);
    
    index = ((unsigned)bw->exp[bw->scan_exp] >> ((unsigned)bw->available - tc)) & ((1U << tc) - 1);
    
    bw->available -= tc;
    bw->tg -= tc;
        
    /** A few bits (<8) might still be needed from the next byte **/
    if (bw->tg > 0) {
        bw->scan_exp++;
        index = (index << bw->tg) | ((unsigned)bw->exp[bw->scan_exp] >> (8 - bw->tg));
        bw->available = 8 - bw->tg;
    }

    bw->tg = bw->window_size;

    return index;
}

