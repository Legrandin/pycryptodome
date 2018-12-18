#ifndef _MONT_H
#define _MONT_H

#include "common.h"

typedef struct mont_context {
    unsigned words;
    unsigned bytes;
    uint64_t *modulus;
    uint64_t *one;
    uint64_t *r2_mod_n;     /* R^2 mod N */ 
    uint64_t m0;
} MontContext;

size_t mont_bytes(MontContext *ctx);
int mont_context_init(MontContext **out, const uint8_t *modulus, size_t mod_len);
int mont_from_bytes(uint64_t **out, const MontContext *ctx, const uint8_t *number, size_t len);
int mont_to_bytes(uint8_t *number, const MontContext *ctx, const uint64_t* mont_number);

#endif
