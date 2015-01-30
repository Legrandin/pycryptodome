#ifndef _BLOCK_BASE
#define _BLOCK_BASE

#include <stdint.h>
#include "errors.h"

typedef struct _BlockBase BlockBase;

typedef int (*CipherOperation)(const BlockBase *state, const uint8_t *in, uint8_t *out, size_t data_len);

typedef struct _BlockBase {
    CipherOperation encrypt;
    CipherOperation decrypt;
    int (*destructor)(BlockBase *state);
    size_t block_len;
} BlockBase;

#endif
