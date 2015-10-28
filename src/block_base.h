#ifndef _BLOCK_BASE
#define _BLOCK_BASE

#include "pycrypto_common.h"

struct _BlockBase;

typedef int (*CipherOperation)(const struct _BlockBase *state, const uint8_t *in, uint8_t *out, size_t data_len);

typedef struct _BlockBase {
    CipherOperation encrypt;
    CipherOperation decrypt;
    int (*destructor)(struct _BlockBase *state);
    size_t block_len;
} BlockBase;

#endif
