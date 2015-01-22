#ifndef _BLOCK_BASE
#define _BLOCK_BASE

#include <stdint.h>

typedef struct _BlockBase BlockBase;

typedef int (*CipherOperation)(const BlockBase *state, const uint8_t *in, uint8_t *out, size_t data_len);

typedef struct _BlockBase {
    CipherOperation encrypt;
    CipherOperation decrypt;
    int (*destructor)(BlockBase *state);
    size_t block_len;
} BlockBase;

/** Standard errors common to all ciphers **/
#define ERR_NULL                1
#define ERR_MEMORY              2
#define ERR_NOT_ENOUGH_DATA     3
#define ERR_ENCRYPT             4
#define ERR_DECRYPT             5
#define ERR_KEY_SIZE            6
#define ERR_NR_ROUNDS           7
#define ERR_UNKNOWN             8

#endif
