/*
 * This is a program to generate certain test vectors for cSHAKE128 and cSHAKE256.
 */
#include <stdlib.h>
#include <stdio.h>

#include "SP800-185.h"

typedef int (*cSHAKE)(const BitSequence *input, BitLength inputBitLen, BitSequence *output, BitLength outputBitLen, const BitSequence *name, BitLength nameBitLen, const BitSequence *customization, BitLength customBitLen );

uint8_t* datahex(const char* string) {

    if(string == NULL)
       return NULL;

    size_t slength = strlen(string);
    if((slength % 2) != 0) // must be even
       return NULL;

    size_t dlength = slength / 2;

    uint8_t* data = malloc(dlength);
    memset(data, 0, dlength);

    size_t index = 0;
    while (index < slength) {
        char c = string[index];
        int value = 0;
        if(c >= '0' && c <= '9')
          value = (c - '0');
        else if (c >= 'A' && c <= 'F')
          value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
          value = (10 + (c - 'a'));
        else {
          free(data);
          return NULL;
        }

        data[(index/2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}

void printhex(const char *prefix, const unsigned char *b, size_t len)
{
    if (len == 0) {
        printf("%s00\n", prefix);
        return;
    }

    printf("%s", prefix);
    for (; len>0; len--, b++) {
        printf("%02X", *b);
    }
    printf("\n");
}

static unsigned index_test = 1;

void make_test_vector(const char* message_hex, const char *custom_hex, const char *function_hex, unsigned md_len, cSHAKE func)
{
    unsigned char *message_b;
    unsigned char *custom_b;
    unsigned char *function_b;
    unsigned char *md;

    unsigned message_len;
    unsigned custom_len;
    unsigned function_len;

    message_b = datahex(message_hex);
    message_len = message_hex ? strlen(message_hex) / 2 : 0;

    custom_b = datahex(custom_hex);
    custom_len = custom_hex ? strlen(custom_hex) / 2 : 0;

    function_b = datahex(function_hex);
    function_len = function_hex ? strlen(function_hex) / 2 : 0;

    md = malloc(md_len);

    printf("\n# Sample %d\n", index_test++);
    printf("NLen = %d\n", function_len*8);
    printf("SLen = %d\n", custom_len*8);
    printf("Len = %d\n", message_len*8);
    printhex("N = ", function_b, function_len);
    printhex("S = ", custom_b, custom_len);
    printhex("Msg = ", message_b, message_len);

    func(message_b, message_len*8, md, md_len*8, function_b, function_len*8, custom_b, custom_len*8);

    printhex("MD = ", md, md_len);
    printf("\n");

    free(message_b);
    free(custom_b);
    free(function_b);
    free(md);
}

void make_tv(unsigned msg_len, unsigned custom_len, unsigned md_len, cSHAKE func)
{
    char *message;
    char *custom;

    message = malloc(msg_len*2 + 1);
    custom = malloc(custom_len*2 + 1);

    for (unsigned i=0; i<msg_len; i++)
        sprintf(message + i*2, "%02X", i & 0xFF);
    message[msg_len*2] = 0;

    for (unsigned i=0; i<custom_len; i++)
        sprintf(custom + i*2, "%02X", i & 0xFF);
    custom[custom_len*2] = 0;

    make_test_vector(message, custom, "", md_len, func);

    free(message);
    free(custom);
}


int main(int argc, char *argv[])
{
    cSHAKE func;

    if (argc != 2) {
        fprintf(stderr, "%s [128|256]\n", argv[0]);
        return -1;
    }

    if (0 == strcmp(argv[1], "128"))
        func = cSHAKE128;
    else {
        if (0 == strcmp(argv[1], "256"))
            func = cSHAKE256;
        else {
            fprintf(stderr, "%s [128|256]\n", argv[0]);
            return -1;
        }
    }

    make_tv(0, 0, 32, func);
    make_tv(0, 16, 32, func);
    make_tv(16, 0, 32, func);

    make_tv(255, 15, 32, func);
    make_tv(1024, 15, 32, func);

    make_tv(256, 0, 32, func);
    make_tv(256, 255, 32, func);
    make_tv(256, 256, 32, func);
    make_tv(256, 257, 32, func);
    make_tv(256, 258, 32, func);
    make_tv(256, 500, 32, func);
    make_tv(256, 1024, 32, func);

    return 0;
}
