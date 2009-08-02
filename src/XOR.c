/*
 *  xor.c : Source for the trivial cipher which XORs the message with the key.
 *          The key can be up to 32 bytes long.
 *
 * Part of the Python Cryptography Toolkit
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.
 *
 */

#include "Python.h"

#define MODULE_NAME XOR
#define BLOCK_SIZE 1
#define KEY_SIZE 0

#define MAX_KEY_SIZE 32

typedef struct 
{
	unsigned char key[MAX_KEY_SIZE];
	int keylen, last_pos;
} stream_state;

static void
stream_init(stream_state *self, unsigned char *key, int len)
{
	int i;

        if (len > MAX_KEY_SIZE)
        {
		PyErr_Format(PyExc_ValueError,
				"XOR key must be no longer than %d bytes",
                                MAX_KEY_SIZE);
		return;
        }
	self->keylen = len;
	self->last_pos = 0;

	for(i=0; i<len; i++)
	{
		self->key[i] = key[i];
	}
}

/* Encryption and decryption are symmetric */
#define stream_decrypt stream_encrypt	

static void stream_encrypt(stream_state *self, unsigned char *block, 
			   int len)
{
	int i, j = self->last_pos;
	for(i=0; i<len; i++, j=(j+1) % self->keylen)
	{
		block[i] ^= self->key[j];
	}
	self->last_pos = j;
}

#include "stream_template.c"
