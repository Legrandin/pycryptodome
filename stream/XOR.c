/*
 *  xor.c : Source for the trivial cipher which XORs the message with the key.
 *          The key can be up to 32 bytes long.
 *
 * Part of the Python Cryptography Toolkit, version 1.1
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.
 *
 */

typedef struct 
{
 PCTObject_HEAD;
 unsigned char key[32];
 int keylen, last_pos;
} XORobject;

static inline void
XORinit(self, key, len)
     XORobject *self;
     unsigned char *key;
     int len;
{
  int i;
  
  if (32 <= len) len=32;
  self->keylen = len;
  self->last_pos = 0;

  for(i=0; i<len; i++)
    {
      self->key[i] = key[i];
    }
}

static inline void XORencrypt(self, block, len)
     XORobject *self;
     unsigned char *block;
     int len;
{
  int i, j = self->last_pos;
  for(i=0; i<len; i++, j=(j+1) % self->keylen)
    {
      block[i] ^= self->key[j];
    }
  self->last_pos = j;
}

#define XORdecrypt XORencrypt
