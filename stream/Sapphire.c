
/*
 *  sapphire.c : Implementation for the Sapphire stream cipher
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
 unsigned char state[256];
 unsigned char index[5];/* Rotor, ratchet, avalanche, last_plain, last_cipher */
} Sapphireobject;

#define rotor self->index[0]
#define ratchet self->index[1]
#define avalanche self->index[2]
#define last_plain self->index[3]
#define last_cipher self->index[4]

static inline void Sapphireencrypt(self, block, len)
     Sapphireobject *self;
     unsigned char *block;
     unsigned int len;
{
 unsigned char temp;
 unsigned int i;

 for(i=0; i<len; i++) 
   {
     ratchet += self->state[rotor++];
     temp = self->state[last_cipher];
     self->state[last_cipher] = self->state[ratchet];
     self->state[ratchet] = self->state[last_plain];
     self->state[last_plain] = self->state[rotor];
     self->state[rotor] = temp;
     avalanche += self->state[temp];
     
     temp = block[i];
     block[i] ^= self->state[ 0xFF & (self->state[rotor] + self->state[ratchet]) ]
			       ^ self->state[self->state[(self->state[avalanche] +
							  self->state[last_plain] +
							  self->state[last_cipher]
							  ) & 0xFF
							 ]
					     ];
     last_plain = temp;
     last_cipher = block[i];
   } 
}

static inline void Sapphiredecrypt(self, block, len)
     Sapphireobject *self;
     unsigned char *block;
     unsigned int len;
{
  unsigned char temp;
  unsigned int i;
  
  for(i=0; i<len; i++) 
    {
      ratchet += self->state[rotor++];
      temp = self->state[last_cipher];
      self->state[last_cipher] = self->state[ratchet];
      self->state[ratchet] = self->state[last_plain];
      self->state[last_plain] = self->state[rotor];
      self->state[rotor] = temp;
      avalanche += self->state[temp];
      temp = block[i];
      block[i] ^= self->state[ 0xFF & (self->state[rotor] +self->state[ratchet]) ]
				^ self->state[self->state[(self->state[avalanche] +
							   self->state[last_plain] +
							   self->state[last_cipher]
							   ) & 0xFF
							  ]
					      ];
      last_cipher = temp;
      last_plain = block[i];
    }
}

static void Sapphireinit(self, key, keylen)
     Sapphireobject *self;
     unsigned char *key;
     int keylen;
{
  int i;
  unsigned char toswap, keypos, rsum, swaptemp;

  for (i = 0; i < 256; i++)
    self->state[i] = i;

  keypos = 0;
  rsum = 0;
  for (i = 255; i >= 0; i--)
    {  unsigned int retry_limiter=0, mask=1;
      while (mask < i)
	mask = (mask << 1) + 1;
      do
	{
	  rsum = self->state[rsum] + key[keypos++];
	  if (keypos >= keylen)
	    {
	      keypos = 0;
	      rsum += keylen;
	    }
	  toswap = mask & rsum;
	  if (++retry_limiter > 11)
	    toswap %= i;
	} while (toswap > i);
      swaptemp = self->state[i];
      self->state[i] = self->state[toswap];
      self->state[toswap] = swaptemp;
    }
  rotor=self->state[1];
  ratchet=self->state[3];
  avalanche=self->state[5];
  last_plain=self->state[7];
  last_cipher=self->state[rsum];
}
