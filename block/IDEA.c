
/*
 *  idea.c : Source code for the IDEA block cipher
 *
 * Part of the Python Cryptography Toolkit
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.
 *
 */
  

#define MODULE_NAME IDEA
#define BLOCK_SIZE 8
#define KEY_SIZE 16

#define low16(x) ((x)/* & 0xFFFF*/)
typedef unsigned short uint16;	/* at LEAST 16 bits, maybe more */
typedef unsigned short word16;
typedef unsigned long word32;
typedef unsigned char byte;

#define MUL(x,y) (x = low16(x-1), t16 = low16((y)-1), \
		t32 = (word32)x*t16 + x + t16, x = low16(t32), \
		t16 = t32>>16, x = (x-t16) + (x<t16) + 1)

#ifdef _GNUC_
/* __const__ simply means there are no side effects for this function,
 * which is useful info for the gcc optimizer
 */
#define CONST __const__
#else
#define CONST
#endif

typedef struct 
{
 word16 EK[6*8+4], DK[6*8+4];
} block_state;

CONST static uint16
mulInv(uint16 x)
{
    uint16 t0, t1;
    uint16 q, y;

    if (x <= 1)
	return x;		/* 0 and 1 are self-inverse */
    t1 = 0x10001L / x;		/* Since x >= 2, this fits into 16 bits */
    y = 0x10001L % x;
    if (y == 1)
	return low16(1 - t1);
    t0 = 1;
    do {
	q = x / y;
	x = x % y;
	t0 += q * t1;
	if (x == 1)
	    return t0;
	q = y / x;
	y = y % x;
	t1 += q * t0;
    } while (y != 1);
    return low16(1 - t1);
}				/* mukInv */

static void
block_init(block_state *self, unsigned char *key, int dummy)
{
    int i, j;
    uint16 t1, t2, t3;
    word16 *DK, *EK;    

    EK = self->EK;
    for (j = 0; j < 8; j++) {
	EK[j] = (key[0] << 8) + key[1];
	key += 2;
    }
    for (i = 0; j < 6*8+4; j++) {
	i++;
	EK[i + 7] = (EK[i & 7] << 9) | (EK[(i + 1) & 7] >> 7);
	EK += i & 8;
	i &= 7;
    }
    EK = self->EK;
    DK = self->DK+6*8+4;    
    t1 = mulInv(*EK++);
    t2 = -*EK++;
    t3 = -*EK++;
    *--DK = mulInv(*EK++);
    *--DK = t3;
    *--DK = t2;
    *--DK = t1;

    for (i = 0; i < 8 - 1; i++) {
	t1 = *EK++;
	*--DK = *EK++;
	*--DK = t1;

	t1 = mulInv(*EK++);
	t2 = -*EK++;
	t3 = -*EK++;
	*--DK = mulInv(*EK++);
	*--DK = t2;
	*--DK = t3;
	*--DK = t1;
    }
    t1 = *EK++;
    *--DK = *EK++;
    *--DK = t1;

    t1 = mulInv(*EK++);
    t2 = -*EK++;
    t3 = -*EK++;
    *--DK = mulInv(*EK++);
    *--DK = t3;
    *--DK = t2;
    *--DK = t1;
}

/*      IDEA encryption/decryption algorithm */
/* Note that in and out can be the same buffer */
static void ideaCipher(block_state *self, byte *block_in, 
		       byte *block_out, word16 const *key)
{
    register uint16 x1, x2, x3, x4, s2, s3;
    word16 *in, *out;
    register uint16 t16;	/* Temporaries needed by MUL macro */
    register word32 t32;
    int r = 8;

    in = (word16 *) block_in;
    x1 = *in++;
    x2 = *in++;
    x3 = *in++;
    x4 = *in;
#ifndef WORDS_BIGENDIAN
	x1 = (x1 >> 8) | (x1 << 8);
	x2 = (x2 >> 8) | (x2 << 8);
	x3 = (x3 >> 8) | (x3 << 8);
	x4 = (x4 >> 8) | (x4 << 8);
#endif
    do {
	MUL(x1, *key++);
	x2 += *key++;
	x3 += *key++;
	MUL(x4, *key++);

	s3 = x3;
	x3 ^= x1;
	MUL(x3, *key++);
	s2 = x2;
	x2 ^= x4;
	x2 += x3;
	MUL(x2, *key++);
	x3 += x2;

	x1 ^= x2;
	x4 ^= x3;

	x2 ^= s3;
	x3 ^= s2;
    } while (--r);
    MUL(x1, *key++);
    x3 += *key++;
    x2 += *key++;
    MUL(x4, *key);

    out = (word16 *) block_out;
   
#ifdef WORDS_BIGENDIAN
	*out++ = x1;
	*out++ = x3;
	*out++ = x2;
	*out = x4;
#else
	x1 = low16(x1);
	x2 = low16(x2);
	x3 = low16(x3);
	x4 = low16(x4);
	
	*out++ = (x1 >> 8) | (x1 << 8);
	*out++ = (x3 >> 8) | (x3 << 8);
	*out++ = (x2 >> 8) | (x2 << 8);
	*out = (x4 >> 8) | (x4 << 8);
#endif
}				/* ideaCipher */


static void block_encrypt(block_state *self, 
			  unsigned char *in, 
			  unsigned char *out)
{
  ideaCipher(self, in, out, self->EK);
}

static void block_decrypt(block_state *self,
			  unsigned char *in, 
			  unsigned char *out)
{
  ideaCipher(self, in, out, self->DK);
}
   
#include "block_template.c"
