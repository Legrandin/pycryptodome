
/*
 *  diamond.c : Implementation of the Diamond block encryption algorithm
 *
 * Part of the Python Cryptography Toolkit, version 1.1
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.
 *
 */
  

#define MAX_NUM_ROUNDS 16

typedef struct 
{
 PCTObject_HEAD
  unsigned char s[4096*MAX_NUM_ROUNDS], si[4096*MAX_NUM_ROUNDS]; 
  int keyindex, rounds;
  unsigned long accum;
} Diamondobject;


/* Make sure that the following macro is called after BuildCRCTable(). */

#define crc32(crc, c)(((crc>>8)&0x00FFFFFFL)^(Ccitt32Table[(unsigned int)((unsigned int)crc^c)&0xFF]))

/* crc.cpp -- contains table based CCITT 32 bit CRC function.
   This file is in the Public Domain.
   */

#define CRC_MASK           0xFFFFFFFFL
#define CRC32_POLYNOMIAL   0xEDB88320L

static const unsigned int Ccitt32Table[256] = 
{
 0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 
 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3, 
 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 
 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 
 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 
 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 
 0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 
 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5, 
 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 
 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 
 0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 
 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59, 
 0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 
 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f, 
 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 
 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 
 0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 
 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433, 
 0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 
 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01, 
 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 
 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 
 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 
 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65, 
 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 
 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 
 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 
 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 
 0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 
 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f, 
 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 
 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 
 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 
 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 
 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 
 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 
 0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 
 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, 
 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 
 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 
 0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 
 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 
 0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 
 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79, 
 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 
 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 
 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 
 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 
 0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 
 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, 
 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 
 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 
 0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 
 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 
 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 
 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 
 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 
 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 
 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 
 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9, 
 0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 
 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf, 
 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 
 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

#if 0   /* Not used, since Ccitt32Table is statically initialized */
/****************************************************************************/

/*
 * This routine simply builds the coefficient table used to calculate
 * 32 bit CRC values throughout this program.  The 256 long word table
 * has to be set up once when the program starts.  Alternatively, the
 * values could be hard coded in, which would offer a miniscule improvement
 * in overall performance of the program.
 */

int  BuildCRCTable()
{
  int i;
  int j;
  unsigned int value;

  for ( i = 0; i <= 255 ; i++ )
    {
      value = i;
      for ( j = 8 ; j > 0; j-- )
	{
	  if ( value & 1 )
	    value = ( value >> 1 ) ^ CRC32_POLYNOMIAL;
	  else
	    value >>= 1;
	}
      Ccitt32Table[ i ] = value;
    }
  return 0;
}
#endif


/* diamond.c - Encryption designed to exceed DES in security.
   This file and the Diamond and Diamond Lite Encryption Algorithms
   described herein are hereby dedicated to the Public Domain by the
   author and inventor, Michael Paul Johnson.  Feel free to use these
   for any purpose that is legally and morally right.  The names
   "Diamond Encryption Algorithm" and "Diamond Lite Encryption
    Algorithm" should only be used to describe the algorithms described
    in this file, to avoid confusion.
    
    Disclaimers:  the following comes with no warranty, expressed or
    implied.  You, the user, must determine the suitability of this
    information to your own uses.  You must also find out what legal
    requirements exist with respect to this data and programs using
    it, and comply with whatever valid requirements exist.
    */

int inline keyrand(self, max_value, key, keysize)
     Diamondobject *self;
     int max_value;
     unsigned char *key;
     int keysize;
{				/* value based on key[], sized keysize */
  int prandvalue, i;
  unsigned long mask;

  if (!max_value) return 0;
  mask = 0L;			/* Create a mask to get the minimum */
  for (i=max_value; i > 0; i = i >> 1) /* number of bits to cover the */
    mask = (mask << 1) | 1L;	/* range 0 to max_value. */
  i=0;
  do
    {
      self->accum = crc32(self->accum, key[self->keyindex++]);
      if (self->keyindex >= keysize)
	{
	  self->keyindex = 0;		/* Recycle thru the key */
	  self->accum = crc32(self->accum, (keysize & 0xFF));
	  self->accum = crc32(self->accum, ((keysize >> 8) & 0xFF));
	}
      prandvalue = (int) (self->accum & mask);
      if ((++i>97) && (prandvalue > max_value))	/* Don't loop forever. */
	prandvalue -= max_value; /* Introduce negligible bias. */
    }
  while (prandvalue > max_value); /* Discard out of range values. */
  return prandvalue;
}

static void inline makeonebox(self, i, j, key, keylen)
     Diamondobject *self;
     int i, j;
     unsigned char *key;
     int keylen;
{
  int n;
  int pos, m, p;
  int filled[256];
  
  for (m = 0; m < 256; m++)	/* The filled array is used to make
				   sure that */
    filled[m] = 0;		/* each byte of the array is filled only once. */
  for (n = 255; n >= 0 ; n--)	/* n counts the number of bytes left to fill */
    {
      pos = keyrand(self, n, key, keylen);		/* pos is the position among the UNFILLED */
      /* components of the s array that the */
      /* number n should be placed.  */
      p=0;
      while (filled[p]) p++;
      for (m=0; m<pos; m++)
	{
	  p++;
	  while (filled[p]) p++;
	}
      self->s[(4096*i) + (256*j) + p] = n;
      filled[p] = 1;
    }
}

static inline void Diamondinit(self, key, keylen)
     Diamondobject *self;
     unsigned char *key;
     int keylen;
{
  int i, j, k;
#if 0
  BuildCRCTable();
#endif
  self->keyindex = 0;
  self->accum = 0xFFFFFFFFL;

  if (self->rounds<5 || MAX_NUM_ROUNDS<=self->rounds) 
    {
      PyErr_SetString(PyExc_ValueError, "Number of rounds for Diamond must be "
		    "between 5 and 15.");
      return;
    }
  for (i = 0; i < self->rounds; i++)
    {
      for (j = 0; j < 16; j++)
	{
	  makeonebox(self, i, j, key, keylen);
	}
    }
  for (i = 0; i < self->rounds; i++)
    {
      for (j = 0; j < 16; j++)
	{
	  for (k = 0; k < 256; k++)
	    {
	      self->si[(4096 * i) + (256 * j) + self->s[(4096 * i) + (256 * j) + k]] = k;
	    }
	}
    }
}

static void permute(self, x, y)   /* x and y must be different. */
     Diamondobject *self;
     unsigned char *x, *y;
     {
     y[0] = (x[0] & 1) | (x[1] & 2) | (x[2] & 4) |
	     (x[3] & 8) | (x[4] & 16) | (x[5] & 32) |
	     (x[6] & 64) | (x[7] & 128);
     y[1] = (x[1] & 1) | (x[2] & 2) | (x[3] & 4) |
	     (x[4] & 8) | (x[5] & 16) | (x[6] & 32) |
	     (x[7] & 64) | (x[8] & 128);
     y[2] = (x[2] & 1) | (x[3] & 2) | (x[4] & 4) |
	     (x[5] & 8) | (x[6] & 16) | (x[7] & 32) |
	     (x[8] & 64) | (x[9] & 128);
     y[3] = (x[3] & 1) | (x[4] & 2) | (x[5] & 4) |
	     (x[6] & 8) | (x[7] & 16) | (x[8] & 32) |
	     (x[9] & 64) | (x[10] & 128);
     y[4] = (x[4] & 1) | (x[5] & 2) | (x[6] & 4) |
	     (x[7] & 8) | (x[8] & 16) | (x[9] & 32) |
	     (x[10] & 64) | (x[11] & 128);
     y[5] = (x[5] & 1) | (x[6] & 2) | (x[7] & 4) |
	     (x[8] & 8) | (x[9] & 16) | (x[10] & 32) |
	     (x[11] & 64) | (x[12] & 128);
     y[6] = (x[6] & 1) | (x[7] & 2) | (x[8] & 4) |
	     (x[9] & 8) | (x[10] & 16) | (x[11] & 32) |
	     (x[12] & 64) | (x[13] & 128);
     y[7] = (x[7] & 1) | (x[8] & 2) | (x[9] & 4) |
	     (x[10] & 8) | (x[11] & 16) | (x[12] & 32) |
	     (x[13] & 64) | (x[14] & 128);
     y[8] = (x[8] & 1) | (x[9] & 2) | (x[10] & 4) |
	     (x[11] & 8) | (x[12] & 16) | (x[13] & 32) |
	     (x[14] & 64) | (x[15] & 128);
     y[9] = (x[9] & 1) | (x[10] & 2) | (x[11] & 4) |
	     (x[12] & 8) | (x[13] & 16) | (x[14] & 32) |
	     (x[15] & 64) | (x[0] & 128);
     y[10] = (x[10] & 1) | (x[11] & 2) | (x[12] & 4) |
	     (x[13] & 8) | (x[14] & 16) | (x[15] & 32) |
	     (x[0] & 64) | (x[1] & 128);
     y[11] = (x[11] & 1) | (x[12] & 2) | (x[13] & 4) |
	     (x[14] & 8) | (x[15] & 16) | (x[0] & 32) |
	     (x[1] & 64) | (x[2] & 128);
     y[12] = (x[12] & 1) | (x[13] & 2) | (x[14] & 4) |
	     (x[15] & 8) | (x[0] & 16) | (x[1] & 32) |
	     (x[2] & 64) | (x[3] & 128);
     y[13] = (x[13] & 1) | (x[14] & 2) | (x[15] & 4) |
	     (x[0] & 8) | (x[1] & 16) | (x[2] & 32) |
	     (x[3] & 64) | (x[4] & 128);
     y[14] = (x[14] & 1) | (x[15] & 2) | (x[0] & 4) |
	     (x[1] & 8) | (x[2] & 16) | (x[3] & 32) |
	     (x[4] & 64) | (x[5] & 128);
     y[15] = (x[15] & 1) | (x[0] & 2) | (x[1] & 4) |
	     (x[2] & 8) | (x[3] & 16) | (x[4] & 32) |
	     (x[5] & 64) | (x[6] & 128);
   }

static void ipermute(self, x, y) /* x!=y */
     Diamondobject *self;
     unsigned char *x, *y;
     {
     y[0] = (x[0] & 1) | (x[15] & 2) | (x[14] & 4) |
	     (x[13] & 8) | (x[12] & 16) | (x[11] & 32) |
	     (x[10] & 64) | (x[9] & 128);
     y[1] = (x[1] & 1) | (x[0] & 2) | (x[15] & 4) |
	     (x[14] & 8) | (x[13] & 16) | (x[12] & 32) |
	     (x[11] & 64) | (x[10] & 128);
     y[2] = (x[2] & 1) | (x[1] & 2) | (x[0] & 4) |
	     (x[15] & 8) | (x[14] & 16) | (x[13] & 32) |
	     (x[12] & 64) | (x[11] & 128);
     y[3] = (x[3] & 1) | (x[2] & 2) | (x[1] & 4) |
	     (x[0] & 8) | (x[15] & 16) | (x[14] & 32) |
	     (x[13] & 64) | (x[12] & 128);
     y[4] = (x[4] & 1) | (x[3] & 2) | (x[2] & 4) |
	     (x[1] & 8) | (x[0] & 16) | (x[15] & 32) |
	     (x[14] & 64) | (x[13] & 128);
     y[5] = (x[5] & 1) | (x[4] & 2) | (x[3] & 4) |
	     (x[2] & 8) | (x[1] & 16) | (x[0] & 32) |
	     (x[15] & 64) | (x[14] & 128);
     y[6] = (x[6] & 1) | (x[5] & 2) | (x[4] & 4) |
	     (x[3] & 8) | (x[2] & 16) | (x[1] & 32) |
	     (x[0] & 64) | (x[15] & 128);
     y[7] = (x[7] & 1) | (x[6] & 2) | (x[5] & 4) |
	     (x[4] & 8) | (x[3] & 16) | (x[2] & 32) |
	     (x[1] & 64) | (x[0] & 128);
     y[8] = (x[8] & 1) | (x[7] & 2) | (x[6] & 4) |
	     (x[5] & 8) | (x[4] & 16) | (x[3] & 32) |
	     (x[2] & 64) | (x[1] & 128);
     y[9] = (x[9] & 1) | (x[8] & 2) | (x[7] & 4) |
	     (x[6] & 8) | (x[5] & 16) | (x[4] & 32) |
	     (x[3] & 64) | (x[2] & 128);
     y[10] = (x[10] & 1) | (x[9] & 2) | (x[8] & 4) |
	     (x[7] & 8) | (x[6] & 16) | (x[5] & 32) |
	     (x[4] & 64) | (x[3] & 128);
     y[11] = (x[11] & 1) | (x[10] & 2) | (x[9] & 4) |
	     (x[8] & 8) | (x[7] & 16) | (x[6] & 32) |
	     (x[5] & 64) | (x[4] & 128);
     y[12] = (x[12] & 1) | (x[11] & 2) | (x[10] & 4) |
	     (x[9] & 8) | (x[8] & 16) | (x[7] & 32) |
	     (x[6] & 64) | (x[5] & 128);
     y[13] = (x[13] & 1) | (x[12] & 2) | (x[11] & 4) |
	     (x[10] & 8) | (x[9] & 16) | (x[8] & 32) |
	     (x[7] & 64) | (x[6] & 128);
     y[14] = (x[14] & 1) | (x[13] & 2) | (x[12] & 4) |
	     (x[11] & 8) | (x[10] & 16) | (x[9] & 32) |
	     (x[8] & 64) | (x[7] & 128);
     y[15] = (x[15] & 1) | (x[14] & 2) | (x[13] & 4) |
	     (x[12] & 8) | (x[11] & 16) | (x[10] & 32) |
	     (x[9] & 64) | (x[8] & 128);
   }

static void inline substitute(self, round, x, y)
     Diamondobject *self;
     int round;
     unsigned char *x, *y;
{
  int i;
  
  for (i = 0; i < 16; i++)
    y[i] = self->s[(4096*round) + (256*i) + x[i]];
}

static void inline isubst(self, round, x, y)
     Diamondobject *self;
     int round;
     unsigned char *x, *y;
{
  int i;
  
  for (i = 0; i < 16; i++)
    y[i] = self->si[(4096*round) + (256*i) + x[i]];
}

void Diamondencrypt(self, block)
      Diamondobject *self;
      unsigned char *block;
 {
   int round;
   unsigned char y[16], z[16];

   substitute(self, 0, block, y);
   for (round=1; round < self->rounds; round++)
     {
       permute(self, y, z);
       substitute(self, round, z, y);
     }
   for(round=0; round<16; round++) block[round]=y[round];
 }

 void Diamonddecrypt(self, block)
      Diamondobject *self;
      unsigned char *block;
 {
   int round;
   unsigned char y[16], z[16];

   isubst(self, self->rounds-1, block, y);
   for (round=self->rounds-2; round >= 0; round--)
     {
       ipermute(self, y, z);
       isubst(self, round, z, y);
     }
   for(round=0; round<16; round++) block[round]=y[round];
 }



