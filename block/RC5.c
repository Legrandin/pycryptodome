/*
 *  RC5.c : Implementation code for the RC5 block cipher
 *
 * Part of the Python Cryptography Toolkit
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.
 *
 */

#include "Python.h"

#define MODULE_NAME RC5
#define BLOCK_SIZE 8
#define KEY_SIZE 0
#define PCT_RC5_MODULE          /* Define this to get RC5's additional 
				   keywords */ 
#define MAXTABLE 100		/* Maximum size of S-box table; changing this
				   affects the maximum number of rounds
				   possible. */
typedef unsigned int U32;
#define LEFT(v,x,y,w,MASK)  {U32 t1=(y) % (w), t2,t3=x;\
		        t2=(w)-t1;\
		        v= ( (t3 << t1) & MASK) | \
   		           ( (t3 >> t2) & MASK);}
#define RIGHT(v,x,y,w,MASK)  {U32 t1=(y) % (w), t2,t3=x;\
		        t2=(w)-t1;\
		        v= ( (t3 >> t1) & MASK) | \
   		           ( (t3 << t2) & MASK);}



typedef struct 
{
  int version;			/* Version number of algorithm */
  int word_size;			/* Word size */
  int rounds;			/* Number of rounds */
  U32 S[MAXTABLE];
  U32 mask;
} block_state;

static inline void
block_init(block_state *self, unsigned char *key, int keylen)
{
  unsigned int P = 0, Q = 0;
  int i;
  
  switch(self->word_size)
    {
    case(16):
      P=0xb7e1; Q=0x9e37; self->mask=0xffff;
      break;
    case(32):
      P=0xb7e15163; Q=0x9e3779b9; self->mask=0xffffffff;
      break;
    }
  for(i=0; i<2*self->rounds+2; i++) self->S[i]=0;
  {
    unsigned int *L, A, B;
    int u=self->word_size/8, num;
    int j, t=2*(self->rounds+1), c=(keylen-1)/u;
    if ((keylen-1) % u) c++;
    L=malloc(sizeof(unsigned int)*c);
    if (L==NULL) 
      {
	PyErr_SetString(PyExc_MemoryError,
			"RC5: Can't allocate memory");
      }
    for(i=0; i<c; i++) L[i]=0;
    for(i=keylen-1; 0<=i; i--) L[i/u]=(L[i/u]<<8)+key[i];
    self->S[0]=P;
    for(i=1; i<t; i++) self->S[i]=(self->S[i-1]+Q) & self->mask;
    i=j=0;
    A=B=0;
    for(num = (t>c) ? 3*t : 3*c; 0<num; num--) 
      {
	LEFT(A, self->S[i]+A+B, 3, self->word_size, self->mask);
	self->S[i]=A;
	LEFT(B, L[j]+A+B, A+B, self->word_size, self->mask);
	L[j]=B;
	i=(i+1)%t;
	j=(j+1)%c;
      }
    free(L);
  }
}

static void RC5Encipher(block_state *self, U32 *Aptr, U32 *Bptr)
{
  int i;
  register U32 A, B;

  A=(*Aptr+self->S[0]) & self->mask;
  B=(*Bptr+self->S[1]) & self->mask;

  if (self->rounds)
  for (i=2; i<=2*self->rounds; i+=2) 
    {
      LEFT(A,A^B,B,self->word_size,self->mask);
      A += self->S[i];
      LEFT(B,A^B,A,self->word_size,self->mask);
      B += self->S[i+1];
    }
  *Aptr=A;
  *Bptr=B;
}

static void RC5Decipher(block_state *self, unsigned int *Aptr, 
			unsigned int *Bptr)
{
  int i;
  U32 A, B;

  A=*Aptr;
  B=*Bptr;

  if (self->rounds)
  for (i=2*self->rounds; 2<=i; i-=2) 
    {
      RIGHT(B,B-self->S[i+1],A,self->word_size,self->mask);
      B ^= A;
      RIGHT(A,A-self->S[i],B,self->word_size,self->mask);
      A ^= B;
    }
  A = (A-self->S[0]) & self->mask;
  B = (B-self->S[1]) & self->mask;
  if (self->word_size==32) 
    {
      *Aptr=A;
      *Bptr=B;
    }
  else /* self->word_size==16 */
    {
      *Aptr=A;
      *Bptr=B;
    }
}

static inline void block_encrypt(block_state *self, unsigned char *block)
{
  U32 A,B;
  
  switch(self->word_size)
    {
    case (32):
      A=block[0] | block[1]<<8 | block[2]<<16 | block[3]<<24;
      B=block[4] | block[5]<<8 | block[6]<<16 | block[7]<<24;
      RC5Encipher(self, &A, &B);
      block[0]=A & 255; A>>=8;      
      block[1]=A & 255; A>>=8;      
      block[2]=A & 255; A>>=8;      
      block[3]=A; 
      block[4]=B & 255; B>>=8;      
      block[5]=B & 255; B>>=8;      
      block[6]=B & 255; B>>=8;      
      block[7]=B; 
      break;
    case (16):
      A=block[0] + block[1]*256;
      B=block[2] + block[3]*256;
      RC5Encipher(self, &A, &B);
      block[0] = A & 255; block[1] = A>>8;
      block[2] = B & 255; block[3] = B>>8;
      
      A=block[4] + block[5]*256;
      B=block[6] + block[7]*256;
      RC5Encipher(self, &A, &B);
      block[4] = A & 255; block[5] = A>>8; 
      block[6] = B & 255; block[7] = B>>8;
      break;
    }
}

static inline void block_decrypt(block_state *self, unsigned char *block)
{
  U32 A,B;
  
  switch(self->word_size)
    {
    case (32):
      A=block[0] | block[1]<<8 | block[2]<<16 | block[3]<<24;
      B=block[4] | block[5]<<8 | block[6]<<16 | block[7]<<24;
      RC5Decipher(self, &A, &B);
      block[0]=A & 255; A>>=8;      
      block[1]=A & 255; A>>=8;      
      block[2]=A & 255; A>>=8;      
      block[3]=A; 
      block[4]=B & 255; B>>=8;      
      block[5]=B & 255; B>>=8;      
      block[6]=B & 255; B>>=8;      
      block[7]=B; 
      break;
    case (16):
      A=block[0] + block[1]*256;
      B=block[2] + block[3]*256;
      RC5Decipher(self, &A, &B);
      block[0] = A & 255; block[1] = A>>8;
      block[2] = B & 255; block[3] = B>>8;
      
      A=block[4] + block[5]*256;
      B=block[6] + block[7]*256;
      RC5Decipher(self, &A, &B);
      block[4] = A & 255; block[5] = A>>8;
      block[6] = B & 255; block[7] = B>>8;
      break;
    }
}

#include "block_template.c"
