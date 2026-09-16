/**************************************************
 *						  *
 *	Camellia Block Encryption Algorithm	  *
 *	  in ANSI-C Language : Camellia.c	  *
 *						  *
 *	  Version M1.02 September 24 2001	  *
 *  Copyright Mitsubishi Electric Corp 2000-2001  *
 *						  *
 **************************************************/


#include "block_base.h"
#define MODULE_NAME Camellia
#define BLOCK_SIZE 16
#define KEY_SIZE 0

typedef unsigned char Byte;
typedef unsigned long Word;

struct block_state {
	unsigned int key_size;
	uint8_t key[34 * sizeof(Word)];
};

void Camellia_Ekeygen( const int, const Byte *, Byte * );
void Camellia_Encrypt( const int, const Byte *, const Byte *, Byte * );
void Camellia_Decrypt( const int, const Byte *, const Byte *, Byte * );
void Camellia_Feistel( const Byte *, const Byte *, Byte * );
void Camellia_FLlayer( Byte *, const Byte *, const Byte * );

void ByteWord( const Byte *, Word * );
void WordByte( const Word *, Byte * );
void XorBlock( const Byte *, const Byte *, Byte * );
void SwapHalf( Byte * );
void RotBlock( const Word *, const int, Word * );

const Byte SIGMA[48] = {
0xa0,0x9e,0x66,0x7f,0x3b,0xcc,0x90,0x8b,
0xb6,0x7a,0xe8,0x58,0x4c,0xaa,0x73,0xb2,
0xc6,0xef,0x37,0x2f,0xe9,0x4f,0x82,0xbe,
0x54,0xff,0x53,0xa5,0xf1,0xd3,0x6f,0x1c,
0x10,0xe5,0x27,0xfa,0xde,0x68,0x2d,0x1d,
0xb0,0x56,0x88,0xc2,0xb3,0xe6,0xc1,0xfd};

const int KSFT1[26] = {
0,64,0,64,15,79,15,79,30,94,45,109,45,124,60,124,77,13,
94,30,94,30,111,47,111,47 };
const int KIDX1[26] = {
0,0,4,4,0,0,4,4,4,4,0,0,4,0,4,4,0,0,0,0,4,4,0,0,4,4 };
const int KSFT2[34] = {
0,64,0,64,15,79,15,79,30,94,30,94,45,109,45,109,60,124,
60,124,60,124,77,13,77,13,94,30,94,30,111,47,111,47 };
const int KIDX2[34] = {
0,0,12,12,8,8,4,4,8,8,12,12,0,0,4,4,0,0,8,8,12,12,
0,0,4,4,8,8,4,4,0,0,12,12 };

const Byte SBOX[256] = {
112,130, 44,236,179, 39,192,229,228,133, 87, 53,234, 12,174, 65,
35,239,107,147, 69, 25,165, 33,237, 14, 79, 78, 29,101,146,189,
134,184,175,143,124,235, 31,206, 62, 48,220, 95, 94,197, 11, 26,
166,225, 57,202,213, 71, 93, 61,217,  1, 90,214, 81, 86,108, 77,
139, 13,154,102,251,204,176, 45,116, 18, 43, 32,240,177,132,153,
223, 76,203,194, 52,126,118,  5,109,183,169, 49,209, 23,  4,215,
20, 88, 58, 97,222, 27, 17, 28, 50, 15,156, 22, 83, 24,242, 34,
254, 68,207,178,195,181,122,145, 36,  8,232,168, 96,252,105, 80,
170,208,160,125,161,137, 98,151, 84, 91, 30,149,224,255,100,210,
16,196,  0, 72,163,247,117,219,138,  3,230,218,  9, 63,221,148,
135, 92,131,  2,205, 74,144, 51,115,103,246,243,157,127,191,226,
82,155,216, 38,200, 55,198, 59,129,150,111, 75, 19,190, 99, 46,
233,121,167,140,159,110,188,142, 41,245,249,182, 47,253,180, 89,
120,152,  6,106,231, 70,113,186,212, 37,171, 66,136,162,141,250,
114,  7,185, 85,248,238,172, 10, 54, 73, 42,104, 60, 56,241,164,
64, 40,211,123,187,201, 67,193, 21,227,173,244,119,199,128,158};

#define SBOX1(n) SBOX[(n)]
#define SBOX2(n) (Byte)((SBOX[(n)]>>7^SBOX[(n)]<<1)&0xff)
#define SBOX3(n) (Byte)((SBOX[(n)]>>1^SBOX[(n)]<<7)&0xff)
#define SBOX4(n) SBOX[((n)<<1^(n)>>7)&0xff]

void Camellia_Ekeygen( const int n, const Byte *k, Byte *e )
{
	Byte t[64];
	Word u[20];
	int  i;

	if( n == 128 ){
		for( i=0 ; i<16; i++ ) t[i] = k[i];
		for( i=16; i<32; i++ ) t[i] = 0;
	}
	else if( n == 192 ){
		for( i=0 ; i<24; i++ ) t[i] = k[i];
		for( i=24; i<32; i++ ) t[i] = k[i-8]^0xff;
	}
	else if( n == 256 ){
		for( i=0 ; i<32; i++ ) t[i] = k[i];
	}

	XorBlock( t+0, t+16, t+32 );

	Camellia_Feistel( t+32, SIGMA+0, t+40 );
	Camellia_Feistel( t+40, SIGMA+8, t+32 );

	XorBlock( t+32, t+0, t+32 );

	Camellia_Feistel( t+32, SIGMA+16, t+40 );
	Camellia_Feistel( t+40, SIGMA+24, t+32 );

	ByteWord( t+0,  u+0 );
	ByteWord( t+32, u+4 );

	if( n == 128 ){
		for( i=0; i<26; i+=2 ){
			RotBlock( u+KIDX1[i+0], KSFT1[i+0], u+16 );
			RotBlock( u+KIDX1[i+1], KSFT1[i+1], u+18 );
			WordByte( u+16, e+i*8 );
		}
	}
	else{
		XorBlock( t+32, t+16, t+48 );

		Camellia_Feistel( t+48, SIGMA+32, t+56 );
		Camellia_Feistel( t+56, SIGMA+40, t+48 );

		ByteWord( t+16, u+8  );
		ByteWord( t+48, u+12 );

		for( i=0; i<34; i+=2 ){
			RotBlock( u+KIDX2[i+0], KSFT2[i+0], u+16 );
			RotBlock( u+KIDX2[i+1], KSFT2[i+1], u+18 );
			WordByte( u+16, e+(i<<3) );
		}
	}
}

void Camellia_Encrypt( const int n, const Byte *p, const Byte *e, Byte *c )
{
	int i;

	XorBlock( p, e+0, c );

	for( i=0; i<3; i++ ){
		Camellia_Feistel( c+0, e+16+(i<<4), c+8 );
		Camellia_Feistel( c+8, e+24+(i<<4), c+0 );
	}

	Camellia_FLlayer( c, e+64, e+72 );

	for( i=0; i<3; i++ ){
		Camellia_Feistel( c+0, e+80+(i<<4), c+8 );
		Camellia_Feistel( c+8, e+88+(i<<4), c+0 );
	}

	Camellia_FLlayer( c, e+128, e+136 );

	for( i=0; i<3; i++ ){
		Camellia_Feistel( c+0, e+144+(i<<4), c+8 );
		Camellia_Feistel( c+8, e+152+(i<<4), c+0 );
	}

	if( n == 128 ){
		SwapHalf( c );
		XorBlock( c, e+192, c );
	}
	else{
		Camellia_FLlayer( c, e+192, e+200 );

		for( i=0; i<3; i++ ){
			Camellia_Feistel( c+0, e+208+(i<<4), c+8 );
			Camellia_Feistel( c+8, e+216+(i<<4), c+0 );
		}

		SwapHalf( c );
		XorBlock( c, e+256, c );
	}
}

void Camellia_Decrypt( const int n, const Byte *c, const Byte *e, Byte *p )
{
	int i;

	if( n == 128 ){
		XorBlock( c, e+192, p );
	}
	else{
		XorBlock( c, e+256, p );

		for( i=2; i>=0; i-- ){
			Camellia_Feistel( p+0, e+216+(i<<4), p+8 );
			Camellia_Feistel( p+8, e+208+(i<<4), p+0 );
		}

		Camellia_FLlayer( p, e+200, e+192 );
	}

	for( i=2; i>=0; i-- ){
		Camellia_Feistel( p+0, e+152+(i<<4), p+8 );
		Camellia_Feistel( p+8, e+144+(i<<4), p+0 );
	}

	Camellia_FLlayer( p, e+136, e+128 );

	for( i=2; i>=0; i-- ){
		Camellia_Feistel( p+0, e+88+(i<<4), p+8 );
		Camellia_Feistel( p+8, e+80+(i<<4), p+0 );
	}

	Camellia_FLlayer( p, e+72, e+64 );

	for( i=2; i>=0; i-- ){
		Camellia_Feistel( p+0, e+24+(i<<4), p+8 );
		Camellia_Feistel( p+8, e+16+(i<<4), p+0 );
	}

	SwapHalf( p );
	XorBlock( p, e+0, p );
}

void Camellia_Feistel( const Byte *x, const Byte *k, Byte *y )
{
	Byte t[8];

	t[0] = SBOX1(x[0]^k[0]);
	t[1] = SBOX2(x[1]^k[1]);
	t[2] = SBOX3(x[2]^k[2]);
	t[3] = SBOX4(x[3]^k[3]);
	t[4] = SBOX2(x[4]^k[4]);
	t[5] = SBOX3(x[5]^k[5]);
	t[6] = SBOX4(x[6]^k[6]);
	t[7] = SBOX1(x[7]^k[7]);

	y[0] ^= t[0]^t[2]^t[3]^t[5]^t[6]^t[7];
	y[1] ^= t[0]^t[1]^t[3]^t[4]^t[6]^t[7];
	y[2] ^= t[0]^t[1]^t[2]^t[4]^t[5]^t[7];
	y[3] ^= t[1]^t[2]^t[3]^t[4]^t[5]^t[6];
	y[4] ^= t[0]^t[1]^t[5]^t[6]^t[7];
	y[5] ^= t[1]^t[2]^t[4]^t[6]^t[7];
	y[6] ^= t[2]^t[3]^t[4]^t[5]^t[7];
	y[7] ^= t[0]^t[3]^t[4]^t[5]^t[6];
	}

	void Camellia_FLlayer( Byte *x, const Byte *kl, const Byte *kr )
	{
	Word t[4],u[4],v[4];

	ByteWord( x, t );
	ByteWord( kl, u );
	ByteWord( kr, v );

	t[1] ^= (t[0]&u[0])<<1^(t[0]&u[0])>>31;
	t[0] ^= t[1]|u[1];
	t[2] ^= t[3]|v[1];
	t[3] ^= (t[2]&v[0])<<1^(t[2]&v[0])>>31;

	WordByte( t, x );
}

void ByteWord( const Byte *x, Word *y )
{
	int i;
	for( i=0; i<4; i++ ){
		y[i] = ((Word)x[(i<<2)+0]<<24) + ((Word)x[(i<<2)+1]<<16)
				+ ((Word)x[(i<<2)+2]<<8 ) + ((Word)x[(i<<2)+3]<<0 );
	}
}

void WordByte( const Word *x, Byte *y )
{
	int i;
	for( i=0; i<4; i++ ){
		y[(i<<2)+0] = (Byte)(x[i]>>24&0xff);
		y[(i<<2)+1] = (Byte)(x[i]>>16&0xff);
		y[(i<<2)+2] = (Byte)(x[i]>> 8&0xff);
		y[(i<<2)+3] = (Byte)(x[i]>> 0&0xff);
	}
}

void RotBlock( const Word *x, const int n, Word *y )
{
	int r;
	if( r = (n & 31) ){
		y[0] = x[((n>>5)+0)&3]<<r^x[((n>>5)+1)&3]>>(32-r);
		y[1] = x[((n>>5)+1)&3]<<r^x[((n>>5)+2)&3]>>(32-r);
	}
	else{
		y[0] = x[((n>>5)+0)&3];
		y[1] = x[((n>>5)+1)&3];
	}
}

void SwapHalf( Byte *x )
{
	Byte t;
	int  i;
	for( i=0; i<8; i++ ){
		t = x[i];
		x[i] = x[8+i];
		x[8+i] = t;
	}
}

void XorBlock( const Byte *x, const Byte *y, Byte *z )
{
	int i;
	for( i=0; i<16; i++ ) z[i] = x[i] ^ y[i];
}

static int block_init(struct block_state *state, const uint8_t *key, size_t keylen){
	// weird note: of course the original source doesn't crash if the key size doesn't match
	// any expected values, yet it still XORs its way through uninitialised arrays.
	switch(keylen){
		case 16:
			state->key_size = 128;
			break;
		case 24:
			state->key_size = 192;
			break;
		case 32:
			state->key_size = 256;
			break;
		default:
			return ERR_KEY_SIZE;
	}
	Camellia_Ekeygen(state->key_size, key, state->key);
	return 0;
}

static void block_encrypt(struct block_state *state, const uint8_t *in, uint8_t *out){
	Camellia_Encrypt(state->key_size, in, state->key, out);
}

static void block_decrypt(struct block_state *state, const uint8_t *in, uint8_t *out){
	Camellia_Decrypt(state->key_size, in, state->key, out);
}

static void block_finalize(struct block_state *state){
	// Nothing to do here
	// but it could be used to zero the key
}  

#include "block_common.c"
