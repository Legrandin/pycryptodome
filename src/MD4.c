/*
 *  md4.c : MD4 hash algorithm.
 *
 * Part of the Python Cryptography Toolkit
 *
 * Originally written by: A.M. Kuchling
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain.  To
 * the extent that dedication to the public domain is not available,
 * everyone is granted a worldwide, perpetual, royalty-free,
 * non-exclusive license to exercise all rights associated with the
 * contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ===================================================================
 *
 */

#include "pycrypto_common.h"

FAKE_INIT(MD4)

typedef struct {
	uint32_t A,B,C,D, count;
	uint32_t len1, len2;
	uint8_t buf[64];
} hash_state;

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits */
#define ROL(x, n) (((x) << n) | ((x) >> (32-n) ))

EXPORT_SYM int md4_init (hash_state **md4State)
{
    hash_state *hs;
    
    if (NULL == md4State) {
        return ERR_NULL;
    }

    *md4State = hs = (hash_state*) calloc(1, sizeof(hash_state));
    if (NULL == hs)
        return ERR_MEMORY;
 
    hs->A=0x67452301;
    hs->B=0xefcdab89;
    hs->C=0x98badcfe;
    hs->D=0x10325476;

    return 0;
}

EXPORT_SYM int md4_destroy(hash_state *hs)
{
    free(hs);
    return 0;
}

EXPORT_SYM int md4_copy(const hash_state *src, hash_state *dst)
{
    if (NULL == src || NULL == dst) {
        return ERR_NULL;
    }

    *dst = *src;
    return 0;
}

EXPORT_SYM int md4_update(hash_state *hs, const uint8_t *buf, size_t len)
{
	uint32_t L;

        if (NULL == hs || NULL == buf)
            return ERR_NULL;
	
        if ((hs->len1+(len<<3))<hs->len1)
	{
		hs->len2++;
	}
	hs->len1+=len<< 3;
	hs->len2+=len>>29;
	while (len>0) 
	{
		L=(64-hs->count) < len ? (64-hs->count) : len;
		memcpy(hs->buf+hs->count, buf, L);
		hs->count+=L;
		buf+=L;
		len-=L;
		if (hs->count==64) 
		{
			uint32_t X[16], A, B, C, D;
			int i,j;
			hs->count=0;
			for(i=j=0; j<16; i+=4, j++) 
				X[j]=((uint32_t)hs->buf[i]       +
                                      ((uint32_t)hs->buf[i+1]<<8) +
				      ((uint32_t)hs->buf[i+2]<<16) +
                                      ((uint32_t)hs->buf[i+3]<<24));


			A=hs->A; B=hs->B; C=hs->C; D=hs->D;

#define function(a,b,c,d,k,s) a=ROL(a+F(b,c,d)+X[k],s);	 
			function(A,B,C,D, 0, 3);
			function(D,A,B,C, 1, 7);
			function(C,D,A,B, 2,11);
			function(B,C,D,A, 3,19);
			function(A,B,C,D, 4, 3);
			function(D,A,B,C, 5, 7);
			function(C,D,A,B, 6,11);
			function(B,C,D,A, 7,19);
			function(A,B,C,D, 8, 3);
			function(D,A,B,C, 9, 7);
			function(C,D,A,B,10,11);
			function(B,C,D,A,11,19);
			function(A,B,C,D,12, 3);
			function(D,A,B,C,13, 7);
			function(C,D,A,B,14,11);
			function(B,C,D,A,15,19);

#undef function	  
#define function(a,b,c,d,k,s) a=ROL(a+G(b,c,d)+X[k]+(uint32_t)0x5a827999,s);	 
			function(A,B,C,D, 0, 3);
			function(D,A,B,C, 4, 5);
			function(C,D,A,B, 8, 9);
			function(B,C,D,A,12,13);
			function(A,B,C,D, 1, 3);
			function(D,A,B,C, 5, 5);
			function(C,D,A,B, 9, 9);
			function(B,C,D,A,13,13);
			function(A,B,C,D, 2, 3);
			function(D,A,B,C, 6, 5);
			function(C,D,A,B,10, 9);
			function(B,C,D,A,14,13);
			function(A,B,C,D, 3, 3);
			function(D,A,B,C, 7, 5);
			function(C,D,A,B,11, 9);
			function(B,C,D,A,15,13);

#undef function	 
#define function(a,b,c,d,k,s) a=ROL(a+H(b,c,d)+X[k]+(uint32_t)0x6ed9eba1,s);	 
			function(A,B,C,D, 0, 3);
			function(D,A,B,C, 8, 9);
			function(C,D,A,B, 4,11);
			function(B,C,D,A,12,15);
			function(A,B,C,D, 2, 3);
			function(D,A,B,C,10, 9);
			function(C,D,A,B, 6,11);
			function(B,C,D,A,14,15);
			function(A,B,C,D, 1, 3);
			function(D,A,B,C, 9, 9);
			function(C,D,A,B, 5,11);
			function(B,C,D,A,13,15);
			function(A,B,C,D, 3, 3);
			function(D,A,B,C,11, 9);
			function(C,D,A,B, 7,11);
			function(B,C,D,A,15,15);

			hs->A+=A; hs->B+=B; hs->C+=C; hs->D+=D;
		}
	}

        return 0;
}

EXPORT_SYM int md4_digest(const hash_state *hs, uint8_t digest[16])
{
	static uint8_t s[8];
	uint32_t padlen, oldlen1, oldlen2;
	hash_state temp;
	static const uint8_t padding[64] = {
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

        if (NULL==hs || NULL==digest)
            return ERR_NULL;

        temp = *hs;
	oldlen1=temp.len1; oldlen2=temp.len2;  /* Save current length */
	padlen= (56<=hs->count) ? 56-hs->count+64: 56-hs->count;
	md4_update(&temp, padding, padlen);
	s[0]= oldlen1       & 255;
	s[1]=(oldlen1 >>  8) & 255;
	s[2]=(oldlen1 >> 16) & 255;
	s[3]=(oldlen1 >> 24) & 255;
	s[4]= oldlen2        & 255;
	s[5]=(oldlen2 >>  8) & 255;
	s[6]=(oldlen2 >> 16) & 255;
	s[7]=(oldlen2 >> 24) & 255;
	md4_update(&temp, s, 8);
  
	digest[ 0]= temp.A        & 255;
	digest[ 1]=(temp.A >>  8) & 255;
	digest[ 2]=(temp.A >> 16) & 255;
	digest[ 3]=(temp.A >> 24) & 255;
	digest[ 4]= temp.B        & 255;
	digest[ 5]=(temp.B >>  8) & 255;
	digest[ 6]=(temp.B >> 16) & 255;
	digest[ 7]=(temp.B >> 24) & 255;
	digest[ 8]= temp.C        & 255;
	digest[ 9]=(temp.C >>  8) & 255;
	digest[10]=(temp.C >> 16) & 255;
	digest[11]=(temp.C >> 24) & 255;
	digest[12]= temp.D        & 255;
	digest[13]=(temp.D >>  8) & 255;
	digest[14]=(temp.D >> 16) & 255;
	digest[15]=(temp.D >> 24) & 255;

        return 0;
}
