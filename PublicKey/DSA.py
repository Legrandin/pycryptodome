
#
#   DSA.py : Digital Signature Algorithm
# 
#  Part of the Python Cryptography Toolkit
# 
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.  This software is provided "as is" without
# warranty of fitness for use or suitability for any purpose, express
# or implied. Use at your own risk or not at all. 
# 

__revision__ = "$Id: DSA.py,v 1.4 2002-07-11 14:31:19 akuchling Exp $"

from Crypto.PublicKey.pubkey import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import SHA

class error (Exception):
    pass

def generateQ(randfunc):
    S=randfunc(20)
    hash1=SHA.new(S).digest()
    hash2=SHA.new(long_to_bytes(bytes_to_long(S)+1)).digest()
    q = bignum(0)
    for i in range(0,20):
        c=ord(hash1[i])^ord(hash2[i])
        if i==0: c=c | 128
        if i==19: c= c | 1
        q=q*256+c
    while (not isPrime(q)):
        q=q+2
    if pow(2,159L)<q<pow(2,160L): return S, q
    raise error, 'Bad q value generated'
    
def generate(bits, randfunc, progress_func=None):
    """generate(bits:int, randfunc:callable, progress_func:callable)

    Generate a DSA key of length 'bits', using 'randfunc' to get
    random data and 'progress_func', if present, to display
    the progress of the key generation.
    """
    
    if bits<160: raise error, 'Key length <160 bits'
    obj=DSAobj()
    # Generate string S and prime q
    if progress_func: progress_func('p,q\n')
    while (1):
        S, obj.q = generateQ(randfunc)
        n=(bits-1)/160
        C, N, V = 0, 2, {}
	b=(obj.q >> 5) & 15
	powb=pow(bignum(2), b)
	powL1=pow(bignum(2), bits-1)
        while C<4096:
            for k in range(0, n+1):
		V[k]=bytes_to_long(SHA.new(S+str(N)+str(k)).digest())
            W=V[n] % powb
            for k in range(n-1, -1, -1): W=(W<<160L)+V[k]
            X=W+powL1
            p=X-(X%(2*obj.q)-1)
            if powL1<=p and isPrime(p): break
            C, N = C+1, N+n+1
        if C<4096: break
	if progress_func: progress_func('4096 multiples failed\n')
    obj.p = p
    power=(p-1)/obj.q
    if progress_func: progress_func('h,g\n')
    while (1):
        h=bytes_to_long(randfunc(bits)) % (p-1)
        g=pow(h, power, p)
        if 1<h<p-1 and g>1: break
    obj.g=g
    if progress_func: progress_func('x,y\n')
    while (1):
        x=bytes_to_long(randfunc(20))
        if 0<x<obj.q: break
    obj.x, obj.y=x, pow(g, x, p)
    return obj
    
def construct(tuple):
    """construct(tuple:(long,long,long,long)|(long,long,long,long,long)):DSAobj
    Construct a DSA object from a 4- or 5-tuple of numbers.
    """
    obj=DSAobj()
    if len(tuple) not in [4,5]:
        raise error, 'argument for construct() wrong length' 
    for i in range(len(tuple)):
	field = obj.keydata[i]
	setattr(obj, field, tuple[i])
    return obj
    
class DSAobj(pubkey):
    keydata=['y', 'g', 'p', 'q', 'x']

    def _encrypt(self, s, Kstr):
        raise error, 'DSA algorithm cannot encrypt data'

    def _decrypt(self, s):
        raise error, 'DSA algorithm cannot decrypt data'

    def _sign(self, M, K):
	if (K<2 or self.q<=K): raise error, 'K is not between 2 and q'
        r=pow(self.g, K, self.p) % self.q
        s=(inverse(K, self.q)*(M+self.x*r)) % self.q
        return (r,s)

    def _verify(self, M, sig):
        r, s = sig
	if r<=0 or r>=self.q or s<=0 or s>=self.q: return 0
        w=inverse(s, self.q)
        u1, u2 = (M*w) % self.q, (r*w) % self.q
        v1=pow(self.g, u1, self.p)
	v2=pow(self.y, u2, self.p)
	v=((v1*v2) % self.p)
	v=v % self.q
        if v==r: return 1
        return 0
                
    def size(self):
	"Return the maximum number of bits that can be handled by this key."
        bits, power = 0,1L
	while (power<self.p): bits, power = bits+1, power<<1
	return bits-1
	
    def hasprivate(self):
	"""Return a Boolean denoting whether the object contains
	private components."""
	if hasattr(self, 'x'): return 1
	else: return 0

    def cansign(self):
	"""Return a Boolean value recording whether this algorithm can generate signatures."""
	return 1

    def canencrypt(self):
	"""Return a Boolean value recording whether this algorithm can encrypt data."""
	return 0
	
    def publickey(self):
	"""Return a new key object containing only the public information."""
        return construct((self.y, self.g, self.p, self.q))

object=DSAobj


