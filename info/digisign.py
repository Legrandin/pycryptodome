#
#   digisign.py : Digital signature (using the q-NEW algorithm)
#
# Maintained by A.M. Kuchling (amk@magnet.com)
# Date: 1997/09/05
# 
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.
# 

# TODO : 
#   Add more comments and docstrings
#   Write documentation
#   Use mpz or gmp if available
#   Add assertions (later)
     
import types, string, marshal

# The code will try to use the SHA module, if present; otherwise
# the MD5 module will be used.  HASHBITS is the number of bits 
# in the hashing algorithm.

try:
    import sha ; hash = sha ; HASHBITS=160
except ImportError: 
    import md5 ; hash = md5 ; HASHBITS=128

class RandomPool:
    """Cryptographically strong generation of random strings"""
    def __init__(self, seed=None):
	"""Initialize the generator, using a provided string as the seed.
	If the string is omitted, the class will try to do its best to get 
	some random data, and print a warning."""
	if seed==None: seed=self.getseed()
	S=range(256)
	seed=map(ord, seed)
	x = y = 0 ; i1 = i2 = 0
	for i in range(256):
	    i2 = (seed[i1] + S[i] + i2) % 256
	    S[i], S[i2] = S[i2], S[i]
	    i1 = (i1 + 1) % len(seed)
	self.S, self.x, self.y = S,x,y

    def random(self, N):
	"Return an N-byte string containing random bytes"
	x,y, S = self.x, self.y, self.S
	output=[None]*N
	for i in range(N):
	    x = (x + 1) % 256
	    y = (y + S[x]) % 256
	    S[x], S[y] = S[y], S[x]
	    xorIndex = (S[x] + S[y]) % 256
	    output[i] = chr( S[xorIndex] )
	self.x, self.y = x,y
	return string.join(output, '')
    def getseed(self):
	"""If no seed was provided by the user (bad user!), try to generate
	a useful seed.  This may print a warning."""
	try:
	    # If possible, use /dev/urandom.  On FreeBSD 2.1.5 or later,
	    # and Linux 1.3.X or later, /dev/urandom is maintained by the
	    # OS, and uses random things like disk interrupt timings and 
	    # keyboard noise.  It must be opened in unbuffered mode
	    # for some reason.
	    f=open('/dev/urandom', 'r', 0)
	    seed=f.read(256)
	    f.close()
	    return seed
	except IOError:
	    # Presumably /dev/urandom isn't there...  Use a lame
 	    # time-based scheme that isn't very good, and print a warning
 	    # to encourage the programmer to improve things.
	    import time, os, sys
	    print " (Using poor time-based scheme to initialize random-number generator)"
	    seed=str( 'dummy data' )
	    for i in range(0, 16):
		rand='%s%s%s' % (time.time(), os.getpid(), sys.getrefcount(i) )
		rand=hash.new( rand ).digest()
		seed=seed+rand
	    return seed

_randpool=None

def RandomNumber(N, randfunc):
    "Return an N-bit random number. N must be a multiple of 8."
    if N % 8 != 0:
        raise ValueError, "N must be a multiple of 8"
    str=randfunc(N/8)
    char=ord(str[0])|128
    return Str2Int(chr(char)+str[1:])
    
def Int2Str(n):
    "Convert a long integer to a string form"
    s=''
    while n>0:
        s=chr(n & 255)+s
        n=n>>8
    return s

def Str2Int(s):
    "Convert a string to a long integer"
    if type(s)!=types.StringType: return s   # Integers will be left alone
    return reduce(lambda x,y : x*256+ord(y), s, 0L)
    
sieve=[2,3,5,7,11,13,17,19,23,29,31,37,41]
def isPrime(N):
    """Test if a number N is prime, using a simple sieve check, 
    followed by a more elaborate XXX test."""
    for i in sieve:
        if (N % i)==0: return 0
    N1=N - 1L ; n=1L
    while (n<N): n=n<<1L # Compute number of bits in N
    for j in sieve:
        a=long(j) ; d=1L ; t=n
        while (t):  # Iterate over the bits in N1
            x=(d*d) % N
            if x==1L and d!=1L and d!=N1: return 0  # Square root of 1 found
            if N1 & t: d=(x*a) % N
            else: d=x
            t=t>>1L
        if d!=1L: return 0
        return 1

def getPrime(N, randfunc):
    "Find a prime number measuring N bits"
    number=RandomNumber(N, randfunc) | 1 # Ensure the number is odd
    while (not isPrime(number)):
        number=number+2
    return number



class Key:
    """Key object (both public and private)

    Methods
    generate -- Generate a fresh public/private key pair
    sign      -- Sign a message, returning the signature
    verify    -- Verify a signature for the message 
    cansign   -- Return TRUE if the key can sign messages
    publickey -- Return a new key containing only the public data
 
    Attributes:
    size      -- Size (in bits) of messages that can be processed.
    """
    def generate(self, bits=1024, randfunc=None, progress_func=None):
	"""Generate a private key with a modulus of the given size
        bits -- modulus size of the generated key; the bigger it is,
        	the more secure the key (and the slower key generation
		and signing is).  For security, use a bit size of 768
 	        or 1024; 512 or 384 is too small for comfort (though you may
		use it in testing).
        randfunc -- A function that generates random data. 
	            (Optional, but recommended)
	progress_func -- (Optional) As a key is generated, this function
	                 will be used to output progress messages.
	"""
	global _randpool
	if randfunc==None:
	    _randpool=RandomPool()
	    randfunc=_randpool.random

	if bits<384: raise ValueError, 'Key length <384 bits'

	# Generate prime numbers p and q.  q is a 160-bit prime
	# number.  p is another prime number (the modulus) whose bit
	# size is chosen by the caller, and is generated so that p-1
	# is a multiple of q.  
	#
	# Note that only a single seed is used to
	# generate p and q; if someone generates a key for you, you can
	# use the seed to duplicate the key generation.  This can
	# protect you from someone generating values of p,q that have
	# some special form that's easy to break.
	if progress_func: progress_func('p,q\n')
	while (1):
	    self.q = getPrime(160, randfunc)
#	    assert pow(2, 159L)<self.q<pow(2, 160L)
            self.seed = S = Int2Str(self.q)
	    C, N, V = 0, 2, {}
	    # Compute b and n such that bits-1 = b + n*HASHBITS
	    n= (bits-1) / HASHBITS
            b= (bits-1) % HASHBITS ; powb=pow(long(2), b)
	    powL1=pow(long(2), bits-1)
	    while C<4096:
		# The V array will contain (bits-1) bits of random
	        # data, that are assembled to produce a candidate
		# value for p.
		for k in range(0, n+1):
		    V[k]=Str2Int(hash.new(S+str(N)+str(k)).digest())
		p = V[n] % powb
		for k in range(n-1, -1, -1): 
                    p= (p << long(HASHBITS) )+V[k]
		p = p+powL1		# Ensure the high bit is set

		# Ensure that p-1 is a multiple of q 
		p = p - (p % (2*self.q)-1)

		# If p is still the right size, and it's prime, we're done!
		if powL1<=p and isPrime(p): break

		# Otherwise, increment the counter and try again
		C, N = C+1, N+n+1
	    if C<4096: break   # Ended early, so exit the while loop
	    if progress_func: progress_func('4096 values of p tried\n')

	self.p = p
	power=(p-1)/self.q

	# Next parameter: g = h**((p-1)/q) mod p, such that h is any 
	# number <p-1, and g>1.  g is kept; h can be discarded.
	if progress_func: progress_func('h,g\n')
	while (1):
	    h=Str2Int(randfunc(bits)) % (p-1)
	    g=pow(h, power, p)
	    if 1<h<p-1 and g>1: break
	self.g=g

	# x is the private key information, and is 
	# just a random number between 0 and q.
	# y=g**x mod p, and is part of the public information.
	if progress_func: progress_func('x,y\n')
	while (1):
	    x=Str2Int(randfunc(20))
	    if 0<x<self.q: break
	self.x, self.y=x, pow(g, x, p)

	self.size = 160
	
    def cansign(self):
	"""Return a Boolean denoting whether the object contains 
	private components, and hence can sign messages."""
	if hasattr(self, 'x'): return 1
	else: return 0
    def canencrypt(self):
	return 0
	
    def publickey(self):
	new=Key()
	new.p = self.p 
	new.q = self.q 
	new.g = self.g 
	new.y = self.y
	# x isn't copied, of course, since it's the private key.
#	assert not (hasattr(new, 'x') or hasattr(new, 'seed') )
        return new

    def _sign(self, M, K):
	if (self.q<=K):
	    raise ValueError, 'K is greater than q'
	if M<0: 
	    raise ValueError, 'Illegal value of M (<0)'
	if M>=pow(2,161L): 
	    raise ValueError, 'Illegal value of M (too large)'
        r=pow(self.g, K, self.p) % self.q
        s=(K- (r*M*self.x % self.q)) % self.q
        return marshal.dumps( (r,s) )
    def _verify(self, M, sig):
        r, s = marshal.loads(sig)
	if r<=0 or r>=self.q or s<=0 or s>=self.q: return 0
 	if M<0: 
 	    raise ValueError, 'Illegal value of M (<0)'
 	if M>=pow(2,161L): 
 	    raise ValueError, 'Illegal value of M (too large)'
	if M<=0 or M>=pow(2,161L): return 0
        v1=pow(self.g, s, self.p)
	v2=pow(self.y, M*r, self.p)
	v=((v1*v2) % self.p)
	v=v % self.q
        if v==r: return 1
        return 0

    def sign(self, M, randfunc=None, K=None):
	if (not self.cansign()):
	    raise TypeError, 'Not a private key object'
	if type(M)==types.StringType: M=Str2Int(M)

	if K==None:
            # Generate a random value of K, that must be <q
            global _randpool
            if randfunc==None:
                if _randpool==None:
                    _randpool=RandomPool()
                randfunc=_randpool.random
            K=RandomNumber(160, randfunc) >> 1
#            assert K<self.q
	else:
	    if type(K)==types.StringType: K=Str2Int(K)
	return self._sign(M, K)
    def verify(self, M, signature):
	if type(M)==types.StringType: M=Str2Int(M)
	return self._verify(M, signature)
    validate=verify

new=Key

if __name__=='__main__':
    import sys, string
    BITS=512
    if len(sys.argv)>1:
        BITS=string.atoi(sys.argv[1])
    print ' Generating', BITS, 'bit key'
    key=new()
    key.generate(BITS, progress_func=sys.stdout.write)
    print ' Key data: (the private key is x)'
    for i in 'xygqp': print '\t', i, ':', hex(getattr(key, i))
    message="This is a contract."

    if key.cansign():
	print ' Signature test'
	print "Message:", message
	signature=key.sign(message)
	print "Signature:", repr(signature)
	result=key.verify(message, signature)
	if not result:
	    print " Sig. verification failed when it should have succeeded"
	else: print 'Signature verified'

	# Test on a mangled message
	result=key.verify(message[:-1], signature)
	if result:
	    print " Sig. verification succeeded when it should have failed"

	# Change a single bit in the message
	badtext=message[:-3]+chr( 1 ^ ord(message[-3]) )+message[-3:]
	result=key.verify(badtext, signature)
	if result:
	    print " Sig. verification succeeded when it should have failed"

	import pickle
	print 'Removing private key data'
	pubonly=key.publickey()
	pickledata=pickle.dumps(pubonly)
	pubonly=pickle.loads(pickledata)
	result=pubonly.verify(message, signature)
	if not result:
	    print " Sig. verification failed when it should have succeeded"
        else: 
            print 'Signature verified'
