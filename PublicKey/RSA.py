#
#   RSA.py : RSA encryption/decryption
# 
#  Part of the Python Cryptography Toolkit
# 
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.  This software is provided "as is" without
# warranty of fitness for use or suitability for any purpose, express
# or implied. Use at your own risk or not at all. 
# 

__revision__ = "$Id: RSA.py,v 1.10 2002-12-23 21:42:03 z3p Exp $"

from Crypto.PublicKey import pubkey

try:
    from Crypto.PublicKey import _rsa
except:
    _rsa = None

class error (Exception):
    pass

def generate(bits, randfunc, progress_func=None):
    """generate(bits:int, randfunc:callable, progress_func:callable)

    Generate an RSA key of length 'bits', using 'randfunc' to get
    random data and 'progress_func', if present, to display
    the progress of the key generation.
    """
    obj=RSAobj()
    # Generate random number from 0 to 7
    difference=ord(randfunc(1)) & 7
    
    # Generate the prime factors of n
    if progress_func: progress_func('p\n')
    obj.p=pubkey.getPrime(bits/2, randfunc)
    if progress_func: progress_func('q\n')
    obj.q=pubkey.getPrime((bits/2)+difference, randfunc)
    obj.n=obj.p*obj.q
    
    # Generate encryption exponent
    if progress_func: progress_func('e\n')
    obj.e=pubkey.getPrime(17, randfunc)
    if progress_func: progress_func('d\n')
    obj.d=pubkey.inverse(obj.e, (obj.p-1)*(obj.q-1))
    return obj

def construct(tuple):
    """construct(tuple:(long,long)|(long,long,long)|(long,long,long,long,long))
             : RSAobj
    Construct an RSA object from a 2-, 3-, or 5-tuple of numbers.
    """
    
    obj=RSAobj()
    if len(tuple) not in [2,3,5]:
        raise error, 'argument for construct() wrong length' 
    for i in range(len(tuple)):
	field = obj.keydata[i]
	setattr(obj, field, tuple[i])
    return obj

class RSAobj(pubkey.pubkey):
    keydata=['n', 'e', 'd', 'p','q']
    def _encrypt(self, plaintext, K=''):
    	if self.n<=plaintext:
	    raise error, 'Plaintext too large'
	return (pow(plaintext, self.e, self.n),)

    def _decrypt(self, ciphertext):
	if (not hasattr(self, 'd')):
	    raise error, 'Private key not available in this object'
	if self.n<=ciphertext[0]:
	    raise error, 'Ciphertext too large'
	return pow(ciphertext[0], self.d, self.n)

    def _sign(self, M, K=''):
	return (self._decrypt((M,)),)

    def _verify(self, M, sig):
	m2=self._encrypt(sig[0])
	if m2[0]==M: return 1
	else: return 0
	
    def size(self):
	"""size() : int
        Return the maximum number of bits that can be handled by this key.
        """
        bits, power = 0,1L
	while (power<self.n): bits, power = bits+1, power<<1
	return bits-1
	
    def hasprivate(self):
	"""hasprivate() : bool
        Return a Boolean denoting whether the object contains
	private components.
        """
	if hasattr(self, 'd'): return 1
	else: return 0

    def publickey(self):
	"""publickey(): RSAobj
        Return a new key object containing only the public key information.
        """
        return construct((self.n, self.e))
	
class RSAobj_c(pubkey.pubkey):
    keydata = ['n', 'e', 'd', 'p', 'q']

    def __init__(self, key):
        self.key = key
        
    def __getattr__(self, attr):
        if attr in self.keydata:
            return getattr(self.key, attr)
        else:
            if self.__dict__.has_key(attr):
                self.__dict__[attr]
            else:
                raise AttributeError, '%s instance has no attribute %s' % (self.__class__, attr)

    def __getstate__(self):
        d = {}
        for k in self.keydata:
            if hasattr(self.key, k):
                d[k]=getattr(self.key, k)
        return d

    def __setstate__(self, state):
        n,e = state['n'], state['e']
        if 'd' not in state:
            self.key = _rsa.construct(n,e)
        else:
            d = state['d']
            if 'q' not in state:
                self.key = _rsa.construct(n,e,d)
            else:
                p, q = state['p'], state['q']
                self.key = _rsa.construct(n,e,d,p,q)

    def _encrypt(self, plain, K):
        return (self.key._encrypt(plain),)

    def _decrypt(self, cipher):
        return self.key._decrypt(cipher[0])
    
    def _sign(self, M, K):
        return (self.key._sign(M),)
    
    def _verify(self, M, sig):
        return self.key._verify(M, sig[0])
    
    def size(self):
        return self.key.size()
    
    def hasprivate(self):
        return self.key.hasprivate()
    
    def publickey(self):
        return construct_c((self.key.n, self.key.e))
 
def generate_c(bits, randfunc, progress_func = None):
    difference=ord(randfunc(1)) & 7
 
    # Generate the prime factors of n
    if progress_func: progress_func('p\n')
    p=pubkey.getPrime(bits/2, randfunc)
    if progress_func: progress_func('q\n')
    q=pubkey.getPrime((bits/2)+difference, randfunc)
    n=p*q
 
    # Generate encryption exponent
    if progress_func: progress_func('e\n')
    e=pubkey.getPrime(17, randfunc)
    if progress_func: progress_func('d\n')
    d=pubkey.inverse(e, (p-1)*(q-1))
    key = _rsa.construct(n,e,d,p,q)
    return RSAobj_c(key)

def construct_c(tuple):
    key = apply(_rsa.construct, tuple)
    return RSAobj_c(key)

object = RSAobj

generate_py = generate
construct_py = construct

if _rsa:
    #print "using C version of RSA"
    generate = generate_c
    construct = construct_c
    error = _rsa.error
