#
#   pubkey.py : Internal functions for public key operations
# 
#  Part of the Python Cryptography Toolkit, version 1.1
# 
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.  This software is provided "as is" without
# warranty of fitness for use or suitability for any purpose, express
# or implied. Use at your own risk or not at all. 
# 

from Crypto.Util.number import *

# Basic public key class
import types
class pubkey:
    def __init__(self):
	pass
    def __getstate__(self): 
        """To keep key objects platform-independent, the key data is
        converted to standard Python long integers before being
        written out.  It will then be reconverted as necessary on
        restoration."""
        d=self.__dict__
        for key in self.keydata:
            if d.has_key(key): d[key]=long(d[key])
        return d

    def __setstate__(self, d): 
        """On unpickling a key object, the key data is converted to the big
number representation being used, whether that is Python long
integers, MPZ objects, or whatever."""
        for key in self.keydata:
            if d.has_key(key): self.__dict__[key]=bignum(d[key])

    def encrypt(self, plaintext, K):
	"""Encrypt the string or integer plaintext.  K is a random
	parameter required by some algorithms."""
	wasString=0
	if type(plaintext)==types.StringType:
	    plaintext=bytestolong(plaintext) ; wasString=1
	if type(K)==types.StringType:
	    K=bytestolong(K)
	ciphertext=self._encrypt(plaintext, K)
	if wasString: return tuple(map(longtobytes, ciphertext))
	else: return ciphertext
	
    def decrypt(self, ciphertext):
	"""Decrypt the string or integer ciphertext."""
	wasString=0
	if type(ciphertext)!=types.TupleType:
	    ciphertext=(ciphertext,)
	if types.StringType in map(type, ciphertext):
	    ciphertext=tuple(map(bytestolong, ciphertext)) ; wasString=1
	plaintext=self._decrypt(ciphertext)
	if wasString: return longtobytes(plaintext)
	else: return plaintext

    def sign(self, M, K):
	"""Return a tuple containing the signature for the message M.   K is a random
	parameter required by some algorithms."""
	if (not self.hasprivate()):
	    raise error, 'Private key not available in this object'
	if type(M)==types.StringType: M=bytestolong(M)
	if type(K)==types.StringType: K=bytestolong(K)
	return self._sign(M, K)

    def verify(self, M, signature):
	"""Verify that the signature is valid for the message M;
	returns true if the signature checks out."""
	if type(M)==types.StringType: M=bytestolong(M)
	return self._verify(M, signature)

    validate = verify   # alias to compensate for the old validate() name

    # The following methods will usually be left alone, except for
    # signature-only algorithms.  They both return Boolean values
    # recording whether this key's algorithm can sign and encrypt.
    def cansign(self): 
	"""Return a Boolean value recording whether this algorithm can generate signatures."""
	return 1
    def canencrypt(self): 
	"""Return a Boolean value recording whether this algorithm can encrypt data."""
	return 1

    # The following methods will certainly be overridden by
    # subclasses.
    
    def size(self): 
	"Return the maximum number of bits that can be handled by this key."
	return 0

    def hasprivate(self): 
	"""Return a Boolean denoting whether the object contains
	private components."""
	return 0

    def publickey(self): 
	"""Return a new key object containing only the public information."""
	return self
	
    
