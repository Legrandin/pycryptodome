#!/usr/bin/env python

""" Example of Chaumian blinding """

import time, pprint, os, sha
from Crypto.PublicKey import *
from Crypto.Util.randpool import RandomPool
from Crypto.Util import number
import cPickle as pickle

# Globals
pool = RandomPool()
pool.stir()

# use SHA-1 by default, if you want to use SHA-256, SHA-384 or SHA-512 you
# need shax-py from http://philosophysw.com/software/
digest = sha.sha

KEYSIZE = 1024
KEYFILE = "tokenkey.pickle"
HASHSIZE = sha.digestsize*8

### Initialization ###

if os.path.isfile(KEYFILE):
    # Load existing key """
    print "Server: load key..."
    ff = file(KEYFILE, 'r')
    key = pickle.load(ff)
    rsa = RSA.construct(key)
else:
    # Generate an RSA key-pair of KEYSIZE bits and store the key
    print "Server: create key (will take a while, but only has to be done once)..."
    begintime=time.time()
    rsa=RSA.generate(KEYSIZE, pool.get_bytes) 
    endtime=time.time()
    print "Server: Generate %d bit RSA key: %f s" % (KEYSIZE, endtime-begintime)

    key = (rsa.n, rsa.e, rsa.d, rsa.p, rsa.q, rsa.u)
    ff = file(KEYFILE, 'w')
    pickle.dump(key, ff)

print "RSA key:"
print "n = %s" % pprint.pformat(rsa.n)  # Public key
print "e = %s" % pprint.pformat(rsa.e)  # Public key

print "d = %s" % pprint.pformat(rsa.d)  # Private key
# Values below are not really needed, but cause a big speedup since the Chinese Remainders Theorem can be used
print "p = %s" % pprint.pformat(rsa.p)  # Private key
print "q = %s" % pprint.pformat(rsa.q)  # Private key
print "u = %s" % pprint.pformat(rsa.u)  # Private key
print

### Client ###

# Generate random tokenId of HASHSIZE bits
tokenId = number.getRandomNumber(HASHSIZE, pool.get_bytes)

# Generate random blindingFactor of KEYSIZE-1 (so it can still be signed) bits
while 1:
    blindingFactor = number.getRandomNumber(KEYSIZE-1, pool.get_bytes)
    # Verify that GCD(r, n) ==1
    if number.GCD(blindingFactor, rsa.n)==1:
        break

# Calculate the hash of the tokenId
tokenHash = number.bytes_to_long(digest(number.long_to_bytes(tokenId)).digest())

print "tokenId = %s" % pprint.pformat(tokenId)
print "blindingFactor = %s" % pprint.pformat(blindingFactor)
print "tokenHash = %s" % pprint.pformat(tokenHash)
print

# Blind the hashed tokenId with blindingFactor
begintime=time.time()
blindedToken=rsa.blind(tokenHash, blindingFactor)
endtime=time.time()
print "Client: Blinding: %f s" % (endtime-begintime)
print "blindedToken = %s" % pprint.pformat(blindedToken)

# Send blindedToken to the server
print "Client -> Server: blindedToken"
print

### Server ###

# Sign the blindedToken
begintime=time.time()
blindedSignature=rsa.sign(blindedToken, None)[0]
endtime=time.time()
print "Server: Signing: %f s" % (endtime-begintime)
print "blindedSignature = %s" % pprint.pformat(blindedSignature)

# Send the blindedSignature back to the client
print "Server -> Client: blindedSignature"
print

### Client ###

# Unblind the blindedSignature
begintime=time.time()
signature=rsa.unblind(blindedSignature, blindingFactor)
endtime=time.time()
print "Client: Unblinding: %f s" % (endtime-begintime)
print "signature = %s" % pprint.pformat(signature)
print

# Token is ready
token = (tokenId, signature)
print "Client: token = %s" % pprint.pformat(token)

print
print "... user can now use the token..."
print "Client -> Server: token"
print

### Server ###

# Verify that the signature of hash(tokenId) is right
begintime=time.time()
v=rsa.verify(number.bytes_to_long(digest(number.long_to_bytes(token[0])).digest()), (token[1],))
endtime=time.time()
print "Server: Verifying: %f s" % (endtime-begintime)

if v:
    print "Server: SIGNATURE OK"
else:
    print "Server: SIGNATURE NOT OK"

