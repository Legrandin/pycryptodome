#!/usr/bin/env python

import time, pprint, os, sha
from Crypto.PublicKey import *
from Crypto.Util.randpool import RandomPool
from Crypto.Util import number
import cPickle as pickle

pool = RandomPool()
pool.stir()

digest=sha.sha

KEYSIZE=1024
COINSIZE=256
HASHSIZE=sha.digestsize*8

DENOMINATIONPICKLE = 'denomination.pickle'

if os.path.isfile(DENOMINATIONPICKLE):
    print "Server: load denomination..."
    ff = file(DENOMINATIONPICKLE, 'r')
    key = pickle.load(ff)
    rsa = RSA.construct(key)
else:
    print "Server: create denomination (will take a while, only has to be done once for each denomiation of coin you want)..."
    begintime=time.time()
    rsa=RSA.generate(KEYSIZE, pool.get_bytes)
    endtime=time.time()
    print "Server: Generate %d bit RSA key: %f s" % (KEYSIZE, endtime-begintime)

    key = (rsa.n, rsa.e, rsa.d)
    ff = file(DENOMINATIONPICKLE, 'w')
    pickle.dump(key, ff)


print "n = %s" % pprint.pformat(rsa.n)
print "e = %s" % pprint.pformat(rsa.e)
print "d = %s" % pprint.pformat(rsa.d)
print

coinId = number.getRandomNumber(COINSIZE, pool.get_bytes)
while 1:
    blindingFactor = number.getRandomNumber(HASHSIZE, pool.get_bytes)
    if number.GCD(blindingFactor, rsa.n)==1:
        break
coinHash = number.bytes_to_long(digest(number.long_to_bytes(coinId)).digest())

print "coinId = %s" % pprint.pformat(coinId)
print "blindingFactor = %s" % pprint.pformat(blindingFactor)
print "coinHash = %s" % pprint.pformat(coinHash)
print

begintime=time.time()
blindedCoin=rsa.blind(coinHash, blindingFactor)
endtime=time.time()
print "Client: Blinding: %f s" % (endtime-begintime)
print "blindedCoin = %s" % pprint.pformat(blindedCoin)
print

begintime=time.time()
blindedSignature=rsa.sign(blindedCoin, None)[0]
endtime=time.time()
print "Server: Signing: %f s" % (endtime-begintime)
print "blindedSignature = %s" % pprint.pformat(blindedSignature)
print

begintime=time.time()
signature=rsa.unblind(blindedSignature, blindingFactor)
endtime=time.time()
print "Client: Unblinding: %f s" % (endtime-begintime)
print "signature = %s" % pprint.pformat(signature)
print


#rawSignature=rsa.sign(coinHash, None)[0]
#print "rawSignature = %s" % pprint.pformat(rawSignature)
#print

print "... user can now spend coin..."
print "... merchant deposits coin..."
print

begintime=time.time()
v=rsa.verify(coinHash, (signature,))
endtime=time.time()
print "Server: Verifying: %f s" % (endtime-begintime)

if v:
    print "OK"
else:
    print "NOT OK"


