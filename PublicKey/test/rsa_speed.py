#!/usr/bin/env python

# Script to time fast and slow RSA operations
# Contributed by Joris Bontje.

import time, pprint
from Crypto.PublicKey import *
from Crypto.Util.randpool import RandomPool
from Crypto.Util import number

pool = RandomPool()
pool.stir()

KEYSIZE=2048
COUNT=5
fasttime=0
slowtime=0
for x in range(COUNT):
    begintime=time.time()
    rsa=RSA.generate(KEYSIZE, pool.get_bytes)
    endtime=time.time()
    print "Server: Generating %d bit RSA key: %f s" % (KEYSIZE, endtime-begintime)
    rsa_slow=RSA.construct((rsa.n,rsa.e,rsa.d))

    code=number.getRandomNumber(256, pool.get_bytes)
    begintime=time.time()
    signature=rsa.sign(code,None)[0]
    endtime=time.time()
    fast=(endtime-begintime)
    fasttime=fasttime+fast
    print "Fast signing took %f s" % fast

    begintime=time.time()
    signature_slow=rsa_slow.sign(code,None)[0]
    endtime=time.time()
    slow=(endtime-begintime)
    slowtime=slowtime+slow
    print "Slow signing took %f s" % slow

    if rsa.verify(code,(signature,)) and signature==signature_slow:
        print "Signature okay"
    else:
        print "Signature WRONG"

    print "faster: %f" % (slow/fast)

print "Based on %d signatures with %d bits keys the optimized\n RSA decryption/signing algorithm is %f times faster" % (COUNT, KEYSIZE, (slowtime/fasttime))

