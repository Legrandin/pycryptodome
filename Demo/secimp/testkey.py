
import sys
#sys.path = ['../../..', sys.path]

import Crypto.PublicKey.DSA

key = Crypto.PublicKey.DSA.construct((
 # y
 0x43E9162E224CBD1B66D7C27EB7E795392310B5E7AC6E0B1F60021F5E03F90E851CB7F76603FAE73907154371AE04EDBF0D9D557DF03488F34C18324B8DFEF5D2L,
 # g
 0x4D6DB63479E55D0BE31CF1BEA58AB9365FC5EA267FFCD8424B56390E6EE7DD9BF788F696EED8475516353E61F37B8441137FA4F8DC82A9F84FA52BCD37517C32L,
 # p
 0x8000011124427A59DC0AF8AC982B490C75B1B3E94042F50F500E0636391C6FCC8C13E628528B4B75E158618A34592D5A68CA684371F9678BBA54DD40C0020F25L,
 # q
 0x9B128544B02353FF961E1774D2FA94E52E078F5DL,
 # x
 0x991386B7B92C221E42B1386D61255F5C58FD79A7L,
))

if __name__ == '__main__':
    # Running this script directly will generate a new key and print it out
    from Crypto.PublicKey import DSA
    from Crypto.Util.randpool import KeyboardRandomPool
    
    pool = KeyboardRandomPool(numbytes = 64)
    pool.Randomize()

    key = DSA.generate(512, pool.getBytes, sys.stdout.write)
    print "key = Crypto.PublicKey.DSA.construct(("
    for field in key.keydata:
	print " #", field
	print " " + hex(getattr(key, field)) + ","
    print '))'


    
