#
#   test.py : Functions used for testing the modules
# 
#  Part of the Python Cryptography Toolkit, version 1.1
# 
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.  This software is provided "as is" without
# warranty of fitness for use or suitability for any purpose, express
# or implied. Use at your own risk or not at all. 
# 

from Crypto.Hash import *
from Crypto.Cipher import *

def die(string):
    import sys
    print '***ERROR: ', string
#    sys.exit(0)   # Will default to continuing onward...

def hex2str(str):
    s=''
    for i in range(0,len(str),2):
	s=s+chr(string.atoi(str[i:i+2], 16))
    return s
    
def exerciseBlockCipher(cipher, verbose):
    import string, time
    try:
        ciph = eval(cipher)
    except NameError:
        print cipher, 'module not available'
        return None
    print cipher+ ':'
    str='1'				# Build 128K of test data
    for i in xrange(0, 17):
        str=str+str
    if ciph.key_size==0: ciph.key_size=16
    password = 'password12345678Extra text for password'[0:ciph.key_size]
    IV = 'Test IV Test IV Test IV Test'[0:ciph.block_size]

    if verbose: print '  Testing ECB mode with key '+ `password`
    obj=ciph.new(password, ciph.MODE_ECB)
    if verbose: print '    Sanity check'
    if obj.block_size != ciph.block_size:
        die("Module and cipher object block_size don't match")
        
    text='1234567812345678'[0:ciph.block_size]
    c=obj.encrypt(text)
    if (obj.decrypt(c)!=text): die('Error encrypting "'+text+'"')
    text='KuchlingKuchling'[0:ciph.block_size]
    c=obj.encrypt(text)
    if (obj.decrypt(c)!=text): die('Error encrypting "'+text+'"')
    text='NotTodayNotEver!'[0:ciph.block_size]
    c=obj.encrypt(text)
    if (obj.decrypt(c)!=text): die('Error encrypting "'+text+'"')

    start=time.time()
    s=obj.encrypt(str)
    s2=obj.decrypt(s)
    end=time.time()
    if (str!=s2):
	die('Error in resulting plaintext from ECB mode')
    if verbose: print '    Benchmark for 256K: ', 256/(end-start), 'K/sec'
    del obj
    
    if verbose: print '  Testing CFB mode with key ' + `password`+ ' IV "Test IV@"'
    obj1=ciph.new(password, ciph.MODE_CFB, IV)
    obj2=ciph.new(password, ciph.MODE_CFB, IV)
    start=time.time()
    ciphertext=obj1.encrypt(str[0:65536])
    plaintext=obj2.decrypt(ciphertext)
    end=time.time()
    if (plaintext!=str[0:65536]):
	die('Error in resulting plaintext from CFB mode')
    if verbose: print '    Benchmark for  64K: ', 64/(end-start), 'K/sec'
    del obj1, obj2
    
    if verbose: print '  Testing CBC mode with key ' + `password`+ ' IV "Test IV@"'
    obj1=ciph.new(password, ciph.MODE_CBC, IV)
    obj2=ciph.new(password, ciph.MODE_CBC, IV)
    start=time.time()
    ciphertext=obj1.encrypt(str)
    plaintext=obj2.decrypt(ciphertext)
    end=time.time()
    if (plaintext!=str):
	die('Error in resulting plaintext from CBC mode')
    if verbose: print '    Benchmark for 256K: ', 256/(end-start), 'K/sec'
    del obj1, obj2

    if verbose: print '  Testing PGP mode with key ' + `password`+ ' IV "Test IV@"'
    obj1=ciph.new(password, ciph.MODE_PGP, IV)
    obj2=ciph.new(password, ciph.MODE_PGP, IV)
    start=time.time()
    ciphertext=obj1.encrypt(str)
    plaintext=obj2.decrypt(ciphertext)
    end=time.time()
    if (plaintext!=str):
	die('Error in resulting plaintext from PGP mode')
    if verbose: print '    Benchmark for 256K: ', 256/(end-start), 'K/sec'
    del obj1, obj2

    # Test the IV handling
    if verbose: print '  Testing IV handling'
    obj1=ciph.new(password, ciph.MODE_CBC, IV)
    plaintext='Test'*(ciph.block_size/4)*3
    ciphertext1=obj1.encrypt(plaintext)
    obj1.IV=IV
    ciphertext2=obj1.encrypt(plaintext)
    if ciphertext1!=ciphertext2:
        die('Error in setting IV')

    # Test keyword arguments
    obj1=ciph.new(key=password)
    obj1=ciph.new(password, mode=ciph.MODE_CBC)
    obj1=ciph.new(mode=ciph.MODE_CBC, key=password)
    obj1=ciph.new(IV=IV, mode=ciph.MODE_CBC, key=password)

    return ciph

def exerciseStreamCipher(cipher, verbose):
    import string, time
    try:
        ciph = eval(cipher)
    except (NameError):
        print cipher, 'module not available'
        return None
    print cipher + ':'
    str='1'				# Build 128K of test data
    for i in xrange(0, 17):
        str=str+str
    key_size = ciph.key_size or 16
    password = 'password12345678Extra text for password'[0:key_size]
    
    obj1=ciph.new(password)
    obj2=ciph.new(password)
    if verbose: print '  Sanity check'
    if obj1.block_size != ciph.block_size:
        die("Module and cipher object block_size don't match")
    if obj1.key_size != ciph.key_size:
        die("Module and cipher object key_size don't match")

    text='1234567812345678Python'
    c=obj1.encrypt(text)
    if (obj2.decrypt(c)!=text): die('Error encrypting "'+text+'"')
    text='B1FF I2 A R3A11Y |<00L D00D!!!!!'
    c=obj1.encrypt(text)
    if (obj2.decrypt(c)!=text): die('Error encrypting "'+text+'"')
    text='SpamSpamSpamSpamSpamSpamSpamSpamSpam'
    c=obj1.encrypt(text)
    if (obj2.decrypt(c)!=text): die('Error encrypting "'+text+'"')

    start=time.time()
    s=obj1.encrypt(str)
    str=obj2.decrypt(s)
    end=time.time()
    if verbose: print '    Benchmark for 256K: ', 256/(end-start), 'K/sec'
    del obj1, obj2

    return ciph

def exercisePublicKey(randfunc, module, verbose):
    N=256				# Key size, measured in bits

    if verbose: print ' Generating', N, 'bit key'
    import sys
    import Crypto.Util.number
    def write(s):
	import sys ; sys.stdout.write('  '+s)
    if verbose: key=module.generate(N, randfunc, write)
    else: key=module.generate(N, randfunc)

    if verbose: 
        print ' Key data:'
        for field in key.keydata:
            print "  ", field, ':', hex(getattr(key,field))

    def testkey(key, randfunc, verbose):
	plaintext="Hello"

	if key.canencrypt():
	    if verbose: print '  Encryption/decryption test'
	    K=Crypto.Util.number.getPrime(10, randfunc)
	    ciphertext=key.encrypt(plaintext, K)
	    if key.decrypt(ciphertext)!=plaintext:
		print '***ERROR: Mismatch decrypting plaintext'

	if key.cansign():
	    if verbose: print '  Signature test'
	    K=Crypto.Util.number.getPrime(30, randfunc)
	    signature=key.sign(plaintext, K)
	    result=key.verify(plaintext, signature)
	    if not result:
		print "***ERROR 1: Sig. verification failed when it should have succeeded"
	    result=key.verify(plaintext[:-1], signature)
	    if result:
		print "***ERROR 2: Sig. verification succeeded when it should have failed"
	    # Change a single bit in the plaintext
	    badtext=plaintext[:-3]+chr( 1 ^ ord(plaintext[-3]) )+plaintext[-3:]
	    result=key.verify(badtext, signature)
	    if result:
		print "***ERROR 3: Sig. verification succeeded when it should have failed"
	    if verbose: print '  Removing private key data'
	    pubonly=key.publickey()
	    result=pubonly.verify(plaintext, signature)
	    if not result:
		print "***ERROR 4: Sig. verification failed when it should have succeeded"

    if verbose: print " Testing newly generated key"
    testkey(key, randfunc, verbose)
    if verbose: print " Testing pickled/unpickled key"
    import pickle
    s = pickle.dumps(key) ; key2 = pickle.loads(s)
    testkey(key2, randfunc, verbose)

    if verbose: print " Testing cPickled key"
    import cPickle
    s = cPickle.dumps(key) ; key2 = cPickle.loads(s)
    testkey(key2, randfunc, verbose)
    if verbose: print

import string
def compareHashResult(hash, strg, result):
    obj=hash.new(strg)
    s=obj.digest()
    s1=s
    temp=0L
    while (s!=''):
	temp=temp*256+ord(s[0])
	s=s[1:]

    # Check that the right hash result is produced
    if (result!=temp):
	die(`hash`+' produces incorrect result on string "'+strg+'"')
	return

    # Check that .hexdigest() produces the same output
    hex_result = string.lower( hex(result)[2:-1] )
    if len(hex_result) % 2: hex_result = '0'+hex_result 
    if hex_result != obj.hexdigest():
	die(`hash`+' produces incorrect result on string "'+strg+'" using hexdigest()')
	return 

    # Test second hashing, and copying of a hashing object
    s2=obj.digest()
    if s2!=s1: die(`hash`+' produces incorrect result on second hashing')
    s3=obj.copy().digest()
    if s3!=s1: die(`hash`+' produces incorrect result after copying')

    del temp, s

    
import Crypto.Util.testdata

def TestHashModules(args=['ripemd', 'md2', 'md4'], 
		    verbose=1):
    import string
    args=map(string.lower, args)

    teststr='1'				# Build 128K of test data
    for i in xrange(0, 17):
	teststr=teststr+teststr

    if 'ripemd' in args:
	# Test/benchmark RIPEMD hash algorithm ; the test data is taken from
	# the README in rmd.zip
	try:
	    from Crypto.Hash import RIPEMD
	except ImportError:
	    print 'RIPEMD module not available'
	else:
	    print 'RIPEMD:'
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for text, hash in Crypto.Util.testdata.ripemd:
		    compareHashResult(RIPEMD, text, hash)
		# Compute value for 1 megabyte of a's...
		obj, astring=RIPEMD.new(), 1000*'a'
		for i in range(0,1000): obj.update(astring)
		result=obj.digest()
		if result!=hex2str("52783243c1697bdbe16d37f97f68f08325dc1528"):
		    die('RIPEMD produces incorrect result on 1E6*"a"')

		if verbose: print '  Completed'
		import time
		obj=RIPEMD.new()
		start=time.time()
		s=obj.update(teststr)
		end=time.time()
		if verbose: print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
		del obj
		
    if 'md2' in args:
	# Test/benchmark MD2 hash algorithm ; the test data is taken from
	# RFC1319, "The MD2 Message-Digest Algorithm"
	try:
	    from Crypto.Hash import MD2
	except ImportError:
	    print 'MD2 module not available'
	else:
	    print 'MD2:'
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for text, hash in Crypto.Util.testdata.md2:
		    compareHashResult(MD2, text, hash)
		if verbose: print '  Completed'
		import time
		obj=MD2.new()
		start=time.time()
		s=obj.update(teststr)
		end=time.time()
		if verbose: print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
		del obj

    if 'md4' in args:
	# Test/benchmark MD4 hash algorithm ; the test data is taken from
	# RFC1186B, "The MD4 Message-Digest Algorithm"
	try:
	    from Crypto.Hash import MD4
	except ImportError:
	    print 'MD4 module not available'
	else:
	    print 'MD4:'
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for text, hash in Crypto.Util.testdata.md4:
		    compareHashResult(MD4, text, hash)
		if verbose: print '  Completed'
		import time
		obj=MD4.new()
		start=time.time()
		s=obj.update(teststr)
		end=time.time()
		if verbose: print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
		del obj

    if 'md5' in args:
	# Test/benchmark MD5 hash algorithm ; the test data is taken from
	# RFC1321, "The MD5 Message-Digest Algorithm"
	try:
	    from Crypto.Hash import MD5
	except ImportError:
	    print 'MD5 module not available'
	else:
	    print 'MD5:'
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for text, hash in Crypto.Util.testdata.md5:
		    compareHashResult(MD5, text, hash)
		if verbose: print '  Completed'
		import time
		obj=MD5.new()
		start=time.time()
		s=obj.update(teststr)
		end=time.time()
		if verbose: print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
		del obj

    if 'haval' in args:
	# Test/benchmark HAVAL
	try:
	    from Crypto.Hash import HAVAL
	except ImportError:
	    print 'HAVAL module not available'
	else:
	    print 'HAVAL:'
	    try:
		import Crypto.Util.testdata
		if verbose: print '  Verifying against test suite...'
		for (passes, length, text, hash) in Crypto.Util.testdata.haval:
		    ID=str(passes)+'-pass, '+str(length)+'-bit HAVAL '
		    obj=HAVAL.new('', rounds=passes, digestsize=length)
		    obj.update(text)
		    s1=obj.digest()
		    if (s1!=hex2str(hash)):
			die(ID+'produces incorrect result on string "'+text+'"')
		    s2=obj.digest()
		    if s2!=s1: die(ID+'produces incorrect result on second hashing')
		    s3=obj.copy().digest()
		    if s3!=s1: die(ID+'produces incorrect result after copying')
		if verbose: print '  Completed'
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    obj=HAVAL.new()
	    import time
	    start=time.time()
	    s=obj.update(teststr)
	    end=time.time()
	    if verbose: print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
	    del obj

    if 'sha' in args:
	# Test/benchmark SHA hash algorithm
	try:
	    from Crypto.Hash import SHA
	except ImportError:
	    print 'SHA module not available'
	else:
	    print 'SHA:'
	    if verbose: print '  Verifying against test suite...'
	    for text, hash in Crypto.Util.testdata.sha:
		compareHashResult(SHA, text, hash)
	    # Compute value for 1 megabyte of a's...
	    obj, astring=SHA.new(), 1000*'a'
	    for i in range(0,1000): obj.update(astring)
	    result=obj.digest()
	    if result!=hex2str('34AA973CD4C4DAA4F61EEB2BDBAD27316534016F'):
		die('SHA produces incorrect result on 1E6*"a"')
	    if verbose: print '  Completed'
	    obj=SHA.new()
	    start=time.time()
	    s=obj.update(teststr)
	    end=time.time()
	    if verbose: print '  Benchmark for 128K: ', 128/(end-start), 'K/sec'
	    del obj, astring

def TestStreamModules(args=['arc4', 'XOR'], verbose=1):
    import sys, string
    args=map(string.lower, args)

    if 'arc4' in args:
	# Test ARC4 stream cipher
	arc4=exerciseStreamCipher('ARC4', verbose)
	if (arc4!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		for entry in Crypto.Util.testdata.arc4:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=arc4.new(key)
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('ARC4 failed on entry '+`entry`)
		if verbose: print '  ARC4 test suite completed'

    if 'sapphire' in args:
	# Test Sapphire stream cipher
	sapphire=exerciseStreamCipher('Sapphire', verbose)
	if (sapphire!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		result=hex2str(Crypto.Util.testdata.sapphire)
		obj=sapphire.new('testSapphirekey')
		s=''
		for i in range(0,256):
		    s=s+chr(i)
		s=obj.encrypt(s)
		if (s!=result):
		    die('Sapphire fails verification test')
		if verbose: print '  Sapphire test suite completed'

    if 'xor' in args:
	# Test XOR stream cipher
	XOR=exerciseStreamCipher('XOR', verbose)
	if (XOR!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		for entry in Crypto.Util.testdata.xor:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=XOR.new(key)
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('XOR failed on entry '+`entry`)
		if verbose: print '  XOR test suite completed'


def TestBlockModules(args=['aes', 'arc2', 'des', 'blowfish', 'cast', 'des3',
			   'idea', ],#'rc5'],
		     verbose=1):
    import string
    args=map(string.lower, args)
    if 'aes' in args:
        ciph=exerciseBlockCipher('AES', verbose)        # AES
	if (ciph!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for entry in Crypto.Util.testdata.aes:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=ciph.new(key, ciph.MODE_ECB)
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('AES failed on entry '+`entry`)
			for i in ciphertext: 
			    if verbose: print hex(ord(i)),
			if verbose: print

    if 'arc2' in args:
        ciph=exerciseBlockCipher('ARC2', verbose)	    # Alleged RC2
	if (ciph!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for entry in Crypto.Util.testdata.arc2:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=ciph.new(key, ciph.MODE_ECB)
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('ARC2 failed on entry '+`entry`)
			for i in ciphertext: 
			    if verbose: print hex(ord(i)),
			print 
		if verbose: print '  Completed'

    if 'blowfish' in args:
        ciph=exerciseBlockCipher('Blowfish',verbose)# Bruce Schneier's Blowfish cipher
	if (ciph!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for entry in Crypto.Util.testdata.blowfish:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=ciph.new(key, ciph.MODE_ECB)
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('Blowfish failed on entry '+`entry`)
			for i in ciphertext: 
			    if verbose: print hex(ord(i)),
			if verbose: print
		if verbose: print '  Completed'

    if 'cast' in args:
        ciph=exerciseBlockCipher('CAST', verbose)        # CAST-128
	if (ciph!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for entry in Crypto.Util.testdata.cast:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=ciph.new(key, ciph.MODE_ECB)
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('CAST failed on entry '+`entry`)
			for i in ciphertext: 
			    if verbose: print hex(ord(i)),
			if verbose: print

		if 0:
		    # The full-maintenance test; it requires 4 million encryptions,
		    # and correspondingly is quite time-consuming.  I've disabled
		    # it; it's faster to compile block/cast.c with -DTEST and run
		    # the resulting program.
		    a = b = '\x01\x23\x45\x67\x12\x34\x56\x78\x23\x45\x67\x89\x34\x56\x78\x9A'

		    for i in range(0, 1000000):
			obj = cast.new(b, cast.MODE_ECB)
			a = obj.encrypt(a[:8]) + obj.encrypt(a[-8:])		
			obj = cast.new(a, cast.MODE_ECB)
			b = obj.encrypt(b[:8]) + obj.encrypt(b[-8:])		

		    if a!="\xEE\xA9\xD0\xA2\x49\xFD\x3B\xA6\xB3\x43\x6F\xB8\x9D\x6D\xCA\x92":
			if verbose: print 'CAST test failed: value of "a" doesn\'t match'
		    if b!="\xB2\xC9\x5E\xB0\x0C\x31\xAD\x71\x80\xAC\x05\xB8\xE8\x3D\x69\x6E": 
			if verbose: print 'CAST test failed: value of "b" doesn\'t match'
		if verbose: print '  Completed'

    if 'des' in args:
	# Test/benchmark DES block cipher
	des=exerciseBlockCipher('DES', verbose)
	if (des!=None):
	    # Various tests taken from the DES library packaged with Kerberos V4
	    obj=des.new(hex2str('0123456789abcdef'), des.MODE_ECB)
	    s=obj.encrypt('Now is t')
	    if (s!=hex2str('3fa40e8a984d4815')):
		die('DES fails test 1')
	    obj=des.new(hex2str('08192a3b4c5d6e7f'), des.MODE_ECB)
	    s=obj.encrypt('\000\000\000\000\000\000\000\000')
	    if (s!=hex2str('25ddac3e96176467')):
		die('DES fails test 2')
	    obj=des.new(hex2str('0123456789abcdef'), des.MODE_CBC,
			hex2str('1234567890abcdef'))
	    s=obj.encrypt("Now is the time for all ")
	    if (s!=hex2str('e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6')):
		die('DES fails test 3')
	    obj=des.new(hex2str('0123456789abcdef'), des.MODE_CBC,
			hex2str('fedcba9876543210'))
	    s=obj.encrypt("7654321 Now is the time for \000\000\000\000")
	    if (s!=hex2str("ccd173ffab2039f4acd8aefddfd8a1eb468e91157888ba681d269397f7fe62b4")):
		die('DES fails test 4')
	    del obj,s

	    # R. Rivest's test: see http://theory.lcs.mit.edu/~rivest/destest.txt
	    x=hex2str('9474B8E8C73BCA7D')
	    for i in range(0, 16):
		obj=des.new(x, des.MODE_ECB)
		if (i & 1): x=obj.decrypt(x)
		else: x=obj.encrypt(x)
	    if x!=hex2str('1B1A2DDB4C642438'):
		die("DES fails Rivest's test")

	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for entry in Crypto.Util.testdata.des:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=des.new(key, des.MODE_ECB)
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('DES failed on entry '+`entry`)
		for entry in Crypto.Util.testdata.des_cbc:
		    key, iv, plain, cipher=entry
		    key, iv, cipher=hex2str(key),hex2str(iv),hex2str(cipher)
		    obj1=des.new(key, des.MODE_CBC, iv) 
		    obj2=des.new(key, des.MODE_CBC, iv) 
		    ciphertext=obj1.encrypt(plain)
		    if (ciphertext!=cipher):
			die('DES CBC mode failed on entry '+`entry`)
		if verbose: print '  Completed'

    if 'des3' in args:
	ciph=exerciseBlockCipher('DES3', verbose)        # Triple DES
	if (ciph!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for entry in Crypto.Util.testdata.des3:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=ciph.new(key, ciph.MODE_ECB)
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('DES3 failed on entry '+`entry`)
			for i in ciphertext: 
			    if verbose: print hex(ord(i)),
			if verbose: print
		for entry in Crypto.Util.testdata.des3_cbc:
		    key, iv, plain, cipher=entry
		    key, iv, cipher=hex2str(key),hex2str(iv),hex2str(cipher)
		    obj1=ciph.new(key, ciph.MODE_CBC, iv) 
		    obj2=ciph.new(key, ciph.MODE_CBC, iv) 
		    ciphertext=obj1.encrypt(plain)
		    if (ciphertext!=cipher):
			die('DES3 CBC mode failed on entry '+`entry`)
		if verbose: print '  Completed'

    if 'diamond' in args:
        ciph=exerciseBlockCipher('Diamond', verbose) # M.P. Johnson's Diamond
	if (ciph!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for entry in Crypto.Util.testdata.diamond:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=ciph.new(key[1:], ciph.MODE_ECB, rounds = ord(key[0]) )
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('Diamond failed on entry '+`entry`)
		if verbose: print '  Completed'


    if 'idea' in args:
        ciph=exerciseBlockCipher('IDEA', verbose)       # IDEA block cipher
	if (ciph!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for entry in Crypto.Util.testdata.idea:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=ciph.new(key, ciph.MODE_ECB)
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('IDEA failed on entry '+`entry`)
		if verbose: print '  Completed'

    if 'rc5' in args:
	# Ronald Rivest's RC5 algorithm
	ciph=exerciseBlockCipher('RC5', verbose)
	if (ciph!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for entry in Crypto.Util.testdata.rc5:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=ciph.new(key[4:], ciph.MODE_ECB, 
				 version =ord(key[0]),
				 wordsize=ord(key[1]),
				 rounds  =ord(key[2]) )
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('RC5 failed on entry '+`entry`)
			for i in ciphertext: 
			    if verbose: print hex(ord(i)),
			if verbose: print
		if verbose: print '  Completed'

    if 'skipjack' in args:
        ciph=exerciseBlockCipher('Skipjack', verbose)	    # Skipjack
	if (ciph!=None):
	    try:
		import Crypto.Util.testdata
	    except ImportError:
		if verbose: print '  Test suite data not available'
	    else:
		if verbose: print '  Verifying against test suite...'
		for entry in Crypto.Util.testdata.skipjack:
		    key,plain,cipher=entry
		    key=hex2str(key)
		    plain=hex2str(plain)
		    cipher=hex2str(cipher)
		    obj=ciph.new(key, ciph.MODE_ECB)
		    ciphertext=obj.encrypt(plain)
		    if (ciphertext!=cipher):
			die('Skipjack failed on entry '+`entry`)
			for i in ciphertext: 
			    if verbose: print hex(ord(i)),
			print 
		if verbose: print '  Completed'


def TestPKModules(args=['rsa', 'dsa', 'elgamal', 'qnew'], verbose=1):
    # Set up a random pool; we won't bother to actually fill it with
    # entropy from the keyboard 
    if verbose: print ' Initializing random pool'
    from Crypto.Util.randpool import RandomPool
    r=RandomPool(384)
    r.stir()
    randfunc=r.getBytes

    if 'rsa' in args:
	print 'RSA:'
	from Crypto.PublicKey import RSA
	exercisePublicKey(randfunc, RSA, verbose)
	r.stir()

    if 'dsa' in args:
	print 'DSA:'
	from Crypto.PublicKey import DSA
	exercisePublicKey(randfunc, DSA, verbose)
	r.stir()

    if 'elgamal' in args:
	print 'ElGamal'
	from Crypto.PublicKey import ElGamal
	exercisePublicKey(randfunc, ElGamal, verbose)
	r.stir()

    if 'qnew' in args:
	print 'qNEW'
	from Crypto.PublicKey import qNEW
	exercisePublicKey(randfunc, qNEW, verbose)
	r.stir()


