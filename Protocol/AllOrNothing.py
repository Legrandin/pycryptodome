"""This file implements all-or-nothing package transformations.

An all-or-nothing package transformation is one in which some text is
transformed into message blocks, such that all blocks must be obtained before
the reverse transformation can be applied.  Thus, if any blocks are corrupted
or lost, the original message cannot be reproduced.

An all-or-nothing package transformation is not encryption, although a block
cipher algorithm is used.  The encryption key is randomly generated and is
extractable from the message blocks.

This class implements the All-Or-Nothing package transformation algorithm
described in:

Rivest.  All-Or-Nothing Encryption and The Package Transform.  To appear in
the Proceedings of the 1997 Fast Software Encryption Conference.
http://theory.lcs.mit.edu/~rivest/fusion.ps

"""

import operator
import string
from Crypto.Util.number import bytestolong, longtobytes



class AllOrNothing:
    """Class implementing the All-or-Nothing package transform.

    Public Methods:

        __init__(ciphermodule, mode=None, IV=None):
            Constructor for the class.  ciphermodule is a module implementing
            the cipher algorithm to use.  In essence it must provide the
            following interface:

            ciphermodule.keysize
                Attribute containing the cipher algorithm's key size in
                bytes.  If the cipher supports variable length keys, then
                typically ciphermodule.keysize will be zero.  In that case a
                key size of 16 bytes will be used.

            ciphermodule.blocksize
                Attribute containing the cipher algorithm's input block size
                in bytes

            ciphermodule.new(key, mode, IV)
                Function which returns a new instance of a cipher object,
                initialized to key.  The returned object must have an
                encrypt() method that accepts a string of
                ciphermodule.blocksize bytes and returns a string containing
                the encrypted text.

            Note that the encryption key is randomly generated automatically
            when needed.  Optional arguments mode and IV are passed directly
            through to the ciphermodule.new() method; they are the feedback
            mode and initialization vector to use.  All three arguments must
            be the same for the object used to create the digest, and to
            undigest'ify the message blocks.

        update(text):
            Concatenate text to the string that will be transformed.

        reset(text=''):
            Reset the current string to be transformed to text.

        digest():
            Perform the All-or-Nothing package transform on the current
            string.  Output is a list of message blocks describing the
            transformed text, where each block is a string of bit length equal
            to the ciphermodule's blocksize.

        undigest(mblocks):
            Perform the reverse package transformation on a list of message
            blocks.  Note that the ciphermodule used for both transformations
            must be the same.  mblocks is a list of strings of bit length
            equal to the ciphermodule's blocksize.  Output is a string object.

    Subclass methods:

        _inventkey(keysize):
            Returns a randomly generated key.  Subclasses can use this to
            implement better random key generating algorithms.  The default
            algorithm is probably not very cryptographically secure.

    """
    def __init__(self, ciphermodule, mode=None, IV=None):
        self.__ciphermodule = ciphermodule
        self.__mode = mode
        self.__IV = IV
        self.__text = ''
        self.__keysize = ciphermodule.keysize
        if self.__keysize == 0:
            self.__keysize = 16

    def update(self, text):
        self.__text = self.__text + text

    def reset(self, text=''):
        self.__text = text

    __K0digit = chr(0x69)

    def digest(self):
        text = self.__text
        # generate a random session key and K0, the key used to encrypt the
        # hash blocks.  Rivest calls this a fixed, publically-known encryption
        # key, but says nothing about the security implications of this key or 
        # how to choose it.
        key = self._inventkey(self.__keysize)
        K0 = self.__K0digit * self.__keysize
        # we need to cipher objects here, one that is used to encrypt the
        # message blocks and one that is used to encrypt the hashes.  The
        # former uses the randomly generated key, while the latter uses the
        # well-known key.
        mcipher = self.__newcipher(key)
        hcipher = self.__newcipher(K0)
        # Pad the text so that it's length is a multiple of the cipher's
        # blocksize.  Pad with trailing spaces, which will be eliminated in
        # the undigest() step.
        blocksize = self.__ciphermodule.blocksize
        padbytes = blocksize - (len(text) % blocksize)
        text = text + ' ' * padbytes
        # Run through the algorithm:
        # s: number of message blocks (size of text / blocksize)
        # input sequence: m1, m2, ... ms
        # random key K' (`key' in the code)
        # Compute output sequence: m'1, m'2, ... m's' for s' = s + 1
        # Let m'i = mi ^ E(K', i) for i = 1, 2, 3, ..., s
        # Let m's' = K' ^ h1 ^ h2 ^ ... hs
        # where hi = E(K0, m'i ^ i) for i = 1, 2, ... s
        #
        # The one complication I add is that the last message block is hard
        # coded to the number of padbytes added, so that these can be stripped 
        # during the undigest() step
        s = len(text) / blocksize
        blocks = []
        hashes = []
        for i in range(1, s+1):
            start = (i-1) * blocksize
            end = start + blocksize
            mi = text[start:end]
            assert len(mi) == blocksize
            cipherblock = mcipher.encrypt(longtobytes(i, blocksize))
            mticki = bytestolong(mi) ^ bytestolong(cipherblock)
            blocks.append(mticki)
            # calculate the hash block for this block
            hi = hcipher.encrypt(longtobytes(mticki ^ i, blocksize))
            hashes.append(bytestolong(hi))
        # Add the padbytes length as a message block
        i = i + 1
        cipherblock = mcipher.encrypt(longtobytes(i, blocksize))
        mticki = padbytes ^ bytestolong(cipherblock)
        blocks.append(mticki)
        # calculate this block's hash
        hi = hcipher.encrypt(longtobytes(mticki ^ i, blocksize))
        hashes.append(bytestolong(hi))
        # Now calculate the last message block of the sequence 1..s'.  This
        # will contain the random session key XOR'd with all the hash blocks,
        # so that for undigest(), once all the hash blocks are calculated, the 
        # session key can be trivially extracted.  Calculating all the hash
        # blocks requires that all the message blocks be received, thus the
        # All-or-Nothing algorithm succeeds.
        mtick_stick = bytestolong(key) ^ reduce(operator.xor, hashes)
        blocks.append(mtick_stick)
        # we convert the blocks to strings since in Python, byte sequences are
        # always represented as strings.  This is more consistent with the
        # model that encryption and hash algorithm always operates on strings.
        return map(longtobytes, blocks)

    def undigest(self, blocks):
        # better have at least 2 blocks, for the padbytes package and the hash 
        # block accumulator
        if len(blocks) < 2:
            raise ValueError, "List must be at least length 2."
        # blocks is a list of strings.  We need to deal with them as long
        # integers
        blocks = map(bytestolong, blocks)
        # Calculate the well-known key, to which the hash blocks are
        # encrypted, and create the hash cipher.
        K0 = self.__K0digit * self.__keysize
        hcipher = self.__newcipher(K0)
        # Since we have all the blocks (or this method would have been called
        # prematurely), we can calcualte all the hash blocks.
        hashes = []
        for i in range(1, len(blocks)):
            mticki = blocks[i-1] ^ i
            hi = hcipher.encrypt(longtobytes(mticki))
            hashes.append(bytestolong(hi))
        # now we can calculate K' (key).  remember the last block contains
        # m's' which we don't include here
        key = blocks[-1] ^ reduce(operator.xor, hashes)
        # and now we can create the cipher object
        mcipher = self.__newcipher(longtobytes(key))
        blocksize = self.__ciphermodule.blocksize
        # And we can now decode the original message blocks
        parts = []
        for i in range(1, len(blocks)):
            cipherblock = mcipher.encrypt(longtobytes(i, blocksize))
            mi = blocks[i-1] ^ bytestolong(cipherblock)
            parts.append(mi)
        # The last message block contains the number of pad bytes appended to
        # the original text string, such that its length was an even multiple
        # of the cipher's blocksize.  This number should be small enough that
        # the conversion from long integer to integer should never overflow
        padbytes = int(parts[-1])
        text = string.join(map(longtobytes, parts[:-1]), '')
        return text[:-padbytes]

    def _inventkey(self, keysize):
        # TBD: Not a very secure algorithm.  Eventually, I'd like to use JHy's 
        # kernelrand module
        import time
        from Crypto.Util import randpool
        # TBD: keysize * 2 to work around possible bug in RandomPool?
        pool = randpool.RandomPool(keysize * 2)
        while keysize > pool.addEvent(time.time()) / 8:
            pass
        # we now have enough entropy in the pool to get a keysize'd key
        return pool.getBytes(keysize)

    def __newcipher(self, key):
        if self.__mode is None and self.__IV is None:
            return self.__ciphermodule.new(key)
        elif self.__IV is None:
            return self.__ciphermodule.new(key, self.__mode)
        else:
            return self.__ciphermodule.new(key, self.__mode, self.__IV)



if __name__ == '__main__':
    import sys
    import getopt
    import base64

    usagemsg = '''\
Test module usage: %(program)s [-c cipher] [-l] [-h]

Where:
    --cipher module
    -c module
        Cipher module to use.  Default: %(ciphermodule)s

    --aslong
    -l
        Print the encoded message blocks as long integers instead of base64
        encoded strings

    --help
    -h
        Print this help message
'''        

    ciphermodule = 'XOR'
    aslong = 0

    def usage(code, msg=None):
        if msg:
            print msg
        print usagemsg % {'program': sys.argv[0],
                          'ciphermodule': ciphermodule}
        sys.exit(code)

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   'c:l', ['cipher=', 'aslong'])
    except getopt.error, msg:
        usage(1, msg)

    if args:
        usage(1, 'Too many arguments')

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            usage(0)
        elif opt in ('-c', '--cipher'):
            ciphermodule = arg
        elif opt in ('-l', '--aslong'):
            aslong = 1

    # ugly hack to force __import__ to give us the end-path module
    module = __import__('Crypto.Cipher.'+ciphermodule, None, None, ['new'])

    a = AllOrNothing(module)
    print 'Original text:\n=========='
    print __doc__
    print '=========='
    a.update(__doc__)
    msgblocks = a.digest()
    print 'message blocks:'
    for i, blk in map(None, range(len(msgblocks)), msgblocks):
        # base64 adds a trailing newline
        print '    %3d' % i,
        if aslong:
            print bytestolong(blk)
        else:
            print base64.encodestring(blk)[:-1]
    #
    # get a new undigest-only object so there's no leakage
    b = AllOrNothing(module)
    text = b.undigest(msgblocks)
    if text == __doc__:
        print 'They match!'
    else:
        print 'They differ!'
