"""This file implements message authentication (HMAC).

A MAC is a message authentication code, which is essentially a fancy hash of
some input text.  The text is sent along with the MAC and the receiver can
verify the text by computing their own MAC and comparing results.  The sender
and receiver share a secret key which is used by HMAC.

HMAC is defined in the informational RFC 2104, which describes a procedure for
authenticating messages using pluggable hash functions.  The user of HMAC must 
choose which hash function to use (e.g. SHA-1 or MD5) and this is designated
by HMAC-SHA or HMAC-MD5.  See the RFC for details.

This package can be integrated with Andrew Kuchling's Python Cryptography
Toolkit, http://starship.skyport.net/crew/amk/maintained/crypto.html

"""

from Crypto.Util.number import bytestolong, longtobytes



class HMAC:
    """Class implementing HMAC as defined in RFC 2104.

    Public Methods:

        __init__(hashmodule)
            Constructor for the class.  hashmodule is a module implementing
            the hashing algorithm to use.  In essence it must provide the
            following interface:

            hashmodule.digestsize
                The length of the hash's output in bytes

            hashmodule.new(key)
                Function which returns a new instance of a hash object,
                initialized to key.  The returned object must have a digest()
                method that returns a string of size hashmodule.digestsize,
                and an update() method that accepts strings to add to the
                digest.

        hash(key, blocks):
            Produce the HMAC hashes for the given blocks.  Key is the shared
            secret authentication key, as a string.  For best results RFC 2104
            recommends that the length of key should be at least as large as
            the underlying hash's output block size, but this is not
            enforced.

            If the key length is greater than the hash algorithm's basic
            compression function's block size (typically 64 bytes), then it is
            hashed to get the used key value.  If it is less than this block
            size, it is padded by appending enough zero bytes to the key.

            blocks is a list of strings to generate message authentication
            codes for.  Output is a list of strings containing the MACs.

    """
    def __init__(self, hashmodule):
        self.__hashmodule = hashmodule

    __IPAD = 0x36
    __OPAD = 0x5c

    def hash(self, key, blocks):
        # L is the byte length of hash outputs.
        # B is the byte length of hash algorithm's basic compression
        # function's block size (64 for most hashes)
        #
        # Sanitize the key.  RFC 2104 recommends key length be at least L and
        # if it is longer than B, it should be hashed and the resulting L
        # bytes will be used as the key
        #
        L = self.__hashmodule.digestsize
        B = 64                                    # can't get from module
        keylen = len(key)
        if keylen > B:
            key = self.__hashmodule.new(key).digest()
            keylen = len(key)
            assert keylen == L
        elif keylen < B:
            # append enough zeros to get it to length B
            key = key + '\000' * (B - keylen)
        keylen = len(key)
        #
        # Precompute the inner and outer intermediate values
        kipad = bytestolong(key) ^ bytestolong(chr(self.__IPAD) * keylen)
        kopad = bytestolong(key) ^ bytestolong(chr(self.__OPAD) * keylen)
        kipad = longtobytes(kipad)
        kopad = longtobytes(kopad)
        #
        # perform the inner hashes
        inners = []
        for text in blocks:
            hash = self.__hashmodule.new(kipad)
            hash.update(text)
            inners.append(hash.digest())
        #
        # preform the outer hashes
        outers = []
        for inner in inners:
            hash = self.__hashmodule.new(kopad)
            hash.update(inner)
            outers.append(hash.digest())
        return outers



if __name__ == '__main__':
    from types import StringType

    # Test data taken from RFC 2104
    testdata = [
        # (key, data, digest)
        (0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0bL,
         'Hi There',
         0x9294727a3638bb1c13f48ef8158bfc9dL),
        ("Jefe",
         "what do ya want for nothing?",
         0x750c783e6ab0b503eaa86e310a5db738L),
        (0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL,
         0xDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDL,
         0x56be34521d144c88dbb8c733f0e8b3f6L),
        ]

    # RFC 2104 uses MD5
    from Crypto.Hash import MD5
    for key, data, digest in testdata:
        if type(key) <> StringType:
            key = longtobytes(key)
        if type(data) <> StringType:
            data = longtobytes(data)

        h = HMAC(MD5)
        d = h.hash(key, [data])
        d = bytestolong(d[0])
        if d == digest:
            print 'They match!'
        else:
            print 'They differ...'
            print '    expected:', hex(digest)
            print '         got:', hex(d)
