#
# Test script for Crypto.Util.PublicKey.
#

__revision__ = "$Id: test_publickey.py,v 1.7 2003-04-04 19:38:28 akuchling Exp $"

import sys, cPickle
import unittest
from Crypto.PublicKey import *
from Crypto.Util.randpool import RandomPool
from Crypto.Util import number

class PublicKeyTest (unittest.TestCase):

    def setUp (self):
        # Set up a random pool; we won't bother to actually fill it with
        # entropy from the keyboard
        self.pool = RandomPool(384)
        self.pool.stir()

    def tearDown (self):
        del self.pool

    def check_key (self, key, randfunc, verbose=0):
        plaintext="Hello"
        # Generate maximum-size plaintext
        maxplain = (key.size() // 8) * '\377'

        if key.can_encrypt():
            if verbose: print '  Encryption/decryption test'
            K=number.getPrime(10, randfunc)
            ciphertext=key.encrypt(plaintext, K)
            self.assertEquals(key.decrypt(ciphertext), plaintext)
            ciphertext=key.encrypt(maxplain, K)
            self.assertEquals(key.decrypt(ciphertext), maxplain)

        if key.can_sign():
            if verbose: print '  Signature test'
            K=number.getPrime(30, randfunc)
            signature=key.sign(plaintext, K)
            self.assert_(key.verify(plaintext, signature))
            self.assertFalse(key.verify(plaintext[:-1], signature))

            # Change a single bit in the plaintext
            badtext=plaintext[:-3]+chr( 1 ^ ord(plaintext[-3]) )+plaintext[-3:]
            self.assertFalse(key.verify(badtext, signature))

            if verbose: print '  Removing private key data'
            pubonly=key.publickey()
            self.assert_(pubonly.verify(plaintext, signature))

        # Test blinding
        if key.can_blind():
            if verbose: print '  Blinding test'
            K=number.getPrime(30, randfunc)
            B="garbage"
            blindedtext=key.blind(plaintext, B)
            signature=key.sign(blindedtext, K)
            unblindedsignature=(key.unblind(signature[0], B),)
            self.assert_(key.verify(plaintext, unblindedsignature))
            self.assertEquals(key.sign(plaintext, K), unblindedsignature)

            # Change a single bit in the blinding factor
            badB=B[:-3]+chr( 1 ^ ord(B[-3]) )+B[-3:]
            badunblindedsignature=(key.unblind(signature[0], badB),)
            self.assertFalse(key.verify(badtext, badunblindedsignature))

            badblindedtext=key.blind(plaintext, badB)
            badsignature=key.sign(blindedtext, K)
            badunblindedsignature2=(key.unblind(signature[0], B),)
            self.assertFalse(key.verify(badtext, badunblindedsignature2))


    def exercise (self, randfunc, pk_mod, verbose=0):
        N=256                           # Key size, measured in bits

        key=pk_mod.generate(N, randfunc)

        if verbose:
            print ' Key data:'
            for field in key.keydata:
                print "  ", field, ':', hex(getattr(key,field))

        if verbose: print " Testing newly generated key"
        self.check_key(key, randfunc, verbose)
        if verbose: print " Testing pickled/unpickled key"
        import pickle
        s = pickle.dumps(key) ; key2 = pickle.loads(s)
        self.check_key(key2, randfunc, verbose)

        if verbose: print " Testing cPickled key"
        s = cPickle.dumps(key) ; key2 = cPickle.loads(s)
        self.check_key(key2, randfunc, verbose)
        if verbose: print


    def test_rsa(self):
        "Check RSA algorithm"
        self.exercise(self.pool.get_bytes, RSA)

    def test_dsa(self):
        "Check DSA algorithm"
        self.exercise(self.pool.get_bytes, DSA)

    def test_elgamal(self):
        "Check ElGamal algorithm"
        self.exercise(self.pool.get_bytes, ElGamal)

    def test_qnew(self):
        "Check qNEW algorithm"
        self.exercise(self.pool.get_bytes, qNEW)

# class PublicKeyTest


if __name__ == "__main__":
    unittest.main()
