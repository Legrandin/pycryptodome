#
# Test script for Crypto.Util.PublicKey.
#

__revision__ = "$Id: test_publickey.py,v 1.7 2003/04/04 19:38:28 akuchling Exp $"

import sys, cPickle
from sancho.unittest import TestScenario, parse_args, run_scenarios
from Crypto.PublicKey import *
from Crypto.Util.randpool import RandomPool
from Crypto.Util import number

tested_modules = [ "Crypto.PublicKey.RSA", "Crypto.PublicKey.DSA",
                   "Crypto.PublicKey.ElGamal", "Crypto.PublicKey.qNEW"]

class PublicKeyTest (TestScenario):

    def setup (self):
        # Set up a random pool; we won't bother to actually fill it with
        # entropy from the keyboard
        self.pool = RandomPool(384)
        self.pool.stir()

    def shutdown (self):
        del self.pool

    def testkey (self, key, randfunc, verbose=0):
        plaintext="Hello"
        # Generate maximum-size plaintext
        maxplain = (key.size() // 8) * '\377'

        if key.can_encrypt():
            if verbose: print '  Encryption/decryption test'
            K=number.getPrime(10, randfunc)
            ciphertext=key.encrypt(plaintext, K)
            self.test_val('key.decrypt(ciphertext)', plaintext)
            ciphertext=key.encrypt(maxplain, K)
            self.test_val('key.decrypt(ciphertext)', maxplain)

        if key.can_sign():
            if verbose: print '  Signature test'
            K=number.getPrime(30, randfunc)
            signature=key.sign(plaintext, K)
            self.test_bool('key.verify(plaintext, signature)')
            self.test_bool('key.verify(plaintext[:-1], signature)',
                           want_true=0)

            # Change a single bit in the plaintext
            badtext=plaintext[:-3]+chr( 1 ^ ord(plaintext[-3]) )+plaintext[-3:]
            self.test_bool('key.verify(badtext, signature)', want_true=0)

            if verbose: print '  Removing private key data'
            pubonly=key.publickey()
            self.test_bool('pubonly.verify(plaintext, signature)')

        # Test blinding
        if key.can_blind():
            if verbose: print '  Blinding test'
            K=number.getPrime(30, randfunc)
            B="garbage"
            blindedtext=key.blind(plaintext, B)
            signature=key.sign(blindedtext, K)
            unblindedsignature=(key.unblind(signature[0], B),)
            self.test_bool('key.verify(plaintext, unblindedsignature)')
            self.test_val('key.sign(plaintext, K)', unblindedsignature)

            # Change a single bit in the blinding factor
            badB=B[:-3]+chr( 1 ^ ord(B[-3]) )+B[-3:]
            badunblindedsignature=(key.unblind(signature[0], badB),)
            self.test_false('key.verify(badtext, badunblindedsignature)')

            badblindedtext=key.blind(plaintext, badB)
            badsignature=key.sign(blindedtext, K)
            badunblindedsignature2=(key.unblind(signature[0], B),)
            self.test_false('key.verify(badtext, badunblindedsignature2)')


    def exercise (self, randfunc, pk_mod, verbose=0):
        N=256                           # Key size, measured in bits

        key=pk_mod.generate(N, randfunc)

        if verbose:
            print ' Key data:'
            for field in key.keydata:
                print "  ", field, ':', hex(getattr(key,field))

        if verbose: print " Testing newly generated key"
        self.testkey(key, randfunc, verbose)
        if verbose: print " Testing pickled/unpickled key"
        import pickle
        s = pickle.dumps(key) ; key2 = pickle.loads(s)
        self.testkey(key2, randfunc, verbose)

        if verbose: print " Testing cPickled key"
        s = cPickle.dumps(key) ; key2 = cPickle.loads(s)
        self.testkey(key2, randfunc, verbose)
        if verbose: print


    def check_rsa(self):
        "Check RSA algorithm"
        self.exercise(self.pool.get_bytes, RSA)

    def check_dsa(self):
        "Check DSA algorithm"
        self.exercise(self.pool.get_bytes, DSA)

    def check_elgamal(self):
        "Check ElGamal algorithm"
        self.exercise(self.pool.get_bytes, ElGamal)

    def check_qnew(self):
        "Check qNEW algorithm"
        self.exercise(self.pool.get_bytes, qNEW)

# class PublicKeyTest


if __name__ == "__main__":
    (scenarios, options) = parse_args()
    run_scenarios(scenarios, options)
