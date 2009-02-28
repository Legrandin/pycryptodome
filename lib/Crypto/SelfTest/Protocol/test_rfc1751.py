#
# Test script for Crypto.Util.randpool.
#
# Part of PyCrypto 2.0.1; Presumably written by A. M. Kuchling.

__revision__ = "$Id$"

import binascii
import unittest
from Crypto.Util import RFC1751

test_data = [('EB33F77EE73D4053', 'TIDE ITCH SLOW REIN RULE MOT'),
             ('CCAC2AED591056BE4F90FD441C534766',
              'RASH BUSH MILK LOOK BAD BRIM AVID GAFF BAIT ROT POD LOVE'),
             ('EFF81F9BFBC65350920CDD7416DE8009',
              'TROD MUTE TAIL WARM CHAR KONG HAAG CITY BORE O TEAL AWL')
             ]

class RFC1751Test_k2e (unittest.TestCase):

    def runTest (self):
        "Check converting keys to English"
        for key, words in test_data:
            key=binascii.a2b_hex(key)
            self.assertEquals(RFC1751.key_to_english(key), words)

class RFC1751Test_e2k (unittest.TestCase):

    def runTest (self):
        "Check converting English strings to keys"
        for key, words in test_data:
            key=binascii.a2b_hex(key)
            self.assertEquals(RFC1751.english_to_key(words), key)

# class RFC1751Test

def get_tests(config={}):
    return [RFC1751Test_k2e(), RFC1751Test_e2k()]

if __name__ == "__main__":
    unittest.main()
