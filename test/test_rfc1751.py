#
# Test script for Crypto.Util.randpool.
#

__revision__ = "$Id: test_rfc1751.py,v 1.3 2003-02-28 15:24:01 akuchling Exp $"

import binascii
import unittest
from Crypto.Util import RFC1751

test_data = [('EB33F77EE73D4053', 'TIDE ITCH SLOW REIN RULE MOT'),
             ('CCAC2AED591056BE4F90FD441C534766',
              'RASH BUSH MILK LOOK BAD BRIM AVID GAFF BAIT ROT POD LOVE'),
             ('EFF81F9BFBC65350920CDD7416DE8009',
              'TROD MUTE TAIL WARM CHAR KONG HAAG CITY BORE O TEAL AWL')
             ]

class RFC1751Test (unittest.TestCase):

    def test_k2e (self):
        "Check converting keys to English"
        for key, words in test_data:
            key=binascii.a2b_hex(key)
            self.assertEquals(RFC1751.key_to_english(key), words)

    def test_e2k (self):
        "Check converting English strings to keys"
        for key, words in test_data:
            key=binascii.a2b_hex(key)
            self.assertEquals(RFC1751.english_to_key(words), key)

# class RFC1751Test


if __name__ == "__main__":
    unittest.main()
