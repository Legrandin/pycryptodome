#
# Test script for Crypto.Util.randpool.
#

__revision__ = "$Id: test_rfc1751.py,v 1.1 2002-05-17 13:31:48 akuchling Exp $"

import binascii
from sancho.unittest import TestScenario, parse_args, run_scenarios
from Crypto.Util import RFC1751

tested_modules = [ "Crypto.Util.RFC1751" ]

test_data = [('EB33F77EE73D4053', 'TIDE ITCH SLOW REIN RULE MOT'),
             ('CCAC2AED591056BE4F90FD441C534766',
              'RASH BUSH MILK LOOK BAD BRIM AVID GAFF BAIT ROT POD LOVE'),
             ('EFF81F9BFBC65350920CDD7416DE8009',
              'TROD MUTE TAIL WARM CHAR KONG HAAG CITY BORE O TEAL AWL')
             ]

class RFC1751Test (TestScenario):

    def setup (self):
	pass

    def shutdown (self):
	pass

    def check_k2e (self):
        "Check converting keys to English"
        for key, words in test_data:
            key=binascii.a2b_hex(key)
            self.test_val('RFC1751.Key2English(key)', words)

    def check_e2k (self):
        "Check converting English strings to keys"
        for key, words in test_data:
            key=binascii.a2b_hex(key)
            self.test_val('RFC1751.English2Key(words)', key)

# class RFC1751Test


if __name__ == "__main__":
    (scenarios, options) = parse_args()
    run_scenarios(scenarios, options)
