#
# Test script for Crypto.Util.randpool.
#

__revision__ = "$Id: test_randpool.py,v 1.1 2002-05-17 13:31:48 akuchling Exp $"

from sancho.unittest import TestScenario, parse_args, run_scenarios
from Crypto.Util import randpool

tested_modules = [ "Crypto.Util.randpool" ]

class RandomPoolTest (TestScenario):

    def setup (self):
        self.pool = randpool.RandomPool(160, hash='SHA')
    
    def shutdown (self):
        del self.pool


    def check_init (self):
        "Check initial state"
        pass
        #self.test_val('self.pool.entropy', 0)

# class RandomPoolTest


if __name__ == "__main__":
    (scenarios, options) = parse_args()
    run_scenarios(scenarios, options)
