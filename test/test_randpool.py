#
# Test script for Crypto.Util.randpool.
#

__revision__ = "$Id: test_randpool.py,v 1.3 2003/02/28 15:24:01 akuchling Exp $"

from sancho.unittest import TestScenario, parse_args, run_scenarios
from Crypto.Hash import SHA
from Crypto.Util import randpool

tested_modules = [ "Crypto.Util.randpool" ]

class RandomPoolTest (TestScenario):

    def setup (self):
        self.pool = randpool.RandomPool(160, hash=SHA)

    def shutdown (self):
        del self.pool

    def check_init (self):
        "Check initial state"
        self.test_val('self.pool.entropy', self.pool.bits)

    def check_get_bytes (self):
        "Check retrieving of bytes from the pool"
        start_entropy = self.pool.entropy
        self.test_bool('self.pool.entropy > 0')

        # Draw out half of the pool's entropy
        size = self.pool.entropy / 8 / 2
        self.test_stmt('self.pool.get_bytes(size)')
        self.test_val('self.pool.entropy', start_entropy - size*8)

        # Draw out the rest of the pool's entropy
        self.test_stmt('self.pool.get_bytes(size)')
        self.test_val('self.pool.entropy', 0)

        # Remove yet more data; entropy stays at zero
        self.test_stmt('self.pool.get_bytes(size)')
        self.test_val('self.pool.entropy', 0)

# class RandomPoolTest


if __name__ == "__main__":
    (scenarios, options) = parse_args()
    run_scenarios(scenarios, options)
