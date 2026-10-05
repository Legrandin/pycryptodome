#
#  SelfTest/Util/test_Counter: Self-test for the Crypto.Util.Counter module
#
# Written in 2009 by Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

"""Self-tests for Crypto.Util.Counter"""

import unittest


class CounterTests(unittest.TestCase):
    def setUp(self):
        global Counter
        from Crypto.Util import Counter

    def test_BE(self):
        """Big endian"""
        Counter.new(128)
        Counter.new(128, little_endian=False)

    def test_LE(self):
        """Little endian"""
        Counter.new(128, little_endian=True)

    def test_nbits(self):
        Counter.new(nbits=128)
        self.assertRaises(ValueError, Counter.new, 129)

    def test_prefix(self):
        Counter.new(128, prefix=b"xx")

    def test_suffix(self):
        Counter.new(128, suffix=b"xx")

    def test_iv(self):
        Counter.new(128, initial_value=2)
        self.assertRaises(ValueError, Counter.new, 16, initial_value=0x1FFFF)
