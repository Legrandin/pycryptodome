#
#  SelfTest/Util/test_number.py: Self-test for parts of the Crypto.Util.number module
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
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

"""Self-tests for (some of) Crypto.Util.number"""

import pytest

from Crypto.Util import number
from Crypto.Util.number import long_to_bytes


class MyError(Exception):
    """Dummy exception used for tests"""


# NB: In some places, we compare tuples instead of just output values so that
# if any inputs cause a test failure, we'll be able to tell which ones.


class TestMisc:
    def test_ceil_div(self):
        """Util.number.ceil_div"""
        with pytest.raises(TypeError):
            number.ceil_div("1", 1)
        with pytest.raises(ZeroDivisionError):
            number.ceil_div(1, 0)
        with pytest.raises(ZeroDivisionError):
            number.ceil_div(-1, 0)

        # b = 1
        assert number.ceil_div(0, 1) == 0
        assert number.ceil_div(1, 1) == 1
        assert number.ceil_div(2, 1) == 2
        assert number.ceil_div(3, 1) == 3

        # b = 2
        assert number.ceil_div(0, 2) == 0
        assert number.ceil_div(1, 2) == 1
        assert number.ceil_div(2, 2) == 1
        assert number.ceil_div(3, 2) == 2
        assert number.ceil_div(4, 2) == 2
        assert number.ceil_div(5, 2) == 3

        # b = 3
        assert number.ceil_div(0, 3) == 0
        assert number.ceil_div(1, 3) == 1
        assert number.ceil_div(2, 3) == 1
        assert number.ceil_div(3, 3) == 1
        assert number.ceil_div(4, 3) == 2
        assert number.ceil_div(5, 3) == 2
        assert number.ceil_div(6, 3) == 2
        assert number.ceil_div(7, 3) == 3

        # b = 4
        assert number.ceil_div(0, 4) == 0
        assert number.ceil_div(1, 4) == 1
        assert number.ceil_div(2, 4) == 1
        assert number.ceil_div(3, 4) == 1
        assert number.ceil_div(4, 4) == 1
        assert number.ceil_div(5, 4) == 2
        assert number.ceil_div(6, 4) == 2
        assert number.ceil_div(7, 4) == 2
        assert number.ceil_div(8, 4) == 2
        assert number.ceil_div(9, 4) == 3

    def test_getPrime(self):
        """Util.number.getPrime"""
        with pytest.raises(ValueError):
            number.getPrime(-100)
        with pytest.raises(ValueError):
            number.getPrime(0)
        with pytest.raises(ValueError):
            number.getPrime(1)

        bits = 4
        for _i in range(100):
            x = number.getPrime(bits)
            assert (x >= (1 << bits - 1)) == 1
            assert (x < (1 << bits)) == 1

        bits = 512
        x = number.getPrime(bits)
        assert x % 2 != 0
        assert (x >= (1 << bits - 1)) == 1
        assert (x < (1 << bits)) == 1

    def test_getStrongPrime(self):
        """Util.number.getStrongPrime"""
        with pytest.raises(ValueError):
            number.getStrongPrime(256)
        with pytest.raises(ValueError):
            number.getStrongPrime(513)
        bits = 512
        x = number.getStrongPrime(bits)
        assert x % 2 != 0
        assert (x > (1 << bits - 1) - 1) == 1
        assert (x < (1 << bits)) == 1
        e = 2**16 + 1
        x = number.getStrongPrime(bits, e)
        assert number.GCD(x - 1, e) == 1
        assert x % 2 != 0
        assert (x > (1 << bits - 1) - 1) == 1
        assert (x < (1 << bits)) == 1
        e = 2**16 + 2
        x = number.getStrongPrime(bits, e)
        assert number.GCD((x - 1) >> 1, e) == 1
        assert x % 2 != 0
        assert (x > (1 << bits - 1) - 1) == 1
        assert (x < (1 << bits)) == 1

    def test_isPrime(self):
        """Util.number.isPrime"""
        assert number.isPrime(-3) is False  # Regression test: negative numbers should not be prime
        assert number.isPrime(-2) is False  # Regression test: negative numbers should not be prime
        # Regression test: isPrime(1) caused some versions of PyCrypto to crash.
        assert number.isPrime(1) is False
        assert number.isPrime(2) is True
        assert number.isPrime(3) is True
        assert number.isPrime(4) is False
        assert number.isPrime(2**1279 - 1) is True
        # Regression test: negative numbers should not be prime
        assert number.isPrime(-(2**1279 - 1)) is False
        # test some known gmp pseudo-primes taken from
        # http://www.trnicely.net/misc/mpzspsp.html
        for composite in (
            43 * 127 * 211,
            61 * 151 * 211,
            15259 * 30517,
            346141 * 692281,
            1007119 * 2014237,
            3589477 * 7178953,
            4859419 * 9718837,
            2730439 * 5460877,
            245127919 * 490255837,
            963939391 * 1927878781,
            4186358431 * 8372716861,
            1576820467 * 3153640933,
        ):
            assert number.isPrime(int(composite)) is False

    def test_size(self):
        assert number.size(2) == 2
        assert number.size(3) == 2
        assert number.size(0xA2) == 8
        assert number.size(0xA2BA40) == 8 * 3
        assert (
            number.size(
                0xA2BA40EE07E3B2BD2F02CE227F36A195024486E49C19CB41BBBDFBBA98B22B0E577C2EEAFFA20D883A76E65E394C69D4B3C05A1E8FADDA27EDB2A42BC000FE888B9B32C22D15ADD0CD76B3E7936E19955B220DD17D4EA904B1EC102B2E4DE7751222AA99151024C7CB41CC5EA21D00EEB41F7C800834D2C6E06BCE3BCE7EA9A5
            )
            == 1024
        )
        with pytest.raises(ValueError):
            number.size(-1)


class TestLong:
    def test1(self):
        assert long_to_bytes(0) == b"\x00"
        assert long_to_bytes(1) == b"\x01"
        assert long_to_bytes(0x100) == b"\x01\x00"
        assert long_to_bytes(0xFF00000000) == b"\xff\x00\x00\x00\x00"
        assert long_to_bytes(0xFF00000000) == b"\xff\x00\x00\x00\x00"
        assert long_to_bytes(0x1122334455667788) == b"\x11\x22\x33\x44\x55\x66\x77\x88"
        assert long_to_bytes(0x112233445566778899) == b"\x11\x22\x33\x44\x55\x66\x77\x88\x99"

    def test2(self):
        assert long_to_bytes(0, 1) == b"\x00"
        assert long_to_bytes(0, 2) == b"\x00\x00"
        assert long_to_bytes(1, 3) == b"\x00\x00\x01"
        assert long_to_bytes(65535, 2) == b"\xff\xff"
        assert long_to_bytes(65536, 2) == b"\x00\x01\x00\x00"
        assert long_to_bytes(0x100, 1) == b"\x01\x00"
        assert long_to_bytes(0xFF00000001, 6) == b"\x00\xff\x00\x00\x00\x01"
        assert long_to_bytes(0xFF00000001, 8) == b"\x00\x00\x00\xff\x00\x00\x00\x01"
        assert long_to_bytes(0xFF00000001, 10) == b"\x00\x00\x00\x00\x00\xff\x00\x00\x00\x01"
        assert long_to_bytes(0xFF00000001, 11) == b"\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x01"

    def test_err1(self):
        with pytest.raises(ValueError):
            long_to_bytes(-1)
