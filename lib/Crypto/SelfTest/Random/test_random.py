#
#  SelfTest/Util/test_generic.py: Self-test for the Crypto.Random.new() function
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

"""Self-test suite for Crypto.Random.new()"""

import pytest


class TestSimple:
    def test(self):
        """Crypto.Random.new()"""
        # Import the Random module and try to use it
        from Crypto import Random

        randobj = Random.new()
        x = randobj.read(16)
        y = randobj.read(16)
        assert x != y
        z = Random.get_random_bytes(16)
        assert x != z
        assert y != z
        # Test the Random.random module, which
        # implements a subset of Python's random API
        # Not implemented:
        # seed(), getstate(), setstate(), jumpahead()
        # random(), uniform(), triangular(), betavariate()
        # expovariate(), gammavariate(), gauss(),
        # longnormvariate(), normalvariate(),
        # vonmisesvariate(), paretovariate()
        # weibullvariate()
        # WichmannHill(), whseed(), SystemRandom()
        from Crypto.Random import random

        x = random.getrandbits(16 * 8)
        y = random.getrandbits(16 * 8)
        assert x != y
        # Test randrange
        if x > y:
            start = y
            stop = x
        else:
            start = x
            stop = y
        for step in range(1, 10):
            x = random.randrange(start, stop, step)
            y = random.randrange(start, stop, step)
            assert x != y
            assert start <= x < stop
            assert start <= y < stop
            assert (x - start) % step == 0
            assert (y - start) % step == 0
        for _ in range(10):
            assert random.randrange(1, 2) == 1
        with pytest.raises(ValueError):
            random.randrange(start, start)
        with pytest.raises(ValueError):
            random.randrange(stop, start, step)
        with pytest.raises(TypeError):
            random.randrange(start, stop, step, step)
        with pytest.raises(TypeError):
            random.randrange(start, stop, "1")
        with pytest.raises(TypeError):
            random.randrange("1", stop, step)
        with pytest.raises(TypeError):
            random.randrange(1, "2", step)
        with pytest.raises(ValueError):
            random.randrange(start, stop, 0)
        # Test randint
        x = random.randint(start, stop)
        y = random.randint(start, stop)
        assert x != y
        assert (start <= x <= stop) is True
        assert (start <= y <= stop) is True
        for _ in range(10):
            assert random.randint(1, 1) == 1
        with pytest.raises(ValueError):
            random.randint(stop, start)
        with pytest.raises(TypeError):
            random.randint(start, stop, step)
        with pytest.raises(TypeError):
            random.randint("1", stop)
        with pytest.raises(TypeError):
            random.randint(1, "2")
        # Test choice
        seq = range(10000)
        x = random.choice(seq)
        y = random.choice(seq)
        assert x != y
        assert (x in seq) is True
        assert (y in seq) is True
        for _ in range(10):
            assert (random.choice((1, 2, 3)) in (1, 2, 3)) is True
        assert (random.choice([1, 2, 3]) in [1, 2, 3]) is True
        assert (random.choice(bytearray(b"123")) in bytearray(b"123")) is True
        assert random.choice([1]) == 1
        with pytest.raises(IndexError):
            random.choice([])
        with pytest.raises(TypeError):
            random.choice(1)
        # Test shuffle. Lacks random parameter to specify function.
        # Make copies of seq
        seq = range(500)
        x = list(seq)
        y = list(seq)
        random.shuffle(x)
        random.shuffle(y)
        assert x != y
        assert len(seq) == len(x)
        assert len(seq) == len(y)
        for i in range(len(seq)):
            assert (x[i] in seq) is True
            assert (y[i] in seq) is True
            assert (seq[i] in x) is True
            assert (seq[i] in y) is True
        z = [1]
        random.shuffle(z)
        assert z == [1]
        z = bytearray(b"12")
        random.shuffle(z)
        assert (b"1" in z) is True
        with pytest.raises(TypeError):
            random.shuffle(b"12")
        with pytest.raises(TypeError):
            random.shuffle(1)
        with pytest.raises(TypeError):
            random.shuffle("11")
        with pytest.raises(TypeError):
            random.shuffle((1, 2))
        # Test sample
        x = random.sample(seq, 20)
        y = random.sample(seq, 20)
        assert x != y
        for i in range(20):
            assert (x[i] in seq) is True
            assert (y[i] in seq) is True
        z = random.sample([1], 1)
        assert z == [1]
        z = random.sample((1, 2, 3), 1)
        assert (z[0] in (1, 2, 3)) is True
        z = random.sample("123", 1)
        assert (z[0] in "123") is True
        z = random.sample(range(3), 1)
        assert (z[0] in range(3)) is True
        z = random.sample(b"123", 1)
        assert (z[0] in b"123") is True
        z = random.sample(bytearray(b"123"), 1)
        assert (z[0] in bytearray(b"123")) is True
        with pytest.raises(TypeError):
            random.sample(1)
