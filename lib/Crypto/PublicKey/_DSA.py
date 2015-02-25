
#
#   DSA.py : Digital Signature Algorithm
#
#  Part of the Python Cryptography Toolkit
#
#  Written by Andrew Kuchling, Paul Swartz, and others
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
#

from Crypto.Hash import SHA1

from Crypto.Util.py3compat import *

from Crypto.Math.Numbers import Integer
from Crypto.Math.Primality import (
            test_probable_prime, COMPOSITE, PROBABLY_PRIME )

def generateQ(randfunc):
    S = randfunc(20)
    S_next = (Integer.from_bytes(S) + 1).to_bytes(block_size=20)
    hash1, hash2 = [ SHA1.new(x).digest() for x in S, S_next ]
    q = Integer(0)
    for i in range(0,20):
        c = bord(hash1[i]) ^ bord(hash2[i])
        if i == 0:
            c = c | 128
        if i == 19:
            c = c | 1
        q = q * 256 + c
    while test_probable_prime(q) == COMPOSITE:
        q += 2
    if q.size_in_bits() == 160:
        return S, q
    raise RuntimeError('Bad q value generated')

def generate_py(bits, randfunc, domain=None):
    """generate(bits:int, randfunc:callable, domain:list)

    Generate a DSA key of length 'bits', using 'randfunc' to get
    random data.
    """

    if bits<160:
        raise ValueError('Key length < 160 bits')

    # Domain parameters may be given
    two = Integer(2)
    if domain is not None:
        p, q, g = map(Integer, domain)
    else:
        while True:
            S, q = generateQ(randfunc)
            n = (bits - 1) // 160
            C, N, V = 0, 2, {}
            b = (q >> 5) & 15
            powb = pow(2, int(b))
            powL1 = pow(2, int(bits - 1))
            while C < 4096:
                for k in range(0, n + 1):
                    V[k] = Integer.from_bytes(SHA1.new(
                             S + bstr(N) + bstr(k)).digest())
                W = V[n] % powb
                for k in range(n - 1, -1, -1):
                    W = (W << 160) + V[k]
                X = W + powL1
                p = X - (X % (q * 2) - 1)
                if powL1 <= p and test_probable_prime(p) == PROBABLY_PRIME:
                    break
                C, N = C + 1, N + n +1
            if C < 4096:
                break

        power = (p - 1) // q
        while True:
            h = Integer.from_bytes(randfunc(bits)) % (p - 1)
            g = pow(h, power, p)
            if 1 < h < p - 1 and g  >1:
                break

    while True:
        x = Integer.from_bytes(randfunc(20))
        if 0 < x < q:
            break
    y = pow(g, x, p)
    return y, g, p, q, x
