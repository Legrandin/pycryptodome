
import time
from Crypto.Util import number

# Test of prime-generation speed

# This randfunc is deterministic, so we should always find the same primes.
chars = ''.join(map(chr, range(255, 0, -1)))
def randfunc (N):
    s = ''
    while len(s)<N:
        s += chars
    return s[:N]

def main ():
    for i in range(2048, 2049, 128):
        s = time.time()
        N = number.getPrime(i, randfunc)
        e = time.time()
        N = str(N)
        print '%5i' % i, '%-7.03fsec' % (e-s), N[:10] + '...' + N[-10:]

if __name__ == '__main__':
    main()
