import struct

class Count(object):
    def __init__(self):
        self.count = 0

    def next(self):
        self.count += 1
        return self.count
counter = Count()


def split32(long_int, n):
    """Split long_int into n 32-bit words big-endian"""

    assert(long_int >= 0)

    result = []
    for x in range(n):
        result += [ "0x%08xUL" % (long_int & (2**32-1)) ]
        long_int >>= 32
    return result


def split64(long_int):
    """Split long_int into 64-bit words big-endian"""

    assert(long_int >= 0)

    if long_int == 0:
        return [ "0" ]

    result = []
    while long_int:
        result += [ "0x%xULL" % (long_int & (2**64-1)) ]
        long_int >>= 64
    return result

def inverse(x, modulus):
    if modulus == 0:
        raise ZeroDivisionError("Modulus cannot be zero")
    if modulus < 0:
        raise ValueError("Modulus cannot be negative")
    r_p, r_n = x, modulus
    s_p, s_n = 1, 0
    while r_n > 0:
        q = r_p // r_n
        r_p, r_n = r_n, r_p - q * r_n
        s_p, s_n = s_n, s_p - q * s_n
    if r_p != 1:
        raise ValueError("No inverse value can be computed" + str(r_p))
    while s_p < 0:
        s_p += modulus
    return s_p


def bin2int(bs):
    res = 0
    while len(bs) > 0:
        res = res*256 + struct.unpack("B", bs[:1])[0]
        bs = bs[1:]
    return res


def make_main():
    print "int main(void) {"
    for i in xrange(1, counter.next()):
        print "    test_%d();" % i
    print "    return 0;"
    print "}"


