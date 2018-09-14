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


def make_main():
    print "int main(void) {"
    for i in xrange(1, counter.next()):
        print "    test_%d();" % i
    print "    return 0;"
    print "}"


