#
#  randpool.py : Cryptographically strong random number generation
#
# Part of the Python Cryptography Toolkit
#
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.  This software is provided "as is" without
# warranty of fitness for use or suitability for any purpose, express
# or implied. Use at your own risk or not at all. 
#
  

"""randpool.py : Cryptographically strong random number generation.

The implementation here is similar to the one in PGP.  To be
cryptographically strong, it must be difficult to determine the RNG's
output, whether in the future or the past.  This is done by using
encryption algorithms to "stir" the random data.

Entropy is gathered in the same fashion as PGP; the highest-resolution
clock around is read and the data is added to the random number pool.
A conservative estimate of the entropy is then kept.
"""

import time, array

from Crypto.Util.number import longtobytes

class RandomPool:
    def __init__(self, numbytes = 160, cipher=None, hash='SHA'):
        # The cipher argument is vestigial; it was removed from
        # version 1.1 so RandomPool would work even in the limited
        # exportable subset of the code

        if type(hash) == type(''):
            # ugly hack to force __import__ to give us the end-path module
            hash = __import__('Crypto.Hash.'+hash,
                              None, None, ['new'])
            
        self.entropy, self._addPos = 0,0
        self._event1, self._event2 = 0,0
        self._addPos, self._getPos = 0,hash.digestsize
        self.bytes, self.hash=numbytes, hash
        self.bits=self.bytes*8
        self.__counter = 0

        # Construct an array to hold the random pool
        a = []
        while len(a) < self.bytes:
            a = a + range( min(256, self.bytes-len(a)) )
        self._randpool = array.array('B', a)
            
	# Linux supports a /dev/urandom device; soon other OSes will, too.
	# We'll grab some randomness from it.
	try:
	    f=open('/dev/urandom')
	    data=f.read(self.bytes)
	    f.close()
	    self._addBytes(data)
	    # Conservative entropy estimate: The number of bits of
	    # data obtained from /dev/urandom, divided by 4.
	    self.entropy = self.entropy + (8/2)*len(data)
	except IOError, (num, msg):
	    if num!=2: raise IOError, (num, msg)
	    # If the file wasn't found, ignore the error

    def stir(self):
        entropy=self.entropy
        self.addEvent(time.time())

        for i in range( self.bytes / self.hash.digestsize):
            h = self.hash.new(self._randpool)
            h.update(str(self.__counter) + str(i) + str(self._addPos) )
            self._addBytes( h.digest() )
            self.__counter = (self.__counter + 1) & 0xFFFFffff

        self._addPos, self._getPos = 0, self.hash.digestsize
        self.addEvent(time.time())

        # Paranoia is a Good Thing in cryptographic applications.
        # While the call to addEvent() may be adding entropy to the
        # pool, we won't take that into account.    
        self.entropy=entropy

    def getBytes(self, N):
        "Return num bytes of random data"
        s=''
        i, pool = self._getPos, self._randpool
        h=self.hash.new()
        dsize = self.hash.digestsize
        num = N
        while num>0:
            h.update( self._randpool[i:i+dsize] )
            s = s + h.digest()
            num = num - dsize
            i = (i + dsize) % self.bytes
            if i<dsize:
                self.stir()
                i=self._getPos
                
        self._getPos = i
        self.entropy=self.entropy-8*N
        if self.entropy<0: self.entropy=0
        return s[:N]

    def addEvent(self, event, s=''):
        event=long(event*1000)
        delta=self._noise()
        s=s+longtobytes(event)+4*chr(0xaa)+longtobytes(long(delta))
        self._addBytes(s)
        if event==self._event1 and event==self._event2:
            bits=0
        else:
            bits=0
            while (delta): delta, bits = delta>>1, bits+1
            if (bits>8): bits=8
        self._event1, self._event2 = event, self._event1
        self.entropy=self.entropy+bits
        if self.entropy>self.bytes*8:
            self.entropy=self.bytes*8
        return self.entropy

    # Private functions
    def _noise(self):
        if not self.__dict__.has_key('_lastcounter'):
            self._lastcounter=time.time()
        if not self.__dict__.has_key('_ticksize'):
            self._noiseTickSize()
        t=time.time()
        delta = (t - self._lastcounter)/self._ticksize*1e6
        self._lastcounter = t
        self._addBytes(longtobytes(long(1000*time.time())))
        self._addBytes(longtobytes(long(1000*time.clock())))
        self._addBytes(longtobytes(long(1000*time.time())))
        self._addBytes(longtobytes(long(delta)))
	delta=delta % 0x1000000		# Reduce delta so it fits into an int
        return int(delta)

    def _noiseTickSize(self):
        interval=[]
        t=time.time()
        for i in range(0,100):
            t2=time.time()
            delta=int((t2-t)*1e6)
            t=t2
	    if delta: interval.append(delta)
        interval.sort()
        self._ticksize=interval[len(interval)/2]

    def _addBytes(self, s):
        "XOR the contents of the string S into the random pool"
        i, pool = self._addPos, self._randpool
        for j in range(0, len(s)):
            pool[i]=pool[i] ^ ord(s[j])
            i=(i+1) % self.bytes
        self._addPos = i


class KeyboardRandomPool(RandomPool):
    def __init__(self, filename='', numbytes = 384, cipher=None, hash='MD5'):
        self.filename=filename
	if filename:
	    try:
		import pickle
		f=open(filename, 'r')
		temp=pickle.load(f)
		for key in temp.__dict__.keys():
		    self.__dict__[key]=temp.__dict__[key]
		f.close()
	        self.stir()
	    except IOError:
		RandomPool.__init__(self, numbytes, cipher, hash)
	else:
	    RandomPool.__init__(self, numbytes, cipher, hash)

        self.stir()     # Wash the random pool
        self.stir()
        self.stir()

    def save(self):
        import pickle
	if self.filename == "":
            raise ValueError, "No filename set for this object"
        self.stir()     # Wash the random pool
        self.stir()
        self.stir()
        f=open(self.filename, 'w')
        pickle.dump(self, f)
        f.close()
        
    def randomize(self):
        import os, string, termios, TERMIOS, time
        bits=self.bits-self.entropy
        if bits==0: return              # No entropy required, so we exit.
        print bits,'bits of entropy are now required.  Please type on the keyboard'
        print 'until enough randomness has been accumulated.'
        fd=0
        old=termios.tcgetattr(fd)
        new=termios.tcgetattr(fd)
        new[3]=new[3] & ~TERMIOS.ICANON & ~TERMIOS.ECHO
        termios.tcsetattr(fd, TERMIOS.TCSANOW, new)
        s=''    # We'll save the characters typed and add them to the pool.
        hash = self.hash
        try:
            while (self.entropy<self.bits):
                temp=string.rjust(str(self.bits-self.entropy), 6)
                os.write(1, temp)
                termios.tcflush(0, TERMIOS.TCIFLUSH) # XXX Leave this in?
                s=s+os.read(0, 1)
                self.addEvent(time.time())
                os.write(1, 6*chr(8))
            self.addEvent(time.time(), s+hash.new(s).digest() )
        finally:
            termios.tcsetattr(fd, TERMIOS.TCSAFLUSH, old)
        print '\n\007 Enough.\n'
        time.sleep(3)
        termios.tcflush(0, TERMIOS.TCIFLUSH)


if __name__ == '__main__':
    pool = RandomPool()
    print `pool.getBytes(100)`
