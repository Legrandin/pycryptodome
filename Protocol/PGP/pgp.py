#
#  PGP PACKET CLASSES and KEYRING MANAGER
#
#

from pgpconst import *
import md5

# Find a big number library
try: 
    import gmp ; bignum=gmp.mpz
except ImportError:
    try:
	import mpz ; bignum=mpz.mpz
    except ImportError: bignum=long

Error = 'PGPError'

#
#
# UTILITY FUNCTIONS
#
#

def get_hash_module(v, module_dict={}):
    "Return the module for a given hash algorithm"
    if module_dict.has_key(v): return module_dict[v]
    if v==HASH_MD5: import md5 ; mod=md5
    else: raise Error, 'Unknown hash algorithm '+str(v)
    module_dict[v]=mod ; return mod

def get_cipher_module(v, module_dict={}):
    "Return the module for a given private-key encryption algorithm"
    if module_dict.has_key(v): return module_dict[v]
    if v==CIPHER_IDEA: import idea ; mod=idea
    else: raise Error, 'Unknown cipher algorithm '+str(v)
    module_dict[v]=mod ; return mod

def get_random_bytes(N):
    "Return N bytes of random data"
    if N<0: 
	raise ValueError, 'Attempt to retrieve infinite amount of random data'
    f=open('/dev/urandom', 'r')
    data=f.read(N)
    f.close()
    return data[0:N]

def Str2Int(astr):
        "Convert a string into a long integer"
	curr = bignum(0)
	for char in astr: curr = (curr<<8) + ord(char)
	return curr

def Int2Str(i, bits=0):
        "Convert a long integer into a big-endian string, padding if desired."
	if (i==0): res='\0'
	elif i<0: raise Error, 'Cannot convert negative INT to string.'
	else:
	    res = ''
	    while i > 0:
		    res = chr(int(i&255)) + res
		    i = i>>8
	if bits!=0:
	    bytes=bits/8
	    if len(res)<bytes: res=('\0'*(bytes-len(res)))+res
	return res

def MPILen(str):
    "Extract the length of an MPI from the string encoding"
    length=ord(str[0])*256+ord(str[1])
    length, remainder = divmod(length, 8)
    if remainder!=0: length=length+1
    return length

def MPI2Int(str):
    "Turn a string-encoded MPI into a long integer"
    length=MPILen(str)
    return (Str2Int(str[2:2+length]), (2+length))

def Int2MPI(i):
    "Turn a long integer into an MPI string"
    s=Int2Str(i)
#    while (ord(s[0])==0): s=s[1:] # XXX why is this required?
    if (s==''): return '\000\000'
    first=ord(s[0])
    bits= 1+(len(s)-1) *8
    mask=1
    while (mask<first and mask <256):
        first = first & (255-mask)
        mask=mask << 1
        bits=bits+1
    s=chr(bits/256)+chr(bits & 255)+s
    return s
    
def Checksum(data, cksum=0):
    "Compute a simple checksum, which is just the sum of the bytes."
    for i in range(0,len(data)):
        cksum= ( cksum + ord(data[i]) ) & 65535
    return cksum

def getLen(CTB, pgpstring):
    "Return a length-of-length, and the length, from the CTB and length string"
    LEN = (CTB&3)
    if not PACKET_LENGTH.has_key(LEN):
	raise Error, "Unknown length of length"
    lenlen=PACKET_LENGTH[LEN]
    if lenlen!=0:
	length=int(Str2Int(pgpstring[:lenlen]))
    else: length=None
    return lenlen, length

#
#
# CLASSES
#
#

#
# Base class for PGP packets
#

class Packet:
    def __init__(self, input=None):
	self.CTBT = 0
		    
    def binary(self, CTBT=0):
	"Convert object to its string representation, preceded by the packet header."
	data=self.write_bin()
	header=self.mkHeader(len(data), bits=0, CTBT=CTBT)
	return header+data

    def mkHeader(self, length, bits=0, CTBT=0):
	"Return a packet header from the type and the length"

	# To allow PrivateKey objects to be written either as 
	# public or private objects, there has to be a way to 
	# override the object's CTBT.
	if CTBT==0: packet_type=self.CTBT

	# Check for a constraint on the length-of-length field
	if bits==0 and PACKET_SIZES.has_key(packet_type): 
	    bits=PACKET_SIZES[packet_type]

	if packet_type<1 or packet_type>14: 
	    raise Error, 'Invalid packettype '+str(packet_type)
	CTB = 128 | (packet_type<<2)
	if length==None: return chr(CTB|3)
	elif length<256 and (bits==0 or bits==8): 
	    bits=8
	elif length<65536 and (bits==0 or bits==16): 
	    bits=16 ; CTB = CTB|1
	elif length<4294967296 and (bits==0 or bits==32): 
	    bits=32 ; CTB = CTB|2
	else: raise Error, 'Packet too long.'
	return chr(CTB)+Int2Str(length, bits)

    def parse_bin(self, binstr):
	"""Parse a string containing a PGP packet, into the 'self' object."""
	raise Error, 'Called unimplemented method parse_bin.'

    def write_bin(self):
	"Convert object to its string representation, without the packet header."
	raise Error, 'Called unimplemented method write_bin.'


class PKEncrypted(Packet):
    def __init__(self, version=2):
	Packet.__init__(self)
	self.CTBT=CTBT_PKEP
	self.Version = version
	self.KeyID=bignum(0)
	self.PubkeyAlg=PK_NONE
	self.Data=bignum(0)

    def parse_bin(self, binstring):
	pos=0
	self.Version=ord(binstring[pos])
	if self.Version<>2: raise Error, 'Unsupported packet version '+str(version)
	pos=pos+1
	self.KeyID=Str2Int(binstring[pos:pos+8])
	pos=pos+8
	self.PubkeyAlg=ord(binstring[pos])
	pos=pos+1
	if self.PubkeyAlg==PK_RSA:
	    self.Data, mpilen = MPI2Int(binstring[pos:])
	    pos=pos+mpilen
        else: 
	    raise Error, 'Unknown PK Algorithm '+str(self.PubkeyAlg)
	if pos<>len(binstring):
		print 'WARNING: length mismatch in PK-encrypted packet.'
    def write_bin(self):
	data = (chr(self.Version) + 
		Int2Str( self.KeyID, 64) +chr(self.PubkeyAlg) )
	if self.PubkeyAlg==PK_RSA:
	    d=self.Data 
	    if type(d)==type(''): d=Str2Int(d)
	    data=data+Int2MPI(d)
        else: 
	    raise Error, 'Unknown PK Algorithm '+str(self.PubkeyAlg)
	return data

class Compressed(Packet):
    def __init__(self):
	Packet.__init__(self)
	self.CompressAlg=COMPRESS_NONE
	self.CTBT=CTBT_COMPR
	self.Data=""
    def compress(self, data):
	if self.CompressAlg==COMPRESS_ZLIB:
	    import zlib
	    compr_obj=zlib.compressobj(5, 8, -15)
	    self.Data=compr_obj.compress(data)
	    self.Data=self.Data+compr_obj.flush()
	else:
	    raise Error, 'Unknown compression algorithm'
	
    def decompress(self):
	if self.CompressAlg==COMPRESS_ZLIB:
	    import zlib
	    decompr_obj=zlib.decompressobj(-15)
	    data=decompr_obj.decompress(self.Data)
	    data=data+decompr_obj.flush()
	    return data
        else:
	    raise Error, 'Unknown compression algorithm'

    def parse_bin(self, binstring):
	pos=0
	self.CompressAlg=ord(binstring[pos])
	pos=pos+1
	if self.CompressAlg==COMPRESS_ZLIB:
	    self.Data=binstring[pos:]
	else:
	    raise Error, 'Unknown compression algorithm'
    def write_bin(self):
	return chr(self.CompressAlg)+self.Data

class ConvEncrypted(Packet):
    def __init__(self):
	Packet.__init__(self)
	self.Data="" ; self.CTBT = CTBT_CKEP
    def encrypt(self, key, data, cipheralg=CIPHER_IDEA):
	if cipheralg==CIPHER_IDEA:
	    import idea
	    IV=get_random_bytes(idea.blocksize)
	    cipherobj=idea.new(key, idea.PGP, '\000'*idea.blocksize)
	    output=cipherobj.encrypt(IV+IV[-2:])
	    cipherobj.sync()
	    self.Data=output+cipherobj.encrypt(data)
	else: raise Error, 'Unsupported cipher algorithm '+str(cipheralg)
    def decrypt(self, key, cipheralg):
	if cipheralg==CIPHER_IDEA:
	    import idea
	    cipherobj=idea.new(key, idea.PGP, '\000'*idea.blocksize)
	    data=cipherobj.decrypt(self.Data[:10])
	    if data[6:8]!=data[8:10]:
		raise Error, 'Error during conventional decryption'
	    cipherobj.sync()
	else: raise Error, 'Unsupported cipher algorithm '+str(cipheralg)
	return cipherobj.decrypt(self.Data[10:])
    def parse_bin(self, binstring):
	self.Data=binstring
    def write_bin(self):
	return self.Data
	
class Plaintext(Packet):
    def __init__(self):
	Packet.__init__(self)
	self.CTBT = CTBT_PLAIN
	self.Mode='b' 
	self.Filename=""
	self.Timestamp=0
	self.Data=""
    def isBinary(self):
	if self.Mode in 'bB': return 1
	elif self.Mode in 'tT': return 0
	else: raise Error, 'Unknown Plaintext mode byte'
    def parse_bin(self, binstring):
	pos=0
	self.Mode=binstring[pos] ; pos=pos+1
	if self.Mode not in 'bBtT':
	    raise Error, 'Unknown Plaintext mode byte'
	filename_len=ord(binstring[pos]) ; pos=pos+1
	self.Filename=binstring[pos:pos+filename_len]
	pos=pos+filename_len
	self.Timestamp=Str2Int(binstring[pos:pos+4])
	pos=pos+4
	self.Data=binstring[pos:]
    def write_bin(self):
	if len(self.Filename)>256: 
	    raise Error, "Filename is too long...256 chars maximum"
	return (self.Mode + 
		chr(len(self.Filename)) + self.Filename +
		Int2Str(self.Timestamp, 32) + self.Data )

class Comment(Packet):
    def __init__(self):
	Packet.__init__(self)
	self.CTBT = CTBT_COMMENT
	self.Comment=None
    def parse_bin(self, binstring):
	self.Comment=binstring
    def write_bin(self, binstring): 
	return self.Comment
    def __str__(self): return self.Comment

#
# Base class for Keys (private and public)
#
class Key(Packet):
	def __init__(self, version=3):
		Packet.__init__(self)
		self.ModulusSize = 0
		self.Version = version
		self.KeyID = bignum(0)
		self.Timestamp = 0
		self.Validity = 0
		self.PubkeyAlg = PK_RSA
		self.IDList = []
		self.Trust = None

	def padEncryptionKey(self, M):
	    "Given a Data Encryption Key (DEK), pad it suitably for PK encryption"
	    if type(M)!=type(''): M=Int2Str(M)
	    L=len(M)
	    if L>=384/8:
		# We'll assume that anything larger than 384 bits doesn't
		# need padding.
		return M
	    
	    if self.Version==2:
		pad=self.ModulusSize/8-L-6
		csum=Int2Str(Checksum(M), 16)
		randbytes=get_random_bytes(pad)
		M='\000\001'+M+csum+'\000'+randbytes+'\002'
		return M
	    elif self.Version==3:
		pad=self.ModulusSize/8-L-6
		csum=Int2Str(Checksum(M), 16)
		randbytes=get_random_bytes(pad)
		M='\000\002'+randbytes+'\000\001'+M+csum
		return M
	    else:
		raise Error, 'Unsupported packet version '+str(self.Version)

	def unpadEncryptionKey(self, M):
	    "Return the DEK, by removing the padding."
	    if type(M)!=type(''): M=Int2Str(M)
	    import string
	    if self.Version==2:
		start=string.find(M, '\001')
		if start==-1 or M[0]!='\001' or M[-1]!='\002':
		    raise Error, "Can't undo v2.2 key padding"
		DEK, csum = M[start:start+16], M[start+16:start+18]
		# XXX check csum!
		return DEK
	    elif self.Version==3:
		if M[0]!='\002' or M[-20:-18]!='\000\001':
		    raise Error, "Can't undo v2.3 key padding"
		DEK, csum = M[-18:-2], M[-2:]
		# XXX check csum!
		return DEK
	    else:
		raise Error, 'Unsupported packet version '+str(self.Version)

	def padMessageDigest(self, M):
	    "Pad a message digest appropriately."
	    L=len(M)
	    if L>=384/8:
		# We'll assume that anything larger than 384 bits doesn't
		# need padding.
		return M
	    if self.PubkeyAlg==PK_RSA:
		# RSA encryption
		if L<self.ModulusSize/8:
		    if self.Version==2:
			# PGP 2.2 padding
			pad=self.ModulusSize/8-L-4
			M='\000\001'+M+'\000'+('\377'*pad)+'\001'
			return M
		    elif self.Version==3:
			pad=self.ModulusSize/8-L-21
			M='\000\001'+('\377'*pad)+'\000'+ASN_STRING+M
			return M
		    else: 
			raise Error, 'Unsupported packet version '+str(self.Version)
	    else: raise Error, "Unknown public-key algorithm "+str(PubkeyAlg)

	def unpadMessageDigest(self, M):
	    "Return the message digest, after removing the padding"
	    import string
	    if self.PubkeyAlg==PK_RSA:
		if self.Version==2:
		    end=string.rfind(M, '\000')
		    start=string.find(M, '\001')
		    if start==-1 or end==-1:
			raise Error, "Can't undo v2.2 digest padding"
		    return M[start+1:end]
		elif self.Version==3:
		    start=string.find(M, ASN_STRING)
		    if start==-1:
			raise Error, "Can't undo v2.3 digest padding"
		    return M[start+len(ASN_STRING):]
	    else: raise Error, "Unknown public-key algorithm "+str(PubkeyAlg)

	def isPrivate(self): return 0
	def isUnlocked(self): return 0

#
# Public Keys
#

class PublicKey(Key):
	def __init__(self, version=3):
		Key.__init__(self, version)
		self.CTBT = CTBT_PKCERT
		if (version==2) or (version==3):
			self.PubkeyAlg = PK_RSA
			self.KeyCompromise = None
			self.n = 0
			self.e = 0
		else: raise Error, 'Unsupported packet version '+str(version)

	def __repr__(self):
	    return '<Public '+hex(self.KeyID)+'>'

	def encrypt(self, M):
	    "Encrypt a message with this key object.  Padding the caller's responsibility."
	    if type(M)==type(''): M=Str2Int(M)
	    if self.PubkeyAlg==PK_RSA:
		result=pow(M, self.e, self.n)
#		Mt=pow(result, self.d, self.n)
#		if M!=Mt: print 'Encryption mismatch'
		return Int2Str(result)
	    else:
		raise Error, "Unknown public-key algorithm "+str(self.PubkeyAlg)

	def decrypt(self, M):
	    "Decrypt with this key object"
	    if not self.isPrivate():
		raise Error, "Cannot decrypt with public key"
	    elif not self.isUnlocked():
		raise Error, "Private key is not unlocked."
	    if type(M)==type(''): M=Str2Int(M)
	    if self.PubkeyAlg==PK_RSA:
		result=pow(M, self.d, self.n)
		# XXX remove the following check
		Mt=pow(result, self.e, self.n)
		if M!=Mt: print 'Decryption mismatch'
		return Int2Str(result)
	    else:
		raise Error, "Unknown public-key algorithm "+str(self.PubkeyAlg)

	def sign(self, data, hashAlg=HASH_MD5):
	    import time
	    hash=get_hash_module(hashAlg)
	    hash_obj=hash.new(data)
	    sig=Signature() 
	    sig.Timestamp = long(time.time())
	    sig.SigClass=0 ; sig.HashAlg=hashAlg
	    sig.SigKeyID, sig.PubkeyAlg=self.KeyID, self.PubkeyAlg
	    hash_obj.update(chr(sig.SigClass) + 
			    Int2Str(sig.Timestamp, 32))
	    print `chr(sig.SigClass) + Int2Str(sig.Timestamp, 32)`
	    MD=hash_obj.digest()
	    sig.HashClue=MD[0:2]
	    MD=self.padMessageDigest(MD)
	    sig.signature=Str2Int(self.decrypt(MD))
	    print sig.__dict__
	    return sig

	def is_self_signed(self):
	    "Test if a key is self-signed, returning a Boolean value"
	    for item in self.IDList:
	        for sig in item.SigList:
		    if (sig.SigKeyID==self.KeyID and 
			sig.verify_key_sig(self, self, item)): 
			return 1
	    return 0

	def measureModulus(self):
	    "Determine the maximum message size that this key can handle"
	    if self.PubkeyAlg==PK_RSA:
		t,bits=1L,0
		while t<self.n: t,bits = t<<1L, bits+1
		self.ModulusSize=bits
	    else:
		raise Error, 'Unknown PK Algorithm '+str(self.PubkeyAlg)
	    
	def parse_bin(self, binstring):
		pos = 0
		self.Version = ord(binstring[pos])
		if self.Version not in [2, 3]: raise Error, 'Unknown Public Key version '+str(self.Version)
		pos = pos + 1
		self.Timestamp = Str2Int(binstring[pos:pos+4])
		pos = pos + 4
		self.Validity = Str2Int(binstring[pos:pos+2])
		pos = pos + 2
		self.PubkeyAlg = ord(binstring[pos])
		if self.PubkeyAlg not in PK_LIST: 
		    raise Error, 'Unknown PK Algorithm '+str(self.PubkeyAlg)
		pos = pos + 1
		self.n, mpilen = MPI2Int(binstring[pos:])
		self.KeyID = Str2Int(binstring[pos+mpilen-8:pos+mpilen])
		pos = pos + mpilen
		self.e, mpilen = MPI2Int(binstring[pos:])
		pos = pos + mpilen
		if pos<>len(binstring):
			print 'WARNING: length mismatch in Public Key packet.'
		self.measureModulus()

	def write_bin(self):
	    data = (chr(self.Version) + Int2Str(self.Timestamp, 32) +
		    Int2Str(self.Validity, 16) + chr(self.PubkeyAlg) )
	    if self.PubkeyAlg==PK_RSA:
		data=data+Int2MPI(self.n)+Int2MPI(self.e)
	    else: raise Error, "Unknown public-key algorithm "+str(self.PubkeyAlg)
	    return data


#
# Private Keys
#

class PrivateKey(PublicKey):
	def __init__(self, version=3):
		Key.__init__(self, version)
		self.CTBT = CTBT_SKCERT ; self.CipherAlg=CIPHER_NONE
		self.PubkeyAlg = PK_RSA

	def __repr__(self):
	    return '<Secret key '+hex(self.KeyID)+'>'

	def isPrivate(self): return 1
	def isUnlocked(self):
	    if self.PubkeyAlg==PK_RSA:
		return hasattr(self, 'd')
	    else:
		raise Error, 'Unknown PK Algorithm '+str(self.PubkeyAlg)

	def Unlock(self, passphrase = ""):
	    "Decrypt the private key data, given a passphrase."
	    binstring=self.Data ; pos=0
	    if (self.CipherAlg==CIPHER_NONE):
		# Unencrypted private key, so just unpack
		self.d, mpilen = MPI2Int(binstring[pos:])
		pos = pos + mpilen
		self.p, mpilen = MPI2Int(binstring[pos:])
		pos = pos + mpilen
		self.q, mpilen = MPI2Int(binstring[pos:])
		pos = pos + mpilen
		self.u, mpilen = MPI2Int(binstring[pos:])
		pos = pos + mpilen
		checksum=Str2Int(binstring[pos:pos+2])
		pos = pos + 2
	    elif self.CipherAlg==CIPHER_IDEA:
		cipher_mod=get_cipher_module(CIPHER_IDEA)
		hash_mod=get_hash_module(HASH_MD5)
		key=hash_mod.new(passphrase).digest()
		cipherobj=cipher_mod.new(key, cipher_mod.PGP, 
					 cipher_mod.blocksize*'\000')
		
		IV=binstring[pos:pos+8] ; pos=pos+8
		s=cipherobj.decrypt(IV)
		cipherobj.sync()

		if (self.PubkeyAlg==PK_RSA):
		    d={}
		    cksum=Checksum("")
		    for i in 'dpqu':
			dummy, mpilen = MPI2Int(binstring[pos:])
			MPI=binstring[pos:pos+mpilen]
			pos = pos + mpilen

			plain=MPI[:2]+cipherobj.decrypt(MPI[2:])
			cipherobj.sync()
			cksum=Checksum(plain,cksum)
			value, dummy = MPI2Int(plain)
			setattr(self, i, value)

		    checksum=Str2Int(binstring[pos:pos+2])
		    pos = pos + 2
		    
		    # If the checksum doesn't match, the passphrase must be wrong
		    if (cksum!=checksum): 
			raise Error, 'Incorrect passphrase'

		else: 
		    raise Error, "Unknown public-key algorithm "+str(self.PubkeyAlg)

	def Lock(self, passphrase=None):
	    """Reencipher a PGP private key with a new passphrase, or with
	    the previous passphrase implied.  Note that once a key's private 
	    data has been encrypted, this interface will never let you 
	    revert to having no password, even though PGP permits this.
	    It's probably not a big loss."""

	    if passphrase!=None:
		# Transform passphrase to a 128-bit IDEA key
		import md5
		key=md5.new(passphrase).digest()

		# Create encryption object
		if self.CipherAlg==CIPHER_NONE: self.CipherAlg=CIPHER_IDEA
		cipher_mod=get_cipher_module(self.CipherAlg)
		cipherobj=cipher_mod.new(key, cipher_mod.PGP, 
					 '\000'*cipher_mod.blocksize)
		data=IV=get_random_bytes(cipher_mod.blocksize)
		cipherobj.decrypt(IV)
		cksum=Checksum("")
		for i in 'dpqu': 
		    cipherobj.sync()
		    MPI=Int2MPI(getattr(self, i))
		    cksum=Checksum(MPI, cksum)
		    MPI=MPI[:2]+cipherobj.encrypt(MPI[2:])
		    data=data+MPI 
		self.Data=data+Int2Str(cksum, 16)
	    elif not hasattr(self, 'Data'):
		raise Error, "Can't lock a generated key without a passphrase"
	    # Delete the secret attributes
	    for i in 'dpqu': delattr(self, i)
	    
	def public_binary(self):
	    "Return the string representation of this key as a public certificate"
	    data=PublicKey.write_bin(self)
	    header=self.mkHeader(len(data), CTBT=CTBT_PKCERT)
	    return header+data

	def generate(self, PKalg=PK_RSA, *args):
	    "Generate a new public/private key pair"
	    self.PubkeyAlg=PKalg
	    if PKalg==PK_RSA: self.generateRSA(args)
	    else:
		raise Error, 'Unknown PK Algorithm '+str(self.PubkeyAlg)

	def generateRSA(self, args):
	    "Generate a new RSA public/private key pair"
	    # XXX Comment this section!
	    import pubkey
	    if len(args)==1: bits, = args ; ebits=5
	    elif len(args)==2: bits, ebits = args
	    bits=(bits+7)/8 
	    if bits%2==1: bits=bits+1  # Ensure that an odd number of bytes are required
	    p=Str2Int(get_random_bytes(bits/2)) | pow(2L, bits*8/2-1) | 3
	    q=Str2Int(get_random_bytes(bits-bits/2)) | pow(2L, bits*8/2) | 3
	    p=pubkey.findPrime(p) ; q=pubkey.findPrime(q)
	    if p>q: p,q=q,p
	    phi=(p-1)*(q-1)
	    ebits=(ebits+7)/8 
	    exp= Str2Int(get_random_bytes(ebits))|1
	    exp = exp & (pow(bignum(2), ebits+1) - 1)
	    while pubkey.GCD(exp, phi)!=1: exp=exp+2
	    self.p, self.q, self.n = p, q, p*q
	    self.e, self.d = exp, pubkey.Inverse(exp, phi)
	    self.u = pubkey.Inverse(p, q)

	    import time
	    self.Timestamp=int(time.time()) 
	    self.KeyID = self.n & 0xFFFFffffL
	    self.measureModulus()

 	    print hex(self.p),hex(self.q)
 	    print hex(self.n)
 	    print hex(self.e),hex(self.d)
## 	    M=1972L
## 	    C=pow(M, self.e, self.n)
## 	    M=pow(C, self.d, self.n)
## 	    print M

	def parse_bin(self, binstring):
		pos = 0
		self.Version = ord(binstring[pos])
		if self.Version not in [2, 3]: raise Error, 'Unknown Private Key version '+str(self.Version)
		pos = pos + 1
		self.Timestamp = Str2Int(binstring[pos:pos+4])
		pos = pos + 4
		self.Validity = Str2Int(binstring[pos:pos+2])
		pos = pos + 2
		self.PubkeyAlg = ord(binstring[pos])
		if self.PubkeyAlg==PK_RSA: 
		    pos = pos + 1
		    self.n, mpilen = MPI2Int(binstring[pos:])
		    self.KeyID = Str2Int(binstring[pos+mpilen-8:pos+mpilen])
		    pos = pos + mpilen
		    self.e, mpilen = MPI2Int(binstring[pos:])
		    pos = pos + mpilen
		    self.CipherAlg=ord(binstring[pos])
		    pos = pos + 1
		    if self.CipherAlg in [CIPHER_NONE, CIPHER_IDEA]:
			self.Data=binstring[pos:] 
			pos=len(binstring)
		else:
		    raise Error, 'Unknown PK Algorithm '+str(self.PubkeyAlg)
		self.measureModulus()
		if pos<>len(binstring):
			print 'WARNING: length mismatch in Private Key packet.'

	def write_bin(self):
	    data=(chr(self.Version)+Int2Str(self.Timestamp, 32)+
		  Int2Str(self.Validity, 16)+chr(self.PubkeyAlg))
	    if self.PubkeyAlg==PK_RSA: 
		data=data+Int2MPI(self.n)+Int2MPI(self.e)+self.Data    
	    else:
		raise Error, 'Unknown PK Algorithm '+str(self.PubkeyAlg)
	    return data

#
# User ID's
#
class UserID(Packet):
	def __init__(self):
		Packet.__init__(self)
		self.CTBT=CTBT_USERID
		self.UserID = ""
		self.SigList = []
		self.Trust = None
	def __repr__(self): return '< User ID "'+str(self.UserID)+'" >'
	def parse_bin(self, binstring):
		self.UserID = binstring
	def write_bin(self):
		return self.UserID


#
# Signatures
#
class Signature(Packet):
	def __init__(self, version=3):
		Packet.__init__(self)
		self.CTBT = CTBT_SIG
		self.Version = version
		if (version==2) or (version==3):
			self.SigClass = None
			self.SigKeyID = 0
			self.Timestamp = 0
			self.PubkeyAlg = PK_RSA

#
# Verify that key was used to sign target.  Target is:
#
#    - a binary string for sig classes 0x0 and 0x1
#    - a tuple (pubkey, uid) for a key certification signature
#    - None for key compromise signature (since it should be self-signed)
#    - a signature for a timestamp signature

	def verify(self, key, target):
		if self.SigClass == None: raise Error, "Can't verify uninitialised signature."
		elif (self.SigClass==0 or self.SigClass==1):
			raise Error, "We don't yet check document signatures."
		elif (self.SigClass==0x10 or self.SigClass==0x11 or self.SigClass==0x12 or self.SigClass==0x13):
			return self.verify_key_sig(self, key, target[0], target[1])
		elif (self.SigClass==0x20):
			raise Error, "We don't yet do key compromise signatures."
		elif (self.SigClass==0x30):
			raise Error, "We don't yet do certificate revokation."
		elif (self.SigClass==0x40):
			raise Error, "We don't yet do timestamps."
		else: raise Error, 'Unknown signature class '+str(hex(self.SigClass))

	def verify_key_sig(self, signerkey, signedkey, userid):
		if (self.SigClass<0x10) or (self.SigClass>0x13):
			raise Error, "Can't verify key signature on non key signature."
		hash_mod=get_hash_module(self.HashAlg)
		hash_obj=hash_mod.new()
		if signerkey.KeyID!=self.SigKeyID:
		    raise Error, "Incorrect signator key"
		if signedkey.CTBT!=CTBT_PKCERT:
		    raise Error, "Can only verify signatures on a public key cert"
		data=signedkey.write_bin() 
		data=signedkey.mkHeader(len(data),16) + data
		hash_obj.update (data)
		hash_obj.update (userid.UserID)
		hash_obj.update (chr(self.SigClass))
		hash_obj.update (Int2Str(self.Timestamp, 32))
		hash = hash_obj.digest()
		signature = signerkey.encrypt(self.signature)
		sighash = signerkey.unpadMessageDigest(signature)
		if self.HashClue!=sighash[0:2]:
		    raise Error, 'Signature checking failed--message digest mismatch'
		return sighash==hash

	def parse_bin(self, binstring):
		pos = 0
		self.Version = ord(binstring[pos])
		if self.Version not in [2, 3]: raise Error, 'Unknown signature version '+str(self.Version)
		pos = pos + 1
		if ord(binstring[pos]) <> 5: raise Error, 'Variable-length signature material <> 5.'
		pos = pos + 1
		self.SigClass = ord(binstring[pos])
		pos = pos + 1
		self.Timestamp = Str2Int(binstring[pos:pos+4])
		pos = pos + 4
		self.SigKeyID = Str2Int(binstring[pos:pos+8])
		pos = pos + 8
		self.PubkeyAlg = ord(binstring[pos])
		pos = pos + 1
		if self.PubkeyAlg not in PK_LIST: 
		    raise Error, 'Unknown signature PK Algorithm.'
		self.HashAlg = ord(binstring[pos])
		pos = pos + 1
		if self.HashAlg not in HASH_LIST: 
		    raise Error, 'Unknown hashing Algorithm.'
		self.HashClue = binstring[pos:pos+2]
		pos = pos + 2
		self.signature, siglen = MPI2Int(binstring[pos:])
		if (pos + siglen) <> len(binstring):
			print 'WARNING: length mismatch in signature packet.'
	def write_bin(self):
	    data = (chr(self.Version) + chr(5) + chr(self.SigClass) +
		    Int2Str(self.Timestamp, 32) + 
		    Int2Str(self.SigKeyID, 64) +
		    chr(self.PubkeyAlg))
	    if self.PubkeyAlg==PK_RSA:
		data=data+ chr(self.HashAlg) + self.HashClue
		if type(self.signature)==type(''): data=data+Int2MPI(Str2Int(self.signature))
		else: data=data+Int2MPI(self.signature)
		return data
	    else: raise Error, "Unknown public-key algorithm "+str(PubkeyAlg)

#
# Trust packet
#
class Trust(Packet):
	def __init__(self):
		Packet.__init__(self)
		self.CTBT=CTBT_TRUST
		self.Trust = 0 ; self.Disabled = 0 ; self.Ultimate=0
		

	def parse_bin(self, binstring):
		pos = 0
		trust = ord(binstring[pos])
		self.Trust = trust & 7
		self.Disabled = ((trust & 32) != 0)
		self.Ultimate = ((trust & 128) != 0)

	def write_bin(self):
	    trust=(self.Trust & 7) 
	    if self.Disabled: trust=trust | 32
	    if self.Ultimate: trust=trust | 128
	    return chr(trust)


#
#
# KeyRing class
#
#

class KeyRing:
	def __init__(self):
		self.keyring = {}

	# The following 6 methods simulate a dictionary's interface
	def __getitem__(self, key):
	    return self.keyring[key]
	def __delitem__(self, key):
	    del self.keyring[key]
	def __setitem__(self, key, value):
	    self.keyring[key]=value
	def values(self): return self.keyring.values()
	def items(self): return self.keyring.items()
	def keys(self): return self.keyring.keys()

#
# Parse a binary PGP key string into a keyring
#
	def parseKeyRing(self, input):
		curr_key = None
		curr_uid = None
		while 1:
		        p, dummy = readPacket(input)
			if p==None: break
			elif p.CTBT==CTBT_PKCERT or p.CTBT==CTBT_SKCERT:
				self[p.KeyID]=p
				self[p.KeyID & 0xffffFFFFL]=p
				curr_key = p
				curr_uid = None
			elif p.CTBT==CTBT_USERID:
				if curr_key: curr_key.IDList.append(p)
				else: print 'WARNING: dangling USERID packet.'
				curr_uid = p
			elif p.CTBT==CTBT_TRUST:
				if curr_key:
					if curr_key.Trust: pass#print 'WARNING: multiple Trusts for Key.'
					else: curr_key.Trust = p
				elif curr_uid:
					if curr_uid.Trust: print 'WARNING: multiple Trusts for USERID.'
					else: curr_uid.Trust = p
				else: print 'WARNING:  dangling Trust packet.'
			elif p.CTBT==CTBT_SIG:
			    if not curr_uid: print 'WARNING: dangling signature.'
			    else: 
				curr_uid.SigList.append(p)
			else: raise Error, 'Unknown KeyRing Packet type: '+str(p.CTBT)


class ShelfKeyRing(KeyRing):
	def __init__(self, filename):
	    import shelve
	    self.__shelf=shelve.open(filename)

	# The following 6 methods simulate a dictionary's interface
	def __getitem__(self, key):
	    key=repr(key)
	    return self.__shelf[key]
	def __delitem__(self, key):
	    key=repr(key)
	    del self.__shelf[key]
	def __setitem__(self, key, value):
	    key=repr(key)
	    self.__shelf[key]=value
	def values(self): return self.__shelf.values()
	def items(self): return self.__shelf.items()
	def keys(self): return self.__shelf.keys()
	def __del__(self): 
	    self.__shelf.close()

def readPacket(input):
    if input=="": return None, ""
    retval=""
    import types
    if type(input)==types.StringType:
	CTB=ord(input[0])
	lenlen, length=getLen(CTB, input[1:])
	if length!=None: 
	    s=input[1+lenlen:1+lenlen+length]
	    retval=input[1+lenlen+length:]
	else: s=input[1+lenlen:] 
    elif type(input)==types.FileType:
	CTB=input.read(1) 
	if CTB=="": return None, ""
	CTB=ord(CTB)
	lenlen=PACKET_LENGTH[CTB & 3]
	if lenlen==0:
	    s=input.read()
	else:
	    lenstr=input.read(lenlen)
	    length=Str2Int(lenstr)
	    s=input.read(length)

    if (CTB&128) <> 128: raise Error, 'Keystring contains format error.'
    CTBT = (CTB&60)>>2
    if   CTBT==CTBT_PKEP: packet=PKEncrypted()
    elif CTBT==CTBT_SIG: packet = Signature()
    elif CTBT==CTBT_SKCERT: packet = PrivateKey()
    elif CTBT==CTBT_PKCERT: packet = PublicKey()
    elif CTBT==CTBT_COMPR: packet = Compressed()
    elif CTBT==CTBT_CKEP: packet = ConvEncrypted()
    elif CTBT==CTBT_PLAIN: packet = Plaintext()
    elif CTBT==CTBT_USERID: packet = UserID()
    elif CTBT==CTBT_TRUST: packet = Trust()
    elif CTBT==CTBT_COMMENT: packet = Comment()
    else: raise Error, 'Unknown KeyRing Packet type: '+str(CTBT)
    packet.CTBT=CTBT
    packet.parse_bin(s)
    return packet, retval
			
def EncryptMessage(message, signer=None,
		   recipients=None, DEK=None, 
		   compression=COMPRESS_ZLIB, 
		   cipherAlg=CIPHER_IDEA, hashAlg=HASH_MD5):
    p=Plaintext() ; p.Data=message ; data=p.binary()

    if signer!=None:
 	sig=signer.sign(message, hashAlg=hashAlg)
	data=sig.binary() + data

    if compression!=COMPRESS_NONE:
	p=Compressed() ; p.CompressAlg=compression 
	p.compress(data) ; data=p.binary()
	
    output=data
    cipher_mod=get_cipher_module(cipherAlg)
    if DEK==None: DEK=get_random_bytes(cipher_mod.keysize)
    if recipients!=None and recipients!=[]:
	if cipherAlg!=CIPHER_NONE:
	    p=ConvEncrypted() ; p.encrypt(DEK, data, cipherAlg)
	    output=data=p.binary()
	    
	if type(recipients)!=type([]): recipients=[recipients]
	for rec in recipients:
	    c = PKEncrypted()
	    c.KeyID, c.PubkeyAlg = rec.KeyID, rec.PubkeyAlg 
	    paddedKey=rec.padEncryptionKey(DEK)
	    c.Data = rec.encrypt(paddedKey)
	    output=c.binary()+output
    return output

#
# Tools to handle PGP Armoring and DeArmoring
#

import regex, string
import binascii
import zlib

MAX_LINE_SIZE=80
LINE_LEN=48

begin_whole_pat = regex.compile("^[-]+BEGIN[ \t]+PGP")
end_whole_pat   = regex.compile("^[-]+END[ \t]+PGP")

begin_partial_pat = regex.compile("^[-]+BEGIN[ \t]+PGP[ \t]+MESSAGE,[ \t]+PART[ \t]+\([0-9]+\)/\([0-9]+\)[-]+[ \t\n]+$")
end_partial_pat   = regex.compile("^[-]+END[ \t]+PGP[ \t]+MESSAGE,[ \t]+PART[ \t]+\([0-9]+\)/\([0-9]+\)[-]+[ \t\n]+$")

def ArmorFile(input, output, blocktype="MESSAGE"):
	s=[]
	output.write("-----BEGIN PGP "+blocktype+"-----\n")
	output.write("Version: "+pgp.Version+'\n')
	data=""
	crc=zlib.pgp24("")
	while (1):
		data=input.read(LINE_LEN)
		if data=="": break
		output.write(binascii.b2a_base64(data))
		crc=zlib.pgp24(data, crc)
	crc=chr((crc >> 16) & 0xff) + chr((crc >> 8) & 0xff) + chr(crc & 0xff)
	output.write("="+binascii.b2a_base64(crc))
	output.write("-----END PGP "+blocktype+"-----\n")
	
def UnarmorFile(input, output):
	s=[]
	started = 0
	busy = 0
	crc=zlib.pgp24("")
	while (1):
		data=input.readline()
		if not started:
			if begin_whole_pat.match(data)>=0: started = 1
			if data=="": break
			else: continue
		if not busy:
			if len(string.strip(data))<>0: continue
			busy = 1
		if data=="" or end_whole_pat.match(data)!=-1: break
		if data[0]=='=':
			# The CRC line begins with a padding character
			chkcrc=binascii.a2b_base64(data[1:])
			break
		else:
			data=binascii.a2b_base64(data)
			output.write(data)
			crc=zlib.pgp24(data, crc)
	crc=chr((crc >> 16) & 0xff) + chr((crc >> 8) & 0xff) + chr(crc & 0xff)
	if chkcrc!=crc: raise Error, "CRC checksums don't match"

def armor(binstr):
        import StringIO
	i = StringIO.StringIO(ascstr)
	o = StringIO.StringIO()
	ArmorFile(i,o)
	return o.getvalue()

def unarmor(ascstr):
        import StringIO
	i = StringIO.StringIO(ascstr)
	o = StringIO.StringIO()
	UnarmorFile(i, o)
	return o.getvalue()

