
#  pgpops.py : Various low-level operations related to PGP packets.
#
#  To speed things up, this module could be rewritten as a C extension.
#
# Copyright (C) 1995, 1996, A.M. Kuchling
#
# Distribute and use freely; there are no restrictions on further 
# dissemination and usage except those imposed by the laws of your 
# country of residence.
#

import idea, md5

def MPILength(str):
    length=ord(str[0])*256+ord(str[1])
    length, remainder = divmod(length, 8)
    if remainder!=0: length=length+1
    return length
    
def MPI2Integer(str):
    length=MPILength(str)
    return (String2Int(str[2:2+length]), str[2+length:])

def Integer2MPI(i):
    s=Int2String(i)
    while (ord(s[0])==0): s=s[1:]
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
    
def String2Int(str):
    value=0L
    for i in range(0, len(str)):
        value=value*256+ord(str[i])
    return(value)

def Int2String(i):
    str=''
    if (i==0): return '\000'
    while(i>0):
        str= chr(int(i & 255)) +str
        i=i >> 8
    return str

#      The following two routines read and write PGP packets.  Originally,
# I wrote a huge set of if...elif...else statements to handle different 
# packet types and versions.  This was simple to write, but lengthy and 
# repetitive.  Implementing the writing of packets would require another
# long if statement, and would result in two separate sections of code that 
# would have to be kept consistent.  So, I decided to create a single
# description that would be used for both reading and writing packets.
# The actual description (current up to PGP 2.6.2) can be found below.
#
#      A PGP packet is described as a list of tuples. A tuple can be in
# one of two forms:
# 1) (DataFormat, Variable) : Reads a piece of data and stores it in the 
#    attribute named 'Variable' of the packet object.  DataFormat must be 
#    one of 'Byte', 'U16', 'U32', 'U64', 'String', 'SizedString', 'MPI',
#    or 'Error'.
# 2) (Condition, Sublist) : Evaluates the condition string; if it is true,
#    the sublist is used for further parsing.  

def ReadPacket(object, Type):
    templist=Format[Type]
    while (len(templist)!=0):
	data=""
	s1, s2 = templist[0]
	templist = templist[1:]
	if s1=='Byte':
	    data=object._input.read(1)
	    setattr(object, s2, ord(data[0]))
	elif s1=='U16':
	    data=object._input.read(2)
	    setattr(object, s2, ord(data[0])*256+ord(data[1]))
	elif s1=='U32':
	    data=object._input.read(4)
	    value=0L
	    for j in range(0, 4): value = value * 256 + ord(data[j])
	    setattr(object, s2, value)
        elif s1=='U64':
	    data=object._input.read(8)
            value=0L
            for j in range(0, 8):
                value = value * 256 + ord(data[j])
            setattr(object, s2, value)
        elif s1[0:6]=='String':
            if (s1=='String'):
		if object.LengthType==3: setattr(object, s2, "")
		else:
		    data=object._input.read(object._length)
		    setattr(object, s2, data)
	    else:
		import string
		v=string.atoi(s1[6:])
		data=object._input.read(v)
		setattr(object, s2, data)
	elif s1=='SizedString':
	    data=object._input.read(1)
	    length=ord(data[0])
	    data=data+object._input.read(length)
	    setattr(object, s2, data[1:])
	elif s1=='MPI':
	    data=object._input.read(2)
            length=ord(data[0])*256+ord(data[1])
            if ((length % 8)==0): length=length/8
	    else: length=(length-(length%8))/8+1
	    data=data+object._input.read(length)
	    setattr(object, s2, data)
        elif s1=='Error':
	    raise 'pgp.Exception', s2
	else:
	    if eval(s1, vars(), object.__dict__):
		templist=s2+templist
	object._length=object._length-len(data)
    
def WritePacket(object):
    print `object`
    output=''
    templist=Format[object.Type]
    while (len(templist)!=0):
       s1, s2 = templist[0]
       templist = templist[1:]
       if (type(s2)!=type([])):
           v=getattr(object, s2)
       if s1=='Byte':
           output=output+chr(v)
       elif s1=='U16':
           output=output+chr(v/256)
           output=output+chr(v & 255)
       elif s1=='U32':
           s=''
           for j in range(0, 4):
               s=chr(v & 255)+s
	       v=v/256
	   output=output+s
       elif s1=='U64':
           s=''
           for j in range(0, 8):
               s=chr(v & 255)+s
	       v=v/256
	   output=output+s
       elif s1[0:6]=='String':
	   if s1=='String':
	       if object.LengthType==3: pass
	       else:
		   output=output+v
	   else:
		length=string.atoi(s1[6:])
		output=output+v
       elif s1=='SizedString':
           output=output+chr(len(v))
           output=output+v
       elif s1=='MPI':
           output=output+v
       elif s1=='Error':
           raise 'pgp.Exception', s2
       else:
           if eval(s1, vars(), object.__dict__): templist=s2+templist
    l=long(len(output))
    if object.LengthType==3: lengthType=object.LengthType
    else:
	bytes, lengthType = 4,2
	if object.PacketLength!=None:
	    if l<65536: bytes,lengthType=2,1
	    if l<256: bytes,lengthType=1,0
	# XXX For key ring packets, it seems that the length *must* be
	# two bytes, or PGP 2.6.2 won't read it.  This is broken
	# behaviour on PGP's part. 
        if object.Type==5 or object.Type==6: bytes,lengthType=2,1
	for i in range(0,bytes):
	    output=chr( int(l & 255) ) + output
	    l=l>>8
    output=chr(128 + (object.Type<<2)+ lengthType)+output
    return output
    

# The master description of PGP packets (current up to 2.6.2)

# Packet constants (this table is duplicated in pgp.py)

PK_ENCRYPTED  =  1
SIGNATURE    =  2
PRIVKEY   =  5
PUBKEY    =  6
COMPRESSED   =  8
CIPHERED     =  9
PLAINTEXT    = 11
TRUST        = 12
USERID       = 13
COMMENT      = 14

# Values in CTB for the length of the length of the following packet.
Lengths = {0:1, 1:2, 2:4, 3:-1}

#
#  Here comes a gigantic dictionary from hell!
#  

Format = {
PK_ENCRYPTED:[
             ('Byte', 'Version'),
             ('U64', 'KeyID'),
             ('Byte', 'PKCalg'),
             ('PKCalg==1',
              [
               ('MPI', 'IntegerMPI')
              ]
             ),
             ('PKCalg!=1',
              [
               ('Error', 'Unknown encryption algorithm in PK-encrypted packet')
              ]
             )
            ],
SIGNATURE:  [
             ('Byte', 'Version'),
             ('Version==2 or Version==3', 
              [
               ('Byte', 'MatLength'),
               ('MatLength==5', 
                [
                 ('Byte', 'SecClass'),
                 ('U32', 'TimeStamp'),
                 ('U64', 'KeyID'),
                 ('Byte', 'PKCalg'),
                 ('PKCalg==1',
                  [
                   ('Byte', 'DigestAlg'),
                   ('U16', 'Checksum'),
                   ('MPI', 'IntegerMPI')
                  ]
                 ),
                 ('PKCalg!=1', 
                  [
                   ('Error', 'Unknown encryption algorithm in signature packet')
                  ]
                 )
                ]
               ),
               ('MatLength!=5',
                [
                 ('Error', 'Unknown length of material in signature packet')
                ]
               )
              ]
             ),
             ('Version!=2 and Version!=3',
              [
               ('Error', 'Unknown version number in signature packet')
              ]
             )
            ],
PRIVKEY:    [
             ('Byte', 'Version'),
             ('U32', 'TimeStamp'),
             ('U16', 'Validity'),
             ('Byte', 'PKCalg'),
             ('PKCalg==1',
              [
               ('MPI', 'nMPI'),
               ('MPI', 'eMPI'),
               ('Byte', 'CipherAlg'),
               ('CipherAlg==0',
                [
                 ('MPI', 'dMPI'),
                 ('MPI', 'pMPI'),
                 ('MPI', 'qMPI'),
                 ('MPI', 'uMPI')
                ]
               ),
               ('CipherAlg==1',
                [
                 ('String+8', 'IV'),
                 ('MPI', 'dMPI'),
                 ('MPI', 'pMPI'),
                 ('MPI', 'qMPI'),
                 ('MPI', 'uMPI')
                ]
               ),
               ('CipherAlg!=0 and CipherAlg!=1',
                [
                 ('Error', 'Unknown ciphering algorithm in public key')
                ]
               ),
               ('U16', 'CkSum')
              ]
             ),
             ('PKCalg!=1',
              [
               ('Error', 'Unknown encryption algorithm in private key')
              ]
             )
            ],
PUBKEY:     [
             ('Byte', 'Version'),
             ('Version==2 or Version==3',
              [
               ('U32', 'TimeStamp'),
               ('U16', 'Validity'),
               ('Byte', 'PKCalg'),
               ('PKCalg==1', 
                [
                 ('MPI', 'nMPI'),
                 ('MPI', 'eMPI')
                ]
               ),
               ('PKCalg!=1', 
                [
                 ('Error', 'Unknown encryption algorithm in Public Key packet')
                ]
               )
              ]
             ),
             ('Version!=2 and Version!=3', 
              [
               ('Error', 'Unknown version in Public Key packet')
              ]
             )
            ], 
CIPHERED:   [
             ('String', 'Ciphertext')
            ],
PLAINTEXT:  [
             ('Byte', 'TextMode'),
             ('SizedString', 'Filename'),
             ('U32', 'TimeStamp'),
             ('String', 'Plaintext')
            ],
COMPRESSED: [
             ('Byte', 'CompressAlg'),
             ('String', 'CompressedData')
            ],
TRUST:      [
             ('Byte', 'Trust')
            ],
USERID:     [
             ('String', 'UserID')
            ],
COMMENT:    [
             ('String', 'Comment')
            ]
}
