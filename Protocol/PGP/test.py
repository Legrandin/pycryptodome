#!/usr/local/bin/python

import sys, pgp

abcID=0x57FBBFB1L ; amkID=0x0E304991L
abcPass='secret' ; amkPass='super secret'

def testKeyGeneration():
    key=pgp.PrivateKey()
    key.generate(pgp.PK_RSA, 1024)
    key.Lock('super')
    newID=pgp.UserID()
    newID.UserID='Python'
    key.IDList.append(newID)
    trust=pgp.Trust()
    # Write the secret keyring
    f=open('secring.pgp', 'a')
    f.write(key.binary())
    f.write(newID.binary())
    f.close()
    # Write the public keyring, with trust packets
    f=open('pubring.pgp', 'a')
    f.write(key.public_binary())
    f.write(trust.binary())
    f.write(newID.binary())
    f.write(trust.binary())
    f.close()

def testMessaging():
    pass

def getpubkeys():
    pubring=pgp.KeyRing()
    pubring.parseKeyRing(open('./pubring.pgp', 'r'))
    pub_abc=pubring[abcID]
    pub_amk=pubring[amkID]
    return pub_abc, pub_amk

def getseckeys():
    secring=pgp.KeyRing()
    secring.parseKeyRing(open('./secring.pgp', 'r'))
    sec_abc=secring[abcID]
    sec_amk=secring[amkID]
    return sec_abc, sec_amk

sec_abc, sec_amk = getseckeys()
pub_abc, pub_amk = getpubkeys()

print 'amk=', hex(sec_amk.KeyID)
print 'abc=', hex(sec_abc.KeyID)

f=open('books.txt', 'r') ; message=f.read() ; f.close()

import md5
DEK=md5.new('testp').digest()
sec_amk.Unlock(amkPass)
output=pgp.EncryptMessage(message, recipients=[pub_amk,pub_abc], 
			  signer=sec_amk )

f=open('books.txt.pgp', 'w') ; f.write(output) ; f.close()

sec_amk.Unlock(amkPass)
sec_abc.Unlock(abcPass)
for sig in pub_abc.IDList[0].SigList:
    if sig.SigKeyID==pub_amk.KeyID:
	print sig.verify_key_sig(pub_amk, pub_abc, u)

print "abc's key is self signed:", pub_abc.is_self_signed()
print "amk's key is self signed:", pub_amk.is_self_signed()

# Test the Lock() method of key objects
L=[] ; L2=[]
for i in 'ednpqu': L.append(getattr(sec_amk, i))
sec_amk.Lock(amkPass)
sec_amk.Unlock(amkPass)
for i in 'ednpqu': L2.append(getattr(sec_amk, i))
if L!=L2:
    print "ERROR: key data doesn't match after Lock() and Unlock()"
print L==L2
