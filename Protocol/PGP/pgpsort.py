#!/usr/local/bin/python

# PGP keyring sorter:
# Usage: pgpsort <keyring file>

import os, pgp, string, sys
if len(sys.argv)!=2:
    print 'Usage: pgpsort keyring'
    sys.exit(1)

filename=sys.argv[1]
if filename[-4:]!='.pgp': filename=filename+'.pgp'

try:
    keyfile=open(sys.argv[1], 'r')
except IOError, value:
    print value
    print "pgpsort: Can't open "+filename
    sys.exit(1)
    
sys.stderr.write('Reading...\n')

keylist=[]
while (1):
    key=pgp.Key(keyfile)
    sys.stderr.write('['+key.UserID[0][0].UserID+']\n')
    data=data[key.PacketLength:]
    keylist.append(key)

def Compare(key1, key2):
    id1=string.upper(key1.UserID[0][0].UserID)
    id2=string.upper(key2.UserID[0][0].UserID)
    if id1<id2: return -1
    elif id1>id2:  return 1
    else: return 0
    
backup=filename[:-4]+'.bak'
try:
    os.unlink(backup)
except os.error, (value, message):
    if value!=2: raise os.error, (value, message)
os.rename(filename, backup)

sys.stderr.write('Sorting...')
keylist.sort(Compare)
sys.stderr.write('Writing...\n')
f=open(filename, 'wb')
for i in keylist:
    f.write(i.Write())
f.close()

