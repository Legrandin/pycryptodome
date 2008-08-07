#!/usr/bin/env python

# Using the public key defined in testkey.py, sign all *.pyc files in
# the listed directories.

from testkey import *
from Crypto.Hash import MD5
import os, glob, sys
import marshal, compileall

filelist = []
if (len(sys.argv)>1):
    for dir in sys.argv[1:]:
        dir=os.path.join(dir, '')
        compileall.compile_dir(dir)
        filelist=filelist + glob.glob(dir + '*.pyc')
else:
    print "Usage: sign.py dir1 dir2 dir3 ..."
    print "  All *.pyc files in the listed directories will be signed,"
    print "leaving the signatures in *.pys files."
    sys.exit(0)

if len(filelist)==0:
    print "No *.pyc files found"
    sys.exit(0)

for file in filelist:
    input=open(file, 'rb')
    try:
        os.unlink(file[:-4]+'.pys')     # Delete any existing signed file
    except os.error, tuple:
        if (tuple[0]==2): pass          # Ignore 'file not found' error
        else: raise os.error, tuple
    output=open(file[:-4]+'.pys', 'wb')
    data=input.read()
    hash=MD5.new(data).digest()         # Compute hash of the code object
    K = "random bytes"
    signature=key.sign(hash, K)         # Sign the hash value
    marshal.dump(signature, output)     # Save signature to the file
    output.write(data)                  # Copy code object to signed file
    input.close()
    output.close()
    print os.path.basename(file)+ ' processed.'



