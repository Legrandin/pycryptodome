#!/usr/local/bin/python -Ou

""" enc - encrypt/decrypt files using one of SSLeay's ciphers.

    Copyright (c) 1998 by Marc-Andre Lemburg; All Rights Reserved;
    mailto:mal@lemburg.com; See the documentation for further
    copyright information or contact the author.

    DISCLAIMER & WARNING: This tool comes with NO WARRANTY. Use at
    YOUR OWN RISK. It may destroy data ! There is NO way to recover a
    forgotten pass phrase !
"""
import exceptions,os,string,time,sys
from CryptoWorld import Ciphers,Hashes,Utils
from CommandLine import Application,SwitchOption,ArgumentOption

# Globals
verbose = 0

# Maximum block size used for en/decryption
MAX_BLOCKSIZE = 1024 * 1000

class OperationalError(exceptions.StandardError):
    pass

def filesize(file):

    oldpos = file.tell()
    file.seek(0,2)
    size = file.tell()
    file.seek(oldpos)
    return size

def invisible_input(prompt='>>> '):

    """ Adapted from the Python 1.5.1 docs example getpass()
    """
    import termios,TERMIOS
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    new = termios.tcgetattr(fd)
    new[3] = new[3] & ~TERMIOS.ECHO          # fix lflags
    try:
        termios.tcsetattr(fd, TERMIOS.TCSADRAIN, new)
        passwd = raw_input(prompt)
    finally:
        termios.tcsetattr(fd, TERMIOS.TCSADRAIN, old)
    print
    return passwd

def tempfile(filename='tmp',

             maxint=sys.maxint,time=time.time,int=int,hex=hex,
             exists=os.path.exists):

    """ Return a new filename for a temporary file (based on filename).
    """
    temp = filename + '.' + hex(maxint % int(time())) + '.tmp'
    if not exists(temp):
        return temp
    # Ok, find an alternative name
    i = 0
    while 1:
        temp = '%s.%s-%i.tmp' % (filename,hex(maxint % int(time())),i)
        if not exists(temp):
            return temp
        i = i + 1

# Global key
_key = ''

def get_cipher(name,check=0):

    global _key
    
    cc = getattr(Ciphers,name)
    keysize = cc.keysize
    if not _key:
        while 1:
            key1 = invisible_input('Please enter the key phrase: ')
            if check:
                key2 = invisible_input('Please reenter the phrase: ')
                if key1 != key2:
                    print "Phrases don't match. Please start again..."
                    continue
            if len(key1) == 0:
                print "Empty key phrase. Please start again..."
            else:
                break
        _key = key1
    key = _key
    # Fit key
    if keysize > 0:
        if len(key) < keysize:
            key = key + \
                  'Do not change this string, it is important !'\
                  [:keysize - len(key)]
        elif len(key) > keysize:
            key = key[:keysize]
    cipher = cc(key,Ciphers.CBC)
    return cipher

def reset_key():

    global _key

    _key = ''

###

def encrypt(filename,ciphername,overwrite=0):

    if verbose:
        print  'Encrypting:',filename
    if filename[-4:] == '.enc':
        raise OperationalError,'already encrypted'
    if not os.path.isfile(filename):
        raise OperationalError,'not a file or not found'

    # Check overwrites
    if os.path.exists(filename + '.enc'):
        if not overwrite:
            raise OperationalError,'would overwrite an existing file'
        elif os.path.samefile(filename, filename + '.enc'):
            raise OperationalError,'would overwrite the original file'

    # Open plain file
    f = open(filename,'rb')
    size = filesize(f)
    if verbose:
        print  ' total size: %i bytes' % size

    # Open work file
    workfilename = tempfile(filename)
    out = open(workfilename,'wb')

    try:
        # Init cipher and write header
        cipher = get_cipher(ciphername,check=1)
        out.write('enc %s %s %i\n' % \
                  (repr(filename),ciphername,size))

        # Init hash and blocksize
        hash = Hashes.MD5()
        blocksize = size
        if blocksize > MAX_BLOCKSIZE:
            blocksize = MAX_BLOCKSIZE
        blocksize = ((blocksize + cipher.blocksize - 1) / cipher.blocksize) \
                    * cipher.blocksize

        # Write the encrypted data in blocks
        bytesread = 0
        while bytesread < size:
            if verbose:
                print  ' reading %i bytes...' % blocksize,
            block = f.read(blocksize)
            if verbose:
                print  'read %i bytes' % len(block)
            bytesread = bytesread + len(block)
            hash.update(block)
            if bytesread == size:
                # Final block
                offset = len(block) % cipher.blocksize
                if offset:
                    padsize = cipher.blocksize - offset
                    block = block + '\0'*padsize
                    if verbose:
                        print  ' padding with %i bytes' % (padsize)
            encblock = cipher.encrypt(block)
            out.write(encblock)

        # Write hash value
        hash_value = hash.digest()
        if verbose:
            print ' hash value:',repr(hash_value)
        out.write(hash_value)

        # Copy work file to .enc file
        out.close()
        f.close()
        os.rename(workfilename,filename+'.enc')
        workfilename = None

    finally:
        if workfilename:
            if not out.closed:
                out.close()
            os.remove(workfilename)

###

def decrypt(filename,overwrite=0):

    if verbose:
        print  'Decrypting:',filename
    if filename[-4:] != '.enc':
        raise OperationalError,'decrypt a plain file'
    if not os.path.isfile(filename):
        raise OperationalError,'not a file or not found'

    # Read header from cipher file
    f = open(filename,'rb')
    header = string.split(f.readline())
    if len(header) != 4:
        raise OperationalError,'wrong header format:'+ str(header)
    origfilename = eval(header[1])
    ciphername = header[2]
    size = string.atoi(header[3])
    if verbose:
        print  ' total size: %i bytes' % size

    # Check overwrites
    if os.path.exists(origfilename):
        if not overwrite:
            raise OperationalError,'would overwrite an existing file'
        elif os.path.samefile(origfilename, filename):
            raise OperationalError,'would overwrite the encrypted file'

    # Open work file
    workfilename = tempfile(filename)
    out = open(workfilename,'wb')

    try:

        # Load cipher and init hash
        cipher = get_cipher(ciphername)
        hash = Hashes.MD5()

        # Read the encrypted data in blocks
        blocksize = size
        if blocksize > MAX_BLOCKSIZE:
            blocksize = MAX_BLOCKSIZE
        blocksize = ((blocksize + cipher.blocksize - 1) / cipher.blocksize) \
                    * cipher.blocksize
        bytesread = 0
        while bytesread < size:
            if size - bytesread < blocksize:
                # Read remaining data only
                blocksize = size - bytesread
                blocksize = ((blocksize + cipher.blocksize - 1) / \
                             cipher.blocksize) * cipher.blocksize
            if verbose:
                print  ' reading %i bytes...' % blocksize,
            encblock = f.read(blocksize)
            if verbose:
                print 'read %i bytes' % len(encblock)
            bytesread = bytesread + len(encblock)
            block = cipher.decrypt(encblock)
            if bytesread > size:
                # Depad
                padsize = bytesread - size
                block = block[:-padsize]
                if verbose:
                    print ' depadded last block by %i bytes' % (padsize)
            hash.update(block)
            out.write(block)

        # Check hash value
        hash_value = f.read(hash.digestsize)
        if verbose:
            print ' hash value:',repr(hash_value)
        if hash_value != hash.digest():
            raise OperationalError,'data corrupt'

        # Copy workfile to origfile
        out.close()
        f.close()
        os.rename(workfilename,origfilename)
        workfilename = None

    finally:
        if workfilename:
            if not out.closed:
                out.close()
            os.remove(workfilename)

###

class Encrypt(Application):

    header = "File encryption utility using the SSLeay ciphers"

    about = """\
Encrypts or decrypts the files given on the command line. If no
options are given the filenames extensions are taken as hint: '.enc'
means encrypted, everything else not encrypted. The utility then goes
and switches the state of the files. Overwriting of files only takes
place in case the '-O' switch is set.

The following ciphers are supported:
      RC2, RC4, RC5, IDEA, Blowfish, DES, DES3, CAST

This tool comes with NO WARRANTY. Use at YOUR OWN RISK. It may destroy
data ! There is NO way to recover a forgotten pass phrase !
"""

    options = [SwitchOption('-e', 'encrypt'),
               SwitchOption('-d', 'decyrpt'),
               SwitchOption('-a', 'use the same key for all files'),
               SwitchOption('-O', 'allow overwrites (use with care)'),
               ArgumentOption('-c', 'cipher to use', 'RC5'),
               ]
    
    def main(self):

        overwrite = self.values['-O']
        ciphername = self.values['-c']
        samekey = self.values['-a']
        for file in self.files:
            if not samekey:
                reset_key()
                print '-'*78
                print 'Working on file:',file
            try:
                if self.values['-e']:
                    encrypt(file,ciphername,overwrite)
                elif self.values['-d']:
                    decrypt(file,overwrite)
                elif file[-4:] != '.enc':
                    encrypt(file,ciphername,overwrite)
                else:
                    decrypt(file,overwrite)
            except OperationalError,why:
                print '%s skipped -- %s' % (file,why)
            except IOError,(code,why):
                print '%s skipped -- %s' % (file,why)
            except os.error,why:
                print '%s skipped -- %s' % (file,why)
            except KeyboardInterrupt:
                print '*user break*'
                break

if __name__ == '__main__':
    Encrypt()
