#!/usr/local/bin/python

import sys ; sys.path = ['../../../'] + sys.path

import imp, os
from sys import modules

# Secure import:
def secimport(name, globals=None, locals=None, fromlist=None):
    # Fast path: let's see if it's already in sys.modules.
    # Two speed optimizations are worth mentioning:
    # - We use 'modules' instead of 'sys.modules'; this saves a
    #   dictionary look-up per call.
    # - It's also faster to use a try-except statement than
    #   to use modules.has_key(name) to check if it's there.
    try:
        return modules[name]
    except KeyError:
        pass

    # See if it's a built-in module
    m = imp.init_builtin(name)
    if m:
        return m

    # See if it's a frozen module
    m = imp.init_frozen(name)
    if m:
        return m

    # Search the default path (i.e. sys.path).
    # If this raises an exception, the module is not found --
    # let the caller handle the exception.
    fp, pathname, (suffix, mode, type) = imp.find_module(name)

    # See what we got...
    # Note that fp will be closed automatically when we return.

    # Extensions are written in C, and can just be loaded.
    if type == imp.C_EXTENSION:
        return imp.load_dynamic(name, pathname)

    # For a compiled or source file, we'll check if there is a *.pys file
    # present in the same directory.
    if type == imp.PY_COMPILED or type == imp.PY_SOURCE:
        root, ext = os.path.splitext(pathname)
        testfile = root + '.pys'
        try:
            print testfile
            secfile=open(testfile, 'rb')
        except IOError, tuple:
            if (tuple[0]==2): pass      # Ignore 'file not found' error
            else: raise IOError, tuple
        else:
            # Check the signature (a signed hash of the code object).
            # We could sign the whole code object, but that would
            # require a huge key and would double the size of the
            # *.pys file.
            import marshal
            from Crypto.Hash import MD5
            fp.close()                  # Close the original *.pyc file
            from testkey import *       # Get the key for verification
            signature=marshal.load(secfile) # Read signature
            position=secfile.tell()     # Save position
            data=secfile.read()         # Read code object
            hash=MD5.new(data).digest() # Compute its hash value
            ##print 'sigcheck:', key.verify(hash, signature)
            if (not key.verify(hash, signature)):
                raise ImportError, 'Signature check of '+ testfile + ' failed'
            secfile.seek(position)      # Rewind pointer to the
                                        # beginning of the code object
            fp=secfile
            del secfile
        # Now we can happily import the compiled code object.
        return imp.load_compiled(name, pathname, fp)

    # Shouldn't get here at all.
    raise ImportError, '%s: unknown module type (%d)' % (name, type)

if __name__=='__main__':
    # A sample invocation of the secure import looks like this:
    print 'Attempting secure import'
    r=secimport('testkey')
    print 'Secure import succeeded'
