#
# Test script for the Python Cryptography Toolkit.
#

import os, sys


# Add the build directory to the front of sys.path
from distutils.util import get_platform
s = "build/lib.%s-%.3s" % (get_platform(), sys.version)
s = os.path.join(os.getcwd(), s)
sys.path.insert(0, s)

from Crypto.Util import test

args = sys.argv[1:]
quiet = "--quiet" in args
if quiet: args.remove('--quiet')


if 0:
    if not quiet:
        print 'Public-key Functions:'
        print '====================='

    if args: test.TestPKModules(args, verbose= not quiet)
    else:    test.TestPKModules(verbose= not quiet)


if not quiet:
    print '\nHash Functions:'
    print '==============='

if args: test.TestHashModules(args, verbose= not quiet)
else:    test.TestHashModules(verbose= not quiet)

if not quiet:
    print '\nStream Ciphers:'
    print '==============='

if args: test.TestStreamModules(args, verbose= not quiet)
else: test.TestStreamModules(verbose= not quiet)

if not quiet:
    print '\nBlock Ciphers:'
    print '=============='

if args: test.TestBlockModules(args, verbose= not quiet)
else: test.TestBlockModules(verbose= not quiet)


