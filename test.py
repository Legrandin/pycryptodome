#
# Test script for the Python Cryptography package.
#

import sys
args = sys.argv[1:]
quiet = "--quiet" in args
if quiet: args.remove('--quiet')

from Crypto.Util import test

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


