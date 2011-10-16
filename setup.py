#! /usr/bin/env python
#
#  setup.py : Distutils setup script
#
#  Part of the Python Cryptography Toolkit
#
# ===================================================================
# Portions Copyright (c) 2001, 2002, 2003 Python Software Foundation;
# All Rights Reserved
#
# This file contains code from the Python 2.2 setup.py module (the
# "Original Code"), with modifications made after it was incorporated
# into PyCrypto (the "Modifications").
#
# To the best of our knowledge, the Python Software Foundation is the
# copyright holder of the Original Code, and has licensed it under the
# Python 2.2 license.  See the file LEGAL/copy/LICENSE.python-2.2 for
# details.
#
# The Modifications to this file are dedicated to the public domain.
# To the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.  No rights are
# reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

__revision__ = "$Id$"

from distutils import core
from distutils.core import Extension, Command
from distutils.command.build_ext import build_ext
import distutils
import tempfile
import os, sys
import struct

if sys.version[0:1] == '1':
    raise RuntimeError, ("The Python Cryptography Toolkit requires "
                         "Python 2.x to build.")

if sys.platform == 'win32':
    HTONS_LIBS = ['ws2_32']
    plat_ext = [
                Extension("Crypto.Random.OSRNG.winrandom",
                          libraries = HTONS_LIBS + ['advapi32'],
                          include_dirs=['src/'],
                          sources=["src/winrand.c"])
               ]
else:
    HTONS_LIBS = []
    plat_ext = []

# For test development: Set this to 1 to build with gcov support.
# Use "gcov -p -o build/temp.*/src build/temp.*/src/*.gcda" to build the .gcov files
USE_GCOV = 0

# List of pure Python modules that will be excluded from the binary packages.
# The list consists of (package, module_name) tuples
from distutils.command.build_py import build_py
EXCLUDE_PY = []
#    ('Crypto.Hash', 'RIPEMD160'),  # Included for your amusement, but the C version is much faster.
#]

def libgmp_exists():
    '''Verify that the compiler and the linker can reach libgmp'''

    fname = tempfile.mktemp(".c")
    oname = tempfile.mktemp(".out")
    f = open(fname, 'w')
    f.write("""
    #include <gmp.h>

    int main(void)
    {
        mpz_init((void*)0);
        return 0;
    }
    """)
    f.close()

    result = 1
    try:
        compiler = distutils.ccompiler.new_compiler()
        distutils.sysconfig.customize_compiler(compiler)
        objects = compiler.compile([fname])
        compiler.link_executable(objects, oname, libraries=('gmp',) )
    except Exception:
        result = 0
    for f in objects+[fname, oname]:
        try: os.remove(f)
        except Exception: pass
    return result

def endianness_macro():
    s = struct.pack("@I", 0x33221100)
    if s == "\x00\x11\x22\x33":     # little endian
        return ('PCT_LITTLE_ENDIAN', 1)
    elif s == "\x33\x22\x11\x00":   # big endian
        return ('PCT_BIG_ENDIAN', 1)
    raise AssertionError("Machine is neither little-endian nor big-endian")

class PCTBuildExt (build_ext):
    def build_extensions(self):
        # Detect which modules should be compiled
        self.detect_modules()

        # Tweak compiler options
        if self.compiler.compiler_type in ('unix', 'cygwin', 'mingw32'):
            # Tell GCC to compile using the C99 standard.
            self.__add_compiler_option("-std=c99")

            # Make assert() statements always work
            self.__remove_compiler_option("-DNDEBUG")

            # Choose our own optimization options
            for opt in ["-O", "-O0", "-O1", "-O2", "-O3", "-Os"]:
                self.__remove_compiler_option(opt)
            if self.debug:
                # Basic optimization is still needed when debugging to compile
                # the libtomcrypt code.
                self.__add_compiler_option("-O")
            else:
                # Speed up execution by tweaking compiler options.  This
                # especially helps the DES modules.
                self.__add_compiler_option("-O3")
                self.__add_compiler_option("-fomit-frame-pointer")
                # Don't include debug symbols unless debugging
                self.__remove_compiler_option("-g")
                # Don't include profiling information (incompatible with -fomit-frame-pointer)
                self.__remove_compiler_option("-pg")
            if USE_GCOV:
                self.__add_compiler_option("-fprofile-arcs")
                self.__add_compiler_option("-ftest-coverage")
                self.compiler.libraries += ['gcov']

        # Call the superclass's build_extensions method
        build_ext.build_extensions(self)

    def detect_modules (self):
        # Add special include directory for MSVC (because MSVC is special)
        if self.compiler.compiler_type == 'msvc':
            self.compiler.include_dirs.insert(0, "src/inc-msvc/")

        # Detect libgmp and don't build _fastmath if it is missing.
        if not libgmp_exists():
            print >>sys.stderr, "warning: GMP library not found; Not building Crypto.PublicKey._fastmath."
            self.__remove_extensions(["Crypto.PublicKey._fastmath"])

    def __remove_extensions(self, names):
        """Remove the specified extension from the list of extensions to build"""
        i = 0
        while i < len(self.extensions):
            if self.extensions[i].name in names:
                del self.extensions[i]
                continue
            i += 1

    def __remove_compiler_option(self, option):
        """Remove the specified compiler option.

        Return true if the option was found.  Return false otherwise.
        """
        found = 0
        for attrname in ('compiler', 'compiler_so'):
            compiler = getattr(self.compiler, attrname, None)
            if compiler is not None:
                while option in compiler:
                    compiler.remove(option)
                    found += 1
        return found

    def __add_compiler_option(self, option):
        for attrname in ('compiler', 'compiler_so'):
            compiler = getattr(self.compiler, attrname, None)
            if compiler is not None:
                compiler.append(option)

class PCTBuildPy(build_py):
    def find_package_modules(self, package, package_dir, *args, **kwargs):
        modules = build_py.find_package_modules(self, package, package_dir, *args, **kwargs)

        # Exclude certain modules
        retval = []
        for item in modules:
            pkg, module = item[:2]
            if (pkg, module) in EXCLUDE_PY:
                continue
            retval.append(item)
        return retval

class TestCommand(Command):

    description = "Run self-test"

    # Long option name, short option name, description
    user_options = [
        ('skip-slow-tests', None,
            'Skip slow tests'),
        ('module=', 'm', 'Test a single module (e.g. Cipher, PublicKey)')
    ]

    def initialize_options(self):
        self.build_dir = None
        self.skip_slow_tests = None
        self.module = None

    def finalize_options(self):
        self.set_undefined_options('install', ('build_lib', 'build_dir'))
        self.config = {'slow_tests': not self.skip_slow_tests}

    def run(self):
        # Run SelfTest
        self.announce("running self-tests")
        old_path = sys.path[:]
        try:
            sys.path.insert(0, self.build_dir)
            from Crypto import SelfTest
            moduleObj = None
            if self.module:
                if self.module.count('.')==0:
                    # Test a whole a sub-package
                    full_module = "Crypto.SelfTest." + self.module
                    module_name = self.module
                else:
                    # Test only a module
                    # Assume only one dot is present
                    comps = self.module.split('.')
                    module_name = "test_" + comps[1]
                    full_module = "Crypto.SelfTest." + comps[0] + "." + module_name
                # Import sub-package or module
                moduleObj = __import__( full_module, globals(), locals(), module_name )
            SelfTest.run(module=moduleObj, verbosity=self.verbose, stream=sys.stdout, config=self.config)
        finally:
            # Restore sys.path
            sys.path[:] = old_path

        # Run slower self-tests
        self.announce("running extended self-tests")

kw = {'name':"pycrypto",
      'version':"2.3",  # See also: lib/Crypto/__init__.py
      'description':"Cryptographic modules for Python.",
      'author':"Dwayne C. Litzenberger",
      'author_email':"dlitz@dlitz.net",
      'url':"http://www.pycrypto.org/",

      'cmdclass' : {'build_ext':PCTBuildExt, 'build_py': PCTBuildPy, 'test': TestCommand },
      'packages' : ["Crypto", "Crypto.Hash", "Crypto.Cipher", "Crypto.Util",
                  "Crypto.Random",
                  "Crypto.Random.Fortuna",
                  "Crypto.Random.OSRNG",
                  "Crypto.SelfTest",
                  "Crypto.SelfTest.Cipher",
                  "Crypto.SelfTest.Hash",
                  "Crypto.SelfTest.Protocol",
                  "Crypto.SelfTest.PublicKey",
                  "Crypto.SelfTest.Random",
                  "Crypto.SelfTest.Random.Fortuna",
                  "Crypto.SelfTest.Random.OSRNG",
                  "Crypto.SelfTest.Util",
                  "Crypto.SelfTest.Signature",
                  "Crypto.Protocol",
                  "Crypto.PublicKey",
                  "Crypto.Signature"],
      'package_dir' : { "Crypto": "lib/Crypto" },
      'ext_modules': plat_ext + [
            # _fastmath (uses GNU mp library)
            Extension("Crypto.PublicKey._fastmath",
                      include_dirs=['src/'],
                      libraries=['gmp'],
                      sources=["src/_fastmath.c"]),

            # Hash functions
            Extension("Crypto.Hash._MD2",
                      include_dirs=['src/'],
                      sources=["src/MD2.c"]),
            Extension("Crypto.Hash._MD4",
                      include_dirs=['src/'],
                      sources=["src/MD4.c"]),
            Extension("Crypto.Hash._SHA256",
                      include_dirs=['src/'],
                      sources=["src/SHA256.c"]),
            Extension("Crypto.Hash._SHA224",
                      include_dirs=['src/'],
                      sources=["src/SHA224.c"]),
            Extension("Crypto.Hash._SHA384",
                      include_dirs=['src/'],
                      sources=["src/SHA384.c"]),
            Extension("Crypto.Hash._SHA512",
                      include_dirs=['src/'],
                      sources=["src/SHA512.c"]),
            Extension("Crypto.Hash._RIPEMD160",
                      include_dirs=['src/'],
                      sources=["src/RIPEMD160.c"],
                      define_macros=[endianness_macro()]),

            # Block encryption algorithms
            Extension("Crypto.Cipher.AES",
                      include_dirs=['src/'],
                      sources=["src/AES.c"]),
            Extension("Crypto.Cipher.ARC2",
                      include_dirs=['src/'],
                      sources=["src/ARC2.c"]),
            Extension("Crypto.Cipher.Blowfish",
                      include_dirs=['src/'],
                      sources=["src/Blowfish.c"]),
            Extension("Crypto.Cipher.CAST",
                      include_dirs=['src/'],
                      sources=["src/CAST.c"]),
            Extension("Crypto.Cipher.DES",
                      include_dirs=['src/', 'src/libtom/'],
                      sources=["src/DES.c"]),
            Extension("Crypto.Cipher.DES3",
                      include_dirs=['src/', 'src/libtom/'],
                      sources=["src/DES3.c"]),

            # Stream ciphers
            Extension("Crypto.Cipher.ARC4",
                      include_dirs=['src/'],
                      sources=["src/ARC4.c"]),
            Extension("Crypto.Cipher.XOR",
                      include_dirs=['src/'],
                      sources=["src/XOR.c"]),

            # Utility modules
            Extension("Crypto.Util.strxor",
                      include_dirs=['src/'],
                      sources=['src/strxor.c']),

            # Counter modules
            Extension("Crypto.Util._counter",
                      include_dirs=['src/'],
                      sources=['src/_counter.c']),
    ]
}

# If we're running Python 2.3, add extra information
if hasattr(core, 'setup_keywords'):
    if 'classifiers' in core.setup_keywords:
        kw['classifiers'] = [
          'Development Status :: 4 - Beta',
          'License :: Public Domain',
          'Intended Audience :: Developers',
          'Operating System :: Unix',
          'Operating System :: Microsoft :: Windows',
          'Operating System :: MacOS :: MacOS X',
          'Topic :: Security :: Cryptography',
          ]
    if 'download_url' in core.setup_keywords:
        kw['download_url'] = ('http://www.pycrypto.org/files/'
                              '%s-%s.tar.gz' % (kw['name'], kw['version']) )

core.setup(**kw)

