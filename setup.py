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
from distutils.ccompiler import new_compiler
from distutils.core import Extension, Command
from distutils.command.build import build
from distutils.command.build_ext import build_ext
import os, sys, re
import struct

if sys.version[0:1] == '1':
    raise RuntimeError ("The Python Cryptography Toolkit requires "
                         "Python 2.x or 3.x to build.")

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
# Use "gcov -p -o build/temp.*/src build/temp.*/src/*.gcda" to build the
# .gcov files
USE_GCOV = 0


try:
    # Python 3
    from distutils.command.build_py import build_py_2to3 as build_py
except ImportError:
    # Python 2
    from distutils.command.build_py import build_py

# List of pure Python modules that will be excluded from the binary packages.
# The list consists of (package, module_name) tuples
if sys.version_info[0] == 2:
    EXCLUDE_PY = []
else:
    EXCLUDE_PY = [
        # We don't want Py3k to choke on the 2.x compat code
        ('Crypto.Util', 'py21compat'), 
    ]
    if sys.platform != "win32": # Avoid nt.py, as 2to3 can't fix it w/o winrandom
        EXCLUDE_PY += [('Crypto.Random.OSRNG','nt')]

# Work around the print / print() issue with Python 2.x and 3.x. We only need
# to print at one point of the code, which makes this easy

def PrintErr(*args, **kwd):
    fout = kwd.get("file", sys.stderr)
    w = fout.write
    if args:
        w(str(args[0]))
        sep = kwd.get("sep", " ")
        for a in args[1:]:
            w(sep)
            w(str(a))
        w(kwd.get("end", "\n"))

def endianness_macro():
    s = struct.pack("@I", 0x33221100)
    if s == "\x00\x11\x22\x33".encode():     # little endian
        return ('PCT_LITTLE_ENDIAN', 1)
    elif s == "\x33\x22\x11\x00".encode():   # big endian
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

            # ... but don't tell that to the aCC compiler on HP-UX
            if self.compiler.compiler_so[0] == 'cc' and sys.platform.startswith('hp-ux'):
                self.__remove_compiler_option("-std=c99")

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
                # Don't include profiling information (incompatible with
                # -fomit-frame-pointer)
                self.__remove_compiler_option("-pg")
            if USE_GCOV:
                self.__add_compiler_option("-fprofile-arcs")
                self.__add_compiler_option("-ftest-coverage")
                self.compiler.libraries += ['gcov']

        # Call the superclass's build_extensions method
        build_ext.build_extensions(self)

    def detect_modules (self):
        # Read the config.h file (usually generated by autoconf)
        if self.compiler.compiler_type == 'msvc':
            # Add special include directory for MSVC (because MSVC is special)
            self.compiler.include_dirs.insert(0, "src/inc-msvc/")
            ac = self.__read_autoconf("src/inc-msvc/config.h")
        else:
            ac = self.__read_autoconf("src/config.h")

        # Detect libgmp or libmpir and don't build _fastmath if both are missing.
        if ac.get("HAVE_LIBGMP"):
            # Default; no changes needed
            pass
        elif ac.get("HAVE_LIBMPIR"):
            # Change library to libmpir if libgmp is missing
            self.__change_extension_lib(["Crypto.PublicKey._fastmath"],
                ['mpir'])
            # And if this is MSVC, we need to add a linker option
            # to make a static libmpir link well into a dynamic _fastmath
            if self.compiler.compiler_type == 'msvc':
                self.__add_extension_link_option(["Crypto.PublicKey._fastmath"],
                    ["/NODEFAULTLIB:LIBCMT"])
        else:
            # No MP library; use _slowmath.
            PrintErr ("warning: GMP or MPIR library not found; Not building "+
                "Crypto.PublicKey._fastmath.")
            self.__remove_extensions(["Crypto.PublicKey._fastmath"])

    def __add_extension_link_option(self, names, options):
        """Add linker options for the specified extension(s)"""
        i = 0
        while i < len(self.extensions):
            if self.extensions[i].name in names:
                self.extensions[i].extra_link_args = options
            i += 1

    def __change_extension_lib(self, names, libs):
        """Change the libraries to be used for the specified extension(s)"""
        i = 0
        while i < len(self.extensions):
           if self.extensions[i].name in names:
                self.extensions[i].libraries = libs
           i += 1

    def __remove_extensions(self, names):
        """Remove the specified extension(s) from the list of extensions
       to build"""
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

    def __read_autoconf(self, filename):
        rx_define = re.compile(r"""^#define (\S+) (?:(\d+)|(".*"))$""")

        result = {}
        f = open(filename, "r")
        try:
            config_lines = f.read().replace("\r\n", "\n").split("\n")
            for line in config_lines:
                m = rx_define.search(line)
                if not m: continue
                sym = m.group(1)
                n = m.group(2)
                s = m.group(3)
                if n:
                    result[sym] = int(n)
                elif s:
                    result[sym] = eval(s)     # XXX - hack to unescape C-style string
                else:
                    continue
        finally:
            f.close()
        return result

    def run(self):
        for cmd_name in self.get_sub_commands():
            self.run_command(cmd_name)

        build_ext.run(self)

    def has_configure(self):
        compiler = new_compiler(compiler=self.compiler)
        return compiler.compiler_type != 'msvc'

    sub_commands = [ ('build_configure', has_configure) ] + build_ext.sub_commands

class PCTBuildConfigure(Command):
    description = "Generate config.h using ./configure (autoconf)"

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        if not os.path.exists("config.status"):
            if os.system("chmod 0755 configure") != 0:
                raise RuntimeError("chmod error")
            cmd = "sh configure"    # we use "sh" here so that it'll work on mingw32 with standard python.org binaries
            if self.verbose < 1:
                cmd += " -q"
            if os.system(cmd) != 0:
                raise RuntimeError("autoconf error")

class PCTBuildPy(build_py):
    def find_package_modules(self, package, package_dir, *args, **kwargs):
        modules = build_py.find_package_modules(self, package, package_dir,
            *args, **kwargs)

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
      'version':"2.6.1",  # See also: lib/Crypto/__init__.py
      'description':"Cryptographic modules for Python.",
      'author':"Dwayne C. Litzenberger",
      'author_email':"dlitz@dlitz.net",
      'url':"http://www.pycrypto.org/",

      'cmdclass' : {'build_configure': PCTBuildConfigure, 'build_ext': PCTBuildExt, 'build_py': PCTBuildPy, 'test': TestCommand },
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
                      include_dirs=['src/','/usr/include/'],
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
            Extension("Crypto.Cipher._AES",
                      include_dirs=['src/'],
                      sources=["src/AES.c"]),
            Extension("Crypto.Cipher._ARC2",
                      include_dirs=['src/'],
                      sources=["src/ARC2.c"]),
            Extension("Crypto.Cipher._Blowfish",
                      include_dirs=['src/'],
                      sources=["src/Blowfish.c"]),
            Extension("Crypto.Cipher._CAST",
                      include_dirs=['src/'],
                      sources=["src/CAST.c"]),
            Extension("Crypto.Cipher._DES",
                      include_dirs=['src/', 'src/libtom/'],
                      sources=["src/DES.c"]),
            Extension("Crypto.Cipher._DES3",
                      include_dirs=['src/', 'src/libtom/'],
                      sources=["src/DES3.c"]),

            # Stream ciphers
            Extension("Crypto.Cipher._ARC4",
                      include_dirs=['src/'],
                      sources=["src/ARC4.c"]),
            Extension("Crypto.Cipher._XOR",
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
          'Development Status :: 5 - Production/Stable',
          'License :: Public Domain',
          'Intended Audience :: Developers',
          'Operating System :: Unix',
          'Operating System :: Microsoft :: Windows',
          'Operating System :: MacOS :: MacOS X',
          'Topic :: Security :: Cryptography',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3',
          ]

core.setup(**kw)

def touch(path):
    import os, time
    now = time.time()
    try:
        # assume it's there
        os.utime(path, (now, now))
    except os.error:
        PrintErr("Failed to update timestamp of "+path)

# PY3K: Workaround for winrandom.pyd not existing during the first pass.
# It needs to be there for 2to3 to fix the import in nt.py
if (sys.platform == 'win32' and sys.version_info[0] == 3 and
    'build' in sys.argv[1:]):
    PrintErr("\nSecond pass to allow 2to3 to fix nt.py. No cause for alarm.\n")
    touch("./lib/Crypto/Random/OSRNG/nt.py")
    core.setup(**kw)
