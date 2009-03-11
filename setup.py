#! /usr/bin/env python

__revision__ = "$Id$"

from distutils import core
from distutils.core import Extension, Command
from distutils.command.build_ext import build_ext
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

# List of pure Python modules that will be excluded from the binary packages.
# The list consists of (package, module_name) tuples
from distutils.command.build_py import build_py
EXCLUDE_PY = [
    ('Crypto.Hash', 'RIPEMD160'),  # Included for your amusement, but the C version is much faster.
]

# Functions for finding libraries and files, copied from Python's setup.py.

def find_file(filename, std_dirs, paths):
    """Searches for the directory where a given file is located,
    and returns a possibly-empty list of additional directories, or None
    if the file couldn't be found at all.

    'filename' is the name of a file, such as readline.h or libcrypto.a.
    'std_dirs' is the list of standard system directories; if the
        file is found in one of them, no additional directives are needed.
    'paths' is a list of additional locations to check; if the file is
        found in one of them, the resulting list will contain the directory.
    """

    # Check the standard locations
    for dir in std_dirs:
        f = os.path.join(dir, filename)
        if os.path.exists(f): return []

    # Check the additional directories
    for dir in paths:
        f = os.path.join(dir, filename)
        if os.path.exists(f):
            return [dir]

    # Not found anywhere
    return None

def find_library_file(compiler, libname, std_dirs, paths):
    filename = compiler.library_filename(libname, lib_type='shared')
    result = find_file(filename, std_dirs, paths)
    if result is not None: return result

    filename = compiler.library_filename(libname, lib_type='static')
    result = find_file(filename, std_dirs, paths)
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
        self.extensions += [
            # Hash functions
            Extension("Crypto.Hash.MD4",
                      include_dirs=['src/'],
                      sources=["src/MD4.c"]),
            Extension("Crypto.Hash.SHA256",
                      include_dirs=['src/'],
                      sources=["src/SHA256.c"]),
            Extension("Crypto.Hash.RIPEMD160",
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

            # Utility modules
            Extension("Crypto.Util.strxor",
                      include_dirs=['src/'],
                      sources=['src/strxor.c']),

            # Counter modules
            Extension("Crypto.Util._counter",
                      include_dirs=['src/'],
                      sources=['src/_counter.c']),
            ]

        # Platform-specific modules
        self.extensions += plat_ext

        # Detect which modules should be compiled
        self.detect_modules()

        # Speed up execution by tweaking compiler options.  This especially
        # helps the DES modules.
        if not self.debug and self.compiler.compiler_type in ('unix', 'cygwin', 'mingw32'):
            self.__remove_compiler_option("-g")
            self.__remove_compiler_option("-O")
            self.__remove_compiler_option("-O2")
            self.__add_compiler_option("-O3")
            self.__add_compiler_option("-fomit-frame-pointer")

        # Call the superclass's build_extensions method
        build_ext.build_extensions(self)

    def detect_modules (self):
        if self.compiler.compiler_type == 'msvc':
            self.compiler.include_dirs.insert(0, "src/inc-msvc/")
        lib_dirs = self.compiler.library_dirs + ['/lib', '/usr/lib']
        inc_dirs = self.compiler.include_dirs + ['/usr/include']
        exts = []
        if (self.compiler.find_library_file(lib_dirs, 'gmp')):
            exts.append(Extension("Crypto.PublicKey._fastmath",
                                  include_dirs=['src/'],
                                  libraries=['gmp'],
                                  sources=["src/_fastmath.c"]))
        else:
            print >>sys.stderr, "warning: GMP library not found; Not building Crypto.PublicKey._fastmath."
        self.extensions += exts

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

    user_options = [
        ('skip-slow-tests', None,
            'Skip slow tests')
    ]

    def initialize_options(self):
        self.build_dir = None
        self.skip_slow_tests = None

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
            SelfTest.run(verbosity=self.verbose, stream=sys.stdout, config=self.config)
        finally:
            # Restore sys.path
            sys.path[:] = old_path

        # Run slower self-tests
        self.announce("running extended self-tests")

kw = {'name':"pycrypto",
      'version':"2.0.2",
      'description':"Cryptographic modules for Python.",
      'author':"A.M. Kuchling",
      'author_email':"amk@amk.ca",
      'url':"http://www.amk.ca/python/code/crypto",

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
                  "Crypto.Protocol", "Crypto.PublicKey"],
      'package_dir' : { "Crypto": "lib/Crypto" },
      # One module is defined here, because build_ext won't be
      # called unless there's at least one extension module defined.
      'ext_modules':[Extension("Crypto.Hash.MD2",
                             include_dirs=['src/'],
                             sources=["src/MD2.c"])],
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
        kw['download_url'] = ('http://www.amk.ca/files/python/crypto/'
                              '%s-%s.tar.gz' % (kw['name'], kw['version']) )

core.setup(**kw)

