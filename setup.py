#! /usr/bin/env python

__revision__ = "$Id: setup.py,v 1.22 2003-02-28 16:55:21 akuchling Exp $"

from distutils import core
from distutils.core import Extension
from distutils.command.build_ext import build_ext
import os, sys

if sys.version[0:1] == '1':
    raise RuntimeError, ("The Python Cryptography Toolkit requires "
                         "Python 2.x to build.")

if sys.platform == 'win32':
    HTONS_LIBS = ['ws2_32']
    plat_ext = [
                Extension("Crypto.Util.winrandom",
                          libraries = HTONS_LIBS + ['advapi32'],
                          include_dirs=['src/'],
                          sources=["src/winrand.c"])
               ]
else:
    HTONS_LIBS = []
    plat_ext = []

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

class PCTBuildExt (build_ext):
    def build_extensions(self):
        self.extensions += [
            # Hash functions
            Extension("Crypto.Hash.MD4",
                      include_dirs=['src/'],
                      sources=["src/MD4.c"]),
            Extension("Crypto.Hash.RIPEMD",
                      include_dirs=['src/'],
                      sources=["src/RIPEMD.c"],
                      libraries=HTONS_LIBS),

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
                      include_dirs=['src/'],
                      sources=["src/DES.c"]),
            Extension("Crypto.Cipher.DES3",
                      include_dirs=['src/'],
                      sources=["src/DES3.c"]),
            Extension("Crypto.Cipher.IDEA",
                      include_dirs=['src/'],
                      sources=["src/IDEA.c"],
                      libraries=HTONS_LIBS),
            Extension("Crypto.Cipher.RC5",
                      include_dirs=['src/'],
                      sources=["src/RC5.c"]),

            # Stream ciphers
            Extension("Crypto.Cipher.ARC4",
                      include_dirs=['src/'],
                      sources=["src/ARC4.c"]),
            Extension("Crypto.Cipher.XOR",
                      include_dirs=['src/'],
                      sources=["src/XOR.c"]),
            ]

        # Detect which modules should be compiled
        self.detect_modules()
        build_ext.build_extensions(self)

    def detect_modules (self):
        lib_dirs = self.compiler.library_dirs + ['/lib', '/usr/lib']
        inc_dirs = self.compiler.include_dirs + ['/usr/include']
        exts = []
        if (self.compiler.find_library_file(lib_dirs, 'gmp')):
            exts.append(Extension("Crypto.PublicKey._rsa",
                                  include_dirs=['src/'],
                                  libraries=['gmp'],
                                  sources=["src/_rsa.c"]))
            exts.append(Extension("Crypto.PublicKey._dsa",
                                  include_dirs=['src/'],
                                  libraries=['gmp'],
                                  sources=["src/_dsa.c"]))
        self.extensions += exts

kw = {'name':"pycrypto",
      'version':"1.9a5",
      'description':"Cryptographic modules for Python.",
      'author':"A.M. Kuchling",
      'author_email':"akuchlin@mems-exchange.org",
      'url':"http://pycrypto.sourceforge.net",

      'cmdclass' : {'build_ext':PCTBuildExt},
      'packages' : ["Crypto", "Crypto.Hash", "Crypto.Cipher", "Crypto.Util",
                  "Crypto.Protocol", "Crypto.PublicKey"],
      'package_dir' : { "Crypto":"." },
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
        kw['download_url'] = ('http://www.amk.ca/files/python/'
                              '%s-%s.tar.gz' % (kw['name'], kw['version']) )

core.setup(**kw)

