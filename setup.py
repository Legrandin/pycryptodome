#! /usr/bin/env python

__revision__ = "$Id: setup.py,v 1.19 2002-11-21 01:23:15 z3p Exp $"

from distutils.core import setup, Extension
import sys

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
    
setup(name="pycrypto",
      version="1.9a5",
      description="Cryptographic modules for Python.",
      author="A.M. Kuchling",
      author_email="akuchlin@mems-exchange.org",
      url="http://pycrypto.sourceforge.net",
      
      packages = ["Crypto", "Crypto.Hash", "Crypto.Cipher", "Crypto.Util",
                  "Crypto.Protocol", "Crypto.PublicKey"],
      package_dir = { "Crypto":"." },
      ext_modules = [
                     # Hash functions
                     Extension("Crypto.Hash.MD2",
                               include_dirs=['src/'],
                               sources=["src/MD2.c"]),
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
                    
                     # Public Key crypto
                     Extension("Crypto.PublicKey._rsa",
                               include_dirs=['src/'],
                               libraries=['gmp'],
                               extra_compile_args=['-pedantic'],
                               sources=["src/_rsa.c"]),
                     Extension("Crypto.PublicKey._dsa",
                               include_dirs=['src/'],
                               libraries=['gmp'],
                               extra_compile_args=['-pedantic'],
                               sources=["src/_dsa.c"]),
                     
                    ] + plat_ext
     )

      

