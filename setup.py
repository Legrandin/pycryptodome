#! /usr/bin/env python
from distutils.core import setup, Extension

setup(name="pycrypto",
      version="1.9a3",
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
                               sources=["src/RIPEMD.c"]),

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
                               sources=["src/IDEA.c"]),
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
     )

      

