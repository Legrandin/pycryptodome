#! /usr/bin/env python
from distutils.core import setup, Extension

setup(name="pycrypto",
      version="1.9a1",
      description="Cryptographic modules for Python.",
      author="A.M. Kuchling",
      author_email="akuchlin@mems-exchange.org",
      url="http://pycrypto.sourceforge.net",
      
      packages = ["Crypto", "Crypto.Hash", "Crypto.Cipher", "Crypto.Util"],
      package_dir = { "Crypto":"." },
      ext_modules = [
                     # Hash functions
                     Extension("Crypto.Hash.MD2",
                               include_dirs=['src/'],
                               sources=["hash/MD2.c"]),
                     Extension("Crypto.Hash.MD4",
                               include_dirs=['src/'],
                               sources=["hash/MD4.c"]),
                     Extension("Crypto.Hash.RIPEMD",
                               include_dirs=['src/'],
                               sources=["hash/RIPEMD.c"]),

                     # Block encryption algorithms
                     Extension("Crypto.Cipher.AES",
                               include_dirs=['src/'],
                               sources=["block/AES.c"]),
                     Extension("Crypto.Cipher.ARC2",
                               include_dirs=['src/'],
                               sources=["block/ARC2.c"]),
                     Extension("Crypto.Cipher.Blowfish",
                               include_dirs=['src/'],
                               sources=["block/Blowfish.c"]),
                     Extension("Crypto.Cipher.CAST",
                               include_dirs=['src/'],
                               sources=["block/CAST.c"]),
                     Extension("Crypto.Cipher.DES",
                               include_dirs=['src/'],
                               sources=["block/DES.c"]),
                     Extension("Crypto.Cipher.DES3",
                               include_dirs=['src/'],
                               sources=["block/DES3.c"]),
                     Extension("Crypto.Cipher.IDEA",
                               include_dirs=['src/'],
                               sources=["block/IDEA.c"]),
                     Extension("Crypto.Cipher.RC5",
                               include_dirs=['src/'],
                               sources=["block/RC5.c"]),

                     # Stream ciphers
                     Extension("Crypto.Cipher.ARC4",
                               include_dirs=['src/'],
                               sources=["stream/ARC4.c"]),
                     Extension("Crypto.Cipher.XOR",
                               include_dirs=['src/'],
                               sources=["stream/XOR.c"]),
                     
                    ]
     )

      

