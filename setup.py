#! /usr/bin/env python
from distutils.core import setup, Extension

setup(name="amkCrypto",
      version="1.9a1",
      description="Cryptographic modules for Python.",
      author="A.M. Kuchling",
      author_email="akuchlin@mems-exchange.org",
      url="http://pycrypto.sourceforge.net",
      
      packages = ["Crypto", "Crypto.Hash", "Crypto.Cipher", "Crypto.Util",
                  "Crypto.PublicKey"],
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
                     Extension("Crypto.Cipher.DES",
                               include_dirs=['src/'],
                               sources=["block/DES.c"]),
                    ]
     )

      

