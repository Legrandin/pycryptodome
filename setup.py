#! /usr/bin/env python
#
#  setup.py : Distutils setup script
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
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

import os
import sys
import sysconfig

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

sys.path.append(os.getcwd())

from compiler_opt import set_compiler_options


class PCTBuildExt(build_ext):
    # Avoid linking Python's dynamic library
    def get_libraries(self, ext):
        return []


ext_modules = [
    # Hash functions
    Extension("Crypto.Hash._MD2", include_dirs=["src/"], sources=["src/MD2.c"], py_limited_api=True),
    Extension("Crypto.Hash._MD4", include_dirs=["src/"], sources=["src/MD4.c"], py_limited_api=True),
    Extension("Crypto.Hash._MD5", include_dirs=["src/"], sources=["src/MD5.c"], py_limited_api=True),
    Extension("Crypto.Hash._SHA1", include_dirs=["src/"], sources=["src/SHA1.c"], py_limited_api=True),
    Extension("Crypto.Hash._SHA256", include_dirs=["src/"], sources=["src/SHA256.c"], py_limited_api=True),
    Extension(
        "Crypto.Hash._SHA224_shani",
        include_dirs=["src/"],
        sources=["src/SHA224_shani.c"],
        py_limited_api=True,
    ),
    Extension(
        "Crypto.Hash._SHA256_shani",
        include_dirs=["src/"],
        sources=["src/SHA256_shani.c"],
        py_limited_api=True,
    ),
    Extension("Crypto.Hash._SHA224", include_dirs=["src/"], sources=["src/SHA224.c"], py_limited_api=True),
    Extension("Crypto.Hash._SHA384", include_dirs=["src/"], sources=["src/SHA384.c"], py_limited_api=True),
    Extension("Crypto.Hash._SHA512", include_dirs=["src/"], sources=["src/SHA512.c"], py_limited_api=True),
    Extension(
        "Crypto.Hash._RIPEMD160", include_dirs=["src/"], sources=["src/RIPEMD160.c"], py_limited_api=True
    ),
    Extension("Crypto.Hash._keccak", include_dirs=["src/"], sources=["src/keccak.c"], py_limited_api=True),
    Extension("Crypto.Hash._k12", include_dirs=["src/"], sources=["src/k12.c"], py_limited_api=True),
    Extension(
        "Crypto.Hash._keccak_avx2_bmi2",
        include_dirs=["src/"],
        sources=["src/keccak_avx2_bmi2.c"],
        py_limited_api=True,
    ),
    Extension(
        "Crypto.Hash._k12_avx2_bmi2",
        include_dirs=["src/"],
        sources=["src/k12_avx2_bmi2.c"],
        py_limited_api=True,
    ),
    Extension("Crypto.Hash._BLAKE2b", include_dirs=["src/"], sources=["src/blake2b.c"], py_limited_api=True),
    Extension("Crypto.Hash._BLAKE2s", include_dirs=["src/"], sources=["src/blake2s.c"], py_limited_api=True),
    Extension(
        "Crypto.Hash._ghash_portable",
        include_dirs=["src/"],
        sources=["src/ghash_portable.c"],
        py_limited_api=True,
    ),
    Extension(
        "Crypto.Hash._ghash_clmul", include_dirs=["src/"], sources=["src/ghash_clmul.c"], py_limited_api=True
    ),
    # MACs
    Extension(
        "Crypto.Hash._poly1305", include_dirs=["src/"], sources=["src/poly1305.c"], py_limited_api=True
    ),
    # Block encryption algorithms
    Extension("Crypto.Cipher._raw_aes", include_dirs=["src/"], sources=["src/AES.c"], py_limited_api=True),
    Extension(
        "Crypto.Cipher._raw_aesni", include_dirs=["src/"], sources=["src/AESNI.c"], py_limited_api=True
    ),
    Extension("Crypto.Cipher._raw_arc2", include_dirs=["src/"], sources=["src/ARC2.c"], py_limited_api=True),
    Extension(
        "Crypto.Cipher._raw_blowfish", include_dirs=["src/"], sources=["src/blowfish.c"], py_limited_api=True
    ),
    Extension(
        "Crypto.Cipher._raw_eksblowfish",
        include_dirs=["src/"],
        sources=["src/blowfish_eks.c"],
        py_limited_api=True,
    ),
    Extension("Crypto.Cipher._raw_cast", include_dirs=["src/"], sources=["src/CAST.c"], py_limited_api=True),
    Extension(
        "Crypto.Cipher._raw_des",
        include_dirs=["src/", "src/libtom/"],
        sources=["src/DES.c"],
        py_limited_api=True,
    ),
    Extension(
        "Crypto.Cipher._raw_des3",
        include_dirs=["src/", "src/libtom/"],
        sources=["src/DES3.c"],
        py_limited_api=True,
    ),
    Extension("Crypto.Util._cpuid_c", include_dirs=["src/"], sources=["src/cpuid.c"], py_limited_api=True),
    Extension(
        "Crypto.Cipher._pkcs1_decode",
        include_dirs=["src/"],
        sources=["src/pkcs1_decode.c"],
        py_limited_api=True,
    ),
    # Chaining modes
    Extension(
        "Crypto.Cipher._raw_ecb", include_dirs=["src/"], sources=["src/raw_ecb.c"], py_limited_api=True
    ),
    Extension(
        "Crypto.Cipher._raw_cbc", include_dirs=["src/"], sources=["src/raw_cbc.c"], py_limited_api=True
    ),
    Extension(
        "Crypto.Cipher._raw_cfb", include_dirs=["src/"], sources=["src/raw_cfb.c"], py_limited_api=True
    ),
    Extension(
        "Crypto.Cipher._raw_ofb", include_dirs=["src/"], sources=["src/raw_ofb.c"], py_limited_api=True
    ),
    Extension(
        "Crypto.Cipher._raw_ctr", include_dirs=["src/"], sources=["src/raw_ctr.c"], py_limited_api=True
    ),
    Extension("Crypto.Cipher._raw_ocb", sources=["src/raw_ocb.c"], py_limited_api=True),
    # Stream ciphers
    Extension("Crypto.Cipher._ARC4", include_dirs=["src/"], sources=["src/ARC4.c"], py_limited_api=True),
    Extension(
        "Crypto.Cipher._Salsa20",
        include_dirs=["src/", "src/libtom/"],
        sources=["src/Salsa20.c"],
        py_limited_api=True,
    ),
    Extension(
        "Crypto.Cipher._chacha20", include_dirs=["src/"], sources=["src/chacha20.c"], py_limited_api=True
    ),
    # Others
    Extension(
        "Crypto.Protocol._scrypt", include_dirs=["src/"], sources=["src/scrypt.c"], py_limited_api=True
    ),
    # Utility modules
    Extension("Crypto.Util._strxor", include_dirs=["src/"], sources=["src/strxor.c"], py_limited_api=True),
    # ECC
    Extension(
        "Crypto.PublicKey._ec_ws",
        include_dirs=["src/"],
        sources=["src/ec_ws.c", "src/mont.c", "src/p256_table.c", "src/p384_table.c", "src/p521_table.c"],
        py_limited_api=True,
    ),
    Extension(
        "Crypto.PublicKey._curve25519",
        include_dirs=["src/"],
        sources=["src/curve25519.c"],
        py_limited_api=True,
    ),
    Extension(
        "Crypto.PublicKey._curve448",
        include_dirs=["src/"],
        sources=["src/curve448.c", "src/mont1.c"],
        py_limited_api=True,
    ),
    Extension(
        "Crypto.PublicKey._ed25519",
        include_dirs=["src/"],
        sources=["src/ed25519.c"],
        py_limited_api=True,
    ),
    Extension(
        "Crypto.PublicKey._ed448",
        include_dirs=["src/"],
        sources=["src/ed448.c", "src/mont2.c"],
        py_limited_api=True,
    ),
    # Math
    Extension(
        "Crypto.Math._modexp",
        include_dirs=["src/"],
        sources=["src/modexp.c", "src/mont3.c"],
        py_limited_api=True,
    ),
    Extension(
        "Crypto.Math._nat",
        include_dirs=["src/"],
        sources=["src/nat.c", "src/nat_div.c", "src/nat_mod.c", "src/nat_gcd.c", "src/nat_prime.c"],
        py_limited_api=True,
    ),
    # The same, for x86-64 CPUs with BMI2 and ADX (removed if the compiler cannot build it)
    Extension(
        "Crypto.Math._nat_bmi2_adx",
        include_dirs=["src/"],
        sources=["src/nat_bmi2_adx.c"],
        py_limited_api=True,
    ),
]

# Add compiler specific options.
set_compiler_options(ext_modules)

# Set the minimum ABI3 version for bdist_wheel to 3.9
# unless Python is running without GIL (as there is no established way yet to
# specify multiple ABI levels)
setup_options = {}
if not sysconfig.get_config_var("Py_GIL_DISABLED"):
    setup_options["options"] = {"bdist_wheel": {"py_limited_api": "cp39"}}

setup(
    cmdclass={"build_ext": PCTBuildExt},
    ext_modules=ext_modules,
    **setup_options,
)
