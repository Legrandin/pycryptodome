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

from __future__ import print_function

try:
    from setuptools import Extension, Command, setup
except ImportError:
    from distutils.core import Extension, Command, setup
from distutils.command.build_ext import build_ext
from distutils.command.build_py import build_py
import re
import os
import sys
import shutil
import struct

from compiler_opt import set_compiler_options


use_separate_namespace = os.path.isfile(".separate_namespace")

project_name = "pycryptodome"
package_root = "Crypto"
other_project = "pycryptodomex"
other_root = "Cryptodome"

if use_separate_namespace:
    project_name, other_project = other_project, project_name
    package_root, other_root = other_root, package_root

longdesc = """
PyCryptodome
============

PyCryptodome is a self-contained Python package of low-level
cryptographic primitives.

It supports Python 2.6 and 2.7, Python 3.4 and newer, and PyPy.

You can install it with::

    pip install THIS_PROJECT

All modules are installed under the ``THIS_ROOT`` package.

Check the OTHER_PROJECT_ project for the equivalent library that
works under the ``OTHER_ROOT`` package.

PyCryptodome is a fork of PyCrypto. It brings several enhancements
with respect to the last official version of PyCrypto (2.6.1),
for instance:

* Authenticated encryption modes (GCM, CCM, EAX, SIV, OCB)
* Accelerated AES on Intel platforms via AES-NI
* First class support for PyPy
* Elliptic curves cryptography (NIST P-256 curve only)
* Better and more compact API (`nonce` and `iv` attributes for ciphers,
  automatic generation of random nonces and IVs, simplified CTR cipher mode,
  and more)
* SHA-3 (including SHAKE XOFs) and BLAKE2 hash algorithms
* Salsa20 and ChaCha20 stream ciphers
* scrypt and HKDF
* Deterministic (EC)DSA
* Password-protected PKCS#8 key containers
* Shamir's Secret Sharing scheme
* Random numbers get sourced directly from the OS (and not from a CSPRNG in userspace)
* Simplified install process, including better support for Windows
* Cleaner RSA and DSA key generation (largely based on FIPS 186-4)
* Major clean ups and simplification of the code base

PyCryptodome is not a wrapper to a separate C library like *OpenSSL*.
To the largest possible extent, algorithms are implemented in pure Python.
Only the pieces that are extremely critical to performance (e.g. block ciphers)
are implemented as C extensions.

For more information, see the `homepage`_.

All the code can be downloaded from `GitHub`_.

.. _OTHER_PROJECT: https://pypi.python.org/pypi/OTHER_PROJECT
.. _`homepage`: http://www.pycryptodome.org
.. _GitHub: https://github.com/Legrandin/pycryptodome
""".replace("THIS_PROJECT", project_name).\
    replace("THIS_ROOT", package_root).\
    replace("OTHER_PROJECT", other_project).\
    replace("OTHER_ROOT", other_root)


class PCTBuildExt (build_ext):

    # Avoid linking Python's dynamic library
    def get_libraries(self, ext):
        return []


class PCTBuildPy(build_py):
    def find_package_modules(self, package, package_dir, *args, **kwargs):
        modules = build_py.find_package_modules(self, package, package_dir,
                                                *args, **kwargs)

        # Exclude certain modules
        retval = []
        for item in modules:
            pkg, module = item[:2]
            retval.append(item)
        return retval


class TestCommand(Command):
    "Run self-test"

    # Long option name, short option name, description
    user_options = [
        ('skip-slow-tests', None, 'Skip slow tests'),
        ('wycheproof-warnings', None, 'Show warnings from wycheproof tests'),
        ('module=', 'm', 'Test a single module (e.g. Cipher, PublicKey)'),
    ]

    def initialize_options(self):
        self.build_dir = None
        self.skip_slow_tests = None
        self.wycheproof_warnings = None
        self.module = None

    def finalize_options(self):
        self.set_undefined_options('install', ('build_lib', 'build_dir'))
        self.config = {'slow_tests': not self.skip_slow_tests,
                       'wycheproof_warnings': self.wycheproof_warnings}

    def run(self):
        # Run sub commands
        for cmd_name in self.get_sub_commands():
            self.run_command(cmd_name)

        # Run SelfTest
        old_path = sys.path[:]
        self.announce("running self-tests on " + package_root)
        try:
            sys.path.insert(0, self.build_dir)

            if use_separate_namespace:
                from Cryptodome import SelfTest
                from Cryptodome.Math import Numbers
            else:
                from Crypto import SelfTest
                from Crypto.Math import Numbers

            moduleObj = None
            if self.module:
                if self.module.count('.') == 0:
                    # Test a whole a sub-package
                    full_module = package_root + ".SelfTest." + self.module
                    module_name = self.module
                else:
                    # Test only a module
                    # Assume only one dot is present
                    comps = self.module.split('.')
                    module_name = "test_" + comps[1]
                    full_module = package_root + ".SelfTest." + comps[0] + "." + module_name
                # Import sub-package or module
                moduleObj = __import__(full_module, globals(), locals(), module_name)

            print(package_root + ".Math implementation:",
                     str(Numbers._implementation))

            SelfTest.run(module=moduleObj, verbosity=self.verbose, stream=sys.stdout, config=self.config)
        finally:
            # Restore sys.path
            sys.path[:] = old_path

        # Run slower self-tests
        self.announce("running extended self-tests")

    sub_commands = [('build', None)]


def create_cryptodome_lib():
    assert os.path.isdir("lib/Crypto")

    try:
        shutil.rmtree("lib/Cryptodome")
    except OSError:
        pass
    for root_src, dirs, files in os.walk("lib/Crypto"):

        root_dst, nr_repl = re.subn('Crypto', 'Cryptodome', root_src)
        assert nr_repl == 1

        for dir_name in dirs:
            full_dir_name_dst = os.path.join(root_dst, dir_name)
            if not os.path.exists(full_dir_name_dst):
                os.makedirs(full_dir_name_dst)

        for file_name in files:
            full_file_name_src = os.path.join(root_src, file_name)
            full_file_name_dst = os.path.join(root_dst, file_name)

            print("Copying file %s to %s" % (full_file_name_src, full_file_name_dst))
            shutil.copy2(full_file_name_src, full_file_name_dst)

            if full_file_name_src.split(".")[-1] not in ("py", "pyi"):
                if full_file_name_src != "py.typed":
                    continue

            with open(full_file_name_dst, "rt") as fd:
                content = (fd.read().
                           replace("Crypto.", "Cryptodome.").
                           replace("Crypto ", "Cryptodome ").
                           replace("'Crypto'", "'Cryptodome'").
                           replace('"Crypto"', '"Cryptodome"'))
            os.remove(full_file_name_dst)
            with open(full_file_name_dst, "wt") as fd:
                fd.write(content)


# Parameters for setup
packages =  [
    "Crypto",
    "Crypto.Cipher",
    "Crypto.Hash",
    "Crypto.IO",
    "Crypto.PublicKey",
    "Crypto.Protocol",
    "Crypto.Random",
    "Crypto.Signature",
    "Crypto.Util",
    "Crypto.Math",
    "Crypto.SelfTest",
    "Crypto.SelfTest.Cipher",
    "Crypto.SelfTest.Hash",
    "Crypto.SelfTest.IO",
    "Crypto.SelfTest.Protocol",
    "Crypto.SelfTest.PublicKey",
    "Crypto.SelfTest.Random",
    "Crypto.SelfTest.Signature",
    "Crypto.SelfTest.Util",
    "Crypto.SelfTest.Math",
]
package_dir = {"Crypto": "lib/Crypto"}
package_data = {
    "Crypto" : [ "py.typed", "*.pyi" ],
    "Crypto.Cipher" : [ "*.pyi" ],
    "Crypto.Hash" : [ "*.pyi" ],
    "Crypto.Math" : [ "*.pyi" ],
    "Crypto.Protocol" : [ "*.pyi" ],
    "Crypto.PublicKey" : [ "*.pyi" ],
    "Crypto.Random" : [ "*.pyi" ],
    "Crypto.Signature" : [ "*.pyi" ],
    "Crypto.IO" : [ "*.pyi" ],
    "Crypto.Util" : [ "*.pyi" ],
    "Crypto.SelfTest.Cipher" : [
        "test_vectors/AES/*.*",
        "test_vectors/TDES/*.*",
        "test_vectors/wycheproof/*.*",
    ],
    "Crypto.SelfTest.Hash" : [
        "test_vectors/SHA1/*.*",
        "test_vectors/SHA2/*.*",
        "test_vectors/SHA3/*.*",
        "test_vectors/keccak/*.*",
        "test_vectors/BLAKE2s/*.*",
        "test_vectors/BLAKE2b/*.*",
        "test_vectors/wycheproof/*.*",
    ],
    "Crypto.SelfTest.Signature" : [
        "test_vectors/DSA/*.*",
        "test_vectors/ECDSA/*.*",
        "test_vectors/PKCS1-v1.5/*.*",
        "test_vectors/PKCS1-PSS/*.*",
        "test_vectors/wycheproof/*.*",
    ],
    "Crypto.SelfTest.PublicKey" : [
        "test_vectors/ECC/*.*",
    ],
}

ext_modules = [
    # Hash functions
    Extension("Crypto.Hash._MD2",
        include_dirs=['src/'],
        sources=["src/MD2.c"]),
    Extension("Crypto.Hash._MD4",
        include_dirs=['src/'],
        sources=["src/MD4.c"]),
    Extension("Crypto.Hash._MD5",
        include_dirs=['src/'],
        sources=["src/MD5.c"]),
    Extension("Crypto.Hash._SHA1",
        include_dirs=['src/'],
        sources=["src/SHA1.c"]),
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
        sources=["src/RIPEMD160.c"]),
    Extension("Crypto.Hash._keccak",
        include_dirs=['src/'],
        sources=["src/keccak.c"]),
    Extension("Crypto.Hash._BLAKE2b",
        include_dirs=['src/'],
        sources=["src/blake2b.c"]),
    Extension("Crypto.Hash._BLAKE2s",
        include_dirs=['src/'],
        sources=["src/blake2s.c"]),
    Extension("Crypto.Hash._ghash_portable",
        include_dirs=['src/'],
        sources=['src/ghash_portable.c']),
    Extension("Crypto.Hash._ghash_clmul",
        include_dirs=['src/'],
        sources=['src/ghash_clmul.c']),

    # MACs
    Extension("Crypto.Hash._poly1305",
        include_dirs=['src/'],
        sources=["src/poly1305.c"]),

    # Block encryption algorithms
    Extension("Crypto.Cipher._raw_aes",
        include_dirs=['src/'],
        sources=["src/AES.c"]),
    Extension("Crypto.Cipher._raw_aesni",
        include_dirs=['src/'],
        sources=["src/AESNI.c"]),
    Extension("Crypto.Cipher._raw_arc2",
        include_dirs=['src/'],
        sources=["src/ARC2.c"]),
    Extension("Crypto.Cipher._raw_blowfish",
        include_dirs=['src/'],
        sources=["src/Blowfish.c"]),
    Extension("Crypto.Cipher._raw_cast",
        include_dirs=['src/'],
        sources=["src/CAST.c"]),
    Extension("Crypto.Cipher._raw_des",
        include_dirs=['src/', 'src/libtom/'],
        sources=["src/DES.c"]),
    Extension("Crypto.Cipher._raw_des3",
        include_dirs=['src/', 'src/libtom/'],
        sources=["src/DES3.c"]),
    Extension("Crypto.Util._cpuid_c",
        include_dirs=['src/'],
        sources=['src/cpuid.c']),

    # Chaining modes
    Extension("Crypto.Cipher._raw_ecb",
        include_dirs=['src/'],
        sources=["src/raw_ecb.c"]),
    Extension("Crypto.Cipher._raw_cbc",
        include_dirs=['src/'],
        sources=["src/raw_cbc.c"]),
    Extension("Crypto.Cipher._raw_cfb",
        include_dirs=['src/'],
        sources=["src/raw_cfb.c"]),
    Extension("Crypto.Cipher._raw_ofb",
        include_dirs=['src/'],
        sources=["src/raw_ofb.c"]),
    Extension("Crypto.Cipher._raw_ctr",
        include_dirs=['src/'],
        sources=["src/raw_ctr.c"]),
    Extension("Crypto.Cipher._raw_ocb",
        sources=["src/raw_ocb.c"]),

    # Stream ciphers
    Extension("Crypto.Cipher._ARC4",
        include_dirs=['src/'],
        sources=["src/ARC4.c"]),
    Extension("Crypto.Cipher._Salsa20",
        include_dirs=['src/', 'src/libtom/'],
        sources=["src/Salsa20.c"]),
    Extension("Crypto.Cipher._chacha20",
        include_dirs=['src/'],
        sources=["src/chacha20.c"]),

    # Others
    Extension("Crypto.Protocol._scrypt",
        include_dirs=['src/'],
        sources=["src/scrypt.c"]),

    # Utility modules
    Extension("Crypto.Util._strxor",
        include_dirs=['src/'],
        sources=['src/strxor.c']),

    # ECC
    Extension("Crypto.PublicKey._ec_ws",
        include_dirs=['src/'],
        sources=['src/modexp_utils.c', 'src/siphash.c', 'src/ec_ws.c', 'src/mont.c'],
        ),

    # Math
    Extension("Crypto.Math._modexp",
        include_dirs=['src/'],
        sources=['src/modexp.c', 'src/siphash.c', 'src/modexp_utils.c', 'src/mont.c'],
        ),
]

if use_separate_namespace:

    # Fix-up setup information
    for i in range(len(packages)):
        packages[i] = packages[i].replace("Crypto", "Cryptodome")
    package_dir = {"Cryptodome": "lib/Cryptodome"}
    new_package_data = {}
    for k, v in package_data.items():
        new_package_data[k.replace("Crypto", "Cryptodome")] = v
    package_data = new_package_data
    for ext in ext_modules:
        ext.name = ext.name.replace("Crypto", "Cryptodome")

    # Recreate lib/Cryptodome from scratch, unless it is the only
    # directory available
    if os.path.isdir("lib/Crypto"):
        create_cryptodome_lib()

# Add compiler specific options.
set_compiler_options(package_root, ext_modules)

# By doing this we need to change version information in a single file
with open(os.path.join("lib", package_root, "__init__.py")) as init_root:
    for line in init_root:
        if line.startswith("version_info"):
            version_tuple = eval(line.split("=")[1])

version_string = ".".join([str(x) for x in version_tuple])

setup(
    name=project_name,
    version=version_string,
    description="Cryptographic library for Python",
    long_description=longdesc,
    author="Helder Eijs",
    author_email="helderijs@gmail.com",
    url="https://www.pycryptodome.org",
    platforms='Posix; MacOS X; Windows',
    zip_safe=False,
    python_requires='>=2.6, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: BSD License',
        'License :: Public Domain',
        'Intended Audience :: Developers',
        'Operating System :: Unix',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    license="BSD, Public Domain",
    packages=packages,
    package_dir=package_dir,
    package_data=package_data,
    cmdclass={
        'build_ext': PCTBuildExt,
        'build_py': PCTBuildPy,
        'test': TestCommand,
        },
    ext_modules=ext_modules,
)
