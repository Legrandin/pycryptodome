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
from distutils.errors import CCompilerError
from distutils import ccompiler
import distutils
import re
import os
import sys
import shutil
import struct
if sys.version_info[0:2] == (2, 6):
    from distutils import sysconfig
else:
    import sysconfig

# Monkey patch for https://bugs.python.org/issue34108
if sys.version_info[0:3] == (3, 7, 0) and os.name == 'nt':
    import io
    from lib2to3.refactor import RefactoringTool

    def new_write_file(self, new_text, filename, old_text, encoding=None):
        fp = io.open(filename, "w", encoding=encoding, newline='')
        fp.write(new_text)
        self.wrote = True
    RefactoringTool.write_file = new_write_file

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

try:
    # Python 3
    from distutils.command.build_py import build_py_2to3 as build_py
except ImportError:
    # Python 2
    from distutils.command.build_py import build_py


def test_compilation(program, extra_cc_options=None, extra_libraries=None, msg=''):
    """Test if a certain C program can be compiled."""

    # Create a temporary file with the C program
    if not os.path.exists("build"):
        os.makedirs("build")
    fname = os.path.join("build", "test1.c")
    f = open(fname, 'w')
    f.write(program)
    f.close()

    # Name for the temporary executable
    oname = os.path.join("build", "test1.out")

    debug = False
    # Mute the compiler and the linker
    if msg:
        print("Testing support for %s" % msg)
    if not (debug or os.name == 'nt'):
        old_stdout = os.dup(sys.stdout.fileno())
        old_stderr = os.dup(sys.stderr.fileno())
        dev_null = open(os.devnull, "w")
        os.dup2(dev_null.fileno(), sys.stdout.fileno())
        os.dup2(dev_null.fileno(), sys.stderr.fileno())

    objects = []
    try:
        compiler = ccompiler.new_compiler()
        distutils.sysconfig.customize_compiler(compiler)

        if compiler.compiler_type in [ 'msvc' ]:
            # Force creation of the manifest file (http://bugs.python.org/issue16296)
            # as needed by VS2010
            extra_linker_options = [ "/MANIFEST" ]
        else:
            extra_linker_options = []

        # In Unix, force the linker step to use CFLAGS and not CC alone (see GH#180)
        if compiler.compiler_type in [ 'unix' ]:
            compiler.set_executables(linker_exe=compiler.compiler)

        objects = compiler.compile([fname], extra_postargs=extra_cc_options)
        compiler.link_executable(objects, oname, libraries=extra_libraries, extra_preargs=extra_linker_options)
        result = True
    except CCompilerError:
        result = False
    for f in objects + [fname, oname]:
        try:
            os.remove(f)
        except OSError:
            pass

    # Restore stdout and stderr
    if not (debug or os.name=='nt'):
        if old_stdout is not None:
            os.dup2(old_stdout, sys.stdout.fileno())
        if old_stderr is not None:
            os.dup2(old_stderr, sys.stderr.fileno())
        if dev_null is not None:
            dev_null.close()
    if msg:
        if result:
            x = ""
        else:
            x = " not"
        print("Target does%s support %s" % (x, msg))

    return result


class PCTBuildExt (build_ext):

    # Avoid linking Python's dynamic library
    def get_libraries(self, ext):
        return []

    def build_extensions(self):
        # Disable any assembly in libtomcrypt files
        self.compiler.define_macro("LTC_NO_ASM")

        # Detect which modules should be compiled
        self.detect_modules()

        # Call the superclass's build_extensions method
        build_ext.build_extensions(self)

    def compiler_supports_uint128(self):
        source = """
        int main(void)
        {
            __uint128_t x;
            return 0;
        }
        """
        return test_compilation(source, msg="128-bit integer")

    def compiler_has_intrin_h(self):
        # Windows
        source = """
        #include <intrin.h>
        int main(void)
        {
            int a, b[4];
            __cpuid(b, a);
            return 0;
        }
        """
        return test_compilation(source, msg="intrin.h header")

    def compiler_has_cpuid_h(self):
        # UNIX
        source = """
        #include <cpuid.h>
        int main(void)
        {
            unsigned int eax, ebx, ecx, edx;
            __get_cpuid(1, &eax, &ebx, &ecx, &edx);
            return 0;
        }
        """
        return test_compilation(source, msg="cpuid.h header")

    def compiler_supports_aesni(self):
        source = """
        #include <wmmintrin.h>
        __m128i f(__m128i x, __m128i y) {
            return _mm_aesenc_si128(x, y);
        }
        int main(void) {
            return 0;
        }
        """

        if test_compilation(source):
            return {'extra_options':[]}

        if test_compilation(source, extra_cc_options=['-maes'], msg='AESNI intrinsics'):
            return {'extra_options':['-maes']}

        return False

    def compiler_supports_clmul(self):
        source = """
        #include <wmmintrin.h>
        __m128i f(__m128i x, __m128i y) {
            return _mm_clmulepi64_si128(x, y, 0x00);
        }
        int main(void) {
            return 0;
        }
        """

        if test_compilation(source):
            return {'extra_options':[]}

        if test_compilation(source, extra_cc_options=['-mpclmul','-mssse3'], msg='CLMUL intrinsics'):
            return {'extra_options':['-mpclmul', '-mssse3']}

        return False

    def compiler_has_posix_memalign(self):
        source = """
        #include <stdlib.h>
        int main(void) {
            void *new_mem;
            posix_memalign((void**)&new_mem, 16, 101);
            return 0;
        }
        """
        return test_compilation(source, msg="posix_memalign")

    def compiler_has_memalign(self):
        source = """
        #include <malloc.h>
        int main(void) {
            void *p;
            p = memalign(16, 101);
            return 0;
        }
        """
        return test_compilation(source, msg="memalign")

    def detect_modules (self):

        if self.compiler_supports_uint128():
            self.compiler.define_macro("HAVE_UINT128")

        intrin_h_present = self.compiler_has_intrin_h()
        if intrin_h_present:
            self.compiler.define_macro("HAVE_INTRIN_H")

        cpuid_h_present = self.compiler_has_cpuid_h()
        if cpuid_h_present:
            self.compiler.define_macro("HAVE_CPUID_H")

        if self.compiler_has_posix_memalign():
            self.compiler.define_macro("HAVE_POSIX_MEMALIGN")
        elif self.compiler_has_memalign():
            self.compiler.define_macro("HAVE_MEMALIGN")

        # AESNI
        aesni_result = (cpuid_h_present or intrin_h_present) and self.compiler_supports_aesni()
        aesni_mod_name = package_root + ".Cipher._raw_aesni"
        if aesni_result:
            print("Compiling support for AESNI instructions")
            aes_mods = [ x for x in self.extensions if x.name == aesni_mod_name ]
            for x in aes_mods:
                x.extra_compile_args += aesni_result['extra_options']
        else:
            print ("Warning: compiler does not support AESNI instructions")
            self.remove_extension(aesni_mod_name)

        # CLMUL
        clmul_result = (cpuid_h_present or intrin_h_present) and self.compiler_supports_clmul()
        clmul_mod_name = package_root + ".Hash._ghash_clmul"
        if clmul_result:
            print("Compiling support for CLMUL instructions")
            clmul_mods = [ x for x in self.extensions if x.name == clmul_mod_name ]
            for x in clmul_mods:
                x.extra_compile_args += clmul_result['extra_options']
        else:
            print ("Warning: compiler does not support CLMUL instructions")
            self.remove_extension(clmul_mod_name)

    def remove_extension(self, name):
        """Remove the specified extension from the list of extensions
        to build"""

        self.extensions = [ x for x in self.extensions if x.name != name ]


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

    description = "Run self-test"

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
        self.config = { 'slow_tests': not self.skip_slow_tests,
                        'wycheproof_warnings': self.wycheproof_warnings }

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
                if self.module.count('.')==0:
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
                moduleObj = __import__( full_module, globals(), locals(), module_name )

            print(package_root + ".Math implementation:",
                     str(Numbers._implementation))

            SelfTest.run(module=moduleObj, verbosity=self.verbose, stream=sys.stdout, config=self.config)
        finally:
            # Restore sys.path
            sys.path[:] = old_path

        # Run slower self-tests
        self.announce("running extended self-tests")

    sub_commands = [ ('build', None) ]


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

            if not full_file_name_dst.endswith(".py"):
                continue

            fd = open(full_file_name_dst, "rt")
            content = (fd.read().
               replace("Crypto.", "Cryptodome.").
               replace("Crypto ", "Cryptodome ").
               replace("'Crypto'", "'Cryptodome'").
               replace('"Crypto"', '"Cryptodome"'))
            fd.close()
            os.remove(full_file_name_dst)
            fd = open(full_file_name_dst, "wt")
            fd.write(content)
            fd.close()


def compiler_supports_sse2():
    source = """
    #include <x86intrin.h>
    int main(void)
    {
        __m128i r0;
        r0 = _mm_set1_epi32(0);
        return 0;
    }
    """
    return test_compilation(source, extra_cc_options=['-msse2'], msg="x86intrin.h header")

def enable_compiler_specific_options(extensions):

    def check_compiler(compiler):
        result = compiler in os.environ.get('CC', '')
        builtin = sysconfig.get_config_vars('CC')[0]
        result = result or (builtin and compiler in builtin)
        return result

    clang = check_compiler("clang")
    gcc = check_compiler("gcc")

    if clang or gcc:
        sse2 = compiler_supports_sse2()
        for x in extensions:
            x.extra_compile_args += ['-O3']
            if sse2:
                x.extra_compile_args += ['-msse2']
                x.define_macros += [ ("HAVE_X86INTRIN_H", None) ]

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
package_dir = { "Crypto": "lib/Crypto" }
package_data = {
    "Crypto.SelfTest.Cipher" : [
        "test_vectors/AES/*.rsp",
        "test_vectors/TDES/*.rsp",
        "test_vectors/wycheproof/*.json",
    ],
    "Crypto.SelfTest.Hash" : [
        "test_vectors/SHA1/*.rsp",
        "test_vectors/SHA2/*.rsp",
        "test_vectors/SHA3/*.txt",
        "test_vectors/keccak/*.txt",
        "test_vectors/BLAKE2s/*.txt",
        "test_vectors/BLAKE2b/*.txt",
        "test_vectors/wycheproof/*.json",
    ],
    "Crypto.SelfTest.Signature" : [
        "test_vectors/DSA/*.*",
        "test_vectors/ECDSA/*.*",
        "test_vectors/PKCS1-v1.5/*.*",
        "test_vectors/PKCS1-PSS/*.*",
        "test_vectors/wycheproof/*.json",
    ],
    "Crypto.SelfTest.PublicKey" : [
        "test_vectors/ECC/*.*",
    ],
}

system_bits = 8 * struct.calcsize("P")
if system_bits == 32:
    multiply_cmod = [ 'src/multiply_32.c' ]
else:
    multiply_cmod = [ 'src/multiply_64.c' ]

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
        include_dirs=['src/'],
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

    # Math
    Extension("Crypto.Math._montgomery",
        include_dirs=['src/'],
        sources=['src/montgomery.c', 'src/siphash.c', 'src/montgomery_utils.c'] + multiply_cmod,
        ),
]

# Enable some optimization if we know the compiler
enable_compiler_specific_options(ext_modules)

# Define big/little endian flag
for x in ext_modules:
    x.define_macros += [ ("PYCRYPTO_" + sys.byteorder.upper() + "_ENDIAN", None) ]

if use_separate_namespace:

    # Fix-up setup information
    for i in range(len(packages)):
        packages[i] = packages[i].replace("Crypto", "Cryptodome")
    package_dir = { "Cryptodome": "lib/Cryptodome" }
    new_package_data = {}
    for k,v in package_data.items():
        new_package_data[k.replace("Crypto", "Cryptodome")] = v
    package_data = new_package_data
    for ext in ext_modules:
        ext.name = ext.name.replace("Crypto", "Cryptodome")

    # Recreate lib/Cryptodome from scratch, unless it is the only
    # directory available
    if os.path.isdir("lib/Crypto"):
        create_cryptodome_lib()


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
        'Development Status :: 4 - Beta',
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
    packages=packages,
    package_dir=package_dir,
    package_data=package_data,
    cmdclass={
        'build_ext':PCTBuildExt,
        'build_py': PCTBuildPy,
        'test': TestCommand,
        },
    ext_modules=ext_modules,
)
