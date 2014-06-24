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

from distutils.core import Extension, Command, setup
from distutils.command.build_ext import build_ext
from distutils.errors import CCompilerError
import distutils
import os, sys

longdesc = open("README.rst").read()

# By doing this we neeed to change version information in a single file
for line in open(os.path.join("lib", "Crypto", "__init__.py")):
    if line.startswith("version_info"):
        version_tuple = eval(line.split("=")[1])

version_string = "%d.%d" % version_tuple[:-1]
if version_tuple[2] is not None:
    if str(version_tuple[2]).isdigit():
        version_string += "."
    version_string += str(version_tuple[2])

if sys.version[0:1] == '1':
    raise RuntimeError ("The Python Cryptography Toolkit requires "
                         "Python 2.x or 3.x to build.")

try:
    # Python 3
    from distutils.command.build_py import build_py_2to3 as build_py
except ImportError:
    # Python 2
    from distutils.command.build_py import build_py


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

def test_compilation(program, extra_cc_options=None, extra_libraries=None):
    """Test if a certain C program can be compiled."""

    import tempfile

    # Create a temporary file with the C program
    fname = tempfile.mktemp(".c")
    f = open(fname, 'w')
    f.write(program)
    f.close()

    # Name for the temporary executable
    oname = tempfile.mktemp(".out")

    debug = False
    # Mute the compiler and the linker
    if not debug:
        old_stdout = os.dup(sys.stdout.fileno())
        old_stderr = os.dup(sys.stderr.fileno())
        dev_null = open(os.devnull, "w")
        os.dup2(dev_null.fileno(), sys.stdout.fileno())
        os.dup2(dev_null.fileno(), sys.stderr.fileno())

    objects = []
    try:
        compiler = distutils.ccompiler.new_compiler()
        distutils.sysconfig.customize_compiler(compiler)
        objects = compiler.compile([fname], extra_postargs=extra_cc_options)
        compiler.link_executable(objects, oname, libraries=extra_libraries)
        result = True
    except CCompilerError:
        result = False
    for f in objects + [fname, oname]:
        try:
            os.remove(f)
        except OSError:
            pass

    # Restore stdout and stderr
    if not debug:
        if old_stdout is not None:
            os.dup2(old_stdout, sys.stdout.fileno())
        if old_stderr is not None:
            os.dup2(old_stderr, sys.stderr.fileno())
        if dev_null is not None:
            dev_null.close()

    return result


def libgmp_exists():
    '''Tests if the GMP library is available'''

    source = """
    #include <gmp.h>
    int main(void)
    {
        mpz_init((void*)0);
        return 0;
    }
    """

    return test_compilation(source, extra_libraries=('gmp',))


class PCTBuildExt (build_ext):
    def build_extensions(self):
        # Detect which modules should be compiled
        self.detect_modules()

        # Call the superclass's build_extensions method
        build_ext.build_extensions(self)

    def check_cpuid_h(self):
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
        if test_compilation(source):
            self.compiler.define_macro("HAVE_CPUID_H")
            return True
        else:
            return False

    def check_intrin_h(self):
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
        if test_compilation(source):
            self.compiler.define_macro("HAVE_INTRIN_H")
            return True
        else:
            return False

    def check_aesni(self):

        source = """
        #include <wmmintrin.h>
        __m128i f(__m128i x, __m128i y) {
            return _mm_aesenc_si128(x, y);
        }
        int main(void) {
            return 0;
        }
        """
        aesni = [ x for x in self.extensions if x.name == "Crypto.Cipher._AESNI" ][0]
        result = test_compilation(source)
        if not result:
            result = test_compilation(source, extra_cc_options=['-maes'])
            if result:
                aesni.extra_compile_args += ['-maes']
        return result

    def detect_modules (self):

        # Detect libgmp and don't build _fastmath if it is missing.
        if libgmp_exists():
            PrintErr("Compiling _fastmath using the GMP library")
        else:
            PrintErr ("warning: GMP library not found; Not building " +
                "Crypto.PublicKey._fastmath.")
            self.remove_extensions(["Crypto.PublicKey._fastmath"])

        # Detect compiler support for CPUID instruction and AESNI
        if (self.check_cpuid_h() or self.check_intrin_h()) and self.check_aesni():
            PrintErr("Compiling support for Intel AES instructions")
        else:
            PrintErr ("warning: no support for Intel AESNI instructions; Not building " +
                      "Crypto.Cipher._AESNI")
            self.remove_extensions(["Crypto.Cipher._AESNI"])

    def remove_extensions(self, names):
        """Remove the specified extension from the list of extensions
        to build"""

        self.extensions = [ x for x in self.extensions if x.name not in names ]

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
        # Run sub commands
        for cmd_name in self.get_sub_commands():
            self.run_command(cmd_name)

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

    sub_commands = [ ('build', None) ]


setup(
    name = "pycryptodome",
    version = version_string,
    description = "Cryptographic library for Python",
    long_description = longdesc,
    author = "Legrandin",
    author_email = "helderijs@gmail.com",
    url = "http://www.pycryptodome.org",
    license = "Public Domain",
    platforms = 'Posix; MacOS X; Windows',
    classifiers = [
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: BSD License',
        'Intended Audience :: Developers',
        'Operating System :: Unix',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.4',
        'Programming Language :: Python :: 3',
    ],
    packages =  [
        "Crypto",
        "Crypto.Cipher",
        "Crypto.Hash",
        "Crypto.IO",
        "Crypto.PublicKey",
        "Crypto.Protocol",
        "Crypto.Random",
        "Crypto.Random.Fortuna",
        "Crypto.Signature",
        "Crypto.Util",
        "Crypto.SelfTest",
        "Crypto.SelfTest.Cipher",
        "Crypto.SelfTest.Hash",
        "Crypto.SelfTest.IO",
        "Crypto.SelfTest.Protocol",
        "Crypto.SelfTest.PublicKey",
        "Crypto.SelfTest.Random",
        "Crypto.SelfTest.Random.Fortuna",
        "Crypto.SelfTest.Signature",
        "Crypto.SelfTest.Util",
        ],
    package_dir = { "Crypto": "lib/Crypto" },
    package_data = {
        "Crypto.SelfTest.Hash" : [
            "test_vectors/SHA3/*.txt" ],
        "Crypto.SelfTest.Signature" : [
            "test_vectors/DSA/*.*" ],
        },
    cmdclass = {
        'build_ext':PCTBuildExt,
        'build_py': PCTBuildPy,
        'test': TestCommand
        },
    ext_modules = [
        # _fastmath (uses GNU mp library)
        Extension("Crypto.PublicKey._fastmath",
            include_dirs=['src/'],
            libraries=['gmp'],
            sources=["src/_fastmath.c"]),

        # Hash functions
        Extension("Crypto.Hash.MD2",
            include_dirs=['src/'],
            sources=["src/MD2.c"]),
        Extension("Crypto.Hash.MD4",
            include_dirs=['src/'],
            sources=["src/MD4.c"]),
        Extension("Crypto.Hash.SHA256",
            include_dirs=['src/'],
            sources=["src/SHA256.c"]),
        Extension("Crypto.Hash.SHA224",
            include_dirs=['src/'],
            sources=["src/SHA224.c"]),
        Extension("Crypto.Hash.SHA384",
            include_dirs=['src/'],
            sources=["src/SHA384.c"]),
        Extension("Crypto.Hash.SHA512",
            include_dirs=['src/'],
            sources=["src/SHA512.c"]),
        Extension("Crypto.Hash.RIPEMD160",
            include_dirs=['src/'],
            sources=["src/RIPEMD160.c"]),
        Extension("Crypto.Hash.SHA3_224",
            include_dirs=['src/'],
            sources=["src/SHA3_224.c"]),
        Extension("Crypto.Hash.SHA3_256",
            include_dirs=['src/'],
            sources=["src/SHA3_256.c"]),
        Extension("Crypto.Hash.SHA3_384",
            include_dirs=['src/'],
            sources=["src/SHA3_384.c"]),
        Extension("Crypto.Hash.SHA3_512",
            include_dirs=['src/'],
            sources=["src/SHA3_512.c"]),

        # Block encryption algorithms
        Extension("Crypto.Cipher._AES",
            include_dirs=['src/'],
            sources=["src/AES.c"]),
        Extension("Crypto.Cipher._AESNI",
            include_dirs=['src/'],
            sources=["src/AESNI.c"]),
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
        Extension("Crypto.Util._galois",
            include_dirs=['src/'],
            sources=['src/galois.c']),
        Extension("Crypto.Util.cpuid",
            include_dirs=['src/'],
            sources=['src/cpuid.c']),

        # Stream ciphers
        Extension("Crypto.Cipher._ARC4",
            include_dirs=['src/'],
            sources=["src/ARC4.c"]),
        Extension("Crypto.Cipher._XOR",
            include_dirs=['src/'],
            sources=["src/XOR.c"]),
        Extension("Crypto.Cipher._Salsa20",
            include_dirs=['src/', 'src/libtom/'],
            sources=["src/Salsa20.c"]),

        # Utility modules
        Extension("Crypto.Util.strxor",
            include_dirs=['src/'],
            sources=['src/strxor.c']),

        # Counter modules
        Extension("Crypto.Util._counter",
            include_dirs=['src/'],
            sources=['src/_counter.c']),
        ]
)
