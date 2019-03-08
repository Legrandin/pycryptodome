# ===================================================================
#
# Copyright (c) 2018, Helder Eijs <helderijs@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ===================================================================


import os
import sys
import struct
import distutils
from distutils import ccompiler
from distutils.errors import CCompilerError


def test_compilation(program, extra_cc_options=None, extra_libraries=None,
                     msg=''):
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

    debug = bool(os.environ.get('PYCRYPTODOME_DEBUG', None))
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

        if compiler.compiler_type in ['msvc']:
            # Force creation of the manifest file (http://bugs.python.org/issue16296)
            # as needed by VS2010
            extra_linker_options = ["/MANIFEST"]
        else:
            extra_linker_options = []

        # In Unix, force the linker step to use CFLAGS and not CC alone (see GH#180)
        if compiler.compiler_type in ['unix']:
            compiler.set_executables(linker_exe=compiler.compiler)

        objects = compiler.compile([fname], extra_postargs=extra_cc_options)
        compiler.link_executable(objects, oname, libraries=extra_libraries,
                                 extra_preargs=extra_linker_options)
        result = True
    except (CCompilerError, OSError):
        result = False
    for f in objects + [fname, oname]:
        try:
            os.remove(f)
        except OSError:
            pass

    # Restore stdout and stderr
    if not (debug or os.name == 'nt'):
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


def has_stdint_h():
    source = """
    #include <stdint.h>
    int main(void) {
        uint32_t u;
        u = 0;
        return u + 2;
    }
    """
    return test_compilation(source, msg="stdint.h header")


def compiler_supports_uint128():
    source = """
    int main(void)
    {
        __uint128_t x;
        return 0;
    }
    """
    return test_compilation(source, msg="128-bit integer")


def compiler_has_intrin_h():
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


def compiler_has_cpuid_h():
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


def compiler_supports_aesni():
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
        return {'extra_options': []}

    if test_compilation(source, extra_cc_options=['-maes'], msg='AESNI intrinsics'):
        return {'extra_options': ['-maes']}

    return False


def compiler_supports_clmul():
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
        return {'extra_options': []}

    if test_compilation(source, extra_cc_options=['-mpclmul', '-mssse3'],
                        msg='CLMUL intrinsics'):
        return {'extra_options': ['-mpclmul', '-mssse3']}

    return False


def compiler_has_posix_memalign():
    source = """
    #include <stdlib.h>
    int main(void) {
        void *new_mem;
        int res;
        res = posix_memalign((void**)&new_mem, 16, 101);
        return res == 0;
    }
    """
    return test_compilation(source, msg="posix_memalign")


def compiler_has_memalign():
    source = """
    #include <malloc.h>
    int main(void) {
        void *p;
        p = memalign(16, 101);
        return p != (void*)0;
    }
    """
    return test_compilation(source, msg="memalign")


def compiler_is_clang():
    source = """
    #if !defined(__clang__)
    #error Not clang
    #endif
    int main(void)
    {
        return 0;
    }
    """
    return test_compilation(source, msg="clang")


def compiler_is_gcc():
    source = """
    #if defined(__clang__) || !defined(__GNUC__)
    #error Not GCC
    #endif
    int main(void)
    {
        return 0;
    }"""
    return test_compilation(source, msg="gcc")


def compiler_supports_sse2_with_x86intrin_h():
    source = """
    #include <x86intrin.h>
    int main(void)
    {
        __m128i r0;
        int mask;
        r0 = _mm_set1_epi32(0);
        mask = _mm_movemask_epi8(r0);
        return mask;
    }
    """
    return test_compilation(source, extra_cc_options=['-msse2'],
                            msg="SSE2 (x86intrin.h)")


def compiler_supports_sse2_with_intrin_h():
    source = """
    #include <intrin.h>
    int main(void)
    {
        __m128i r0;
        r0 = _mm_set1_epi32(0);
        mask = _mm_movemask_epi8(r0);
        return mask;
    }
    """
    return test_compilation(source, msg="SSE2 (intrin.h)")


def remove_extension(extensions, name):
    idxs = [i for i, x in enumerate(extensions) if x.name == name]
    if len(idxs) != 1:
        raise ValueError("There is no or there are multiple extensions named '%s'" % name)
    del extensions[idxs[0]]


def set_compiler_options(package_root, extensions):
    """Environment specific settings for extension modules.

    This function modifies how each module gets compiled, to
    match the capabilities of the platform.
    Also, it removes existing modules when not supported, such as:
      - AESNI
      - CLMUL
    """

    extra_cc_options = []
    extra_macros = []

    clang = compiler_is_clang()
    gcc = compiler_is_gcc()

    if has_stdint_h():
        extra_macros.append(("HAVE_STDINT_H", None))

    # Endianess
    extra_macros.append(("PYCRYPTO_" + sys.byteorder.upper() + "_ENDIAN", None))

    # System
    system_bits = 8 * struct.calcsize("P")
    extra_macros.append(("SYS_BITS", str(system_bits)))

    # Disable any assembly in libtomcrypt files
    extra_macros.append(("LTC_NO_ASM", None))

    # Native 128-bit integer
    if compiler_supports_uint128():
        extra_macros.append(("HAVE_UINT128", None))

    # Compiler intrinsics (esp. for MSVC)
    intrin_h_present = compiler_has_intrin_h()
    if intrin_h_present:
        extra_macros.append(("HAVE_INTRIN_H", None))

    # Auto-detecting CPU features
    cpuid_h_present = compiler_has_cpuid_h()
    if cpuid_h_present:
        extra_macros.append(("HAVE_CPUID_H", None))

    # Platform-specific call for getting a block of aligned memory
    if compiler_has_posix_memalign():
        extra_macros.append(("HAVE_POSIX_MEMALIGN", None))
    elif compiler_has_memalign():
        extra_macros.append(("HAVE_MEMALIGN", None))

    # Options specific to GCC and CLANG
    if clang or gcc:
        extra_cc_options.append('-O3')
        if compiler_supports_sse2_with_x86intrin_h():
            extra_cc_options.append('-msse2')
            extra_macros.append(("HAVE_X86INTRIN_H", None))
            extra_macros.append(("USE_SSE2", None))
    elif intrin_h_present and compiler_supports_sse2_with_intrin_h():
        extra_macros.append(("USE_SSE2", None))

    # Module-specific options

    # AESNI
    aesni_result = (cpuid_h_present or intrin_h_present) and compiler_supports_aesni()
    aesni_mod_name = package_root + ".Cipher._raw_aesni"
    if aesni_result:
        print("Compiling support for AESNI instructions")
        aes_mods = [x for x in extensions if x.name == aesni_mod_name]
        for x in aes_mods:
            x.extra_compile_args += aesni_result['extra_options']
    else:
        print("Warning: compiler does not support AESNI instructions")
        remove_extension(extensions, aesni_mod_name)

    # CLMUL
    clmul_result = (cpuid_h_present or intrin_h_present) and compiler_supports_clmul()
    clmul_mod_name = package_root + ".Hash._ghash_clmul"
    if clmul_result:
        print("Compiling support for CLMUL instructions")
        clmul_mods = [x for x in extensions if x.name == clmul_mod_name]
        for x in clmul_mods:
            x.extra_compile_args += clmul_result['extra_options']
    else:
        print("Warning: compiler does not support CLMUL instructions")
        remove_extension(extensions, clmul_mod_name)

    for x in extensions:
        x.extra_compile_args += extra_cc_options
        x.define_macros += extra_macros
