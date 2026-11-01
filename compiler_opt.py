# SPDX-FileCopyrightText: 2018 Helder Eijs <helderijs@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause

import distutils
import os
import shutil
import struct
import subprocess
import sys
from distutils import ccompiler
from distutils.errors import CCompilerError
from distutils.util import get_platform


def _find_clang_cl(compiler, setting):
    """Return the path of clang-cl.exe, or None.

    ``setting`` is the value of PYCRYPTODOME_CLANG_CL: a path to clang-cl.exe,
    or any other value to look for it on the PATH (also the one of Visual Studio)
    and in Visual Studio (component "C++ Clang tools for Windows")."""

    if os.path.isfile(setting):
        return setting

    paths = os.pathsep.join([getattr(compiler, "_paths", ""), os.environ.get("PATH", "")])
    found = shutil.which("clang-cl", path=paths)
    if found:
        return found

    # cl.exe is in VC\Tools\MSVC\<version>\bin\Host<arch>\<arch>,
    # clang-cl.exe in VC\Tools\Llvm\x64\bin
    tools_dir = os.path.dirname(compiler.cc)
    for _ in range(5):
        tools_dir = os.path.dirname(tools_dir)
    candidate = os.path.join(tools_dir, "Llvm", "x64", "bin", "clang-cl.exe")
    if os.path.isfile(candidate):
        return candidate
    return None


def use_clang_cl(compiler):
    """Make a distutils MSVC compiler object compile with clang-cl instead of
    cl.exe, if the environment variable PYCRYPTODOME_CLANG_CL is set
    (to a path to clang-cl.exe, or to 1 to look for it).

    clang-cl is compatible with the ABI and the command line of MSVC, and it
    supports what cl.exe does not: GCC-style inline assembly and cpuid.h, used
    by the code for CPUs with AVX2, BMI2 and ADX. The objects are linked with
    the linker of MSVC as usual. Only for Windows on x86-64: on other targets,
    and if the variable is not set, nothing changes.

    Return True if clang-cl is used."""

    setting = os.environ.get("PYCRYPTODOME_CLANG_CL")
    if not setting or compiler.compiler_type != "msvc" or get_platform() != "win-amd64":
        return False

    if not compiler.initialized:
        compiler.initialize()

    clang_cl = _find_clang_cl(compiler, setting)
    if clang_cl is None:
        raise CCompilerError("PYCRYPTODOME_CLANG_CL is set, but clang-cl.exe was not found")
    compiler.cc = clang_cl

    # Whole program optimization (/GL, /LTCG) is specific to cl.exe
    for options in (compiler.compile_options, compiler.compile_options_debug):
        while "/GL" in options:
            options.remove("/GL")
    for ldflags in compiler._ldflags.values():
        while "/LTCG" in ldflags:
            ldflags.remove("/LTCG")

    return True


def print_clang_cl_version(compiler):
    """Print the path and the version of clang-cl, for the build log"""

    version = subprocess.run([compiler.cc, "--version"], capture_output=True, text=True).stdout
    print("Compiling with %s: %s" % (compiler.cc, version.splitlines()[0] if version else "?"))


def test_compilation(program, extra_cc_options=None, extra_libraries=None, msg=""):
    """Test if a certain C program can be compiled."""

    # Create a temporary file with the C program
    if not os.path.exists("build"):
        os.makedirs("build")
    fname = os.path.join("build", "test1.c")
    f = open(fname, "w")
    f.write(program)
    f.close()

    # Name for the temporary executable
    oname = os.path.join("build", "test1.out")

    debug = bool(os.environ.get("PYCRYPTODOME_DEBUG", None))
    # Mute the compiler and the linker
    if msg:
        print("Testing support for %s" % msg)
    if not (debug or os.name == "nt"):
        old_stdout = os.dup(sys.stdout.fileno())
        old_stderr = os.dup(sys.stderr.fileno())
        dev_null = open(os.devnull, "w")
        os.dup2(dev_null.fileno(), sys.stdout.fileno())
        os.dup2(dev_null.fileno(), sys.stderr.fileno())

    objects = []
    try:
        compiler = ccompiler.new_compiler()
        distutils.sysconfig.customize_compiler(compiler)
        use_clang_cl(compiler)

        if compiler.compiler_type in ["msvc"]:
            # Force creation of the manifest file (http://bugs.python.org/issue16296)
            # as needed by VS2010
            extra_linker_options = ["/MANIFEST"]
        else:
            extra_linker_options = []

        # In Unix, force the linker step to use CFLAGS and not CC alone (see GH#180)
        if compiler.compiler_type in ["unix"]:
            compiler.set_executables(linker_exe=compiler.compiler)

        objects = compiler.compile([fname], extra_postargs=extra_cc_options)
        compiler.link_executable(
            objects, oname, libraries=extra_libraries, extra_preargs=extra_linker_options
        )
        result = True
    except (CCompilerError, OSError):
        result = False
    for f in objects + [fname, oname]:
        try:
            os.remove(f)
        except OSError:
            pass

    # Restore stdout and stderr
    if not (debug or os.name == "nt"):
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
        return a;
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
        return eax;
    }
    """
    return test_compilation(source, msg="cpuid.h header")


def compiler_supports_aesni():
    source = """
    #include <wmmintrin.h>
    #include <string.h>
    __m128i f(__m128i x, __m128i y) {
        return _mm_aesenc_si128(x, y);
    }
    int main(void) {
        int ret;
        __m128i x;
        memset(&x, 0, sizeof(x));
        x = f(x, x);
        memcpy(&ret, &x, sizeof(ret));
        return ret;
    }
    """

    if test_compilation(source):
        return {"extra_cc_options": [], "extra_macros": []}

    if test_compilation(source, extra_cc_options=["-maes"], msg="AESNI intrinsics"):
        return {"extra_cc_options": ["-maes"], "extra_macros": []}

    return False


def compiler_supports_clmul():
    result = {"extra_cc_options": [], "extra_macros": ["HAVE_WMMINTRIN_H", "HAVE_TMMINTRIN_H"]}

    source = """
    #include <wmmintrin.h>
    #include <tmmintrin.h>

    __m128i f(__m128i x, __m128i y) {
        return _mm_clmulepi64_si128(x, y, 0x00);
    }

    __m128i g(__m128i a) {
        __m128i mask;

        mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        return _mm_shuffle_epi8(a, mask);
    }

    int main(void) {
        return 0;
    }
    """

    if test_compilation(source):
        return result

    if test_compilation(source, extra_cc_options=["-mpclmul", "-mssse3"], msg="CLMUL intrinsics"):
        result["extra_cc_options"].extend(["-mpclmul", "-mssse3"])
        return result

    return False


def target_may_be_arm64():
    """Return True if the build targets 64-bit ARM: Linux and other Unix
    systems on AArch64, Windows on ARM64, and macOS on arm64
    (alone or in a universal2 build, together with x86-64)."""

    platform = get_platform()
    return platform.endswith(("aarch64", "arm64", "universal2"))


def compiler_supports_armv8_crypto():
    """Return the compiler options to enable the intrinsics of the ARMv8
    Cryptography Extensions (AES and PMULL), or False if the compiler
    cannot emit them.

    The test program, like the modules, is empty when not compiled for
    AArch64, so that the x86-64 half of a macOS universal2 build succeeds.
    The modules only support little-endian CPUs."""

    source = """
    #if defined(__aarch64__) || defined(_M_ARM64)
    #if defined(__ARM_BIG_ENDIAN)
    #error Only for little-endian CPUs
    #endif
    #include <arm_neon.h>
    #include <stdint.h>
    #include <string.h>
    uint8x16_t f(uint8x16_t x, uint8x16_t k) {
        x = vaesmcq_u8(vaeseq_u8(x, k));
        return vaesimcq_u8(vaesdq_u8(x, k));
    }
    uint64x2_t g(uint64x2_t a, uint64x2_t b) {
        uint64x2_t lo, hi;
    #if defined(_MSC_VER) && !defined(__clang__)
        lo = vmull_p64(vget_low_u64(a), vget_low_u64(b));
        hi = vmull_high_p64(a, b);
    #else
        lo = vreinterpretq_u64_p128(vmull_p64((poly64_t)vgetq_lane_u64(a, 0),
                                              (poly64_t)vgetq_lane_u64(b, 0)));
        hi = vreinterpretq_u64_p128(vmull_high_p64(vreinterpretq_p64_u64(a),
                                                   vreinterpretq_p64_u64(b)));
    #endif
        return veorq_u64(lo, vextq_u64(hi, hi, 1));
    }
    int main(void) {
        int ret;
        uint8x16_t x;
        uint64x2_t y;
        x = vdupq_n_u8(1);
        x = f(x, x);
        y = vreinterpretq_u64_u8(x);
        y = g(y, y);
        memcpy(&ret, &y, sizeof(ret));
        return ret;
    }
    #else
    int main(void) {
        return 0;
    }
    #endif
    """

    if test_compilation(source, msg="ARMv8 Cryptography Extensions intrinsics"):
        return {"extra_cc_options": [], "extra_macros": []}

    options = ["-march=armv8-a+crypto"]
    if test_compilation(source, extra_cc_options=options, msg="ARMv8 Cryptography Extensions intrinsics"):
        return {"extra_cc_options": options, "extra_macros": []}

    return False


def compiler_supports_avx2_bmi2():
    """Return the compiler options to enable AVX2, BMI1 and BMI2 intrinsics
    (all together), or False if the compiler cannot emit all of them.
    Only gcc and clang are supported."""

    source = """
    #include <immintrin.h>
    #include <stdint.h>
    #include <string.h>
    __m256i f(__m256i x, __m256i y) {
        __m256i z = _mm256_andnot_si256(x, y);
        return _mm256_xor_si256(_mm256_slli_epi64(z, 1), _mm256_srli_epi64(z, 63));
    }
    uint64_t g(uint64_t x, uint64_t y) {
        /* BMI1 and BMI2 */
        return _andn_u64(x, y) ^ _bzhi_u64(x, 7);
    }
    int main(void) {
        int ret;
        __m256i x;
        x = _mm256_set1_epi64x(1);
        x = f(x, x);
        memcpy(&ret, &x, sizeof(ret));
        return ret + (int)g(3, 5);
    }
    """

    options = ["-mavx2", "-mbmi", "-mbmi2"]
    if test_compilation(source, extra_cc_options=options, msg="AVX2, BMI1 and BMI2 intrinsics"):
        return {"extra_cc_options": options, "extra_macros": []}

    return False


def compiler_supports_sha_ni():
    """Return the compiler options to enable the SHA-NI intrinsics
    (with SSSE3 and SSE4.1), or False if the compiler cannot emit them.
    MSVC needs no options; gcc and clang need -msha and -msse4.1."""

    source = """
    #include <immintrin.h>
    #include <string.h>
    __m128i f(__m128i a, __m128i b, __m128i k) {
        __m128i x = _mm_sha256rnds2_epu32(a, b, k);
        x = _mm_sha256msg2_epu32(_mm_sha256msg1_epu32(x, a), b);
        return _mm_blend_epi16(_mm_alignr_epi8(x, a, 8), b, 0xF0);
    }
    int main(void) {
        int ret;
        __m128i x;
        x = _mm_set1_epi32(1);
        x = f(x, x, x);
        memcpy(&ret, &x, sizeof(ret));
        return ret;
    }
    """

    if test_compilation(source, msg="SHA-NI intrinsics"):
        return {"extra_cc_options": [], "extra_macros": []}

    options = ["-msha", "-msse4.1"]
    if test_compilation(source, extra_cc_options=options, msg="SHA-NI intrinsics"):
        return {"extra_cc_options": options, "extra_macros": []}


def compiler_supports_bmi2_adx():
    """Return the compiler options to build the code for x86-64 CPUs with
    BMI2 and ADX (inline assembly with MULX, ADCX and ADOX), or False if
    the compiler cannot. Only gcc and clang are supported."""

    source = """
    #include <stdint.h>
    #if !defined(__x86_64__)
    #error Only for x86-64
    #endif
    int main(void) {
        uint64_t lo, hi, x = 3, y = 5;
        __asm__ volatile (
            "xor %%r8d, %%r8d\\n\\t"
            "mulx %[y], %[lo], %[hi]\\n\\t"
            "adcx %%r8, %[lo]\\n\\t"
            "adox %%r8, %[hi]\\n\\t"
            : [lo] "=&r" (lo), [hi] "=&r" (hi)
            : "d" (x), [y] "r" (y)
            : "r8", "cc");
        return (int)(lo + hi) - 15;
    }
    """

    options = ["-mbmi2", "-madx"]
    if test_compilation(source, extra_cc_options=options, msg="BMI2 and ADX inline assembly"):
        return {"extra_cc_options": options, "extra_macros": []}

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


def check_compiler_works():
    """Raise CCompilerError if the C compiler cannot build a minimal program.

    With a broken toolchain (e.g. an assembler too old for the compiler),
    all the tests of the platform features fail, and the build stops later
    with misleading errors (GH#386)."""

    source = """
    int main(void)
    {
        return 0;
    }
    """
    if not test_compilation(source, msg="a minimal C program"):
        raise CCompilerError(
            "The C compiler cannot build a minimal program: check the C toolchain "
            "(compiler, assembler and linker). "
            "Set the environment variable PYCRYPTODOME_DEBUG=1 to see its errors."
        )


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


def compiler_is_gcc(extra_cc_options=None):
    source = """
    #if defined(__clang__) || !defined(__GNUC__)
    #error Not GCC
    #endif
    int main(void)
    {
        return 0;
    }"""
    return test_compilation(source, msg="gcc", extra_cc_options=extra_cc_options)


def compiler_supports_sse2():
    source_template = """
    %s
    int main(void)
    {
        __m128i r0;
        int mask;
        r0 = _mm_set1_epi32(0);
        mask = _mm_movemask_epi8(r0);
        return mask;
    }
    """

    source_intrin_h = source_template % "#include <intrin.h>"
    source_x86intrin_h = source_template % "#include <x86intrin.h>"
    source_xemmintrin_h = source_template % "#include <xmmintrin.h>\n#include <emmintrin.h>"

    system_bits = 8 * struct.calcsize("P")

    result = None
    if test_compilation(source_intrin_h, msg="SSE2(intrin.h)"):
        result = {"extra_cc_options": [], "extra_macros": ["HAVE_INTRIN_H", "USE_SSE2"]}
    elif test_compilation(source_x86intrin_h, extra_cc_options=["-msse2"], msg="SSE2(x86intrin.h)"):
        result = {"extra_cc_options": ["-msse2"], "extra_macros": ["HAVE_X86INTRIN_H", "USE_SSE2"]}
    elif test_compilation(source_xemmintrin_h, extra_cc_options=["-msse2"], msg="SSE2(emmintrin.h)"):
        result = {"extra_cc_options": ["-msse2"], "extra_macros": ["HAVE_EMMINTRIN_H", "USE_SSE2"]}
    else:
        result = False

    # On 32-bit x86 platforms, gcc assumes the stack to be aligned to 16
    # bytes, but the caller may actually only align it to 4 bytes, which
    # make functions crash if they use SSE2 intrinsics.
    # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=40838
    if result and system_bits == 32 and compiler_is_gcc(extra_cc_options=["-mstackrealign"]):
        result["extra_cc_options"].append("-mstackrealign")

    return result


def remove_extension(extensions, name):
    idxs = [i for i, x in enumerate(extensions) if x.name == name]
    if len(idxs) != 1:
        raise ValueError("There is no or there are multiple extensions named '%s'" % name)
    del extensions[idxs[0]]


def set_compiler_options(extensions):
    """Environment specific settings for extension modules.

    This function modifies how each module gets compiled, to
    match the capabilities of the platform.
    Also, it removes existing modules when not supported, such as:
      - AESNI
      - CLMUL
      - ARMv8 Cryptography Extensions
      - AVX2 and BMI2
    """

    extra_cc_options = []
    extra_macros = []

    if has_stdint_h():
        extra_macros.append(("HAVE_STDINT_H", None))

    # Endianess
    extra_macros.append(("PYCRYPTO_" + sys.byteorder.upper() + "_ENDIAN", None))

    # System
    system_bits = 8 * struct.calcsize("P")
    extra_macros.append(("SYS_BITS", str(system_bits)))

    # Native 128-bit integer
    if compiler_supports_uint128():
        extra_macros.append(("HAVE_UINT128", None))

    # Auto-detecting CPU features
    cpuid_h_present = compiler_has_cpuid_h()
    if cpuid_h_present:
        extra_macros.append(("HAVE_CPUID_H", None))
    intrin_h_present = compiler_has_intrin_h()
    if intrin_h_present:
        extra_macros.append(("HAVE_INTRIN_H", None))

    # Platform-specific call for getting a block of aligned memory
    if compiler_has_posix_memalign():
        extra_macros.append(("HAVE_POSIX_MEMALIGN", None))
    elif compiler_has_memalign():
        extra_macros.append(("HAVE_MEMALIGN", None))

    # SSE2
    sse2_result = compiler_supports_sse2()
    if sse2_result:
        extra_cc_options.extend(sse2_result["extra_cc_options"])
        for macro in sse2_result["extra_macros"]:
            extra_macros.append((macro, None))

    # Module-specific options

    # AESNI
    aesni_result = (cpuid_h_present or intrin_h_present) and compiler_supports_aesni()
    aesni_mod_name = "Crypto.Cipher._raw_aesni"
    if aesni_result:
        print("Compiling support for AESNI instructions")
        aes_mods = [x for x in extensions if x.name == aesni_mod_name]
        for x in aes_mods:
            x.extra_compile_args.extend(aesni_result["extra_cc_options"])
            for macro in aesni_result["extra_macros"]:
                x.define_macros.append((macro, None))
    else:
        print("Warning: compiler does not support AESNI instructions")
        remove_extension(extensions, aesni_mod_name)

    # CLMUL
    clmul_result = (cpuid_h_present or intrin_h_present) and compiler_supports_clmul()
    clmul_mod_name = "Crypto.Hash._ghash_clmul"
    if clmul_result:
        print("Compiling support for CLMUL instructions")
        clmul_mods = [x for x in extensions if x.name == clmul_mod_name]
        for x in clmul_mods:
            x.extra_compile_args.extend(clmul_result["extra_cc_options"])
            for macro in clmul_result["extra_macros"]:
                x.define_macros.append((macro, None))
    else:
        print("Warning: compiler does not support CLMUL instructions")
        remove_extension(extensions, clmul_mod_name)

    # ARMv8 Cryptography Extensions (AES and PMULL), on 64-bit ARM only
    armv8_crypto_result = target_may_be_arm64() and compiler_supports_armv8_crypto()
    armv8_crypto_mod_names = ["Crypto.Cipher._raw_aes_armv8", "Crypto.Hash._ghash_pmull"]
    if armv8_crypto_result:
        print("Compiling support for ARMv8 Cryptography Extensions")
        for x in extensions:
            if x.name in armv8_crypto_mod_names:
                x.extra_compile_args.extend(armv8_crypto_result["extra_cc_options"])
    else:
        print("Warning: compiler does not support ARMv8 Cryptography Extensions")
        for mod_name in armv8_crypto_mod_names:
            remove_extension(extensions, mod_name)

    # AVX2, BMI1 and BMI2, all together (gcc and clang only)
    # Detecting them at runtime requires cpuid.h
    avx2_bmi2_result = cpuid_h_present and compiler_supports_avx2_bmi2()
    avx2_bmi2_mod_names = [
        "Crypto.Hash._keccak_avx2_bmi2",
        "Crypto.Hash._k12_avx2_bmi2",
        "Crypto.Cipher._Salsa20_avx2_bmi2",
        "Crypto.Cipher._chacha20_avx2_bmi2",
        "Crypto.PublicKey._mldsa_avx2_bmi2",
        "Crypto.PublicKey._mlkem_avx2_bmi2",
    ]
    if avx2_bmi2_result:
        print("Compiling support for AVX2 and BMI2 instructions")
        avx2_bmi2_mods = [x for x in extensions if x.name in avx2_bmi2_mod_names]
        for x in avx2_bmi2_mods:
            x.extra_compile_args.extend(avx2_bmi2_result["extra_cc_options"])
            for macro in avx2_bmi2_result["extra_macros"]:
                x.define_macros.append((macro, None))
    else:
        print("Warning: compiler does not support AVX2 and BMI2 instructions")
        for mod_name in avx2_bmi2_mod_names:
            remove_extension(extensions, mod_name)

    # SHA-NI
    sha_ni_result = (cpuid_h_present or intrin_h_present) and compiler_supports_sha_ni()
    sha_ni_mod_names = ["Crypto.Hash._SHA224_shani", "Crypto.Hash._SHA256_shani"]
    if sha_ni_result:
        print("Compiling support for SHA-NI instructions")
        sha_ni_mods = [x for x in extensions if x.name in sha_ni_mod_names]
        for x in sha_ni_mods:
            x.extra_compile_args.extend(sha_ni_result["extra_cc_options"])
            for macro in sha_ni_result["extra_macros"]:
                x.define_macros.append((macro, None))
    else:
        print("Warning: compiler does not support SHA-NI instructions")
        for mod_name in sha_ni_mod_names:
            remove_extension(extensions, mod_name)

    # BMI2 and ADX, for the big integer code (gcc and clang on x86-64 only)
    # Detecting them at runtime requires cpuid.h
    bmi2_adx_result = cpuid_h_present and compiler_supports_bmi2_adx()
    bmi2_adx_mod_names = ["Crypto.Math._nat_bmi2_adx", "Crypto.PublicKey._ec_nat_bmi2_adx"]
    if bmi2_adx_result:
        print("Compiling support for BMI2 and ADX instructions")
        for x in extensions:
            if x.name in bmi2_adx_mod_names:
                x.extra_compile_args.extend(bmi2_adx_result["extra_cc_options"])
    else:
        print("Warning: compiler does not support BMI2 and ADX instructions")
        for mod_name in bmi2_adx_mod_names:
            remove_extension(extensions, mod_name)

    for x in extensions:
        x.extra_compile_args.extend(extra_cc_options)
        x.define_macros.extend(extra_macros)
