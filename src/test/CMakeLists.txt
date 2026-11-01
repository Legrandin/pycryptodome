cmake_minimum_required(VERSION 3.13)
project(test_crypto LANGUAGES C)
include(CMakePrintHelpers)
enable_testing()

cmake_print_variables(CMAKE_C_COMPILER_ID CMAKE_C_COMPILER_VERSION CMAKE_SIZEOF_VOID_P SSE CMAKE_C_COMPILER_ARCHITECTURE_ID)

if (CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "x86_64|AMD64|i686|X86|x64")
    set(X86 TRUE)
endif()

if (CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "ARM64|aarch64|arm64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
    set(ARM64 TRUE)
endif()

if (X86)
   message(STATUS "Enabling SSE and AESNI")
   option(SSE "Enable SSE instructions on Intel targets" ON)
   option(AESNI "Enable AESNI instructions on Intel targets" ON)
endif()

if (ARM64)
   message(STATUS "Enabling the ARMv8 Cryptography Extensions")
   option(ARMV8_CRYPTO "Enable the ARMv8 Cryptography Extensions on 64-bit ARM targets" ON)
endif()

if (DEFINED ENV{PYTHON})
    set(PYTHON $ENV{PYTHON})
else()
    set(PYTHON python)
endif()

include_directories("${CMAKE_SOURCE_DIR}/..")
INCLUDE (${CMAKE_ROOT}/Modules/CheckIncludeFile.cmake)

# Disable any code related to CPython modules
# This is only required for MSVC, and it avoids a dependency on the CPython libraries
add_compile_definitions(NO_CPYTHON_MODULE)

# Ensure that private functions can be accessed
add_compile_definitions(STATIC=)
# Include the reference implementations used by the tests (nat*.c)
add_compile_definitions(NAT_TESTS)

# TODO: add check for big endianess too
add_compile_definitions(PYCRYPTO_LITTLE_ENDIAN)

CHECK_INCLUDE_FILE("stdint.h"    CMAKE_HAVE_STDINT_H)
if (CMAKE_HAVE_STDINT_H)
    add_compile_definitions(HAVE_STDINT_H)
endif()

if (MSVC)
    add_compile_options(/Wall /sdl)
    # Disable certain warnings
    add_compile_options(/wd4100 /wd4820 /wd5045)
else()
    add_compile_definitions(HAVE_POSIX_MEMALIGN)
    add_compile_options(-O2 -g -fstrict-aliasing -Wall -Werror)
    if( CMAKE_SIZEOF_VOID_P EQUAL 8 )
	# Macro HAVE_UINT128 should be defined when __uint128_t type is available,
	# that is, only on Unix 64 bits. It is not available with MSVC or with Unix 32 bits.
        add_compile_definitions(HAVE_UINT128)
    else()
	if (X86)
	   # On 32-bit x86 platforms, gcc assumes the stack to be aligned to 16
	   # bytes, but the caller may actually only align it to 4 bytes, which
	   # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=40838
	   add_compile_options(-mstackrealign)
	endif()
    endif()
    # The sanitizers. On some 32-bit targets (like armel and ppc32), their
    # libraries need libatomic for 64-bit atomics, but gcc does not link it
    # (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110553): add it if needed,
    # and do without the sanitizers if they still cannot link.
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=undefined -fsanitize=address")
    set(CMAKE_REQUIRED_LIBRARIES ubsan)
    check_c_source_compiles("int main(void) { return 0; }" HAVE_SANITIZERS)
    if (NOT HAVE_SANITIZERS)
        set(CMAKE_REQUIRED_LIBRARIES ubsan atomic)
        check_c_source_compiles("int main(void) { return 0; }" HAVE_SANITIZERS_WITH_LIBATOMIC)
    endif()
    unset(CMAKE_REQUIRED_FLAGS)
    unset(CMAKE_REQUIRED_LIBRARIES)

    if (HAVE_SANITIZERS OR HAVE_SANITIZERS_WITH_LIBATOMIC)
        add_compile_options(-fsanitize=undefined -fsanitize=address)
        link_libraries(-lubsan)
        add_link_options(-fsanitize=address)
        if (HAVE_SANITIZERS_WITH_LIBATOMIC)
            message(STATUS "Linking the sanitizers with libatomic")
            link_libraries(-latomic)
        endif()
    else()
        message(WARNING "The sanitizers cannot be linked: the tests run without them")
    endif()
endif()

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_compile_definitions(SYS_BITS=64)
else()
    add_compile_definitions(SYS_BITS=32)
endif()

if (MSVC)
    if (SSE)
    	add_compile_definitions(HAVE_INTRIN_H)
    	add_compile_definitions(USE_SSE2)
    	add_compile_definitions(HAVE_WMMINTRIN_H)
    	add_compile_definitions(HAVE_TMMINTRIN_H)
    endif()

    # Unlike cl.exe, clang-cl only accepts the intrinsics of the
    # instruction sets that are enabled
    if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
        # /Wall is -Weverything for clang-cl: the casts that drop const are expected
        add_compile_options(-Wno-cast-qual)
        if (SSE)
            add_compile_options(-mssse3 -mpclmul)
        endif()
        if (AESNI)
            add_compile_options(-maes)
        endif()
    endif()
else()
    if (SSE)
        message(STATUS "Using SSE instructions")
        add_compile_definitions(HAVE_X86INTRIN_H)
        add_compile_definitions(HAVE_TMMINTRIN_H)
        add_compile_options(-mssse3 -mpclmul)
    endif()

    if (SSE OR AESNI)
	    add_compile_definitions(HAVE_WMMINTRIN_H)
    endif()

    if (AESNI)
	    add_compile_options(-maes)
    endif()
endif()

# -------------------------------------------------------------------------

# constant-time natural numbers
add_library(nat OBJECT ../nat.c ../nat_div.c ../nat_mod.c ../nat_gcd.c ../nat_prime.c)

add_executable(test_nat test_nat.c $<TARGET_OBJECTS:nat>)
add_test(NAME test_nat COMMAND test_nat)

# The build of the natural numbers for x86-64 CPUs with BMI2 and ADX
# (gcc and clang only). The tests do nothing on a CPU without them.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT MSVC)
    set(NAT_BMI2_ADX_TESTS TRUE)
    add_executable(test_nat_bmi2_adx test_nat.c ../nat_bmi2_adx.c)
    target_compile_definitions(test_nat_bmi2_adx PRIVATE TEST_BMI2_ADX)
    target_compile_options(test_nat_bmi2_adx PRIVATE -mbmi2 -madx)
    add_test(NAME test_nat_bmi2_adx COMMAND test_nat_bmi2_adx)
endif()

# The natural numbers on a 32-bit target (no 128-bit type, 32-bit
# kernels), when the compiler can build and run 32-bit code (gcc-multilib)
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND NOT MSVC)
    include(CheckCSourceRuns)
    set(CMAKE_REQUIRED_FLAGS "-m32")
    set(CMAKE_REQUIRED_LINK_OPTIONS "-m32")
    check_c_source_runs("int main(void) { return sizeof(void*) == 4 ? 0 : 1; }" HAVE_M32)
    unset(CMAKE_REQUIRED_FLAGS)
    unset(CMAKE_REQUIRED_LINK_OPTIONS)
    if (HAVE_M32)
        set(NAT_32BIT_TESTS TRUE)
        add_executable(test_nat_32 test_nat.c ../nat.c ../nat_div.c ../nat_mod.c ../nat_gcd.c ../nat_prime.c)
        # Without HAVE_UINT128 and with 32-bit SYS_BITS, as a real 32-bit build
        set_target_properties(test_nat_32 PROPERTIES
            COMPILE_OPTIONS "-m32;-O2;-g;-Wall;-Werror;-fsanitize=undefined;-fsanitize=address;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
            LINK_OPTIONS "-m32;-fsanitize=undefined;-fsanitize=address"
            LINK_LIBRARIES "")
        add_test(NAME test_nat_32 COMMAND test_nat_32)

        # The same with the SSE2 kernels, as in a real 32-bit x86 build
        add_executable(test_nat_32_sse2 test_nat.c ../nat.c ../nat_div.c ../nat_mod.c ../nat_gcd.c ../nat_prime.c)
        set_target_properties(test_nat_32_sse2 PROPERTIES
            COMPILE_OPTIONS "-m32;-msse2;-DUSE_SSE2;-O2;-g;-Wall;-Werror;-fsanitize=undefined;-fsanitize=address;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
            LINK_OPTIONS "-m32;-fsanitize=undefined;-fsanitize=address"
            LINK_LIBRARIES "")
        add_test(NAME test_nat_32_sse2 COMMAND test_nat_32_sse2)
    endif()
endif()

# The elliptic curves on the natural numbers: NIST curves, Ed448, X448
set(EC_SOURCES ../ec_common.c ../ec_nat.c ../ed448.c ../curve448.c)
set(NAT_SOURCES ../nat.c ../nat_div.c ../nat_mod.c ../nat_gcd.c ../nat_prime.c)
add_library(ec OBJECT ${EC_SOURCES})

foreach(ec_test test_ec_common test_ec_nat test_ed448 test_curve448)
    add_executable(${ec_test} ${ec_test}.c $<TARGET_OBJECTS:ec> $<TARGET_OBJECTS:nat>)
    add_test(NAME ${ec_test} COMMAND ${ec_test})

    if (NAT_BMI2_ADX_TESTS)
        add_executable(${ec_test}_bmi2_adx ${ec_test}.c ../ec_nat_bmi2_adx.c)
        target_compile_definitions(${ec_test}_bmi2_adx PRIVATE TEST_BMI2_ADX)
        target_compile_options(${ec_test}_bmi2_adx PRIVATE -mbmi2 -madx)
        add_test(NAME ${ec_test}_bmi2_adx COMMAND ${ec_test}_bmi2_adx)
    endif()

    if (NAT_32BIT_TESTS AND HAVE_M32)
        add_executable(${ec_test}_32 ${ec_test}.c ${EC_SOURCES} ${NAT_SOURCES})
        set_target_properties(${ec_test}_32 PROPERTIES
            COMPILE_OPTIONS "-m32;-O2;-g;-Wall;-Werror;-fsanitize=undefined;-fsanitize=address;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
            LINK_OPTIONS "-m32;-fsanitize=undefined;-fsanitize=address"
            LINK_LIBRARIES "")
        add_test(NAME ${ec_test}_32 COMMAND ${ec_test}_32)

        add_executable(${ec_test}_32_sse2 ${ec_test}.c ${EC_SOURCES} ${NAT_SOURCES})
        set_target_properties(${ec_test}_32_sse2 PROPERTIES
            COMPILE_OPTIONS "-m32;-msse2;-DUSE_SSE2;-O2;-g;-Wall;-Werror;-fsanitize=undefined;-fsanitize=address;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
            LINK_OPTIONS "-m32;-fsanitize=undefined;-fsanitize=address"
            LINK_LIBRARIES "")
        add_test(NAME ${ec_test}_32_sse2 COMMAND ${ec_test}_32_sse2)
    endif()
endforeach()

# The same tests, without the precomputed tables of the generator (EC_NO_TABLES)
foreach(ec_test test_ec_nat test_ed448)
    add_executable(${ec_test}_no_tables ${ec_test}.c ${EC_SOURCES} ${NAT_SOURCES})
    target_compile_definitions(${ec_test}_no_tables PRIVATE EC_NO_TABLES)
    add_test(NAME ${ec_test}_no_tables COMMAND ${ec_test}_no_tables)
endforeach()

# Constant-time check of the natural numbers, with Valgrind memcheck
find_program(VALGRIND valgrind)
CHECK_INCLUDE_FILE("valgrind/memcheck.h" HAVE_VALGRIND_MEMCHECK_H)
if (VALGRIND AND HAVE_VALGRIND_MEMCHECK_H)
    add_executable(test_nat_ct test_nat_ct.c ../nat.c ../nat_div.c ../nat_mod.c ../nat_gcd.c ../nat_prime.c)
    target_compile_definitions(test_nat_ct PRIVATE NAT_CTGRIND)
    # The sanitizers cannot run under Valgrind
    set_target_properties(test_nat_ct PROPERTIES
        COMPILE_OPTIONS "-O2;-g;-Wall;-Werror"
        LINK_OPTIONS ""
        LINK_LIBRARIES "")
    add_test(NAME test_nat_ct COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_nat_ct>)

    add_executable(test_ec_nat_ct test_ec_nat_ct.c ${EC_SOURCES} ${NAT_SOURCES})
    target_compile_definitions(test_ec_nat_ct PRIVATE NAT_CTGRIND)
    set_target_properties(test_ec_nat_ct PROPERTIES
        COMPILE_OPTIONS "-O2;-g;-Wall;-Werror"
        LINK_OPTIONS ""
        LINK_LIBRARIES "")
    add_test(NAME test_ec_nat_ct COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_ec_nat_ct>)

    # Ed25519 and X25519 (each includes mod25519.c, so one executable per curve)
    foreach(CURVE ed25519 curve25519)
        add_executable(test_${CURVE}_ct test_${CURVE}_ct.c ../${CURVE}.c)
        target_compile_definitions(test_${CURVE}_ct PRIVATE NAT_CTGRIND)
        set_target_properties(test_${CURVE}_ct PROPERTIES
            COMPILE_OPTIONS "-O2;-g;-Wall;-Werror"
            LINK_OPTIONS ""
            LINK_LIBRARIES "")
        add_test(NAME test_${CURVE}_ct COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_${CURVE}_ct>)
    endforeach()

    # DES and Triple DES (DES.c is included by the test)
    foreach(CIPHER des des3)
        add_executable(test_${CIPHER}_ct test_des_ct.c)
        if (CIPHER STREQUAL "des3")
            target_compile_definitions(test_${CIPHER}_ct PRIVATE PCT_DES3_MODULE)
        endif()
        set_target_properties(test_${CIPHER}_ct PROPERTIES
            COMPILE_OPTIONS "-O2;-g;-Wall;-Werror"
            LINK_OPTIONS ""
            LINK_LIBRARIES "")
        add_test(NAME test_${CIPHER}_ct COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_${CIPHER}_ct>)

        if (NAT_32BIT_TESTS)
            add_executable(test_${CIPHER}_ct_32 test_des_ct.c)
            if (CIPHER STREQUAL "des3")
                target_compile_definitions(test_${CIPHER}_ct_32 PRIVATE PCT_DES3_MODULE)
            endif()
            set_target_properties(test_${CIPHER}_ct_32 PROPERTIES
                COMPILE_OPTIONS "-m32;-O2;-g;-Wall;-Werror;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
                LINK_OPTIONS "-m32"
                LINK_LIBRARIES "")
            add_test(NAME test_${CIPHER}_ct_32 COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_${CIPHER}_ct_32>)
        endif()
    endforeach()

    if (NAT_32BIT_TESTS)
        add_executable(test_nat_ct_32 test_nat_ct.c ../nat.c ../nat_div.c ../nat_mod.c ../nat_gcd.c ../nat_prime.c)
        target_compile_definitions(test_nat_ct_32 PRIVATE NAT_CTGRIND)
        set_target_properties(test_nat_ct_32 PROPERTIES
            COMPILE_OPTIONS "-m32;-O2;-g;-Wall;-Werror;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
            LINK_OPTIONS "-m32"
            LINK_LIBRARIES "")
        add_test(NAME test_nat_ct_32 COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_nat_ct_32>)

        add_executable(test_ec_nat_ct_32 test_ec_nat_ct.c ${EC_SOURCES} ${NAT_SOURCES})
        target_compile_definitions(test_ec_nat_ct_32 PRIVATE NAT_CTGRIND)
        set_target_properties(test_ec_nat_ct_32 PROPERTIES
            COMPILE_OPTIONS "-m32;-O2;-g;-Wall;-Werror;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
            LINK_OPTIONS "-m32"
            LINK_LIBRARIES "")
        add_test(NAME test_ec_nat_ct_32 COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_ec_nat_ct_32>)

        add_executable(test_nat_ct_32_sse2 test_nat_ct.c ../nat.c ../nat_div.c ../nat_mod.c ../nat_gcd.c ../nat_prime.c)
        target_compile_definitions(test_nat_ct_32_sse2 PRIVATE NAT_CTGRIND)
        set_target_properties(test_nat_ct_32_sse2 PROPERTIES
            COMPILE_OPTIONS "-m32;-msse2;-DUSE_SSE2;-O2;-g;-Wall;-Werror;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
            LINK_OPTIONS "-m32"
            LINK_LIBRARIES "")
        add_test(NAME test_nat_ct_32_sse2 COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_nat_ct_32_sse2>)

        add_executable(test_ec_nat_ct_32_sse2 test_ec_nat_ct.c ${EC_SOURCES} ${NAT_SOURCES})
        target_compile_definitions(test_ec_nat_ct_32_sse2 PRIVATE NAT_CTGRIND)
        set_target_properties(test_ec_nat_ct_32_sse2 PROPERTIES
            COMPILE_OPTIONS "-m32;-msse2;-DUSE_SSE2;-O2;-g;-Wall;-Werror;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
            LINK_OPTIONS "-m32"
            LINK_LIBRARIES "")
        add_test(NAME test_ec_nat_ct_32_sse2 COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_ec_nat_ct_32_sse2>)

        foreach(CURVE ed25519 curve25519)
            add_executable(test_${CURVE}_ct_32 test_${CURVE}_ct.c ../${CURVE}.c)
            target_compile_definitions(test_${CURVE}_ct_32 PRIVATE NAT_CTGRIND)
            set_target_properties(test_${CURVE}_ct_32 PROPERTIES
                COMPILE_OPTIONS "-m32;-O2;-g;-Wall;-Werror;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
                LINK_OPTIONS "-m32"
                LINK_LIBRARIES "")
            add_test(NAME test_${CURVE}_ct_32 COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_${CURVE}_ct_32>)

            add_executable(test_${CURVE}_ct_32_sse2 test_${CURVE}_ct.c ../${CURVE}.c)
            target_compile_definitions(test_${CURVE}_ct_32_sse2 PRIVATE NAT_CTGRIND)
            set_target_properties(test_${CURVE}_ct_32_sse2 PROPERTIES
                COMPILE_OPTIONS "-m32;-msse2;-DUSE_SSE2;-O2;-g;-Wall;-Werror;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
                LINK_OPTIONS "-m32"
                LINK_LIBRARIES "")
            add_test(NAME test_${CURVE}_ct_32_sse2 COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_${CURVE}_ct_32_sse2>)
        endforeach()
    endif()

    if (NAT_BMI2_ADX_TESTS)
        add_executable(test_nat_ct_bmi2_adx test_nat_ct.c ../nat_bmi2_adx.c)
        target_compile_definitions(test_nat_ct_bmi2_adx PRIVATE NAT_CTGRIND TEST_BMI2_ADX)
        set_target_properties(test_nat_ct_bmi2_adx PROPERTIES
            COMPILE_OPTIONS "-O2;-g;-Wall;-Werror;-mbmi2;-madx"
            LINK_OPTIONS ""
            LINK_LIBRARIES "")
        add_test(NAME test_nat_ct_bmi2_adx COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_nat_ct_bmi2_adx>)

        add_executable(test_ec_nat_ct_bmi2_adx test_ec_nat_ct.c ../ec_nat_bmi2_adx.c)
        target_compile_definitions(test_ec_nat_ct_bmi2_adx PRIVATE NAT_CTGRIND TEST_BMI2_ADX)
        set_target_properties(test_ec_nat_ct_bmi2_adx PROPERTIES
            COMPILE_OPTIONS "-O2;-g;-Wall;-Werror;-mbmi2;-madx"
            LINK_OPTIONS ""
            LINK_LIBRARIES "")
        add_test(NAME test_ec_nat_ct_bmi2_adx COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_ec_nat_ct_bmi2_adx>)
    endif()
endif()

# endianess
add_executable(test_endianess test_endianess.c)
add_test(NAME endianess COMMAND test_endianess)

# clmul
if (SSE)
  add_executable(test_clmul test_clmul.c ../ghash_clmul.c)
  add_test(NAME test_clmul COMMAND test_clmul)
endif()

# GHASH: portable, and CLMUL or PMULL when available
if (SSE)
  add_executable(test_ghash test_ghash.c ../ghash_portable.c ../ghash_clmul.c)
  target_compile_definitions(test_ghash PRIVATE TEST_CLMUL)
elseif (ARMV8_CRYPTO)
  add_executable(test_ghash test_ghash.c ../ghash_portable.c ../ghash_pmull.c)
  target_compile_definitions(test_ghash PRIVATE TEST_PMULL)
  if (NOT MSVC)
    set_source_files_properties(../ghash_pmull.c PROPERTIES COMPILE_OPTIONS "-march=armv8-a+crypto")
  endif()
else()
  add_executable(test_ghash test_ghash.c ../ghash_portable.c)
endif()
add_test(NAME test_ghash COMMAND test_ghash)

# poly1305
add_library(poly1305 OBJECT ../poly1305.c)
foreach (f reduce load_r load_m multiply accumulate)
    add_custom_command(
	OUTPUT test_poly1305_${f}.c
	COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/make_tests_poly1305_${f}.py > test_poly1305_${f}.c
	DEPENDS make_tests_poly1305_${f}.py
    )
    add_executable(test_poly1305_${f} ${CMAKE_BINARY_DIR}/test_poly1305_${f}.c $<TARGET_OBJECTS:poly1305>)
    add_test(NAME test_poly1305_${f} COMMAND test_poly1305_${f})
endforeach()

# pkcs1
add_executable(test_pkcs1 test_pkcs1.c ../pkcs1_decode.c)
add_test(NAME test_pkcs1 COMMAND test_pkcs1)

# CTR mode
add_executable(test_raw_ctr test_raw_ctr.c ../raw_ctr.c)
add_test(NAME test_raw_ctr COMMAND test_raw_ctr)

# Salsa20, for each way of computing the key stream
add_executable(test_salsa20 test_salsa20.c ../Salsa20.c)
if (MSVC)
    # Without SSE2, even if enabled for all the other tests
    target_compile_options(test_salsa20 PRIVATE /UUSE_SSE2)
endif()
add_test(NAME test_salsa20 COMMAND test_salsa20)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|i386|i686|X86|x86")
    add_executable(test_salsa20_sse2 test_salsa20.c ../Salsa20.c)
    target_compile_definitions(test_salsa20_sse2 PRIVATE USE_SSE2)
    if (MSVC)
        target_compile_definitions(test_salsa20_sse2 PRIVATE HAVE_INTRIN_H)
    else()
        target_compile_definitions(test_salsa20_sse2 PRIVATE HAVE_X86INTRIN_H)
        target_compile_options(test_salsa20_sse2 PRIVATE -msse2)
    endif()
    add_test(NAME test_salsa20_sse2 COMMAND test_salsa20_sse2)
endif()

# The AVX2 build (gcc and clang only). The test does nothing on a CPU without AVX2.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT MSVC)
    add_executable(test_salsa20_avx2 test_salsa20.c ../Salsa20_avx2_bmi2.c)
    target_compile_definitions(test_salsa20_avx2 PRIVATE TEST_SALSA20_AVX2 USE_SSE2 HAVE_X86INTRIN_H)
    target_compile_options(test_salsa20_avx2 PRIVATE -mavx2 -mbmi -mbmi2 -msse2)
    add_test(NAME test_salsa20_avx2 COMMAND test_salsa20_avx2)
endif()

# ChaCha20, for each way of computing the key stream
add_executable(test_chacha20 test_chacha20.c ../chacha20.c)
if (MSVC)
    # Without SSE2, even if enabled for all the other tests
    target_compile_options(test_chacha20 PRIVATE /UUSE_SSE2)
endif()
add_test(NAME test_chacha20 COMMAND test_chacha20)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64|i386|i686|X86|x86")
    add_executable(test_chacha20_sse2 test_chacha20.c ../chacha20.c)
    target_compile_definitions(test_chacha20_sse2 PRIVATE USE_SSE2)
    if (MSVC)
        target_compile_definitions(test_chacha20_sse2 PRIVATE HAVE_INTRIN_H)
    else()
        target_compile_definitions(test_chacha20_sse2 PRIVATE HAVE_X86INTRIN_H)
        target_compile_options(test_chacha20_sse2 PRIVATE -msse2)
    endif()
    add_test(NAME test_chacha20_sse2 COMMAND test_chacha20_sse2)
endif()

# The AVX2 build (gcc and clang only). The test does nothing on a CPU without AVX2.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64" AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND NOT MSVC)
    add_executable(test_chacha20_avx2 test_chacha20.c ../chacha20_avx2_bmi2.c)
    target_compile_definitions(test_chacha20_avx2 PRIVATE TEST_CHACHA20_AVX2 USE_SSE2 HAVE_X86INTRIN_H)
    target_compile_options(test_chacha20_avx2 PRIVATE -mavx2 -mbmi -mbmi2 -msse2)
    add_test(NAME test_chacha20_avx2 COMMAND test_chacha20_avx2)
endif()

# curve25519
add_library(mod25519 OBJECT ../mod25519.c)
add_library(curve25519 OBJECT ../curve25519.c)

add_executable(test_mod25519 test_mod25519.c $<TARGET_OBJECTS:mod25519>)
add_test(NAME test_mod25519 COMMAND test_mod25519)

add_custom_command(
    OUTPUT test_mul_25519.c
    COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/make_tests_mul_25519.py > test_mul_25519.c
    DEPENDS make_tests_mul_25519.py
)
add_executable(test_mul_25519 test_mul_25519.c $<TARGET_OBJECTS:mod25519>)
add_test(NAME test_mul_25519 COMMAND test_mul_25519)

add_executable(test_curve25519 test_curve25519.c $<TARGET_OBJECTS:curve25519>)
add_test(NAME test_curve25519 COMMAND test_curve25519)

add_custom_command(
    OUTPUT tests_ladder_step.c
    COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/make_tests_ladder_step.py > tests_ladder_step.c
    DEPENDS make_tests_ladder_step.py
)
add_executable(tests_ladder_step tests_ladder_step.c $<TARGET_OBJECTS:curve25519>)
add_test(NAME tests_ladder_step COMMAND tests_ladder_step)

# ed25519
add_executable(test_ed25519 test_ed25519.c ../ed25519.c)
add_test(NAME test_ed25519 COMMAND test_ed25519)
add_executable(test_ed25519_no_tables test_ed25519.c ../ed25519.c)
target_compile_definitions(test_ed25519_no_tables PRIVATE EC_NO_TABLES)
add_test(NAME test_ed25519_no_tables COMMAND test_ed25519_no_tables)

# aesni
if (AESNI)
  add_executable(test_aesni test_aesni.c ../AESNI.c)
  add_test(NAME test_aesni COMMAND test_aesni)
endif()

# AES with the ARMv8 Cryptography Extensions, against the portable AES
if (ARMV8_CRYPTO)
  add_executable(test_aes_armv8 test_aes_armv8.c ../AES_armv8.c ../AES.c)
  if (NOT MSVC)
    set_source_files_properties(../AES_armv8.c PROPERTIES COMPILE_OPTIONS "-march=armv8-a+crypto")
  endif()
  add_test(NAME test_aes_armv8 COMMAND test_aes_armv8)
endif()
