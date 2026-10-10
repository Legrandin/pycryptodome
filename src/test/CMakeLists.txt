cmake_minimum_required(VERSION 3.13)
project(test_crypto LANGUAGES C)
include(CMakePrintHelpers)
enable_testing()

cmake_print_variables(CMAKE_CXX_COMPILER_ID CMAKE_CXX_COMPILER_VERSION CMAKE_SIZEOF_VOID_P SSE CMAKE_C_COMPILER_ARCHITECTURE_ID)

if (CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "x86_64|AMD64|i686|X86|x64")
    set(X86 TRUE)
endif()

if (X86)
   message(STATUS "Enabling SSE and AESNI")
   option(SSE "Enable SSE instructions on Intel targets" ON)
   option(AESNI "Enable AESNI instructions on Intel targets" ON)
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
    add_compile_options(-fsanitize=undefined -fsanitize=address)
    link_libraries(-lubsan)
    add_link_options(-fsanitize=address)
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

# montgomery
add_library(mont OBJECT ../mont.c)

add_executable(test_mont test_mont.c $<TARGET_OBJECTS:mont>)
add_test(NAME test_mont COMMAND test_mont)

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
    endif()
endif()

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

    if (NAT_32BIT_TESTS)
        add_executable(test_nat_ct_32 test_nat_ct.c ../nat.c ../nat_div.c ../nat_mod.c ../nat_gcd.c ../nat_prime.c)
        target_compile_definitions(test_nat_ct_32 PRIVATE NAT_CTGRIND)
        set_target_properties(test_nat_ct_32 PROPERTIES
            COMPILE_OPTIONS "-m32;-O2;-g;-Wall;-Werror;-UHAVE_UINT128;-USYS_BITS;-DSYS_BITS=32"
            LINK_OPTIONS "-m32"
            LINK_LIBRARIES "")
        add_test(NAME test_nat_ct_32 COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_nat_ct_32>)
    endif()

    if (NAT_BMI2_ADX_TESTS)
        add_executable(test_nat_ct_bmi2_adx test_nat_ct.c ../nat_bmi2_adx.c)
        target_compile_definitions(test_nat_ct_bmi2_adx PRIVATE NAT_CTGRIND TEST_BMI2_ADX)
        set_target_properties(test_nat_ct_bmi2_adx PROPERTIES
            COMPILE_OPTIONS "-O2;-g;-Wall;-Werror;-mbmi2;-madx"
            LINK_OPTIONS ""
            LINK_LIBRARIES "")
        add_test(NAME test_nat_ct_bmi2_adx COMMAND ${VALGRIND} -q --error-exitcode=1 $<TARGET_FILE:test_nat_ct_bmi2_adx>)
    endif()
endif()

add_custom_command(
    OUTPUT test_addmul.c
    COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/make_tests_addmul.py > test_addmul.c
    DEPENDS make_tests_addmul.py
)
add_executable(test_addmul test_addmul.c $<TARGET_OBJECTS:mont>)
add_test(NAME test_addmul COMMAND test_addmul)

add_custom_command(
    OUTPUT test_addmul_128.c
    COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/make_tests_addmul128.py > test_addmul_128.c
    DEPENDS make_tests_addmul128.py
)
add_executable(test_addmul128 ${CMAKE_BINARY_DIR}/test_addmul_128.c)
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_sources(test_addmul128 PUBLIC ../multiply_64.c)
else()
    target_sources(test_addmul128 PUBLIC ../multiply_32.c)
endif()
add_test(NAME test_addmul128 COMMAND test_addmul128)

add_custom_command(
    OUTPUT test_product.c
    COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/make_tests_product.py > test_product.c
    DEPENDS make_tests_product.py
)
add_executable(test_product test_product.c $<TARGET_OBJECTS:mont>)
add_test(NAME test_product COMMAND test_product)

add_custom_command(
    OUTPUT test_mont_mult.c
    COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/make_tests_mont_mult.py > test_mont_mult.c
    DEPENDS make_tests_mont_mult.py
)
add_executable(test_mont_mult test_mont_mult.c $<TARGET_OBJECTS:mont>)
add_test(NAME test_mont_mult COMMAND test_mont_mult)

# ec_ws
add_library(tables OBJECT ../p256_table.c ../p384_table.c ../p521_table.c)
add_executable(test_ec_ws test_ec_ws.c ../ec_ws.c $<TARGET_OBJECTS:tables> $<TARGET_OBJECTS:mont>)
add_test(NAME test_ec_ws COMMAND test_ec_ws)

# endianess
add_executable(test_endianess test_endianess.c)
add_test(NAME endianess COMMAND test_endianess)

# clmul
if (SSE)
  add_executable(test_clmul test_clmul.c ../ghash_clmul.c)
  add_test(NAME test_clmul COMMAND test_clmul)
endif()

# GHASH: portable, and CLMUL when available
if (SSE)
  add_executable(test_ghash test_ghash.c ../ghash_portable.c ../ghash_clmul.c)
  target_compile_definitions(test_ghash PRIVATE TEST_CLMUL)
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

# curve25519
add_library(mod25519 OBJECT ../mod25519.c ../multiply_32.c)
add_library(curve25519 OBJECT ../curve25519.c ../multiply_32.c)

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
add_executable(test_ed25519 test_ed25519.c ../ed25519.c ../multiply_32.c)
add_test(NAME test_ed25519 COMMAND test_ed25519)

# ed448
add_executable(test_ed448 test_ed448.c ../ed448.c $<TARGET_OBJECTS:mont>)
add_test(NAME test_ed448 COMMAND test_ed448)

# curve448
add_executable(test_curve448 test_curve448.c ../curve448.c $<TARGET_OBJECTS:mont>)
add_test(NAME test_curve448 COMMAND test_curve448)

# aesni
if (AESNI)
  add_executable(test_aesni test_aesni.c ../AESNI.c)
  add_test(NAME test_aesni COMMAND test_aesni)
endif()
