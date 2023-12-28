cmake_minimum_required(VERSION 3.13)
project(test_crypto LANGUAGES C)
include(CMakePrintHelpers)
enable_testing()

cmake_print_variables(CMAKE_CXX_COMPILER_ID CMAKE_CXX_COMPILER_VERSION CMAKE_SIZEOF_VOID_P CMAKE_SYSTEM_PROCESSOR SSE)

# https://stackoverflow.com/questions/70475665/what-are-the-possible-values-of-cmake-system-processor
if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i686")
    set(X86 TRUE)
endif()

if (X86)
   option(SSE "Enable SSE instructions on Intel targets" ON)
   option(AESNI "Enable AESNI instructions on Intel targets" ON)
endif()

if (DEFINED ENV{PYTHON})
    set(PYTHON $ENV{PYTHON})
else()
    set(PYTHON python)
endif()

include_directories("${CMAKE_SOURCE_DIR}/..")

# Disable any code related to CPython modules
# This is only required for MSVC, and it avoids a dependency on the CPython libraries
add_compile_definitions(NO_CPYTHON_MODULE)

# Ensure that private functions can be accessed
add_compile_definitions(STATIC=)

# TODO: add check for big endianess too
add_compile_definitions(PYCRYPTO_LITTLE_ENDIAN)

if (MSVC)
    add_compile_options(/Wall /sdl)
    # Disable certain warnings
    add_compile_options(/wd4100 /wd4820 /wd5045)
else()
    add_compile_definitions(HAVE_STDINT_H)
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
    add_compile_definitions(HAVE_INTRIN_H)
    add_compile_definitions(USE_SSE2)
    add_compile_definitions(HAVE_WMMINTRIN_H)
    add_compile_definitions(HAVE_TMMINTRIN_H)
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

# curve25519
add_library(mod25519 OBJECT ../mod25519.c ../multiply_32.c)
add_library(x25519 OBJECT ../x25519.c ../multiply_32.c)

add_executable(test_mod25519 test_mod25519.c $<TARGET_OBJECTS:mod25519>)
add_test(NAME test_mod25519 COMMAND test_mod25519)

add_custom_command(
    OUTPUT test_mul_25519.c
    COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/make_tests_mul_25519.py > test_mul_25519.c
    DEPENDS make_tests_mul_25519.py
)
add_executable(test_mul_25519 test_mul_25519.c $<TARGET_OBJECTS:mod25519>)
add_test(NAME test_mul_25519 COMMAND test_mul_25519)

add_executable(test_x25519 test_x25519.c $<TARGET_OBJECTS:x25519>)
add_test(NAME test_x25519 COMMAND test_x25519)

add_custom_command(
    OUTPUT tests_ladder_step.c
    COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/make_tests_ladder_step.py > tests_ladder_step.c
    DEPENDS make_tests_ladder_step.py
)
add_executable(tests_ladder_step tests_ladder_step.c $<TARGET_OBJECTS:x25519>)
add_test(NAME tests_ladder_step COMMAND tests_ladder_step)

# ed25519
add_executable(test_ed25519 test_ed25519.c ../ed25519.c ../multiply_32.c)
add_test(NAME test_ed25519 COMMAND test_ed25519)

# ed448
add_executable(test_ed448 test_ed448.c ../ed448.c $<TARGET_OBJECTS:mont>)
add_test(NAME test_ed448 COMMAND test_ed448)

# aesni
if (AESNI)
  add_executable(test_aesni test_aesni.c ../AESNI.c)
  add_test(NAME test_aesni COMMAND test_aesni)
endif()
