cmake_minimum_required(VERSION 3.13)
project(test_crypto LANGUAGES C)
include(CMakePrintHelpers)
enable_testing()

cmake_print_variables(CMAKE_CXX_COMPILER_ID CMAKE_CXX_COMPILER_VERSION CMAKE_SIZEOF_VOID_P SSE)

option(SSE "Enable SSE instructions on Intel targets" ON)

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
else()
    add_compile_definitions(HAVE_STDINT_H)
    add_compile_definitions(HAVE_POSIX_MEMALIGN)
    add_compile_options(-O2 -g -fstrict-aliasing -Wall -Werror)
    if( CMAKE_SIZEOF_VOID_P EQUAL 8 )
	# Macro HAVE_UINT128 should be defined when __uint128_t type is available,
	# that is, only on Unix 64 bits. It is not available with MSVC or with Unix 32 bits.
        add_compile_definitions(HAVE_UINT128)
    else()
	# On 32-bit x86 platforms, gcc assumes the stack to be aligned to 16
	# bytes, but the caller may actually only align it to 4 bytes, which
	# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=40838
	add_compile_options("-mstackrealign")
    endif()
endif()

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_compile_definitions(SYS_BITS=64)
else()
    add_compile_definitions(SYS_BITS=32)
endif()

# Use processor extensions
# TODO: add exception if non-x86 platform
if (MSVC)
    add_compile_definitions(HAVE_INTRIN_H)
    add_compile_definitions(USE_SSE2)
else()
    if (SSE)
	message(STATUS "Using SSE instructions")
        add_compile_definitions(HAVE_X86INTRIN_H)
    endif()
endif()

#add_compile_definitions(HAVE_WMMINTRIN_H)
#add_compile_definitions(HAVE_TMMINTRIN_H)

add_library(mont OBJECT ../mont.c)

add_library(tables OBJECT ../p256_table.c ../p384_table.c ../p521_table.c)
add_executable(test_ec_ws test_ec_ws.c ../ec_ws.c $<TARGET_OBJECTS:tables> $<TARGET_OBJECTS:mont>)
add_test(NAME test_ec_ws COMMAND test_ec_ws)

add_executable(test_endianess test_endianess.c)
add_test(NAME endianess COMMAND test_endianess)

add_custom_command(
	OUTPUT test_addmul_128.c
	COMMAND ${PYTHON} ${CMAKE_SOURCE_DIR}/make_tests_addmul128.py > test_addmul_128.c
	DEPENDS make_tests_addmul128.py
)
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
	add_executable(test_addmul128 ${CMAKE_BINARY_DIR}/test_addmul_128.c ../multiply_64.c)
else()
	add_executable(test_addmul128 ${CMAKE_BINARY_DIR}/test_addmul_128.c ../multiply_32.c)
endif()
add_test(NAME test_addmul128 COMMAND test_addmul128)
