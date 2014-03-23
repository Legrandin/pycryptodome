#                                               -*- Autoconf -*-
# PyCrypto's configure.ac file.
# Process this file with autoconf to produce a configure script.
#
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

AC_PREREQ([2.67])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([src/pycrypto_compat.h])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_FILES([buildenv])

AM_INIT_AUTOMAKE([foreign no-define no-dist])

# Checks for programs.
AC_PROG_CC_C99

AC_CANONICAL_HOST()
case "$host_os" in  # XXX - Does this break cross-compiling?
openbsd*)
    # According to gcc-local(1), OpenBSD's gcc is modified to ignore /usr/local
    # by default.  However, libgmp is usually installed to /usr/local, so we
    # want to look there for the libraries.
    CFLAGS="$CFLAGS -I/usr/local/include"
    LDFLAGS="$LDFLAGS -L/usr/local/lib"
    ;;
*)
    ;;
esac

AX_CHECK_COMPILE_FLAG([-Wall], [AX_APPEND_FLAG([-Wall])])
AX_CHECK_COMPILE_FLAG([-Wextra], [AX_APPEND_FLAG([-Wextra])])
AX_CHECK_COMPILE_FLAG([-Wno-missing-field-initializers], [AX_APPEND_FLAG([-Wno-missing-field-initializers])])
AX_CHECK_COMPILE_FLAG([-Wno-unused-parameter], [AX_APPEND_FLAG([-Wno-unused-parameter])])
AX_CHECK_COMPILE_FLAG([-maes], [
    have_maes=yes
    AC_DEFINE(HAVE_MAES, [1], [Define if CC supports -maes])
])

# Checks for libraries.
AC_ARG_WITH([gmp], AS_HELP_STRING([--without-gmp], [Build without gmp library (default: test)]))
AS_IF([test "x$with_gmp" != "xno"], [
  AC_CHECK_LIB([gmp], [__gmpz_init])
])

AC_ARG_WITH([mpir], AS_HELP_STRING([--without-mpir], [Build without mpir library (default: test)]))
AS_IF([test "x$with_mpir" != "xno"], [
  AC_CHECK_LIB([mpir], [__gmpz_init])
])

AC_CHECK_DECLS([mpz_powm], [], [], [
[#if HAVE_LIBGMP
# include <gmp.h>
#elif HAVE_LIBMPIR
# include <mpir.h>
#endif
]])
AC_CHECK_DECLS([mpz_powm_sec], [], [], [
[#if HAVE_LIBGMP
# include <gmp.h>
#elif HAVE_LIBMPIR
# include <mpir.h>
#endif
]])

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h sys/inttypes.h cpuid.h limits.h stddef.h stdint.h stdlib.h string.h wchar.h])
old_CPPFLAGS="$CPPFLAGS"
AS_IF([test "x$have_maes" = "xyes"], [
    CPPFLAGS="$CPPFLAGS -maes"
])
AC_CHECK_HEADERS([wmmintrin.h])
CPPFLAGS="$old_CPPFLAGS"

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINTPTR_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memmove memset])
AC_CHECK_FUNCS([posix_memalign aligned_alloc _aligned_malloc])

AC_OUTPUT
