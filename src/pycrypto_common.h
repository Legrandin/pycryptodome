/*
 *  pycrypto_common.h: Common header file for PyCrypto
 *
 * Written in 2013 by Dwayne C. Litzenberger <dlitz@dlitz.net>
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain.  To
 * the extent that dedication to the public domain is not available,
 * everyone is granted a worldwide, perpetual, royalty-free,
 * non-exclusive license to exercise all rights associated with the
 * contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ===================================================================
 */
#ifndef PYCRYPTO_COMMON_H
#define PYCRYPTO_COMMON_H

#define _PASTE(x,y) x##y
#define _PASTE2(x,y) _PASTE(x,y)

#ifdef _MSC_VER

typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

#define inline _inline

#include <malloc.h>

#else /** Not MSC **/
#include <stdint.h>
#endif

#include <stdlib.h>
#include <string.h>

/** Force checking of assertions **/
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>


#include "errors.h"

/*
 * On Windows, distutils expects that a CPython module always exports the symbol init${MODNAME}
 */
#if defined(_MSC_VER) || defined(__MINGW32__)
#include <Python.h>
#if PY_MAJOR_VERSION >= 3
#define FAKE_INIT(x) PyMODINIT_FUNC _PASTE2(PyInit__,x) (void) { return NULL; }
#else
#define FAKE_INIT(x) PyMODINIT_FUNC _PASTE2(init_,x) (void) { return; }
#endif
#else
#define FAKE_INIT(x)
#endif

/*
 * On Windows, functions must be explicitly marked for export.
 */
#if defined(_MSC_VER) || defined(__MINGW32__)
#define EXPORT_SYM __declspec(dllexport)
#else
#define EXPORT_SYM
#endif

#endif /* PYCRYPTO_COMMON_H */
