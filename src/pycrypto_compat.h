/*
 *  pycrypto_compat.h: Compatibility with older versions of Python
 *
 * Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
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
#ifndef PYCRYPTO_COMPAT_H
#define PYCRYPTO_COMPAT_H
#include "Python.h"

/*
 * Python 3.x defines, for conditional compiles
 */

#if PY_MAJOR_VERSION >= 3
# define IS_PY3K
# define PyInt_AS_LONG PyLong_AS_LONG
# define PyInt_CheckExact PyLong_CheckExact
# define PyInt_FromLong PyLong_FromLong
# define PyString_Check PyUnicode_Check
# define PyString_CompareWithASCIIString PyUnicode_CompareWithASCIIString
# define PyString_FromString PyUnicode_FromString
# define staticforward static
#else
# define PyBytes_GET_SIZE PyString_GET_SIZE
# define PyBytes_FromStringAndSize PyString_FromStringAndSize
# define PyBytes_AS_STRING PyString_AS_STRING
# define PyBytes_Check PyString_Check
# define PyBytes_Size PyString_Size
# define PyBytes_AsString PyString_AsString
# define PyBytesObject PyStringObject
# define PyString_CompareWithASCIIString(o,s) \
    (PyString_Check(o) ? strcmp(PyString_AsString(o),(s)) : -1)  /* NB: only compares up to the first NUL byte */
# if PY_MINOR_VERSION <= 5 /* Python 2.5 and earlier */
#  define Py_TYPE(v) ((v)->ob_type)
#  define PyLong_MASK MASK
#  define PyLong_SHIFT SHIFT
#  define PyVarObject_HEAD_INIT(a,b) PyObject_HEAD_INIT(a) 0,
# endif
# if PY_MINOR_VERSION <= 1 /* Python 2.1 only */
#  define METH_O METH_OLDARGS   /* METH_O is a subset of what METH_OLDARGS provides */
#  define PyInt_CheckExact PyInt_Check
#  define PyString_CheckExact PyString_Check
#  define PyType_Ready(t) (((t)->ob_type = &PyType_Type) ? 0 : 0)
# endif
#endif

/* Python 2.1 doesn't have PyModule_AddIntConstant */
#if PYTHON_API_VERSION < 1011
#define PyModule_AddIntConstant(m,n,v)  \
    do { \
        PyObject *o=PyInt_FromLong(v); \
        if (o!=NULL) { \
            PyObject_SetAttrString((m),(n),o); \
            Py_DECREF(o); \
        } \
    } while(0)
#endif

/*
 * Py_CLEAR for Python < 2.4
 * See http://docs.python.org/api/countingRefs.html
 */
#if PY_VERSION_HEX < 0x02040000 && !defined(Py_CLEAR)
#define Py_CLEAR(obj) \
    do {\
        PyObject *tmp = (PyObject *)(obj);\
        (obj) = NULL;\
        Py_XDECREF(tmp);\
    } while(0)
#endif

/*
 * Compatibility code for Python < 2.5 (see PEP 353)
 * PEP 353 has been placed into the public domain, so we can use this code
 * without restriction.
 */
#if PY_VERSION_HEX < 0x02050000 && !defined(PY_SSIZE_T_MIN)
typedef int Py_ssize_t;
#define PY_SSIZE_T_MAX INT_MAX
#define PY_SSIZE_T_MIN INT_MIN
#endif

/* Compatibility code for Python < 2.3 */
#if PY_VERSION_HEX < 0x02030000
typedef void PyMODINIT_FUNC;
#endif

#endif /* PYCRYPTO_COMPAT_H */
/* vim:set ts=4 sw=4 sts=4 expandtab: */
