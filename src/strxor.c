/*
 *  strxor.c: string XOR functions
 *
 * =======================================================================
 * Copyright (C) 2008  Dwayne C. Litzenberger <dlitz@dlitz.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * =======================================================================
 */

#include "Python.h"
#include <stddef.h>
#include <assert.h>
#include <string.h>

#include "pycrypto_compat.h"

static const char rcsid[] = "$Id$";

/*
 * xor_strings - XOR two strings together to produce a third string
 *
 * dest[0..n-1] := src_a[0..n-1] ^ src_b[0..n-1]
 *
 */
static void
xor_strings(char *dest, const char *src_a, const char *src_b, size_t n)
{
    size_t i;

    /* assert no pointer overflow */
    assert(src_a + n > src_a);
    assert(src_b + n > src_b);
    assert(dest + n > dest);

    for (i = 0; i < n; i++) {
        dest[i] = src_a[i] ^ src_b[i];
    }
}

/*
 * xor_string_with_char - XOR a string with a char to produce another string
 *
 * dest[0..n-1] := src[0..n-1] ^ c
 *
 */
static void
xor_string_with_char(char *dest, const char *src, char c, size_t n)
{
    size_t i;

    /* assert no pointer overflow */
    assert(src + n > src);
    assert(dest + n > dest);

    for (i = 0; i < n; i++) {
        dest[i] = src[i] ^ c;
    }
}

/*
 * "Import assertions"
 *
 * These runtime checks are performed when this module is first initialized
 *
 */

#define IMP_ASSERT(exp) do {\
    if (!(exp)) {\
        PyErr_Format(PyExc_AssertionError, "%s:%d: assertion failure: '%s'", __FILE__, __LINE__, #exp);\
        return;\
    }\
} while(0)

static void
runtime_test(void)
{
    /* size_t should be able to represent the length of any size buffer */
    IMP_ASSERT(sizeof(size_t) == sizeof(void *));

    /* we must be able to perform the assignment (Py_ssize_t) -> (size_t)
     * as long as the value is non-negative. */
    IMP_ASSERT(sizeof(size_t) >= sizeof(Py_ssize_t));

    /* char must be one octet */
    IMP_ASSERT(sizeof(char) == 1);

    /* Perform a basic test of the xor_strings function, including a test for
     * an off-by-one bug. */
    {
        char x[7] = "\x00hello";    /* NUL + "hello" + NUL */
        char y[7] = "\xffworld";    /* 0xff + "world" + NUL */
        char z[9] = "[ABCDEFG]";    /* "[ABCDEFG]" + NUL */

        xor_strings(z+1, x, y, 7);
        IMP_ASSERT(!memcmp(z, "[\xff\x1f\x0a\x1e\x00\x0b\x00]", 9));
    }

    /* Perform a basic test of the xor_string_with_char function, including a test for
     * an off-by-one bug. */
    {
        char x[7] = "\x00hello";    /* NUL + "hello" + NUL */
        char y = 170;               /* 0xaa */
        char z[9] = "[ABCDEFG]";    /* "[ABCDEFG]" + NUL */

        xor_string_with_char(z+1, x, y, 7);
        IMP_ASSERT(!memcmp(z, "[\xaa\xc2\xcf\xc6\xc6\xc5\xaa]", 9));
    }
}

/*
 * The strxor Python function
 */

static char strxor__doc__[] =
"strxor(a:str, b:str) -> str\n"
"\n"
"Return a XOR b.  Both a and b must have the same length.\n";

static PyObject *
strxor_function(PyObject *self, PyObject *args)
{
    PyObject *a, *b, *retval;
    Py_ssize_t len_a, len_b;

    if (!PyArg_ParseTuple(args, "SS", &a, &b))
        return NULL;

    len_a = PyString_GET_SIZE(a);
    len_b = PyString_GET_SIZE(b);

    assert(len_a >= 0);
    assert(len_b >= 0);

    if (len_a != len_b) {
        PyErr_SetString(PyExc_ValueError, "length of both strings must be equal");
        return NULL;
    }

    /* Create return string */
    retval = PyString_FromStringAndSize(NULL, len_a);
    if (!retval) {
        return NULL;
    }

    /* retval := a ^ b */
    xor_strings(PyString_AS_STRING(retval), PyString_AS_STRING(a), PyString_AS_STRING(b), len_a);

    return retval;
}

/*
 * The strxor_c Python function
 */

static char strxor_c__doc__[] =
"strxor_c(s:str, c:int) -> str\n"
"\n"
"Return s XOR chr(c).  c must be in range(256).\n";

static PyObject *
strxor_c_function(PyObject *self, PyObject *args)
{
    PyObject *s, *retval;
    int c;
    Py_ssize_t length;

    if (!PyArg_ParseTuple(args, "Si", &s, &c))
        return NULL;

    if ((c < 0) || (c > 255)) {
        PyErr_SetString(PyExc_ValueError, "c must be in range(256)");
        return NULL;
    }

    length = PyString_GET_SIZE(s);
    assert(length >= 0);

    /* Create return string */
    retval = PyString_FromStringAndSize(NULL, length);
    if (!retval) {
        return NULL;
    }

    /* retval := a ^ chr(c)*length */
    xor_string_with_char(PyString_AS_STRING(retval), PyString_AS_STRING(s), (char) c, length);

    return retval;
}

/*
 * Module-level method table and module initialization function
 */

static PyMethodDef strxor_methods[] = {
    {"strxor", strxor_function, METH_VARARGS, strxor__doc__},
    {"strxor_c", strxor_c_function, METH_VARARGS, strxor_c__doc__},

    {NULL, NULL, 0, NULL}   /* end-of-list sentinel value */
};

PyMODINIT_FUNC
initstrxor(void)
{
    PyObject *m;

    /* Initialize the module */
    m = Py_InitModule("strxor", strxor_methods);
    if (m == NULL)
        return;

    /* Perform runtime tests */
    runtime_test();
}

/* vim:set ts=4 sw=4 sts=4 expandtab: */
