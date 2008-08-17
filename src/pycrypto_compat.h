/*
 *  pycrypto_compat.h: Compatibility with older versions of Python
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
#ifndef PYCRYPTO_COMPAT_H
#define PYCRYPTO_COMPAT_H

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
