/*
 *  _counter.c: Fast counter for use with CTR-mode ciphers
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

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "Python.h"

#include "pycrypto_compat.h"

typedef struct {
    PyObject_HEAD;
    PyStringObject *prefix;     /* Prefix (useful for a nonce) */
    PyStringObject *suffix;     /* Suffix (useful for a nonce) */
    uint8_t *val;       /* Buffer for our output string */
    uint32_t buf_size;  /* Size of the buffer */
    uint8_t *p;         /* Pointer to the part of the buffer that we're allowed to update */
    uint16_t nbytes;    /* The number of bytes that from .p that are part of the counter */
} my_CounterObject;

/* NB: This can be called multiple times for a given object, via the __init__ method.  Be careful. */
static int
CounterObject_init(my_CounterObject *self, PyObject *args, PyObject *kwargs)
{
    PyStringObject *prefix=NULL, *suffix=NULL, *initval=NULL;
    Py_ssize_t size;

    if (!PyArg_ParseTuple(args, "SSS", &prefix, &suffix, &initval))
        return -1;

    /* Check string size and set nbytes */
    size = PyString_GET_SIZE(initval);
    if (size < 1) {
        PyErr_SetString(PyExc_ValueError, "initval length too small (must be >= 1 byte)");
        return -1;
    } else if (size > 0xffff) {
        PyErr_SetString(PyExc_ValueError, "initval length too large (must be <= 65535 bytes)");
        return -1;
    }
    self->nbytes = (uint16_t) size;

    /* Check prefix length */
    size = PyString_GET_SIZE(prefix);
    assert(size >= 0);
    if (size > 0xffff) {
        PyErr_SetString(PyExc_ValueError, "prefix length too large (must be <= 65535 bytes)");
        return -1;
    }

    /* Check suffix length */
    size = PyString_GET_SIZE(suffix);
    assert(size >= 0);
    if (size > 0xffff) {
        PyErr_SetString(PyExc_ValueError, "suffix length too large (must be <= 65535 bytes)");
        return -1;
    }

    /* Set prefix, being careful to properly discard any old reference */
    Py_CLEAR(self->prefix);
    Py_INCREF(prefix);
    self->prefix = prefix;

    /* Set prefix, being careful to properly discard any old reference */
    Py_CLEAR(self->suffix);
    Py_INCREF(suffix);
    self->suffix = suffix;

    /* Free old buffer (if any) */
    if (self->val) {
        PyMem_Free(self->val);
        self->val = self->p = NULL;
        self->buf_size = 0;
    }

    /* Allocate new buffer */
    /* buf_size won't overflow because the length of each string will always be <= 0xffff */
    self->buf_size = PyString_GET_SIZE(prefix) + PyString_GET_SIZE(suffix) + self->nbytes;
    self->val = self->p = PyMem_Malloc(self->buf_size);
    if (self->val == NULL) {
        self->buf_size = 0;
        return -1;
    }
    self->p = self->val + PyString_GET_SIZE(prefix);

    /* Copy the prefix, suffix, and initial value into the buffer. */
    memcpy(self->val, PyString_AS_STRING(prefix), PyString_GET_SIZE(prefix));
    memcpy(self->p, PyString_AS_STRING(initval), self->nbytes);
    memcpy(self->p + self->nbytes, PyString_AS_STRING(suffix), PyString_GET_SIZE(suffix));

    return 0;
}

static void
CounterObject_dealloc(my_CounterObject *self)
{
    /* Free the buffer */
    if (self->val) {
        memset(self->val, 0, self->buf_size);   /* wipe the buffer before freeing it */
        PyMem_Free(self->val);
        self->val = self->p = NULL;
        self->buf_size = 0;
    }

    /* Deallocate the prefix and suffix, if they are present. */
    Py_CLEAR(self->prefix);
    Py_CLEAR(self->suffix);

    /* Free this object */
    self->ob_type->tp_free((PyObject*)self);
}

static inline PyObject *
_CounterObject_get_value(my_CounterObject *self, int little_endian)
{
    unsigned int i, increment;
    uint8_t *p;
    PyObject *eight = NULL;
    PyObject *ch = NULL;
    PyObject *y = NULL;
    PyObject *x = NULL;

    eight = PyInt_FromLong(8);
    if (!eight)
        goto err_out;

    /* Make a new Python long integer */
    x = PyLong_FromUnsignedLong(0);
    if (!x)
        goto err_out;

    if (little_endian) {
        /* little endian */
        p = self->p + self->nbytes - 1;
        increment = -1;
    } else {
        /* big endian */
        p = self->p;
        increment = 1;
    }
    for (i = 0; i < self->nbytes; i++, p += increment) {
        /* ch = ord(p) */
        Py_CLEAR(ch);   /* delete old ch */
        ch = PyInt_FromLong((long) *p);
        if (!ch)
            goto err_out;

        /* y = x << 8 */
        Py_CLEAR(y);    /* delete old y */
        y = PyNumber_Lshift(x, eight);
        if (!y)
            goto err_out;

        /* x = y | ch */
        Py_CLEAR(x);    /* delete old x */
        x = PyNumber_Or(y, ch);
    }

    Py_CLEAR(eight);
    Py_CLEAR(ch);
    Py_CLEAR(y);
    return x;

err_out:
    Py_CLEAR(eight);
    Py_CLEAR(ch);
    Py_CLEAR(y);
    Py_CLEAR(x);
    return NULL;
}

static PyObject *
CounterLEObject_get_value(my_CounterObject *self)
{
    return _CounterObject_get_value(self, 1);
}

static PyObject *
CounterBEObject_get_value(my_CounterObject *self)
{
    return _CounterObject_get_value(self, 0);
}

static PyObject *
CounterLEObject_next(my_CounterObject *self)
{
    unsigned int i, tmp, carry;
    uint8_t *p;
    PyObject *retval;

    assert(sizeof(i) >= sizeof(self->nbytes));

    retval = (PyObject *)PyString_FromStringAndSize((const char *)self->val, self->buf_size);

    carry = 1;
    p = self->p;
    for (i = 0; i < self->nbytes; i++, p++) {
        tmp = *p + carry;
        carry = tmp >> 8;   /* This will only ever be 0 or 1 */
        *p = tmp & 0xff;
    }

    return retval;
}

static PyObject *
CounterBEObject_next(my_CounterObject *self)
{
    unsigned int i, tmp, carry;
    uint8_t *p;
    PyObject *retval;

    assert(sizeof(i) >= sizeof(self->nbytes));

    retval = (PyObject *)PyString_FromStringAndSize((const char *)self->val, self->buf_size);

    carry = 1;
    p = self->p + self->nbytes-1;
    for (i = 0; i < self->nbytes; i++, p--) {
        tmp = *p + carry;
        carry = tmp >> 8;   /* This will only ever be 0 or 1 */
        *p = tmp & 0xff;
    }

    return retval;
}

static PyMethodDef CounterLEObject_methods[] = {
    {"next", (PyCFunction)CounterLEObject_next, METH_NOARGS,
        "Return the current counter value, then increment it."},
    {"get_value", (PyCFunction)CounterLEObject_get_value, METH_NOARGS,
        "Get the numerical value of the counter.\n\nThis is a slow operation.\n"},

    {NULL} /* sentinel */
};

static PyMethodDef CounterBEObject_methods[] = {
    {"next", (PyCFunction)CounterBEObject_next, METH_NOARGS,
        "Return the current counter value, then increment it."},
    {"get_value", (PyCFunction)CounterBEObject_get_value, METH_NOARGS,
        "Get the numerical value of the counter.\n\nThis is a slow operation.\n"},

    {NULL} /* sentinel */
};

static PyTypeObject
my_CounterLEType = {
    PyObject_HEAD_INIT(NULL)
    0,                              /* ob_size */
	"_counter.CounterLE",           /* tp_name */
	sizeof(my_CounterObject),       /* tp_basicsize */
    0,                              /* tp_itemsize */
    (destructor)CounterObject_dealloc, /* tp_dealloc */
    0,                              /* tp_print */
    0,                              /* tp_getattr */
    0,                              /* tp_setattr */
    0,                              /* tp_compare */
    0,                              /* tp_repr */
    0,                              /* tp_as_number */
    0,                              /* tp_as_sequence */
    0,                              /* tp_as_mapping */
    0,                              /* tp_hash */
    0,                              /* tp_call */
    0,                              /* tp_str */
    0,                              /* tp_getattro */
    0,                              /* tp_setattro */
    0,                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,             /* tp_flags */
    "Counter (little endian)",      /* tp_doc */
    0,                              /* tp_traverse */
    0,                              /* tp_clear */
    0,                              /* tp_richcompare */
    0,                              /* tp_weaklistoffset */
    0,                              /* tp_iter */
    0,                              /* tp_iternext */
    CounterLEObject_methods,        /* tp_methods */
    0,                              /* tp_members */
    0,                              /* tp_getset */
    0,                              /* tp_base */
    0,                              /* tp_dict */
    0,                              /* tp_descr_get */
    0,                              /* tp_descr_set */
    0,                              /* tp_dictoffset */
    (initproc)CounterObject_init,   /* tp_init */
    0,                              /* tp_alloc */
    0                               /* tp_new */
};

static PyTypeObject
my_CounterBEType = {
    PyObject_HEAD_INIT(NULL)
    0,                              /* ob_size */
	"_counter.CounterBE",           /* tp_name */
	sizeof(my_CounterObject),       /* tp_basicsize */
    0,                              /* tp_itemsize */
    (destructor)CounterObject_dealloc, /* tp_dealloc */
    0,                              /* tp_print */
    0,                              /* tp_getattr */
    0,                              /* tp_setattr */
    0,                              /* tp_compare */
    0,                              /* tp_repr */
    0,                              /* tp_as_number */
    0,                              /* tp_as_sequence */
    0,                              /* tp_as_mapping */
    0,                              /* tp_hash */
    0,                              /* tp_call */
    0,                              /* tp_str */
    0,                              /* tp_getattro */
    0,                              /* tp_setattro */
    0,                              /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,             /* tp_flags */
    "Counter (big endian)",         /* tp_doc */
    0,                              /* tp_traverse */
    0,                              /* tp_clear */
    0,                              /* tp_richcompare */
    0,                              /* tp_weaklistoffset */
    0,                              /* tp_iter */
    0,                              /* tp_iternext */
    CounterBEObject_methods,        /* tp_methods */
    0,                              /* tp_members */
    0,                              /* tp_getset */
    0,                              /* tp_base */
    0,                              /* tp_dict */
    0,                              /* tp_descr_get */
    0,                              /* tp_descr_set */
    0,                              /* tp_dictoffset */
    (initproc)CounterObject_init,   /* tp_init */
    0,                              /* tp_alloc */
    0                               /* tp_new */
};

/*
 * Module-level method table and module initialization function
 */

static PyMethodDef module_methods[] = {
    {NULL, NULL, 0, NULL}   /* end-of-list sentinel value */
};


PyMODINIT_FUNC
init_counter(void)
{
    PyObject *m;

    /* TODO - Is the error handling here correct? */

    /* Initialize the module */
    m = Py_InitModule("_counter", module_methods);
    if (m == NULL)
        return;

    /* Create the CounterLE type */
    my_CounterLEType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&my_CounterLEType) < 0)
        return;
    Py_INCREF(&my_CounterLEType);
    PyModule_AddObject(m, "CounterLE", (PyObject *)&my_CounterLEType);

    /* Create the CounterBE type */
    my_CounterBEType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&my_CounterBEType) < 0)
        return;
    Py_INCREF(&my_CounterBEType);
    PyModule_AddObject(m, "CounterBE", (PyObject *)&my_CounterBEType);
}

/* vim:set ts=4 sw=4 sts=4 expandtab: */
