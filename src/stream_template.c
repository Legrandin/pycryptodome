/* -*- C -*- */

/*
 *  stream_template.c : Generic framework for stream ciphers
 *
 * Written by Andrew Kuchling and others
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

#include "pycrypto_common.h"
#include "modsupport.h"

#define _STR(x) #x
#define _XSTR(x) _STR(x)
#define _PASTE(x,y) x##y
#define _PASTE2(x,y) _PASTE(x,y)
#ifdef IS_PY3K
#define _MODULE_NAME _PASTE2(PyInit_,MODULE_NAME)
#else
#define _MODULE_NAME _PASTE2(init,MODULE_NAME)
#endif
#define _MODULE_STRING _XSTR(MODULE_NAME)

        /*
	 *
	 * Python interface
	 *
	 */

typedef struct 
{
	PyObject_HEAD 
	stream_state st;
} ALGobject;

/* Please see PEP3123 for a discussion of PyObject_HEAD and changes made in 3.x to make it conform to Standard C.
 * These changes also dictate using Py_TYPE to check type, and PyVarObject_HEAD_INIT(NULL, 0) to initialize
 */
staticforward PyTypeObject ALGtype;

static ALGobject *
newALGobject(void)
{
	ALGobject * new;
	new = PyObject_New(ALGobject, &ALGtype);
	return new;
}

static void
ALGdealloc(PyObject *ptr)
{
	ALGobject *self = (ALGobject *)ptr;

	/* Overwrite the contents of the object */
	memset((char*)&(self->st), 0, sizeof(stream_state));
	PyObject_Del(ptr);
}

static char ALGnew__doc__[] = 
"Return a new " _MODULE_STRING " encryption object.";

static char *kwlist[] = {"key", NULL};

static ALGobject *
ALGnew(PyObject *self, PyObject *args, PyObject *kwdict)
{
	unsigned char *key;
	ALGobject * new;
	int keylen;

	new = newALGobject();
	if (!PyArg_ParseTupleAndKeywords(args, kwdict, "s#", kwlist, 
					 &key, &keylen))
	{
		Py_DECREF(new);
		return NULL;
	}

	if (KEY_SIZE!=0 && keylen != KEY_SIZE)
	{
		PyErr_SetString(PyExc_ValueError, 
				_MODULE_STRING " key must be "
				"KEY_SIZE bytes long");
		return NULL;
	}
	if (KEY_SIZE== 0 && keylen == 0)
	{
		PyErr_SetString(PyExc_ValueError, 
				_MODULE_STRING " key cannot be "
				"the null string (0 bytes long)");
		return NULL;
	}
	stream_init(&(new->st), key, keylen);
	if (PyErr_Occurred())
	{
		Py_DECREF(new);
		return NULL;
	}
	return new;
}

static char ALG_Encrypt__doc__[] =
"Decrypt the provided string of binary data.";

static PyObject *
ALG_Encrypt(ALGobject *self, PyObject *args)
{
	unsigned char *buffer, *str;
	int len;
	PyObject *result;

	if (!PyArg_Parse(args, "s#", &str, &len))
		return NULL;
	if (len == 0)			/* Handle empty string */
	{
		return PyBytes_FromStringAndSize(NULL, 0);
	}
	buffer = malloc(len);
	if (buffer == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "No memory available in "
				_MODULE_STRING " encrypt");
		return NULL;
	}
	Py_BEGIN_ALLOW_THREADS;
	memcpy(buffer, str, len);
	stream_encrypt(&(self->st), buffer, len);
	Py_END_ALLOW_THREADS;
	result = PyBytes_FromStringAndSize((char *)buffer, len);
	free(buffer);
	return (result);
}

static char ALG_Decrypt__doc__[] =
"decrypt(string): Decrypt the provided string of binary data.";

static PyObject *
ALG_Decrypt(ALGobject *self, PyObject *args)
{
	unsigned char *buffer, *str;
	int len;
	PyObject *result;

	if (!PyArg_Parse(args, "s#", &str, &len))
		return NULL;
	if (len == 0)			/* Handle empty string */
	{
		return PyBytes_FromStringAndSize(NULL, 0);
	}
	buffer = malloc(len);
	if (buffer == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "No memory available in "
				_MODULE_STRING " decrypt");
		return NULL;
	}
	Py_BEGIN_ALLOW_THREADS;
	memcpy(buffer, str, len);
	stream_decrypt(&(self->st), buffer, len);
	Py_END_ALLOW_THREADS;
	result = PyBytes_FromStringAndSize((char *)buffer, len);
	free(buffer);
	return (result);
}

/* ALGobject methods */
static PyMethodDef ALGmethods[] =
 {
	{"encrypt", (PyCFunction) ALG_Encrypt, METH_O, ALG_Encrypt__doc__},
	{"decrypt", (PyCFunction) ALG_Decrypt, METH_O, ALG_Decrypt__doc__},
 	{NULL, NULL}			/* sentinel */
 };

static PyObject *
ALGgetattro(PyObject *self, PyObject *attr)
{
	if (!PyString_Check(attr))
		goto generic;

	if (PyString_CompareWithASCIIString(attr, "block_size") == 0)
	{
		return PyInt_FromLong(BLOCK_SIZE);
	}
	if (PyString_CompareWithASCIIString(attr, "key_size") == 0)
	{
		return PyInt_FromLong(KEY_SIZE);
	}
  generic:
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	return PyObject_GenericGetAttr(self, attr);
#else
	if (PyString_Check(attr) < 0) {
		PyErr_SetObject(PyExc_AttributeError, attr);
		return NULL;
	}
	return Py_FindMethod(ALGmethods, (PyObject *)self, PyString_AsString(attr));
#endif
}

/* List of functions defined in the module */

static struct PyMethodDef modulemethods[] =
{
	{"new", (PyCFunction) ALGnew, 
	 METH_VARARGS|METH_KEYWORDS, ALGnew__doc__},
	{NULL, NULL}			/* sentinel */
};

static PyTypeObject ALGtype =
 {
	PyVarObject_HEAD_INIT(NULL, 0)  /* deferred type init for compilation on Windows, type will be filled in at runtime */
 	_MODULE_STRING,		/*tp_name*/
 	sizeof(ALGobject),	/*tp_size*/
 	0,				/*tp_itemsize*/
 	/* methods */
	(destructor) ALGdealloc,	/*tp_dealloc*/
 	0,				/*tp_print*/
	0,				/*tp_getattr*/
	0,				/*tp_setattr*/
	0,				/*tp_compare*/
	0,				/*tp_repr*/
 	0,				/*tp_as_number*/
	0,				/*tp_as_sequence*/
	0,				/*tp_as_mapping*/
	0,				/*tp_hash*/
	0,				/*tp_call*/
	0,				/*tp_str*/
	ALGgetattro,	/*tp_getattro*/
	0,				/*tp_setattro*/
	0,				/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,		/*tp_flags*/
	0,				/*tp_doc*/
	0,				/*tp_traverse*/
	0,				/*tp_clear*/
	0,				/*tp_richcompare*/
	0,				/*tp_weaklistoffset*/
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	0,				/*tp_iter*/
	0,				/*tp_iternext*/
	ALGmethods,		/*tp_methods*/
#endif
 };

#ifdef IS_PY3K
 static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"Crypto.Cipher." _MODULE_STRING,
	NULL,
	-1,
	modulemethods,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif

/* Initialization function for the module */

PyMODINIT_FUNC
_MODULE_NAME (void)
{
	PyObject *m = NULL;
	PyObject *__all__ = NULL;

	if (PyType_Ready(&ALGtype) < 0)
		goto errout;

#ifdef IS_PY3K
	/* Create the module and add the functions */
	m = PyModule_Create(&moduledef);
#else
	/* Create the module and add the functions */
	m = Py_InitModule("Crypto.Cipher." _MODULE_STRING, modulemethods);
#endif
	if (m == NULL)
		goto errout;

	/* Add the type object to the module (using the name of the module itself),
	 * so that its methods docstrings are discoverable by introspection tools. */
	PyObject_SetAttrString(m, _MODULE_STRING, (PyObject *)&ALGtype);

	/* Add some symbolic constants to the module */
	PyModule_AddIntConstant(m, "block_size", BLOCK_SIZE);
	PyModule_AddIntConstant(m, "key_size", KEY_SIZE);

	/* Create __all__ (to help generate documentation) */
	__all__ = PyList_New(4);
	if (__all__ == NULL)
		goto errout;
	PyList_SetItem(__all__, 0, PyString_FromString(_MODULE_STRING));	/* This is the ALGType object */
	PyList_SetItem(__all__, 1, PyString_FromString("new"));
	PyList_SetItem(__all__, 2, PyString_FromString("block_size"));
	PyList_SetItem(__all__, 3, PyString_FromString("key_size"));
	PyObject_SetAttrString(m, "__all__", __all__);

out:
	/* Final error check */
	if (m == NULL && !PyErr_Occurred()) {
		PyErr_SetString(PyExc_ImportError, "can't initialize module");
		goto errout;
	}

	/* Free local objects here */
	Py_CLEAR(__all__);

	/* Return */
#ifdef IS_PY3K
	return m;
#else
	return;
#endif

errout:
	/* Free the module and other global objects here */
	Py_CLEAR(m);
	goto out;
}

/* vim:set ts=4 sw=4 sts=0 noexpandtab: */
