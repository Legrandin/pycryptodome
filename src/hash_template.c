/*
 *  hash_template.c : Generic framework for hash function extension modules
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
  
/* Basic object type */

#include "pycrypto_common.h"
#include <string.h>

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

typedef struct {
	PyObject_HEAD
	hash_state st;
} ALGobject;

/* Please see PEP3123 for a discussion of PyObject_HEAD and changes made in 3.x to make it conform to Standard C.
 * These changes also dictate using Py_TYPE to check type, and PyVarObject_HEAD_INIT(NULL, 0) to initialize
 */
staticforward PyTypeObject ALGtype;

static char ALG__doc__[] =
"Class that implements a " _MODULE_STRING " hash.";

static ALGobject *
newALGobject(void)
{
	ALGobject *new;

	new = PyObject_New(ALGobject, &ALGtype);
	return new;
}

/* Internal methods for a hashing object */

static void
ALG_dealloc(PyObject *ptr)
{
	ALGobject *self = (ALGobject *)ptr;

	/* Overwrite the contents of the object */
	memset((char*)&(self->st), 0, sizeof(hash_state));
	PyObject_Del(ptr);
}


/* External methods for a hashing object */

static char ALG_copy__doc__[] =
"copy()\n"
"Return a copy (\"clone\") of the hash object.\n"
"\n"
"The copy will have the same internal state as the original hash\n"
"object.\n"
"This can be used to efficiently compute the digests of strings that\n"
"share a common initial substring.\n"
"\n"
":Return: A hash object of the same type\n";

static PyObject *
ALG_copy(ALGobject *self, PyObject *args)
{
	ALGobject *newobj;

	if (!PyArg_ParseTuple(args, "")) {
		return NULL;
	}
	
	if ( (newobj = newALGobject())==NULL)
		return NULL;

	hash_copy(&(self->st), &(newobj->st));
	return((PyObject *)newobj); 
}

static char ALG_digest__doc__[] =
"digest()\n"
"Return the **binary** (non-printable) digest of the message that has been hashed so far.\n"
"\n"
"This method does not change the state of the hash object.\n"
"You can continue updating the object after calling this function.\n"
"\n"
":Return: A byte string of `digest_size` bytes. It may contain non-ASCII\n"
"characters, including null bytes.\n";

static PyObject *
ALG_digest(ALGobject *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	return (PyObject *)hash_digest(&(self->st));
}

static char ALG_hexdigest__doc__[] =
"hexdigest()\n"
"Return the **printable** digest of the message that has been hashed so far.\n"
"\n"
"This method does not change the state of the hash object.\n"
"\n"
":Return: A string of 2* `digest_size` characters. It contains only\n"
"hexadecimal ASCII digits.\n";

static PyObject *
ALG_hexdigest(ALGobject *self, PyObject *args)
{
	PyObject *value, *retval;
	unsigned char *raw_digest, *hex_digest;
	int i, j, size;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	/* Get the raw (binary) digest value */
	value = (PyObject *)hash_digest(&(self->st));
	size = PyBytes_Size(value);
	raw_digest = (unsigned char *) PyBytes_AsString(value);

	/* Create a new string */
	retval = PyBytes_FromStringAndSize(NULL, size * 2 );
	hex_digest = (unsigned char *) PyBytes_AsString(retval);

	/* Make hex version of the digest */
	for(i=j=0; i<size; i++)
	{
		char c;
		c = raw_digest[i] / 16; c = (c>9) ? c+'a'-10 : c + '0';
		hex_digest[j++] = c;
		c = raw_digest[i] % 16; c = (c>9) ? c+'a'-10 : c + '0';
		hex_digest[j++] = c;
	}
#ifdef IS_PY3K
	/* Create a text string return value */
	retval = PyUnicode_FromEncodedObject(retval,"latin-1","strict");
#endif

	Py_DECREF(value);
	return retval;
}

static char ALG_update__doc__[] =
"update(data)\n"
"Continue hashing of a message by consuming the next chunk of data.\n"
"\n"
"Repeated calls are equivalent to a single call with the concatenation\n"
"of all the arguments. In other words:\n"
"\n"
"   >>> m.update(a); m.update(b)\n"
"\n"
"is equivalent to:\n"
"\n"
"   >>> m.update(a+b)\n"
"\n"
":Parameters:\n"
"  data : byte string\n"
"    The next chunk of the message being hashed.\n";

static PyObject *
ALG_update(ALGobject *self, PyObject *args)
{
	unsigned char *cp;
	int len;

	if (!PyArg_ParseTuple(args, "s#", &cp, &len))
		return NULL;

	Py_BEGIN_ALLOW_THREADS;

	hash_update(&(self->st), cp, len);
	Py_END_ALLOW_THREADS;

	Py_INCREF(Py_None);

	return Py_None;
}

/** Forward declaration for this module's new() method **/
static char ALG_new__doc__[] =
"new(data=None)\n"
"Return a fresh instance of the hash object.\n"
"\n"
":Parameters:\n"
"   data : byte string\n"
"    The very first chunk of the message to hash.\n"
"    It is equivalent to an early call to `" _MODULE_STRING ".update()`.\n"
"    Optional.\n"
"\n"
":Return: A `" _MODULE_STRING "` object\n";

static PyObject *ALG_new(PyObject*, PyObject*);

static PyMethodDef ALG_methods[] = {
	{"copy", (PyCFunction)ALG_copy, METH_VARARGS, ALG_copy__doc__},
	{"digest", (PyCFunction)ALG_digest, METH_VARARGS, ALG_digest__doc__},
	{"hexdigest", (PyCFunction)ALG_hexdigest, METH_VARARGS, ALG_hexdigest__doc__},
	{"update", (PyCFunction)ALG_update, METH_VARARGS, ALG_update__doc__},
	{"new", (PyCFunction)ALG_new, METH_VARARGS, ALG_new__doc__},
	{NULL,			NULL}		/* sentinel */
};

static PyObject *
ALG_getattro(PyObject *self, PyObject *attr)
{
	if (!PyString_Check(attr))
		goto generic;

	if (PyString_CompareWithASCIIString(attr, "digest_size")==0)
		return PyInt_FromLong(DIGEST_SIZE);
	if (PyString_CompareWithASCIIString(attr, "name")==0)
		return PyString_FromString(_MODULE_STRING);     /* we should try to be compatible with hashlib here */

  generic:
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	return PyObject_GenericGetAttr(self, attr);
#else
	if (PyString_Check(attr) < 0) {
		PyErr_SetObject(PyExc_AttributeError, attr);
		return NULL;
	}
	return Py_FindMethod(ALG_methods, (PyObject *)self, PyString_AsString(attr));
#endif
}

static PyTypeObject ALGtype = {
	PyVarObject_HEAD_INIT(NULL, 0)  /* deferred type init for compilation on Windows, type will be filled in at runtime */
 	_MODULE_STRING,			/*tp_name*/
 	sizeof(ALGobject),	/*tp_size*/
 	0,			/*tp_itemsize*/
 	/* methods */
	(destructor) ALG_dealloc, /*tp_dealloc*/
 	0,			/*tp_print*/
	0,			/*tp_getattr*/
 	0,			/*tp_setattr*/
 	0,			/*tp_compare*/
 	0,			/*tp_repr*/
    0,			/*tp_as_number*/
	0,				/*tp_as_sequence */
	0,				/*tp_as_mapping */
	0,				/*tp_hash*/
	0,				/*tp_call*/
	0,				/*tp_str*/
	ALG_getattro,	/*tp_getattro*/
	0,				/*tp_setattro*/
	0,				/*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT,		/*tp_flags*/
	ALG__doc__,	/*tp_doc*/
	0,				/*tp_traverse*/
	0,				/*tp_clear*/
	0,				/*tp_richcompare*/
	0,				/*tp_weaklistoffset*/
#if PYTHON_API_VERSION >= 1011          /* Python 2.2 and later */
	0,				/*tp_iter*/
	0,				/*tp_iternext*/
	ALG_methods,		/*tp_methods*/
#endif
 };

/* The single module-level function: new() */

/** This method belong to both the module and the hash object **/
static PyObject *
ALG_new(PyObject *self, PyObject *args)
{
        ALGobject *new;
	unsigned char *cp = NULL;
	int len;
	
	if ((new = newALGobject()) == NULL)
		return NULL;

	if (!PyArg_ParseTuple(args, "|s#",
			      &cp, &len)) {
	        Py_DECREF(new);
		return NULL;
	}

        hash_init(&(new->st));

	if (PyErr_Occurred()) {
		Py_DECREF(new); 
		return NULL;
	}
	if (cp) {
		Py_BEGIN_ALLOW_THREADS;
		hash_update(&(new->st), cp, len);
		Py_END_ALLOW_THREADS;
	}

	return (PyObject *)new;
}

/* List of functions exported by this module */

static struct PyMethodDef ALG_functions[] = {
	{"new", (PyCFunction)ALG_new, METH_VARARGS, ALG_new__doc__},
	{NULL,			NULL}		 /* Sentinel */
};

#ifdef IS_PY3K
static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"Crypto.Hash." _MODULE_STRING,  /* m_name */
	MODULE__doc__,                  /* m_doc */
	-1,                             /* m_size */
	ALG_functions,                  /* m_methods */
	NULL,                           /* m_reload */
	NULL,                           /* m_traverse */
	NULL,                           /* m_clear */
	NULL                            /* m_free */
};
#endif

/* Initialize this module. */

PyMODINIT_FUNC
_MODULE_NAME (void)
{
	PyObject *m = NULL;
	PyObject *__all__ = NULL;

	if (PyType_Ready(&ALGtype) < 0)
		goto errout;

	/* Create the module and add the functions */
#ifdef IS_PY3K
	m = PyModule_Create(&moduledef);
#else
	m = Py_InitModule3("Crypto.Hash." _MODULE_STRING, ALG_functions, MODULE__doc__);
#endif
	if (m == NULL)
		goto errout;

	/* Add the type object to the module (using the name of the module itself),
	 * so that its methods docstrings are discoverable by introspection tools. */
	PyObject_SetAttrString(m, _MODULE_STRING, (PyObject *)&ALGtype);

	/* Add some symbolic constants to the module */
	PyModule_AddIntConstant(m, "digest_size", DIGEST_SIZE);
	PyModule_AddIntConstant(m, "block_size", BLOCK_SIZE);

	/* Create __all__ (to help generate documentation) */
	__all__ = PyList_New(4);
	if (__all__ == NULL)
		goto errout;
	PyList_SetItem(__all__, 0, PyString_FromString(_MODULE_STRING));	/* This is the ALGType object */
	PyList_SetItem(__all__, 1, PyString_FromString("new"));
	PyList_SetItem(__all__, 2, PyString_FromString("digest_size"));
	PyList_SetItem(__all__, 3, PyString_FromString("block_size"));
	PyObject_SetAttrString(m, "__all__", __all__);

out:
	/* Final error check, then return */
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
