/* -*- C -*- */

/*
 *  stream_template.c : Generic framework for stream ciphers
 *
 * Distribute and use freely; there are no restrictions on further 
 * dissemination and usage except those imposed by the laws of your 
 * country of residence.  This software is provided "as is" without
 * warranty of fitness for use or suitability for any purpose, express
 * or implied. Use at your own risk or not at all. 
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _HAVE_STDC_HEADERS
#include <string.h>
#endif

#include "Python.h"
#include "modsupport.h"

#define _STR(x) #x
#define _XSTR(x) _STR(x)
#define _PASTE(x,y) x##y
#define _PASTE2(x,y) _PASTE(x,y)
#define _MODULE_NAME _PASTE2(init,MODULE_NAME)
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

staticforward PyTypeObject ALGtype;

#define is_ALGobject(v)		((v)->ob_type == &ALGtype)

static ALGobject *
newALGobject(void)
{
	ALGobject * new;
	new = PyObject_NEW(ALGobject, &ALGtype);
	return new;
}

static void
ALGdealloc(PyObject *self)
{
	int i;
	
	/* Overwrite the contents of the object, just in case... */	
	for (i = 0; i < sizeof(ALGobject); i++)
		*((char *) self + i) = '\0';
	PyObject_DEL(self);
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
		return PyString_FromStringAndSize(NULL, 0);
	}
	buffer = malloc(len);
	if (buffer == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "No memory available in "
				_MODULE_STRING " encrypt");
		return NULL;
	}
	memcpy(buffer, str, len);
	stream_encrypt(&(self->st), buffer, len);
	result = PyString_FromStringAndSize(buffer, len);
	free(buffer);
	return (result);
}

static char ALG_Decrypt__doc__[] =
"decrypt(string): Decrypt the provided string of binary data.";

static PyObject *
ALG_Decrypt(ALGobject *self, PyObject *args)
{
	char *buffer, *str;
	int len;
	PyObject *result;

	if (!PyArg_Parse(args, "s#", &str, &len))
		return NULL;
	if (len == 0)			/* Handle empty string */
	{
		return PyString_FromStringAndSize(NULL, 0);
	}
	buffer = malloc(len);
	if (buffer == NULL)
	{
		PyErr_SetString(PyExc_MemoryError, "No memory available in "
				_MODULE_STRING " decrypt");
		return NULL;
	}
	memcpy(buffer, str, len);
	stream_decrypt(&(self->st), buffer, len);
	result = PyString_FromStringAndSize(buffer, len);
	free(buffer);
	return (result);
}

/* ALGobject methods */

static PyMethodDef ALGmethods[] =
{
	{"encrypt", (PyCFunction) ALG_Encrypt, 0, ALG_Encrypt__doc__},
	{"decrypt", (PyCFunction) ALG_Decrypt, 0, ALG_Decrypt__doc__},
	{NULL, NULL}			/* sentinel */
};

static PyObject *
ALGgetattr(PyObject *self, char *name)
{
	if (strcmp(name, "block_size") == 0)
	{
		return PyInt_FromLong(BLOCK_SIZE);
	}
	if (strcmp(name, "key_size") == 0)
	{
		return PyInt_FromLong(KEY_SIZE);
	}
	return Py_FindMethod(ALGmethods, self, name);
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
	PyObject_HEAD_INIT(NULL)
	0,				/*ob_size*/
	_MODULE_STRING,		/*tp_name*/
	sizeof(ALGobject),	/*tp_size*/
	0,				/*tp_itemsize*/
	/* methods */
	ALGdealloc,	/*tp_dealloc*/
	0,				/*tp_print*/
	ALGgetattr,	/*tp_getattr*/
	0,		/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,				/*tp_as_number*/
};

/* Initialization function for the module */

#if PYTHON_API_VERSION < 1011
#define PyModule_AddIntConstant(m,n,v) {PyObject *o=PyInt_FromLong(v); \
           if (o!=NULL) \
             {PyDict_SetItemString(PyModule_GetDict(m),n,o); Py_DECREF(o);}}
#endif

void
_MODULE_NAME (void)
{
	PyObject *m, *d, *x;

	ALGtype.ob_type = &PyType_Type;
	/* Create the module and add the functions */
	m = Py_InitModule("Crypto.Cipher." _MODULE_STRING, modulemethods);

	/* Add some symbolic constants to the module */
	d = PyModule_GetDict(m);
	x = PyString_FromString(_MODULE_STRING ".error");
	PyDict_SetItemString(d, "error", x);

	PyModule_AddIntConstant(m, "block_size", BLOCK_SIZE);
	PyModule_AddIntConstant(m, "key_size", KEY_SIZE);

	/* Check for errors */
	if (PyErr_Occurred())
		Py_FatalError("can't initialize module " _MODULE_STRING);
}
