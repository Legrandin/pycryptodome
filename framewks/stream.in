/* -*- C -*- */

/*
 *  stream.in : Generic framework for stream ciphers
 *
 * Part of the Python Cryptography Toolkit, version 1.1
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

#ifdef __GNUC__
#define inline __inline__
#else
#define inline
#endif


 /* Endianness testing and definitions */
#define TestEndianness(variable) {int i=1; variable=PCT_BIG_ENDIAN;\
                                  if (*((char*)&i)==1) variable=PCT_LITTLE_ENDIAN;}

#define PCT_LITTLE_ENDIAN 1
#define PCT_BIG_ENDIAN 0


        /*
	 *
	 * Python interface
	 *
	 */

#define PCTObject_HEAD PyObject_HEAD int dummy /* dummy is never used */
#define PCT_Str(x) #x
/* GetKeywordArg has been abandoned for PyArg_ParseTupleAndKeywords */
#define GetKeywordArg(name, default) {\
		   PyObject *arg; \
                   if (kwdict==NULL || \
                       (( arg=PyDict_GetItemString(kwdict, PCT_Str(name)))==NULL )) {new->name = default;} else { \
		     if (!PyInt_Check(arg)) \
		       { \
			 PyErr_SetString(PyExc_TypeError, "Keyword argument must have integer value"); \
			 Py_DECREF(new); \
			 return NULL; \
		       } \
		     new->name = PyInt_AsLong(arg); \
		   } \
		 }

@@IMPLEMENTATION@@


staticforward PyTypeObject @@ALGORITHM@@type;

#define is_@@ALGORITHM@@object(v)		((v)->ob_type == &@@ALGORITHM@@type)

static @@ALGORITHM@@object *
 new@@ALGORITHM@@object()
{
 @@ALGORITHM@@object * new;
 new = PyObject_NEW(@@ALGORITHM@@object, &@@ALGORITHM@@type);
 return new;
}

static void
@@ALGORITHM@@dealloc(self)
@@ALGORITHM@@object * self;
{	      	/* Overwrite the contents of the object, just in case... */
 int i;

 for (i = 0; i < sizeof(@@ALGORITHM@@object); i++)
  *((char *) self + i) = '\0';
 PyMem_DEL(self);
}

static char @@ALGORITHM@@new__doc__[] = 
"Return a new @@ALGORITHM@@ encryption object.";

static char *kwlist[] = {"key", @@KEYWORDLIST@@ 
			 NULL};

static @@ALGORITHM@@object *
@@ALGORITHM@@new(self, args, kwdict)
     PyObject *self;		/* Not used */
     PyObject *args;
     PyObject *kwdict;
{
 unsigned char *key;
 @@ALGORITHM@@object * new;
 int keylen;

 new = new@@ALGORITHM@@object();
 @@KEYWORDDEFAULTS@@
 if (!PyArg_ParseTupleAndKeywords(args, kwdict, "s#" @@KEYWORDFMT@@, kwlist, 
				  &key, &keylen @@KEYWORDPTRS@@))
   {
     Py_DECREF(new);
     return (NULL);
   }

 if (@@KEYSIZE@@!=0 && keylen != @@KEYSIZE@@)
   {
    PyErr_SetString(PyExc_ValueError, "@@ALGORITHM@@ key must be "
		    "@@KEYSIZE@@ bytes long");
    return (NULL);
   }
 if (@@KEYSIZE@@== 0 && keylen == 0)
   {
    PyErr_SetString(PyExc_ValueError, "@@ALGORITHM@@ key cannot be "
		    "the null string (0 bytes long)");
    return (NULL);
   }
 @@ALGORITHM@@init(new, key, keylen);
 if (PyErr_Occurred())
   {
    Py_DECREF(new);
    return (NULL);
   }
 return new;
}

static char @@ALGORITHM@@_Encrypt__doc__[] =
"Decrypt the provided string of binary data.";

static PyObject *
@@ALGORITHM@@_Encrypt(self, args)
@@ALGORITHM@@object * self;
     PyObject *args;
{
 unsigned char *buffer, *str;
 int len;
 PyObject *result;

 if (!PyArg_Parse(args, "s#", &str, &len))
  return (NULL);
 if (len == 0)			/* Handle empty string */
   {
    return PyString_FromStringAndSize(NULL, 0);
   }
 buffer = malloc(len);
 if (buffer == NULL)
   {
    PyErr_SetString(PyExc_MemoryError, "No memory available in "
		    "@@ALGORITHM@@ encrypt");
    return (NULL);
   }
 memcpy(buffer, str, len);
 @@ALGORITHM@@encrypt(self, buffer, len);
 result = PyString_FromStringAndSize(buffer, len);
 free(buffer);
 return (result);
}

static char @@ALGORITHM@@_Decrypt__doc__[] =
"Decrypt the provided string of binary data.";

static PyObject *
@@ALGORITHM@@_Decrypt(self, args)
@@ALGORITHM@@object * self;
     PyObject *args;
{
 char *buffer, *str;
 int len;
 PyObject *result;

 if (!PyArg_Parse(args, "s#", &str, &len))
  return (NULL);
 if (len == 0)			/* Handle empty string */
   {
    return PyString_FromStringAndSize(NULL, 0);
   }
 buffer = malloc(len);
 if (buffer == NULL)
   {
    PyErr_SetString(PyExc_MemoryError, "No memory available in "
		    "@@ALGORITHM@@ decrypt");
    return (NULL);
   }
 memcpy(buffer, str, len);
 @@ALGORITHM@@decrypt(self, buffer, len);
 result = PyString_FromStringAndSize(buffer, len);
 free(buffer);
 return (result);
}

/* @@ALGORITHM@@object methods */

static PyMethodDef @@ALGORITHM@@methods[] =
{
 {"encrypt", (PyCFunction) @@ALGORITHM@@_Encrypt, 0, @@ALGORITHM@@_Encrypt__doc__},
 {"decrypt", (PyCFunction) @@ALGORITHM@@_Decrypt, 0, @@ALGORITHM@@_Decrypt__doc__},
 {NULL, NULL}			/* sentinel */
};

static PyObject *
@@ALGORITHM@@getattr(self, name)
@@ALGORITHM@@object * self;
     char *name;
{
  if (strcmp(name, "blocksize") == 0)
     {
       return PyInt_FromLong(@@BLOCKSIZE@@);
     }
  if (strcmp(name, "keysize") == 0)
     {
       return PyInt_FromLong(@@KEYSIZE@@);
     }
 return Py_FindMethod(@@ALGORITHM@@methods, (PyObject *) self, name);
}


/* List of functions defined in the module */

static struct PyMethodDef modulemethods[] =
{
 {"new", (PyCFunction) @@ALGORITHM@@new, METH_VARARGS|METH_KEYWORDS, @@ALGORITHM@@new__doc__},
 {NULL, NULL}			/* sentinel */
};

static PyTypeObject @@ALGORITHM@@type =
{
 PyObject_HEAD_INIT(NULL)
 0,				/*ob_size*/
 "@@ALGORITHM@@",		/*tp_name*/
 sizeof(@@ALGORITHM@@object),	/*tp_size*/
 0,				/*tp_itemsize*/
 /* methods */
 @@ALGORITHM@@dealloc,	/*tp_dealloc*/
 0,				/*tp_print*/
 @@ALGORITHM@@getattr,	/*tp_getattr*/
 0,		/*tp_setattr*/
 0,			/*tp_compare*/
 0,			/*tp_repr*/
 0,				/*tp_as_number*/
};

/* Initialization function for the module (*must* be called initxx) */

#define insint(n,v) {PyObject *o=PyInt_FromLong(v); if (o!=NULL) {PyDict_SetItemString(d,n,o); Py_DECREF(o);}}

void
 init@@MODNAME@@()
{
 PyObject *m, *d, *x;

 @@ALGORITHM@@type.ob_type = &PyType_Type;
 /* Create the module and add the functions */
 m = Py_InitModule("@@MODNAME@@", modulemethods);

 /* Add some symbolic constants to the module */
 d = PyModule_GetDict(m);
 x = PyString_FromString("@@MODNAME@@.error");
 PyDict_SetItemString(d, "error", x);

 insint("blocksize", @@BLOCKSIZE@@);
 insint("keysize", @@KEYSIZE@@);

 /* Check for errors */
 if (PyErr_Occurred())
  Py_FatalError("can't initialize module @@MODNAME@@");
}


